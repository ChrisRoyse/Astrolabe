/*
 * mcp.c — MCP server: JSON-RPC 2.0 over stdio with 14 graph tools.
 *
 * Uses yyjson for fast JSON parsing/building.
 * Single-threaded event loop: read line → parse → dispatch → respond.
 */

// operations

#include "foundation/constants.h"
#include "foundation/schema_version.h"

enum {
    MCP_FIELD_SIZE = 1040,
    MCP_TIMEOUT_MS = 1000,
    MCP_HALF_SEC_US = 500000,
    MCP_MAX_ROWS = 100,
    MCP_COL_2 = 2,
    MCP_COL_3 = 3,
    MCP_COL_4 = 4,
    MCP_COL_7 = 7,
    MCP_COL_10 = 10,
    MCP_COL_16 = 16,
    MCP_DB_EXT = 3,      /* strlen(".db") */
    MCP_MIN_DB_NAME = 4, /* min length for "x.db" */
    MCP_SEPARATOR = 2,   /* space for separator chars */
    MCP_DEFAULT_DEPTH = 3,
    MCP_DEFAULT_BFS_DEPTH = 2,
    MCP_DEFAULT_LIMIT = 10,
    MCP_BFS_LIMIT = 100,
    MCP_N_DEFAULTS_2 = 2,
    MCP_URI_PREFIX = 7,      /* strlen("file://") */
    MCP_CONTENT_PREFIX = 15, /* strlen("Content-Length:") */
    MCP_RETURN_2 = 2,
    MCP_TOOLS_PAGE_SIZE = 8,
};
#define MCP_MS_TO_US 1000LL
#define MCP_S_TO_US 1000000LL

#define SLEN(s) (sizeof(s) - 1)
#include "mcp/mcp.h"
#include "store/store.h"
#include <sqlite3.h>
#include "cypher/cypher.h"
#include "pipeline/pipeline.h"
#include "pipeline/pass_cross_repo.h"
#include "git/git_context.h"
#include "cli/cli.h"
#include "watcher/watcher.h"
#include "foundation/mem.h"
#include "foundation/diagnostics.h"
#include "foundation/platform.h"
#include "foundation/dyn_array.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/log.h"
#include "foundation/limits.h"
#include "mcp/index_supervisor.h"
#include "foundation/str_util.h"
#include "foundation/compat_regex.h"
#include "pipeline/artifact.h"
#include "traces/otlp_decode.h"
#include "traces/trace_ingest.h"

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#endif
#include <yyjson/yyjson.h>
#include <limits.h>
#include <stdint.h> // int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* ── Constants ────────────────────────────────────────────────── */

/* Default snippet fallback line count */
#define SNIPPET_DEFAULT_LINES 50

/* Idle store eviction: close cached project store after this many seconds
 * of inactivity to free SQLite memory during idle periods. */
#define STORE_IDLE_TIMEOUT_S 60

/* Directory permissions: rwxr-xr-x */
#define ADR_DIR_PERMS 0755

/* JSON-RPC 2.0 standard error codes */
#define JSONRPC_PARSE_ERROR (-32700)
#define JSONRPC_METHOD_NOT_FOUND (-32601)

/* ── Helpers ────────────────────────────────────────────────────── */

static char *heap_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *d = malloc(len + SKIP_ONE);
    if (d) {
        memcpy(d, s, len + SKIP_ONE);
    }
    return d;
}

/* Write yyjson_mut_doc to heap-allocated JSON string.
 * ALLOW_INVALID_UNICODE: some database strings may contain non-UTF-8 bytes
 * from older indexing runs — don't fail serialization over it. */
static char *yy_doc_to_str(yyjson_mut_doc *doc) {
    size_t len = 0;
    char *s = yyjson_mut_write(doc, YYJSON_WRITE_ALLOW_INVALID_UNICODE, &len);
    return s;
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON-RPC PARSING
 * ══════════════════════════════════════════════════════════════════ */

int cbm_jsonrpc_parse(const char *line, cbm_jsonrpc_request_t *out) {
    memset(out, 0, sizeof(*out));
    out->id = CBM_NOT_FOUND;

    yyjson_doc *doc = yyjson_read(line, strlen(line), 0);
    if (!doc) {
        return CBM_NOT_FOUND;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return CBM_NOT_FOUND;
    }

    yyjson_val *v_jsonrpc = yyjson_obj_get(root, "jsonrpc");
    yyjson_val *v_method = yyjson_obj_get(root, "method");
    yyjson_val *v_id = yyjson_obj_get(root, "id");
    yyjson_val *v_params = yyjson_obj_get(root, "params");

    if (!v_method || !yyjson_is_str(v_method)) {
        yyjson_doc_free(doc);
        return CBM_NOT_FOUND;
    }

    out->jsonrpc =
        heap_strdup(v_jsonrpc && yyjson_is_str(v_jsonrpc) ? yyjson_get_str(v_jsonrpc) : "2.0");
    out->method = heap_strdup(yyjson_get_str(v_method));

    if (v_id) {
        out->has_id = true;
        if (yyjson_is_int(v_id)) {
            out->id = yyjson_get_int(v_id);
        } else if (yyjson_is_str(v_id)) {
            /* JSON-RPC 2.0 §4 permits string ids (Claude Desktop uses them).
             * Preserve verbatim instead of coercing via strtol (issue #253). */
            out->id_str = heap_strdup(yyjson_get_str(v_id));
        }
    }

    if (v_params) {
        out->params_raw = yyjson_val_write(v_params, 0, NULL);
    }

    yyjson_doc_free(doc);
    return 0;
}

void cbm_jsonrpc_request_free(cbm_jsonrpc_request_t *r) {
    if (!r) {
        return;
    }
    safe_str_free(&r->jsonrpc);
    safe_str_free(&r->method);
    safe_str_free(&r->id_str);
    safe_str_free(&r->params_raw);
    memset(r, 0, sizeof(*r));
}

/* ══════════════════════════════════════════════════════════════════
 *  JSON-RPC FORMATTING
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_jsonrpc_format_response(const cbm_jsonrpc_response_t *resp) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "jsonrpc", "2.0");
    if (resp->id_str) {
        yyjson_mut_obj_add_str(doc, root, "id", resp->id_str);
    } else {
        yyjson_mut_obj_add_int(doc, root, "id", resp->id);
    }

    if (resp->error_json) {
        /* Parse the error JSON and embed */
        yyjson_doc *err_doc = yyjson_read(resp->error_json, strlen(resp->error_json), 0);
        if (err_doc) {
            yyjson_mut_val *err_val = yyjson_val_mut_copy(doc, yyjson_doc_get_root(err_doc));
            yyjson_mut_obj_add_val(doc, root, "error", err_val);
            yyjson_doc_free(err_doc);
        }
    } else if (resp->result_json) {
        /* Parse the result JSON and embed */
        yyjson_doc *res_doc = yyjson_read(resp->result_json, strlen(resp->result_json), 0);
        if (res_doc) {
            yyjson_mut_val *res_val = yyjson_val_mut_copy(doc, yyjson_doc_get_root(res_doc));
            yyjson_mut_obj_add_val(doc, root, "result", res_val);
            yyjson_doc_free(res_doc);
        }
    } else {
        /* JSON-RPC 2.0 spec: response MUST contain "result" or "error" */
        yyjson_mut_obj_add_null(doc, root, "result");
    }

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

char *cbm_jsonrpc_format_error(int64_t id, int code, const char *message) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "jsonrpc", "2.0");
    yyjson_mut_obj_add_int(doc, root, "id", id);

    yyjson_mut_val *err = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_int(doc, err, "code", code);
    yyjson_mut_obj_add_str(doc, err, "message", message);
    yyjson_mut_obj_add_val(doc, root, "error", err);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

/* ══════════════════════════════════════════════════════════════════
 *  MCP PROTOCOL HELPERS
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_mcp_text_result(const char *text, bool is_error) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *content = yyjson_mut_arr(doc);
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, item, "type", "text");
    yyjson_mut_obj_add_str(doc, item, "text", text ? text : "");
    yyjson_mut_arr_add_val(content, item);
    yyjson_mut_obj_add_val(doc, root, "content", content);

    if (!is_error && text) {
        yyjson_doc *structured_doc = yyjson_read(text, strlen(text), 0);
        if (structured_doc) {
            yyjson_val *structured_root = yyjson_doc_get_root(structured_doc);
            if (yyjson_is_obj(structured_root)) {
                yyjson_mut_val *structured = yyjson_val_mut_copy(doc, structured_root);
                yyjson_mut_obj_add_val(doc, root, "structuredContent", structured);
            }
            yyjson_doc_free(structured_doc);
        }
    }
    yyjson_mut_obj_add_bool(doc, root, "isError", is_error);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

bool cbm_mcp_cancel_request_matches(const char *params_json, int64_t active_id,
                                    const char *active_id_str) {
    if (!params_json) {
        return false;
    }

    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return false;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *request_id = yyjson_obj_get(root, "requestId");
    bool matches = false;
    if (request_id) {
        if (active_id_str) {
            matches =
                yyjson_is_str(request_id) && strcmp(yyjson_get_str(request_id), active_id_str) == 0;
        } else {
            matches = yyjson_is_int(request_id) && yyjson_get_int(request_id) == active_id;
        }
    }

    yyjson_doc_free(doc);
    return matches;
}

/* ── Tool definitions ─────────────────────────────────────────── */

typedef struct {
    const char *name;
    const char *title;
    const char *description;
    const char *input_schema; /* JSON string */
} tool_def_t;

static const tool_def_t TOOLS[] = {
    {"index_repository", "Index repository",
     "Index a repository into the knowledge graph. "
     "Special mode 'cross-repo-intelligence': skip extraction, only match Routes/Channels "
     "across projects to create CROSS_HTTP_CALLS/CROSS_ASYNC_CALLS/CROSS_CHANNEL edges. "
     "Requires target_projects param. Ensure target projects have fresh indexes first.",
     "{\"type\":\"object\",\"properties\":{\"repo_path\":{\"type\":\"string\",\"description\":"
     "\"Path to the repository\"},"
     "\"mode\":{\"type\":\"string\","
     "\"enum\":[\"full\",\"moderate\",\"fast\",\"cross-repo-intelligence\"],"
     "\"default\":\"full\",\"description\":\"All modes run type-aware LSP call/usage "
     "resolution (per-file + cross-file). full: all files + similarity/semantic edges. "
     "moderate: filtered files + similarity/semantic. fast: filtered files, no "
     "similarity/semantic. cross-repo-intelligence: match Routes/Channels across projects.\"},"
     "\"target_projects\":{\"type\":\"array\",\"items\":{\"type\":\"string\"},"
     "\"description\":\"Projects to search for cross-repo links (cross-repo-intelligence mode). "
     "Use [\\\"*\\\"] for all indexed projects. Run list_projects to see available projects.\"},"
     "\"name\":{\"type\":\"string\",\"description\":"
     "\"Override the derived project name. Non-ASCII bytes are encoded and unsafe path characters "
     "are normalized.\"},"
     "\"persistence\":{\"type\":\"boolean\",\"default\":false,\"description\":"
     "\"Write compressed artifact to .codebase-memory/graph.db.zst for team sharing. "
     "Teammates can bootstrap from the artifact instead of full re-indexing.\"}"
     "},\"required\":[\"repo_path\"]}"},

    {"search_graph", "Search graph",
     "Search the code knowledge graph for indexed symbols and structural nodes. Use INSTEAD OF "
     "grep/glob when finding code definitions, implementations, or relationships. Search modes: "
     "(1) query='update settings' for BM25 ranked full-text search with camelCase splitting and "
     "symbol-category boosting — recommended for natural-language discovery; (2) "
     "name_pattern='.*regex.*' for exact pattern matching; (3) semantic_query=[...] for vector "
     "cosine search that bridges vocabulary (finds 'publish' when you search 'send'). The query "
     "mode is exclusive and supports project, label, file_pattern, limit, and offset; exact and "
     "semantic modes may be combined only when query is absent. PAGINATION: results are capped "
     "at limit (default 200). The response includes exact 'total' and deterministic 'has_more'; "
     "page by re-calling with offset=offset+limit until has_more is false. Narrow query mode via "
     "label/file_pattern before paginating large result sets. Every returned node carries its "
     "authoritative persisted start_line, end_line, start_byte, and end_byte; genuinely spanless "
     "structural nodes carry explicit zeroes.",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},"
     "\"query\":{\"type\":\"string\",\"description\":\"Natural-language or keyword full-text "
     "search using BM25 ranking. Identifier punctuation separates terms; camelCase identifiers are "
     "indexed as individual words (updateCloudClient → update, cloud, client). Results are "
     "ranked with symbol-category boosting: Functions/Methods +10, Routes +8, "
     "Classes/Interfaces/Types/Enums +5. Without label, structural containers "
     "File/Folder/Module/Section/Project are excluded; Variables and other symbols remain. An "
     "explicit label selects exactly that label, including a structural label. query cannot be "
     "combined with name_pattern, qn_pattern, relationship, degree/connection filters, or "
     "semantic_query.\"},"
     "\"label\":{\"type\":\"string\",\"description\":\"Exact persisted node label. In query mode, "
     "omitting this excludes only structural containers; providing it selects exactly that "
     "label.\"},"
     "\"name_pattern\":{\"type\":\"string\"},\"qn_pattern\":{"
     "\"type\":\"string\"},\"file_pattern\":{\"type\":\"string\"},"
     "\"relationship\":{\"type\":\"string\"},\"min_degree\":{\"type\":\"integer\"},"
     "\"max_degree\":{\"type\":\"integer\"},\"exclude_entry_points\":{\"type\":\"boolean\"},"
     "\"include_connected\":{\"type\":\"boolean\"},\"semantic_query\":{"
     "\"type\":\"array\",\"items\":{\"type\":\"string\"},\"description\":\"MUST be an ARRAY of "
     "keyword strings (e.g. [\\\"send\\\",\\\"pubsub\\\",\\\"publish\\\"]) — NOT a single string. "
     "Each keyword is scored independently via per-keyword min-cosine; results reflect functions "
     "that score well on ALL keywords. Requires moderate/full index mode. Results appear in the "
     "'semantic_results' field (separate from 'results').\"},\"limit\":{\"type\":"
     "\"integer\",\"description\":\"Max results per call. Default 200. Response carries "
     "'total' (full match count) and 'has_more' (true if truncated) so callers can "
     "detect the limit and paginate.\",\"minimum\":1,\"maximum\":2147483647},"
     "\"offset\":{\"type\":\"integer\",\"default\":0,\"minimum\":0,\"maximum\":2147483647,"
     "\"description\":\"Skip the first N matching nodes. Combine with 'limit' to page: "
     "increment offset by limit and re-call while has_more is true.\"}},"
     "\"required\":[\"project\"]}"},

    {"query_graph", "Query graph",
     "Execute a Cypher query against the knowledge graph for complex multi-hop patterns, "
     "aggregations, and cross-service analysis. The response includes 'total' (returned "
     "row count). There is a hard 100k row ceiling — for broad queries add LIMIT in the "
     "Cypher itself or use search_graph + offset/limit pagination instead. "
     "COMPLEXITY / BOTTLENECKS: every Function and Method node carries queryable complexity "
     "properties — cyclomatic (complexity), cognitive, loop_count, loop_depth (max nested-loop "
     "depth, a polynomial-degree proxy), plus interprocedural transitive_loop_depth (worst-case "
     "nested-loop degree propagated along CALLS edges) and a recursive flag. Additional "
     "hot-path signals: linear_scan_in_loop (count of find/contains/indexOf-style scans inside a "
     "loop — the hidden O(n^2) that loop_depth misses), alloc_in_loop (allocations/appends inside "
     "a loop), recursion_in_loop (a self-call inside a loop), unguarded_recursion (recursion with "
     "no conditionally-guarded base case), param_count and max_access_depth (structure smells). "
     "Find all hot-path candidates in one query, e.g. MATCH (f:Function) WHERE "
     "f.transitive_loop_depth >= 3 OR f.linear_scan_in_loop >= 1 RETURN f.qualified_name, "
     "f.transitive_loop_depth, f.linear_scan_in_loop ORDER BY f.transitive_loop_depth DESC.",
     "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\",\"description\":\"Cypher "
     "query\"},\"project\":{\"type\":\"string\"},\"max_rows\":{\"type\":\"integer\","
     "\"description\":"
     "\"Optional row limit. Default: unlimited up to a 100k row "
     "ceiling. No offset support — use search_graph for paginated browsing.\"}},"
     "\"required\":[\"query\",\"project\"]}"},

    {"trace_path", "Trace path",
     "Trace paths through the code graph. Modes: calls (callers/callees), data_flow (value "
     "propagation with args at each hop), cross_service (through HTTP/async Route nodes). "
     "Use INSTEAD OF grep for callers, dependencies, impact analysis, or data flow tracing.",
     "{\"type\":\"object\",\"properties\":{\"function_name\":{\"type\":\"string\"},\"project\":{"
     "\"type\":\"string\"},\"direction\":{\"type\":\"string\",\"enum\":[\"inbound\",\"outbound\","
     "\"both\"],\"default\":\"both\"},\"depth\":{\"type\":\"integer\",\"default\":3},\"mode\":{"
     "\"type\":\"string\",\"enum\":[\"calls\",\"data_flow\",\"cross_service\"],\"default\":"
     "\"calls\",\"description\":\"calls: follow CALLS edges. data_flow: follow CALLS+DATA_FLOWS "
     "with arg expressions. cross_service: follow HTTP_CALLS+ASYNC_CALLS+DATA_FLOWS through "
     "Routes, plus CROSS_* cross-repo edges (CROSS_HTTP_CALLS/ASYNC_CALLS/CHANNEL/GRPC_CALLS/"
     "GRAPHQL_CALLS/TRPC_CALLS) to hop into other services.\"},\"parameter_name\":{\"type\":"
     "\"string\",\"description\":\"For data_flow mode: "
     "scope trace to a specific parameter name\"},\"edge_types\":{\"type\":\"array\",\"items\":{"
     "\"type\":\"string\"}},\"risk_labels\":{\"type\":\"boolean\",\"default\":false,"
     "\"description\":\"Add risk classification (CRITICAL/HIGH/MEDIUM/LOW) based on hop distance"
     "\"},\"include_tests\":{\"type\":\"boolean\",\"default\":false,"
     "\"description\":\"Include test files in results. When false (default), test files are "
     "filtered out. When true, test nodes are included with is_test=true marker."
     "\"}},\"required\":[\"function_name\",\"project\"]}"},

    {"get_code_snippet", "Get code snippet",
     "Read source code for a function/class/symbol. IMPORTANT: First call search_graph to find the "
     "stable atom_id and pass it here. This is a read tool, not a search tool. A qualified_name "
     "lookup remains available only when it resolves to exactly one source atom.",
     "{\"type\":\"object\",\"properties\":{\"atom_id\":{\"type\":\"string\",\"description\":"
     "\"Stable source atom_id from search_graph (preferred)\"},\"qualified_name\":{"
     "\"type\":\"string\",\"description\":\"Qualified name only when unique\"},\"project\":{"
     "\"type\":\"string\"},\"include_neighbors\":{"
     "\"type\":\"boolean\",\"default\":false}},\"required\":[\"project\"]}"},

    {"get_graph_schema", "Get graph schema",
     "Get the schema of the knowledge graph (node labels, edge types)",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":["
     "\"project\"]}"},

    {"get_architecture", "Get architecture",
     "Get high-level architecture overview — packages, services, dependencies, and project "
     "structure at a glance. Includes 'clusters': Leiden community detection over the call/import "
     "graph, surfacing the de-facto modules (each with a label, member count, cohesion score, "
     "representative top_nodes, and the packages/edge_types that bind it) — use these to grasp "
     "the real architectural seams, which often cut across the folder layout. Optional path scopes "
     "analysis to nodes under that directory prefix (file_path).",
     /* The aspects enum mirrors VALID_ASPECTS (see aspect_is_valid) — update both together. */
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"path\":{\"type\":"
     "\"string\",\"description\":\"Optional directory prefix to scope architecture (e.g. "
     "apps/hoa)\"},"
     "\"aspects\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"enum\":[\"all\","
     "\"overview\",\"structure\",\"dependencies\",\"routes\",\"languages\",\"packages\","
     "\"entry_points\",\"hotspots\",\"boundaries\",\"layers\",\"file_tree\",\"clusters\"]},"
     "\"description\":\"Aspects to include. 'all' = everything; 'overview' = compact summary "
     "(all except file_tree); omit = all.\"}},\"required\":[\"project\"]}"},

    {"search_code", "Search code",
     "Graph-augmented code search. Finds text patterns via grep, then enriches results with "
     "the knowledge graph: deduplicates matches into containing functions, ranks by structural "
     "importance (definitions first, popular functions next, tests last). "
     "Modes: compact (default, signatures only — token efficient), full (with source), "
     "files (just file paths). Use path_filter regex to scope results. "
     "TRUNCATION: enriched results are capped at limit (default 10). Response carries "
     "'total_grep_matches' (raw grep hit count) and 'total_results' (deduplicated function "
     "count) — compare to limit to detect truncation. There is no offset parameter; to see "
     "more, raise limit or narrow the query with file_pattern / path_filter.",
     "{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"},\"project\":{\"type\":"
     "\"string\"},\"file_pattern\":{\"type\":\"string\",\"description\":\"Glob for grep "
     "--include (e.g. *.go)\"},\"path_filter\":{\"type\":\"string\",\"description\":\"Regex "
     "filter on result file paths (e.g. ^src/ or \\\\.(go|ts)$)\"},\"mode\":{\"type\":\"string\","
     "\"enum\":[\"compact\",\"full\",\"files\"],\"default\":\"compact\",\"description\":\"compact: "
     "signatures+metadata (default). full: with source. files: just file list.\"},"
     "\"context\":{\"type\":\"integer\",\"description\":\"Lines of context around each match "
     "(like grep -C). Only used in compact mode.\"},"
     "\"regex\":{\"type\":\"boolean\",\"default\":false},\"limit\":{\"type\":\"integer\","
     "\"description\":\"Max enriched results per call. Default 10. Response includes "
     "'total_grep_matches' and 'total_results' so callers can detect truncation. No "
     "offset parameter — raise limit or narrow with file_pattern / path_filter to see more."
     "\",\"default\":10}},\"required\":[\"pattern\",\"project\"]}"},

    {"list_projects", "List projects", "List all indexed projects",
     "{\"type\":\"object\",\"properties\":{}}"},
    {"delete_project", "Delete project", "Delete a project from the index",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":["
     "\"project\"]}"},

    {"index_status", "Index status", "Get the indexing status of a project",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":["
     "\"project\"]}"},

    {"detect_changes", "Detect changes", "Detect code changes and their impact",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"scope\":{\"type\":"
     "\"string\"},\"depth\":{\"type\":\"integer\",\"default\":2},\"base_branch\":{\"type\":"
     "\"string\",\"default\":\"main\"},\"since\":{\"type\":\"string\",\"description\":"
     "\"Git ref or tag to compare from (e.g. HEAD~5, v0.5.0). Diffs <ref>...HEAD.\"}},"
     "\"required\":"
     "[\"project\"]}"},

    {"manage_adr", "Manage ADR", "Create or update Architecture Decision Records",
     "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},\"mode\":{\"type\":"
     "\"string\",\"enum\":[\"get\",\"update\",\"sections\"]},\"content\":{\"type\":\"string\"},"
     "\"sections\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}},\"required\":[\"project\"]"
     "}"},

    {"ingest_traces", "Ingest traces",
     "Ingest runtime traces (OTLP protobuf/JSON or simple {caller,callee,count}) to promote "
     "matching graph edges to Trusted, attach runtime anchors, and flag 5xx incidents",
     "{\"type\":\"object\",\"properties\":{\"traces\":{\"type\":\"array\",\"items\":{\"type\":"
     "\"object\",\"properties\":{\"caller\":{\"type\":\"string\"},\"callee\":{\"type\":"
     "\"string\"},\"count\":{\"type\":\"integer\"}},\"additionalProperties\":false}},"
     "\"resourceSpans\":{\"type\":\"array\",\"items\":{\"type\":\"object\"}},"
     "\"otlp_protobuf_base64\":{\"type\":\"string\"},\"project\":{\"type\":\"string\"}},"
     "\"required\":[\"project\"]}"},
};

static const int TOOL_COUNT = sizeof(TOOLS) / sizeof(TOOLS[0]);

static const char MCP_TOOL_OUTPUT_SCHEMA[] = "{\"type\":\"object\",\"additionalProperties\":true}";

/* search_graph exposes two result arrays because exact/filter and semantic modes may be
 * combined. Keep their common source-location contract explicit while allowing exact results
 * to graft language-specific persisted properties whose names are not a closed protocol enum. */
static const char MCP_SEARCH_GRAPH_OUTPUT_SCHEMA[] =
    "{\"type\":\"object\",\"properties\":{"
    "\"total\":{\"type\":\"integer\",\"minimum\":0},"
    "\"search_mode\":{\"type\":\"string\",\"const\":\"bm25\"},"
    "\"results\":{\"type\":\"array\",\"items\":{\"oneOf\":["
    "{\"type\":\"object\",\"properties\":{"
    "\"atom_id\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"},"
    "\"qualified_name\":{\"type\":\"string\"},\"label\":{\"type\":\"string\"},"
    "\"file_path\":{\"type\":\"string\"},"
    "\"start_line\":{\"type\":\"integer\"},\"end_line\":{\"type\":\"integer\"},"
    "\"start_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"end_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"rank\":{\"type\":\"number\"}},"
    "\"required\":[\"atom_id\",\"name\",\"qualified_name\",\"label\",\"file_path\","
    "\"start_line\",\"end_line\",\"start_byte\",\"end_byte\",\"rank\"],"
    "\"additionalProperties\":false},"
    "{\"type\":\"object\",\"properties\":{"
    "\"atom_id\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"},"
    "\"qualified_name\":{\"type\":\"string\"},\"label\":{\"type\":\"string\"},"
    "\"file_path\":{\"type\":\"string\"},"
    "\"start_line\":{\"type\":\"integer\"},\"end_line\":{\"type\":\"integer\"},"
    "\"start_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"end_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"in_degree\":{\"type\":\"integer\",\"minimum\":0},"
    "\"out_degree\":{\"type\":\"integer\",\"minimum\":0},"
    "\"connected_names\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
    "\"connected_edges\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
    "\"properties\":{\"name\":{\"type\":\"string\"},"
    "\"validated\":{\"type\":\"boolean\"},\"trust\":{\"type\":\"string\"},"
    "\"weight\":{\"type\":\"integer\"},\"provenance\":{\"type\":\"string\"},"
    "\"provenance_error\":{\"type\":\"string\"}},\"required\":[\"name\"],"
    "\"additionalProperties\":false}}},"
    "\"required\":[\"atom_id\",\"name\",\"qualified_name\",\"label\",\"file_path\","
    "\"start_line\",\"end_line\",\"start_byte\",\"end_byte\",\"in_degree\","
    "\"out_degree\"],\"additionalProperties\":true}]}},"
    "\"semantic_results\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
    "\"properties\":{\"atom_id\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"},"
    "\"qualified_name\":{\"type\":\"string\"},\"label\":{\"type\":\"string\"},"
    "\"file_path\":{\"type\":\"string\"},"
    "\"start_line\":{\"type\":\"integer\"},\"end_line\":{\"type\":\"integer\"},"
    "\"start_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"end_byte\":{\"type\":\"integer\",\"minimum\":0},"
    "\"score\":{\"type\":\"number\"}},"
    "\"required\":[\"atom_id\",\"name\",\"qualified_name\",\"label\",\"file_path\","
    "\"start_line\",\"end_line\",\"start_byte\",\"end_byte\",\"score\"],"
    "\"additionalProperties\":false}},"
    "\"has_more\":{\"type\":\"boolean\"},\"hint\":{\"type\":\"string\"}},"
    "\"required\":[\"total\",\"results\",\"has_more\"],\"additionalProperties\":false}";

static void mcp_add_json_schema(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                                const char *schema_json) {
    yyjson_doc *schema_doc = yyjson_read(schema_json, strlen(schema_json), 0);
    if (schema_doc) {
        yyjson_mut_val *schema = yyjson_val_mut_copy(doc, yyjson_doc_get_root(schema_doc));
        if (schema) {
            yyjson_mut_obj_add_val(doc, obj, key, schema);
        }
        yyjson_doc_free(schema_doc);
    }
}

static void mcp_add_tool_def(yyjson_mut_doc *doc, yyjson_mut_val *tools, int i) {
    yyjson_mut_val *tool = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, tool, "name", TOOLS[i].name);
    yyjson_mut_obj_add_str(doc, tool, "title", TOOLS[i].title);
    yyjson_mut_obj_add_str(doc, tool, "description", TOOLS[i].description);

    mcp_add_json_schema(doc, tool, "inputSchema", TOOLS[i].input_schema);
    const char *output_schema = strcmp(TOOLS[i].name, "search_graph") == 0
                                    ? MCP_SEARCH_GRAPH_OUTPUT_SCHEMA
                                    : MCP_TOOL_OUTPUT_SCHEMA;
    mcp_add_json_schema(doc, tool, "outputSchema", output_schema);

    yyjson_mut_arr_add_val(tools, tool);
}

static char *cbm_mcp_tools_list_range(int offset, int limit, bool include_next_cursor) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *tools = yyjson_mut_arr(doc);

    if (offset < 0) {
        offset = 0;
    }
    if (offset > TOOL_COUNT) {
        offset = TOOL_COUNT;
    }
    if (limit < 0 || limit > TOOL_COUNT) {
        limit = TOOL_COUNT;
    }

    int end = offset + limit;
    if (end > TOOL_COUNT) {
        end = TOOL_COUNT;
    }

    for (int i = offset; i < end; i++) {
        mcp_add_tool_def(doc, tools, i);
    }

    yyjson_mut_obj_add_val(doc, root, "tools", tools);
    if (include_next_cursor && end < TOOL_COUNT) {
        char cursor[32];
        snprintf(cursor, sizeof(cursor), "%d", end);
        yyjson_mut_obj_add_strcpy(doc, root, "nextCursor", cursor);
    }

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

char *cbm_mcp_tools_list(void) {
    return cbm_mcp_tools_list_range(0, TOOL_COUNT, false);
}

/* Return the JSON input_schema string for a tool by name, or NULL if unknown.
 * Used by the CLI to build --flag arguments and per-tool --help from the same
 * source of truth the MCP tools/list advertises. Static lifetime; do not free. */
const char *cbm_mcp_tool_input_schema(const char *tool_name) {
    if (!tool_name) {
        return NULL;
    }
    for (int i = 0; i < TOOL_COUNT; i++) {
        if (strcmp(TOOLS[i].name, tool_name) == 0) {
            return TOOLS[i].input_schema;
        }
    }
    return NULL;
}

static int mcp_tools_cursor_offset(const char *params_json) {
    if (!params_json) {
        return 0;
    }

    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return 0;
    }

    int offset = 0;
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *cursor = root ? yyjson_obj_get(root, "cursor") : NULL;
    if (cursor) {
        offset = TOOL_COUNT;
        if (yyjson_is_str(cursor)) {
            const char *cursor_str = yyjson_get_str(cursor);
            if (cursor_str && *cursor_str != '\0') {
                char *endptr = NULL;
                errno = 0;
                long parsed = strtol(cursor_str, &endptr, 10);
                if (endptr && *endptr == '\0' && errno == 0 && parsed >= 0) {
                    offset = parsed > TOOL_COUNT ? TOOL_COUNT : (int)parsed;
                }
            }
        }
    }

    yyjson_doc_free(doc);
    return offset;
}

static char *cbm_mcp_tools_list_page(const char *params_json) {
    return cbm_mcp_tools_list_range(mcp_tools_cursor_offset(params_json), MCP_TOOLS_PAGE_SIZE,
                                    true);
}

/* Supported protocol versions, newest first. The server picks the newest
 * version that it shares with the client (per MCP spec version negotiation). */
static const char *SUPPORTED_PROTOCOL_VERSIONS[] = {
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
};
static const int SUPPORTED_VERSION_COUNT =
    (int)(sizeof(SUPPORTED_PROTOCOL_VERSIONS) / sizeof(SUPPORTED_PROTOCOL_VERSIONS[0]));

char *cbm_mcp_initialize_response(const char *params_json) {
    /* Determine protocol version: if client requests a version we support,
     * echo it back; otherwise respond with our latest. */
    const char *version = SUPPORTED_PROTOCOL_VERSIONS[0]; /* default: latest */
    if (params_json) {
        yyjson_doc *pdoc = yyjson_read(params_json, strlen(params_json), 0);
        if (pdoc) {
            yyjson_val *pv = yyjson_obj_get(yyjson_doc_get_root(pdoc), "protocolVersion");
            if (pv && yyjson_is_str(pv)) {
                const char *requested = yyjson_get_str(pv);
                for (int i = 0; i < SUPPORTED_VERSION_COUNT; i++) {
                    if (strcmp(requested, SUPPORTED_PROTOCOL_VERSIONS[i]) == 0) {
                        version = SUPPORTED_PROTOCOL_VERSIONS[i];
                        break;
                    }
                }
            }
            yyjson_doc_free(pdoc);
        }
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "protocolVersion", version);

    yyjson_mut_val *impl = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, impl, "name", "codebase-memory-mcp");
    yyjson_mut_obj_add_str(doc, impl, "version", cbm_cli_get_version());
    yyjson_mut_obj_add_val(doc, root, "serverInfo", impl);

    yyjson_mut_val *caps = yyjson_mut_obj(doc);
    yyjson_mut_val *tools_cap = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, tools_cap, "listChanged", false);
    yyjson_mut_obj_add_val(doc, caps, "tools", tools_cap);
    yyjson_mut_obj_add_val(doc, root, "capabilities", caps);

    char *out = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    return out;
}

/* ══════════════════════════════════════════════════════════════════
 *  ARGUMENT EXTRACTION
 * ══════════════════════════════════════════════════════════════════ */

char *cbm_mcp_get_tool_name(const char *params_json) {
    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *name = yyjson_obj_get(root, "name");
    char *result = NULL;
    if (name && yyjson_is_str(name)) {
        result = heap_strdup(yyjson_get_str(name));
    }
    yyjson_doc_free(doc);
    return result;
}

char *cbm_mcp_get_arguments(const char *params_json) {
    yyjson_doc *doc = yyjson_read(params_json, strlen(params_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *args = yyjson_obj_get(root, "arguments");
    char *result = NULL;
    if (args) {
        result = yyjson_val_write(args, 0, NULL);
    }
    yyjson_doc_free(doc);
    return result ? result : heap_strdup("{}");
}

char *cbm_mcp_get_string_arg(const char *args_json, const char *key) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    char *result = NULL;
    if (val && yyjson_is_str(val)) {
        result = heap_strdup(yyjson_get_str(val));
    }
    yyjson_doc_free(doc);
    return result;
}

static char *canonicalize_repo_path_if_exists(char *repo_path) {
    if (!repo_path) {
        return NULL;
    }
    /* #432: canonicalize via the long-path-safe wrapper. The old ANSI
     * `_access(...,0) + _fullpath` pair was MAX_PATH-bound, so a repo path deeper
     * than 260 chars failed to canonicalize (false not-found / _fullpath NULL) and
     * was indexed under its raw un-normalized form. cbm_canonicalize_existing_path
     * resolves through GetFullPathNameW + cbm_path_exists ("\\?\"-widened); it
     * returns a heap string (free()) or NULL when the path is absent/unresolvable.
     * Absence is terminal: indexing or project lookup must never continue under a
     * raw path whose filesystem identity was not established. */
    char *canonical = cbm_canonicalize_existing_path(repo_path);
    if (canonical) {
        cbm_normalize_path_sep(canonical);
        free(repo_path);
        return canonical;
    }

    cbm_log_error("repo_path.canonicalize_failed", "code", "CBM_REPO_PATH_UNRESOLVABLE", "path",
                  repo_path, "remediation", "pass an existing readable repository path and retry",
                  NULL);
    free(repo_path);
    return NULL;
}

static char *build_ephemeral_project_root_error(const char *repo_path) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_EPHEMERAL_PROJECT_ROOT\",\"message\":\"repository root is "
            "inside a disposable Astrolabe launcher generation\",\"remediation\":\"index "
            "the stable canonical repository root instead\"}");
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_EPHEMERAL_PROJECT_ROOT");
    yyjson_mut_obj_add_str(
        doc, root, "message",
        "repository root is inside .tmp/windows-gnu-toolchain-*, a disposable Astrolabe "
        "launcher generation that can never be durable project-store provenance");
    yyjson_mut_obj_add_str(doc, root, "repo_path", repo_path ? repo_path : "");
    yyjson_mut_obj_add_str(
        doc, root, "remediation",
        "index the stable canonical repository root; never copy, alias, or preserve a launcher "
        "generation as a project store");
    yyjson_mut_obj_add_bool(doc, root, "index_started", false);
    yyjson_mut_obj_add_bool(doc, root, "store_created", false);
    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    return json ? json : heap_strdup("{\"code\":\"CBM_EPHEMERAL_PROJECT_ROOT\"}");
}

static char *normalize_project_arg(char *project) {
    if (!project || (!strchr(project, '/') && !strchr(project, '\\'))) {
        return project;
    }

    project = canonicalize_repo_path_if_exists(project);
    if (!project) {
        return NULL;
    }
    char *normalized = cbm_project_name_from_path(project);
    if (normalized) {
        free(project);
        return normalized;
    }
    return project;
}

/* Resolve the project argument, accepting the canonical "project" key plus the
 * aliases a caller naturally reaches for (#640): list_projects surfaces the
 * field as "name" and the not-found hint says "pass the project name", so
 * "project_name" is the usual guess; "project_id" / "projectName" are accepted
 * too. NOT bare "name" — index_repository uses "name" for an explicit
 * project-name override. Caller must free() the result. */
static char *get_project_arg(const char *args_json) {
    char *p = cbm_mcp_get_string_arg(args_json, "project");
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "project_name");
    }
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "project_id");
    }
    if (!p) {
        p = cbm_mcp_get_string_arg(args_json, "projectName");
    }
    return normalize_project_arg(p);
}

int cbm_mcp_get_int_arg(const char *args_json, const char *key, int default_val) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return default_val;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    int result = default_val;
    if (val && yyjson_is_int(val)) {
        result = yyjson_get_int(val);
    }
    yyjson_doc_free(doc);
    return result;
}

bool cbm_mcp_get_bool_arg(const char *args_json, const char *key) {
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    if (!doc) {
        return false;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, key);
    bool result = false;
    if (val && yyjson_is_bool(val)) {
        result = yyjson_get_bool(val);
    }
    yyjson_doc_free(doc);
    return result;
}

/* ══════════════════════════════════════════════════════════════════
 *  MCP SERVER
 * ══════════════════════════════════════════════════════════════════ */

struct cbm_mcp_server {
    cbm_store_t *store;     /* currently open project store (or NULL) */
    bool owns_store;        /* true if we opened the store */
    char *current_project;  /* which project store is open for (heap) */
    time_t store_last_used; /* last time resolve_store was called for a named project */
    cbm_store_verify_result_t store_verify; /* last named source-preserving verification */
    char store_error_project[CBM_SZ_256];
    char store_error_db_path[CBM_STORE_VERIFY_PATH_MAX];
    char store_error_wal_path[CBM_STORE_VERIFY_PATH_MAX];
    char store_error_shm_path[CBM_STORE_VERIFY_PATH_MAX];
    char update_notice[CBM_SZ_256]; /* one-shot update notice, cleared after first injection */
    bool update_checked;            /* true after background check has been launched */
    cbm_thread_t update_tid;        /* background update check thread */
    bool update_thread_active;      /* true if update thread was started and needs joining */

    /* Session + auto-index state */
    char session_root[CBM_SZ_1K];     /* detected project root path */
    char session_project[CBM_SZ_256]; /* derived project name */
    bool session_detected;            /* true after first detection attempt */
    struct cbm_watcher *watcher;      /* external watcher ref (not owned) */
    struct cbm_config *config;        /* external config ref (not owned) */
    cbm_thread_t autoindex_tid;
    bool autoindex_active; /* true if auto-index thread was started */

    /* Active pipeline tracking for cancellation support */
    cbm_pipeline_t *active_pipeline; /* non-NULL while index_repository runs */
    int64_t active_request_id;       /* JSON-RPC id of the in-progress tool call */
    char *active_request_id_str;     /* string JSON-RPC id of the in-progress tool call */

    /* Optional row-sink callbacks for embedders that consume index_repository
     * rows directly while preserving the normal MCP result and SQLite output. */
    cbm_pipeline_row_sink_v1_t row_sink;
    bool row_sink_active;
};

cbm_mcp_server_t *cbm_mcp_server_new(const char *store_path) {
    cbm_mcp_server_t *srv = calloc(CBM_ALLOC_ONE, sizeof(*srv));
    if (!srv) {
        return NULL;
    }

    /* If a store_path is given, open that project directly.
     * Otherwise, create an in-memory store for test/embedded use. */
    if (store_path) {
        srv->store = cbm_store_open(store_path);
        srv->current_project = heap_strdup(store_path);
    } else {
        srv->store = cbm_store_open_memory();
    }
    srv->owns_store = true;

    return srv;
}

cbm_store_t *cbm_mcp_server_store(cbm_mcp_server_t *srv) {
    return srv ? srv->store : NULL;
}

void cbm_mcp_server_set_project(cbm_mcp_server_t *srv, const char *project) {
    if (!srv) {
        return;
    }
    free(srv->current_project);
    srv->current_project = project ? heap_strdup(project) : NULL;
}

void cbm_mcp_server_set_watcher(cbm_mcp_server_t *srv, struct cbm_watcher *w) {
    if (srv) {
        srv->watcher = w;
    }
}

void cbm_mcp_server_set_config(cbm_mcp_server_t *srv, struct cbm_config *cfg) {
    if (srv) {
        srv->config = cfg;
    }
}

int cbm_mcp_server_set_row_sink(cbm_mcp_server_t *srv, const cbm_pipeline_row_sink_v1_t *sink) {
    if (!srv) {
        cbm_log_error("mcp.row_sink_refused", "code", "CBM_MCP_ROW_SINK_SERVER_NULL", "message",
                      "a row sink cannot be installed on a NULL server", "remediation",
                      "create the MCP server successfully before installing a sink");
        return CBM_NOT_FOUND;
    }
    if (sink && (sink->abi_version != CBM_PIPELINE_ROW_SINK_ABI_V1 ||
                 sink->struct_size != sizeof(cbm_pipeline_row_sink_v1_t) || !sink->node ||
                 !sink->edge || !sink->file_hash || !sink->complete || !sink->ctx)) {
        cbm_log_error("mcp.row_sink_refused", "code", "CBM_MCP_ROW_SINK_INVALID", "message",
                      "the MCP server requires one complete frozen v1 sink descriptor",
                      "remediation",
                      "provide every v1 callback/context or pass NULL to disable the sink");
        return CBM_NOT_FOUND;
    }
    if (sink) {
        srv->row_sink = *sink;
        srv->row_sink_active = true;
    } else {
        memset(&srv->row_sink, 0, sizeof(srv->row_sink));
        srv->row_sink_active = false;
    }
    if (srv->active_pipeline) {
        if (cbm_pipeline_set_sink(srv->active_pipeline, sink) != 0) {
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

void cbm_mcp_server_free(cbm_mcp_server_t *srv) {
    if (!srv) {
        return;
    }
    if (srv->update_thread_active) {
        cbm_thread_join(&srv->update_tid);
    }
    if (srv->autoindex_active) {
        cbm_thread_join(&srv->autoindex_tid);
    }
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
    }
    free(srv->current_project);
    free(srv->active_request_id_str);
    memset(&srv->row_sink, 0, sizeof(srv->row_sink));
    srv->row_sink_active = false;
    free(srv);
}

/* ── Idle store eviction ──────────────────────────────────────── */

void cbm_mcp_server_evict_idle(cbm_mcp_server_t *srv, int timeout_s) {
    if (!srv || !srv->store) {
        return;
    }
    /* Protect initial in-memory stores that were never accessed via a named project.
     * store_last_used stays 0 until resolve_store is called with a non-NULL project. */
    if (srv->store_last_used == 0) {
        return;
    }

    time_t now = time(NULL);
    if ((now - srv->store_last_used) < timeout_s) {
        return;
    }

    if (srv->owns_store) {
        cbm_store_close(srv->store);
    }
    srv->store = NULL;
    free(srv->current_project);
    srv->current_project = NULL;
    srv->store_last_used = 0;
}

bool cbm_mcp_server_has_cached_store(cbm_mcp_server_t *srv) {
    return (srv && srv->store != NULL) != 0;
}

cbm_pipeline_t *cbm_mcp_server_active_pipeline(cbm_mcp_server_t *srv) {
    return srv ? srv->active_pipeline : NULL;
}

/* ── Cache dir + project DB path helpers ───────────────────────── */

/* Returns the cache directory. Writes to buf, returns buf for convenience. */
static const char *cache_dir(char *buf, size_t bufsz) {
    const char *dir = cbm_resolve_cache_dir();
    if (!dir) {
        dir = cbm_tmpdir();
    }
    snprintf(buf, bufsz, "%s", dir);
    return buf;
}

/* Returns full .db path for a project: <cache_dir>/<project>.db */
static const char *project_db_path(const char *project, char *buf, size_t bufsz) {
    if (!cbm_validate_project_name(project)) {
        buf[0] = '\0';
        return buf;
    }
    char dir[CBM_SZ_1K];
    cache_dir(dir, sizeof(dir));
    snprintf(buf, bufsz, "%s/%s.db", dir, project);
    return buf;
}

/* ── Store resolution ──────────────────────────────────────────── */

typedef enum {
    DB_PROJECT_INSPECT_OK = 0,
    DB_PROJECT_INSPECT_GHOST,
    DB_PROJECT_INSPECT_FAILED,
} db_project_inspect_status_t;

static void reset_store_error_state(cbm_mcp_server_t *srv) {
    memset(&srv->store_verify, 0, sizeof(srv->store_verify));
    srv->store_verify.status = CBM_STORE_VERIFY_OK;
    srv->store_verify.family_guard_release_complete = true;
    srv->store_verify.scratch_cleanup_complete = true;
    srv->store_error_project[0] = '\0';
    srv->store_error_db_path[0] = '\0';
    srv->store_error_wal_path[0] = '\0';
    srv->store_error_shm_path[0] = '\0';
}

static bool store_error_is_provenance(const cbm_store_verify_result_t *verification) {
    if (!verification) {
        return false;
    }
    return strstr(verification->operation, "application.project_identity") != NULL ||
           strstr(verification->operation, "application.project_root") != NULL ||
           strstr(verification->operation, "source.project_filename") != NULL ||
           strstr(verification->operation, "source.project_identity") != NULL;
}

static void record_store_error_state(cbm_mcp_server_t *srv, const char *project,
                                     const char *db_path,
                                     const cbm_store_verify_result_t *verification) {
    srv->store_verify = *verification;
    snprintf(srv->store_error_project, sizeof(srv->store_error_project), "%s",
             project ? project : "");
    snprintf(srv->store_error_db_path, sizeof(srv->store_error_db_path), "%s",
             db_path ? db_path : "");
    snprintf(srv->store_error_wal_path, sizeof(srv->store_error_wal_path), "%s-wal",
             db_path ? db_path : "");
    snprintf(srv->store_error_shm_path, sizeof(srv->store_error_shm_path), "%s-shm",
             db_path ? db_path : "");

    char native_error[CBM_SZ_32];
    char sqlite_error[CBM_SZ_32];
    snprintf(native_error, sizeof(native_error), "%lu",
             (unsigned long)srv->store_verify.native_error);
    snprintf(sqlite_error, sizeof(sqlite_error), "%d", srv->store_verify.sqlite_error);
    bool provenance_failed = store_error_is_provenance(&srv->store_verify);
    cbm_log_error(provenance_failed ? "store.provenance_failed"
                                    : (srv->store_verify.status == CBM_STORE_VERIFY_INTEGRITY_FAILED
                                           ? "store.integrity_failed"
                                           : "store.verification_failed"),
                  "code",
                  provenance_failed ? "CBM_STORE_PROVENANCE_FAILED"
                                    : (srv->store_verify.status == CBM_STORE_VERIFY_INTEGRITY_FAILED
                                           ? "CBM_STORE_INTEGRITY_FAILED"
                                           : "CBM_STORE_VERIFICATION_FAILED"),
                  "project", project ? project : "", "db_path", srv->store_error_db_path,
                  "wal_path", srv->store_error_wal_path, "shm_path", srv->store_error_shm_path,
                  "operation", srv->store_verify.operation, "native_error", native_error,
                  "sqlite_error", sqlite_error, "detail", srv->store_verify.detail, "action",
                  "source family preserved; explicit remediation required");
}

static void record_store_query_failure(cbm_mcp_server_t *srv, const char *project,
                                       const char *db_path, cbm_store_t *store,
                                       cbm_store_verify_status_t status, const char *operation,
                                       const char *detail) {
    cbm_store_verify_result_t failure;
    memset(&failure, 0, sizeof(failure));
    failure.status = status;
    failure.sqlite_error = store ? cbm_store_error_code(store) : SQLITE_ERROR;
    failure.db_present = db_path && cbm_path_exists(db_path);
    failure.family_guard_release_complete = true;
    failure.scratch_cleanup_complete = true;
    snprintf(failure.operation, sizeof(failure.operation), "%s", operation);
    snprintf(failure.detail, sizeof(failure.detail), "%s",
             detail && detail[0] ? detail
                                 : (store ? cbm_store_error(store) : "SQLite query failed"));
    record_store_error_state(srv, project, db_path, &failure);
}

/* Read the sole INTERNAL project name from a .db file at full_path.
 * Opens the file query-mode (no create) and succeeds ONLY when the db holds
 * exactly one project row with a non-empty name — this filters ghost/empty
 * /corrupt dbs (0-byte file, missing `projects` table, or >1 row). On success
 * the internal name is copied into name_out; if out_store is non-NULL the open
 * handle is transferred to the caller (who must cbm_store_close it). On failure
 * the store is always closed. Defined after is_project_db_file below. */
static db_project_inspect_status_t db_internal_project_name(cbm_mcp_server_t *srv,
                                                            const char *error_project,
                                                            const char *full_path, char *name_out,
                                                            size_t name_sz,
                                                            cbm_store_t **out_store);

/* Open the right project's .db file for query tools.
 * Caches the connection — reopens only when project changes.
 * Tracks last-access time so the event loop can evict idle stores. */
static cbm_store_t *resolve_store(cbm_mcp_server_t *srv, const char *project) {
    reset_store_error_state(srv);

    if (!project) {
        return NULL; /* project is required — no implicit fallback */
    }

    srv->store_last_used = time(NULL);

    /* Already open for this project? */
    if (srv->current_project && strcmp(srv->current_project, project) == 0 && srv->store) {
        return srv->store;
    }

    /* Close old store */
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }

    /* Freeze and inspect a verified derivative before SQLite is allowed to open
     * the source.  Read-only WAL access may rewrite the source -shm wal-index;
     * a corrupt family must instead be rejected with every source byte exact. */
    char path[CBM_SZ_1K];
    project_db_path(project, path, sizeof(path));
    cbm_store_verify_result_t verification;
    cbm_store_verify_status_t verify_status =
        cbm_store_open_path_project_query_verified(path, project, &srv->store, &verification);
    if (verify_status == CBM_STORE_VERIFY_INTEGRITY_FAILED ||
        verify_status == CBM_STORE_VERIFY_IO_FAILED) {
        srv->owns_store = false;
        record_store_error_state(srv, project, path, &verification);
        return NULL;
    }

    /* VERIFY_OK already published the exact source query connection while its
     * verified DB/WAL guards were still live.  A missing exact source stays
     * missing: cache-wide fallback adoption made unrelated invalid candidates
     * poison aliases and could bind a caller to a drifted filename/root. */
    if (srv->store) {
        /* Verify the project actually exists in this database.
         * A .db file may exist but be empty (e.g., after delete_project on
         * Linux where unlink defers actual removal). Opening an empty/deleted
         * store without closing it leaks the SQLite connection. */
        cbm_project_t proj_verify = {0};
        int project_rc = cbm_store_get_project(srv->store, project, &proj_verify);
        if (project_rc == CBM_STORE_OK) {
            cbm_project_free_fields(&proj_verify);
            srv->owns_store = true;
            free(srv->current_project);
            srv->current_project = heap_strdup(project);
            return srv->store; /* fast path: filename == internal name */
        }
        /* The verified boundary already required the sole internal name to
         * equal `project`.  Reaching NOT_FOUND here is therefore drift between
         * verification and the published connection, never authority to scan
         * for and adopt another file. */
        if (project_rc != CBM_STORE_NOT_FOUND) {
            record_store_query_failure(srv, project, path, srv->store, CBM_STORE_VERIFY_IO_FAILED,
                                       "source.query_project_row", cbm_store_error(srv->store));
            cbm_store_close(srv->store);
            srv->store = NULL;
            return NULL;
        }
        record_store_query_failure(srv, project, path, srv->store,
                                   CBM_STORE_VERIFY_INTEGRITY_FAILED,
                                   "source.project_identity_post_publish",
                                   "verified exact project row disappeared before query admission");
        cbm_store_close(srv->store);
        srv->store = NULL;
        return NULL;
    }

    return srv->store;
}

/* Convert one verified cached query store into a separate, verified mutation
 * handle without reopening through the create/schema/journal initializer.  The
 * query handle remains open until the writer has opened and verified the same
 * exact path/project/root, binding the pathname against replacement.  It is
 * then closed before the caller can mutate, so this server never blocks its own
 * rollback-journal commit. */
static cbm_store_t *resolve_mutation_store(cbm_mcp_server_t *srv, const char *project,
                                           bool *out_owned) {
    if (out_owned) {
        *out_owned = false;
    }
    cbm_store_t *resolved = resolve_store(srv, project);
    if (!resolved) {
        return NULL;
    }
    const char *db_path = cbm_store_db_path(resolved);
    if (!db_path) {
        return resolved;
    }

    cbm_store_t *writer = NULL;
    cbm_store_verify_result_t verification;
    cbm_store_verify_status_t status =
        cbm_store_open_path_project_writer_existing(db_path, project, &writer, &verification);
    if (status != CBM_STORE_VERIFY_OK || !writer) {
        record_store_error_state(srv, project, db_path, &verification);
        return NULL;
    }

    if (srv->store != resolved || !srv->owns_store) {
        cbm_store_close(writer);
        record_store_query_failure(
            srv, project, db_path, resolved, CBM_STORE_VERIFY_IO_FAILED,
            "source.writer.cached_query_ownership",
            "verified path-backed query store is not owned by this MCP server");
        return NULL;
    }
    cbm_store_close(srv->store);
    srv->store = NULL;
    srv->owns_store = false;
    free(srv->current_project);
    srv->current_project = NULL;
    srv->store_last_used = 0;
    if (out_owned) {
        *out_owned = true;
    }
    return writer;
}

/* Forward decl — definition lives below alongside list_projects. */
static bool is_project_db_file(const char *name, size_t len);

/* Forward decl — definition lives below in handle_trace_call_path's helpers. */
static void free_node_contents(cbm_node_t *n);

/* Scan cache dir for .db files, writing comma-separated quoted names into out.
 * Returns the number of projects found. */
static int collect_db_project_names(cbm_mcp_server_t *srv, const char *dir_path, char *out,
                                    size_t out_sz) {
    int count = 0;
    int offset = 0;
    cbm_dir_t *d = cbm_opendir(dir_path);
    if (!d) {
        if (!cbm_path_exists(dir_path)) {
            return 0;
        }
        record_store_query_failure(srv, "", dir_path, NULL, CBM_STORE_VERIFY_IO_FAILED,
                                   "discovery.open_cache_directory",
                                   "the project cache directory could not be enumerated");
        return CBM_NOT_FOUND;
    }
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(d)) != NULL) {
        const char *n = entry->name;
        size_t len = strlen(n);
        if (!is_project_db_file(n, len)) {
            continue;
        }
        /* #704: advertise the db's INTERNAL project name, not its filename, and
         * skip ghost/empty/corrupt dbs — so the hint lists names the user can
         * actually pass to resolve a store. */
        char full_path[CBM_SZ_2K];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, n);
        char iname[CBM_SZ_1K];
        db_project_inspect_status_t inspect =
            db_internal_project_name(srv, "", full_path, iname, sizeof(iname), NULL);
        if (inspect == DB_PROJECT_INSPECT_FAILED) {
            /* An unrelated unusable candidate is not project identity
             * authority.  It was logged with exact path/operation; omit it
             * from this compact hint and let list_projects expose the complete
             * structured refusal inventory. */
            continue;
        }
        if (inspect == DB_PROJECT_INSPECT_GHOST) {
            continue;
        }
        /* Element-boundary write: only emit this name if the WHOLE element —
         * optional leading comma + "iname" — plus the NUL fits in what remains.
         * Never truncate mid-token; a partial name would corrupt the JSON array
         * (issue #235). Stop cleanly at the last name that fits: the array then
         * always holds complete names and `count` == its length. */
        size_t off = (size_t)offset;
        size_t need = strlen(iname) + 2 /* quotes */ + (count > 0 ? 1u : 0u) /* comma */;
        if (off + need + 1 > out_sz) {
            break; /* would not fit entirely — stop at this element boundary */
        }
        if (count > 0) {
            out[offset++] = ',';
        }
        int wrote = snprintf(out + offset, out_sz - (size_t)offset, "\"%s\"", iname);
        if (wrote > 0) {
            offset += wrote; /* guaranteed to fit (checked above) — no truncation */
        }
        count++;
    }
    cbm_closedir(d);
    return count;
}

static void add_git_context_string(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                                   const char *value) {
    if (value) {
        yyjson_mut_obj_add_strcpy(doc, obj, key, value);
    } else {
        yyjson_mut_obj_add_null(doc, obj, key);
    }
}

static void add_git_context_json(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *root_path) {
    cbm_git_context_t ctx = {0};
    (void)cbm_git_context_resolve(root_path, &ctx);

    yyjson_mut_val *git = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_bool(doc, git, "is_git", ctx.is_git);
    yyjson_mut_obj_add_bool(doc, git, "is_worktree", ctx.is_worktree);
    yyjson_mut_obj_add_bool(doc, git, "is_detached", ctx.is_detached);
    yyjson_mut_obj_add_bool(doc, git, "root_exists", ctx.root_exists);
    add_git_context_string(doc, git, "worktree_root", ctx.worktree_root);
    add_git_context_string(doc, git, "git_dir", ctx.git_dir);
    add_git_context_string(doc, git, "git_common_dir", ctx.git_common_dir);
    add_git_context_string(doc, git, "canonical_root", ctx.canonical_root);
    add_git_context_string(doc, git, "branch", ctx.branch);
    add_git_context_string(doc, git, "branch_slug", ctx.branch_slug);
    add_git_context_string(doc, git, "head_sha", ctx.head_sha);
    add_git_context_string(doc, git, "base_sha", ctx.base_sha);
    yyjson_mut_obj_add_val(doc, obj, "git", git);

    cbm_git_context_free(&ctx);
}

/* Build a helpful error listing available projects. Caller must free() result. */
static char *build_integrity_failed_error(const cbm_mcp_server_t *srv);
static char *build_provenance_failed_error(const cbm_mcp_server_t *srv);
static char *build_store_verification_failed_error(const cbm_mcp_server_t *srv);

static char *build_recorded_store_error(const cbm_mcp_server_t *srv) {
    if (store_error_is_provenance(&srv->store_verify)) {
        return build_provenance_failed_error(srv);
    }
    return srv->store_verify.status == CBM_STORE_VERIFY_INTEGRITY_FAILED
               ? build_integrity_failed_error(srv)
               : build_store_verification_failed_error(srv);
}

static char *build_project_list_error(cbm_mcp_server_t *srv, const char *reason) {
    char dir_path[CBM_SZ_1K];
    cache_dir(dir_path, sizeof(dir_path));

    char projects[CBM_SZ_4K] = "";
    int count = collect_db_project_names(srv, dir_path, projects, sizeof(projects));
    if (count < 0) {
        return build_recorded_store_error(srv);
    }

    enum { ERR_BUF_SZ = 5120 };
    char buf[ERR_BUF_SZ];
    if (count > 0) {
        snprintf(buf, sizeof(buf),
                 "{\"error\":\"%s\",\"hint\":\"Use list_projects to see all indexed projects, "
                 "then pass it as the \\\"project\\\" "
                 "argument.\",\"available_projects\":[%s],\"count\":%d}",
                 reason, projects, count);
    } else {
        snprintf(buf, sizeof(buf),
                 "{\"error\":\"%s\",\"hint\":\"No projects indexed yet. "
                 "Call index_repository first.\"}",
                 reason);
    }
    return heap_strdup(buf);
}

/* Distinct from "unknown project": the caller omitted the project argument
 * entirely (no recognized key). Name the literal "project" key so the fix is
 * obvious (#640). Caller must free() result. */
static char *build_missing_project_error(void) {
    return heap_strdup("{\"error\":\"missing required argument: project\",\"hint\":\"Pass "
                       "the project as the \\\"project\\\" argument, e.g. "
                       "{\\\"project\\\":\\\"<name from list_projects>\\\"}. Run "
                       "list_projects to see indexed projects.\"}");
}

/* Pick the right no-store error: a NULL project means the argument was missing
 * (clearer message); a non-NULL project that didn't resolve means it's
 * unknown/unindexed (list the available ones). */
static char *build_integrity_failed_error(const cbm_mcp_server_t *srv) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_STORE_INTEGRITY_FAILED\","
            "\"message\":\"SQLite integrity verification failed; the complete database family "
            "was preserved in place\","
            "\"remediation\":\"preserve the database, WAL, and SHM together; perform explicit "
            "recovery or archive them before re-indexing\"}");
    }

    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_STORE_INTEGRITY_FAILED");
    yyjson_mut_obj_add_str(doc, root, "message",
                           "SQLite integrity verification failed; the complete database family "
                           "was preserved in place and no source-family mutation was attempted");
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "preserve the database, WAL, and SHM together; use an explicit "
                           "operator-controlled recovery/archive transaction, verify its bytes, "
                           "then re-index into a fresh store");
    yyjson_mut_obj_add_str(doc, root, "project", srv->store_error_project);
    yyjson_mut_obj_add_str(doc, root, "failed_operation", srv->store_verify.operation);
    yyjson_mut_obj_add_int(doc, root, "native_error", (int64_t)srv->store_verify.native_error);
    yyjson_mut_obj_add_int(doc, root, "sqlite_error", srv->store_verify.sqlite_error);
    yyjson_mut_obj_add_str(doc, root, "detail", srv->store_verify.detail);
    yyjson_mut_obj_add_str(doc, root, "db_path", srv->store_error_db_path);
    yyjson_mut_obj_add_str(doc, root, "wal_path", srv->store_error_wal_path);
    yyjson_mut_obj_add_str(doc, root, "shm_path", srv->store_error_shm_path);
    yyjson_mut_obj_add_bool(doc, root, "db_present", cbm_path_exists(srv->store_error_db_path));
    yyjson_mut_obj_add_bool(doc, root, "wal_present", cbm_path_exists(srv->store_error_wal_path));
    yyjson_mut_obj_add_bool(doc, root, "shm_present", cbm_path_exists(srv->store_error_shm_path));
    yyjson_mut_obj_add_bool(doc, root, "family_preserved_in_place", true);
    yyjson_mut_obj_add_bool(doc, root, "family_frozen_during_verification",
                            srv->store_verify.family_frozen);
    yyjson_mut_obj_add_bool(doc, root, "family_guard_release_complete",
                            srv->store_verify.family_guard_release_complete);
    yyjson_mut_obj_add_bool(doc, root, "scratch_created", srv->store_verify.scratch_created);
    yyjson_mut_obj_add_str(doc, root, "scratch_path", srv->store_verify.scratch_path);
    yyjson_mut_obj_add_bool(doc, root, "scratch_cleanup_complete",
                            srv->store_verify.scratch_cleanup_complete);
    if (!srv->store_verify.scratch_cleanup_complete ||
        !srv->store_verify.family_guard_release_complete) {
        yyjson_mut_obj_add_str(doc, root, "cleanup_failed_operation",
                               srv->store_verify.cleanup_operation);
        yyjson_mut_obj_add_int(doc, root, "cleanup_native_error",
                               (int64_t)srv->store_verify.cleanup_native_error);
    }
    yyjson_mut_obj_add_bool(doc, root, "mutation_attempted", false);

    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return heap_strdup(
            "{\"code\":\"CBM_STORE_INTEGRITY_FAILED\","
            "\"message\":\"SQLite integrity verification failed; the complete database family "
            "was preserved in place\","
            "\"remediation\":\"preserve the database, WAL, and SHM together; perform explicit "
            "recovery or archive them before re-indexing\"}");
    }
    return json;
}

static char *build_provenance_failed_error(const cbm_mcp_server_t *srv) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_STORE_PROVENANCE_FAILED\","
            "\"message\":\"project alias and persisted store provenance disagree\","
            "\"remediation\":\"preserve the complete family; archive/reindex the exact "
            "store or restore its canonical source root\"}");
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_STORE_PROVENANCE_FAILED");
    yyjson_mut_obj_add_str(
        doc, root, "message",
        "project alias, canonical database filename, internal project identity, and live source "
        "root did not form one exact provenance chain; query admission was refused");
    yyjson_mut_obj_add_str(
        doc, root, "remediation",
        "preserve the complete DB/WAL/SHM family; use the explicit hash-bound archive/reindex "
        "migration for a legacy store, or restore and re-index the canonical repository root");
    yyjson_mut_obj_add_str(doc, root, "project", srv->store_error_project);
    yyjson_mut_obj_add_str(doc, root, "failed_operation", srv->store_verify.operation);
    yyjson_mut_obj_add_str(doc, root, "detail", srv->store_verify.detail);
    yyjson_mut_obj_add_str(doc, root, "db_path", srv->store_error_db_path);
    yyjson_mut_obj_add_str(doc, root, "wal_path", srv->store_error_wal_path);
    yyjson_mut_obj_add_str(doc, root, "shm_path", srv->store_error_shm_path);
    yyjson_mut_obj_add_int(doc, root, "expected_schema_version", CBM_GRAPH_SCHEMA_VERSION);
    yyjson_mut_obj_add_int(doc, root, "native_error", (int64_t)srv->store_verify.native_error);
    yyjson_mut_obj_add_int(doc, root, "sqlite_error", srv->store_verify.sqlite_error);
    yyjson_mut_obj_add_bool(doc, root, "db_present", srv->store_verify.db_present);
    yyjson_mut_obj_add_bool(doc, root, "wal_present", srv->store_verify.wal_present);
    yyjson_mut_obj_add_bool(doc, root, "shm_present", srv->store_verify.shm_present);
    yyjson_mut_obj_add_bool(doc, root, "family_preserved_in_place", true);
    yyjson_mut_obj_add_bool(doc, root, "source_mutation_attempted", false);
    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    return json ? json : heap_strdup("{\"code\":\"CBM_STORE_PROVENANCE_FAILED\"}");
}

static char *build_store_verification_failed_error(const cbm_mcp_server_t *srv) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_STORE_VERIFICATION_FAILED\","
            "\"message\":\"SQLite source-preserving verification failed closed\","
            "\"remediation\":\"resolve the reported filesystem or SQLite failure, preserve "
            "the complete database family, then retry\"}");
    }

    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_STORE_VERIFICATION_FAILED");
    yyjson_mut_obj_add_str(doc, root, "message",
                           "SQLite source-preserving verification failed closed; the source "
                           "database was not opened for query");
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "preserve the database, WAL, and SHM together; resolve the exact "
                           "reported operation/native or SQLite error, then retry");
    yyjson_mut_obj_add_str(doc, root, "project", srv->store_error_project);
    yyjson_mut_obj_add_str(doc, root, "failed_operation", srv->store_verify.operation);
    yyjson_mut_obj_add_int(doc, root, "native_error", (int64_t)srv->store_verify.native_error);
    yyjson_mut_obj_add_int(doc, root, "sqlite_error", srv->store_verify.sqlite_error);
    yyjson_mut_obj_add_str(doc, root, "detail", srv->store_verify.detail);
    yyjson_mut_obj_add_str(doc, root, "db_path", srv->store_error_db_path);
    yyjson_mut_obj_add_str(doc, root, "wal_path", srv->store_error_wal_path);
    yyjson_mut_obj_add_str(doc, root, "shm_path", srv->store_error_shm_path);
    yyjson_mut_obj_add_bool(doc, root, "db_present", srv->store_verify.db_present);
    yyjson_mut_obj_add_bool(doc, root, "wal_present", srv->store_verify.wal_present);
    yyjson_mut_obj_add_bool(doc, root, "shm_present", srv->store_verify.shm_present);
    yyjson_mut_obj_add_bool(doc, root, "family_frozen_during_verification",
                            srv->store_verify.family_frozen);
    yyjson_mut_obj_add_bool(doc, root, "family_guard_release_complete",
                            srv->store_verify.family_guard_release_complete);
    yyjson_mut_obj_add_bool(doc, root, "scratch_created", srv->store_verify.scratch_created);
    yyjson_mut_obj_add_str(doc, root, "scratch_path", srv->store_verify.scratch_path);
    yyjson_mut_obj_add_bool(doc, root, "scratch_cleanup_complete",
                            srv->store_verify.scratch_cleanup_complete);
    if (!srv->store_verify.scratch_cleanup_complete ||
        !srv->store_verify.family_guard_release_complete) {
        yyjson_mut_obj_add_str(doc, root, "cleanup_failed_operation",
                               srv->store_verify.cleanup_operation);
        yyjson_mut_obj_add_int(doc, root, "cleanup_native_error",
                               (int64_t)srv->store_verify.cleanup_native_error);
    }
    yyjson_mut_obj_add_bool(doc, root, "source_mutation_attempted", false);

    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return heap_strdup(
            "{\"code\":\"CBM_STORE_VERIFICATION_FAILED\","
            "\"message\":\"SQLite source-preserving verification failed closed\","
            "\"remediation\":\"resolve the reported filesystem or SQLite failure, preserve "
            "the complete database family, then retry\"}");
    }
    return json;
}

static char *build_no_store_error(cbm_mcp_server_t *srv, const char *project) {
    if (srv && project && strcmp(srv->store_error_project, project) == 0) {
        if (store_error_is_provenance(&srv->store_verify)) {
            return build_provenance_failed_error(srv);
        }
        if (srv->store_verify.status == CBM_STORE_VERIFY_INTEGRITY_FAILED) {
            return build_integrity_failed_error(srv);
        }
        if (srv->store_verify.status == CBM_STORE_VERIFY_IO_FAILED) {
            return build_store_verification_failed_error(srv);
        }
    }
    return project ? build_project_list_error(srv, "project not found or not indexed")
                   : build_missing_project_error();
}

/* Bail with the right error when no store is available. */
#define REQUIRE_STORE(store, project)                        \
    do {                                                     \
        if (!(store)) {                                      \
            char *_err = build_no_store_error(srv, project); \
            char *_res = cbm_mcp_text_result(_err, true);    \
            free(_err);                                      \
            free(project);                                   \
            return _res;                                     \
        }                                                    \
    } while (0)

static bool project_has_adr(cbm_store_t *store, const char *project, const char *root_path) {
    if (store && project) {
        cbm_adr_t adr;
        memset(&adr, 0, sizeof(adr));
        if (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK) {
            cbm_store_adr_free(&adr);
            return true;
        }
    }

    if (!root_path) {
        return false;
    }

    char adr_path[CBM_SZ_4K];
    snprintf(adr_path, sizeof(adr_path), "%s/.codebase-memory/adr.md", root_path);
    /* #432: extended-length-safe existence probe. The old ANSI stat() was
     * MAX_PATH-bound, so on a deep root_path (>260-char adr path) the ADR file was
     * really present yet this probe reported absent, suppressing ADR detection.
     * cbm_path_exists widens via "\\?\" (GetFileAttributesW). */
    return cbm_path_exists(adr_path);
}

/* ── Tool handler implementations ─────────────────────────────── */

/* True when `name` (length `len`) ends with the NUL-terminated `suffix`. Exact
 * byte suffix match — a name that merely CONTAINS the suffix mid-string is not
 * matched (so a real project "my-astrolabe-lowered-tools" is untouched). */
static bool name_has_suffix(const char *name, size_t len, const char *suffix) {
    size_t slen = strlen(suffix);
    return len >= slen && memcmp(name + len - slen, suffix, slen) == 0;
}

/* Reserved Astrolabe sidecar-artifact suffixes for files that live in the store
 * (cache) dir but are NOT project stores (#414). Every entry is a full filename
 * suffix and is matched exactly against the whole filename by
 * is_astrolabe_reserved_sidecar_db(). Kept as a table so future ".db"-tailed
 * sidecar families route through the one contract. See
 * CBM_ASTRO_LOWERED_DB_SUFFIX in mcp/mcp.h for the drift contract with the Rust
 * host's write-side constants. */
static const char *const CBM_ASTRO_RESERVED_DB_SUFFIXES[] = {
    CBM_ASTRO_LOWERED_DB_SUFFIX,
};

/* Reserved Astrolabe sidecar-artifact PREFIXES: families whose filenames carry
 * a varying nonce tail, so they are matched by prefix instead. Currently the
 * git-archaeology scratch store ".astrolabe-archaeology-<nonce>.db". */
static const char *const CBM_ASTRO_RESERVED_DB_PREFIXES[] = {
    CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX,
};

/* True when `name` is an Astrolabe reserved store-dir sidecar (e.g. the
 * per-project lowered-SQLite mirror or an archaeology scratch store), which
 * must never be enumerated or resolved as a project store. */
static bool is_astrolabe_reserved_sidecar_db(const char *name, size_t len) {
    for (size_t i = 0;
         i < sizeof(CBM_ASTRO_RESERVED_DB_SUFFIXES) / sizeof(CBM_ASTRO_RESERVED_DB_SUFFIXES[0]);
         i++) {
        if (name_has_suffix(name, len, CBM_ASTRO_RESERVED_DB_SUFFIXES[i])) {
            return true;
        }
    }
    for (size_t i = 0;
         i < sizeof(CBM_ASTRO_RESERVED_DB_PREFIXES) / sizeof(CBM_ASTRO_RESERVED_DB_PREFIXES[0]);
         i++) {
        const char *prefix = CBM_ASTRO_RESERVED_DB_PREFIXES[i];
        if (strncmp(name, prefix, strlen(prefix)) == 0) {
            return true;
        }
    }
    return false;
}

/* Return true if filename is a valid project .db file (not temp/internal).
 *
 * Project names derived from /tmp/... source roots legitimately begin with
 * "tmp-" (cbm_project_name_from_path: "/tmp/bench/..." → "tmp-bench-..."),
 * so the prefix must NOT be excluded.
 * The "_" prefix is reserved for internal/hidden DBs, and ":memory:" is the
 * SQLite in-memory marker (defensive — never appears as a real file). */
static bool is_project_db_file(const char *name, size_t len) {
    if (len < MCP_MIN_DB_NAME || strcmp(name + len - MCP_DB_EXT, ".db") != 0) {
        return false;
    }
    if (strncmp(name, "_", SLEN("_")) == 0 || strncmp(name, ":memory:", SLEN(":memory:")) == 0) {
        return false;
    }
    /* #414: Astrolabe sidecar artifacts (e.g. "<name>.astrolabe-lowered.db",
     * written by the Rust host into the same store dir) end in ".db" but are not
     * project stores — skip them so they never appear as phantom projects or get
     * adopted by resolve_store. This is the single reserved-suffix filter; all
     * store-dir walks route through here. */
    if (is_astrolabe_reserved_sidecar_db(name, len)) {
        return false;
    }
    return true;
}

static bool project_name_from_db_path(const char *full_path, char *project, size_t project_sz) {
    const char *base = cbm_path_base(full_path);
    size_t len = base ? strlen(base) : 0;
    if (!base || !is_project_db_file(base, len) || len <= MCP_DB_EXT ||
        len - MCP_DB_EXT >= project_sz) {
        return false;
    }
    memcpy(project, base, len - MCP_DB_EXT);
    project[len - MCP_DB_EXT] = '\0';
    return cbm_validate_project_name(project);
}

/* db_internal_project_name — see forward declaration above resolve_store. */
static db_project_inspect_status_t db_internal_project_name(cbm_mcp_server_t *srv,
                                                            const char *error_project,
                                                            const char *full_path, char *name_out,
                                                            size_t name_sz,
                                                            cbm_store_t **out_store) {
    if (out_store) {
        *out_store = NULL;
    }
    /* A zero-byte file is a recognizable abandoned ghost, not a SQLite
     * database and not evidence of corruption in persisted database bytes. */
    if (cbm_file_size(full_path) == 0) {
        return DB_PROJECT_INSPECT_GHOST;
    }

    char expected_project[CBM_SZ_1K];
    if (!project_name_from_db_path(full_path, expected_project, sizeof(expected_project))) {
        record_store_query_failure(
            srv, error_project, full_path, NULL, CBM_STORE_VERIFY_INTEGRITY_FAILED,
            "source.project_filename",
            "database filename does not encode one valid canonical project name");
        return DB_PROJECT_INSPECT_FAILED;
    }

    cbm_store_t *st = NULL;
    cbm_store_verify_result_t verification;
    cbm_store_verify_status_t verify_status =
        cbm_store_open_path_project_query_verified(full_path, expected_project, &st, &verification);
    if (verify_status == CBM_STORE_VERIFY_SOURCE_MISSING) {
        return DB_PROJECT_INSPECT_GHOST;
    }
    if (verify_status != CBM_STORE_VERIFY_OK || !st) {
        record_store_error_state(srv, error_project, full_path, &verification);
        return DB_PROJECT_INSPECT_FAILED;
    }
    cbm_project_t *projs = NULL;
    int n = 0;
    bool ok = false;
    int list_rc = cbm_store_list_projects(st, &projs, &n);
    if (list_rc == CBM_STORE_OK && n == 1 && projs[0].name && projs[0].name[0]) {
        snprintf(name_out, name_sz, "%s", projs[0].name);
        ok = true;
    } else {
        record_store_query_failure(
            srv, error_project, full_path, st,
            list_rc == CBM_STORE_OK ? CBM_STORE_VERIFY_INTEGRITY_FAILED
                                    : CBM_STORE_VERIFY_IO_FAILED,
            "source.query_internal_project",
            list_rc == CBM_STORE_OK
                ? "verified project store did not yield exactly one non-empty project name"
                : cbm_store_error(st));
    }
    cbm_store_free_projects(projs, n);
    if (ok && out_store) {
        *out_store = st; /* transfer ownership to caller */
    } else {
        cbm_store_close(st);
    }
    return ok ? DB_PROJECT_INSPECT_OK : DB_PROJECT_INSPECT_FAILED;
}

/* Open a .db file briefly, collect node/edge counts and root_path,
 * then append a JSON entry to arr. */
static db_project_inspect_status_t build_project_json_entry(cbm_mcp_server_t *srv,
                                                            yyjson_mut_doc *doc,
                                                            yyjson_mut_val *arr,
                                                            const char *dir_path, const char *name,
                                                            size_t name_len, int64_t size_bytes) {
    (void)name_len;

    char full_path[CBM_SZ_2K];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);

    /* #704: key on the db's INTERNAL project name, not its filename. Node/edge
     * rows are tagged with the internal name, so a drifted filename (copied or
     * renamed db, legacy '.'-vs-'-' username twin) would otherwise report 0
     * nodes/edges and be unresolvable. Skip ghost/empty/corrupt dbs entirely so
     * they don't appear as resolvable projects. */
    char project_name[CBM_SZ_1K];
    cbm_store_t *pstore = NULL;
    db_project_inspect_status_t inspect =
        db_internal_project_name(srv, "", full_path, project_name, sizeof(project_name), &pstore);
    if (inspect != DB_PROJECT_INSPECT_OK) {
        return inspect;
    }

    int nodes = cbm_store_count_nodes(pstore, project_name);
    int edges = cbm_store_count_edges(pstore, project_name);
    char root_path_buf[CBM_SZ_1K] = "";
    cbm_project_t proj = {0};
    int project_rc = cbm_store_get_project(pstore, project_name, &proj);
    if (nodes < 0 || edges < 0 || project_rc != CBM_STORE_OK) {
        record_store_query_failure(srv, "", full_path, pstore, CBM_STORE_VERIFY_IO_FAILED,
                                   "source.query_project_details", cbm_store_error(pstore));
        cbm_project_free_fields(&proj);
        cbm_store_close(pstore);
        return DB_PROJECT_INSPECT_FAILED;
    }
    if (proj.root_path) {
        snprintf(root_path_buf, sizeof(root_path_buf), "%s", proj.root_path);
    }
    cbm_project_free_fields(&proj);
    cbm_store_close(pstore);

    yyjson_mut_val *p = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, p, "name", project_name);
    yyjson_mut_obj_add_strcpy(doc, p, "root_path", root_path_buf);
    add_git_context_json(doc, p, root_path_buf[0] ? root_path_buf : NULL);
    yyjson_mut_obj_add_int(doc, p, "nodes", nodes);
    yyjson_mut_obj_add_int(doc, p, "edges", edges);
    yyjson_mut_obj_add_int(doc, p, "size_bytes", size_bytes);
    yyjson_mut_arr_add_val(arr, p);
    return DB_PROJECT_INSPECT_OK;
}

static const char *recorded_store_error_code(const cbm_mcp_server_t *srv) {
    if (store_error_is_provenance(&srv->store_verify)) {
        return "CBM_STORE_PROVENANCE_FAILED";
    }
    return srv->store_verify.status == CBM_STORE_VERIFY_INTEGRITY_FAILED
               ? "CBM_STORE_INTEGRITY_FAILED"
               : "CBM_STORE_VERIFICATION_FAILED";
}

static void append_store_refusal_json(yyjson_mut_doc *doc, yyjson_mut_val *refusals,
                                      const cbm_mcp_server_t *srv) {
    yyjson_mut_val *item = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_str(doc, item, "code", recorded_store_error_code(srv));
    yyjson_mut_obj_add_str(doc, item, "db_path", srv->store_error_db_path);
    yyjson_mut_obj_add_str(doc, item, "wal_path", srv->store_error_wal_path);
    yyjson_mut_obj_add_str(doc, item, "shm_path", srv->store_error_shm_path);
    yyjson_mut_obj_add_str(doc, item, "failed_operation", srv->store_verify.operation);
    yyjson_mut_obj_add_str(doc, item, "detail", srv->store_verify.detail);
    yyjson_mut_obj_add_int(doc, item, "expected_schema_version", CBM_GRAPH_SCHEMA_VERSION);
    yyjson_mut_obj_add_bool(doc, item, "db_present", srv->store_verify.db_present);
    yyjson_mut_obj_add_bool(doc, item, "wal_present", srv->store_verify.wal_present);
    yyjson_mut_obj_add_bool(doc, item, "shm_present", srv->store_verify.shm_present);
    yyjson_mut_obj_add_bool(doc, item, "source_mutation_attempted", false);
    yyjson_mut_obj_add_str(
        doc, item, "remediation",
        "preserve the complete family; run the explicit hash-bound archive/reindex migration "
        "for this exact path, or repair the reported canonical project provenance");
    yyjson_mut_arr_add_val(refusals, item);
}

/* list_projects: scan cache directory for .db files.
 * Exact filename + internal identity + live canonical root form the registry.
 * Every unusable candidate is reported explicitly and cannot poison valid
 * project discovery. */
static char *handle_list_projects(cbm_mcp_server_t *srv, const char *args) {
    (void)args;
    reset_store_error_state(srv);

    char dir_path[CBM_SZ_1K];
    cache_dir(dir_path, sizeof(dir_path));

    cbm_dir_t *d = cbm_opendir(dir_path);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    yyjson_mut_val *refusals = yyjson_mut_arr(doc);

    if (!d && cbm_path_exists(dir_path)) {
        record_store_query_failure(srv, "", dir_path, NULL, CBM_STORE_VERIFY_IO_FAILED,
                                   "discovery.open_cache_directory",
                                   "the project cache directory could not be enumerated");
        yyjson_mut_doc_free(doc);
        char *error = build_recorded_store_error(srv);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }

    cbm_dirent_t *entry;
    while (d && (entry = cbm_readdir(d)) != NULL) {
        const char *name = entry->name;
        size_t len = strlen(name);
        if (!is_project_db_file(name, len)) {
            continue;
        }
        char full_path[CBM_SZ_2K];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
        int64_t size_bytes = cbm_file_size(full_path);
        if (size_bytes < 0) {
            record_store_query_failure(srv, "", full_path, NULL, CBM_STORE_VERIFY_IO_FAILED,
                                       "discovery.read_candidate_size",
                                       "a project-store candidate could not be stated");
            cbm_closedir(d);
            yyjson_mut_doc_free(doc);
            char *error = build_recorded_store_error(srv);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        db_project_inspect_status_t inspect =
            build_project_json_entry(srv, doc, arr, dir_path, name, len, size_bytes);
        if (inspect == DB_PROJECT_INSPECT_FAILED) {
            append_store_refusal_json(doc, refusals, srv);
            continue;
        }
    }
    cbm_closedir(d);

    yyjson_mut_obj_add_val(doc, root, "projects", arr);
    yyjson_mut_obj_add_val(doc, root, "store_refusals", refusals);
    yyjson_mut_obj_add_int(doc, root, "refused_store_count",
                           (int64_t)yyjson_mut_arr_size(refusals));
    yyjson_mut_obj_add_bool(doc, root, "discovery_complete", true);

    /* Guide user when no projects are indexed */
    if (yyjson_mut_arr_size(arr) == 0) {
        yyjson_mut_obj_add_str(doc, root, "hint",
                               "No projects indexed. Call index_repository(repo_path=...) first.");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* verify_project_indexed — returns a heap-allocated error JSON string when the
 * named project has not been indexed yet, or NULL when the project exists.
 * resolve_store uses cbm_store_open_path_query (no SQLITE_OPEN_CREATE), so
 * store is NULL for missing .db files (REQUIRE_STORE fires first). This
 * function catches the remaining case: a .db file exists but has no indexed
 * nodes (e.g., an empty or half-initialised project).
 * Callers that receive a non-NULL return value must free(project) themselves
 * before returning the error string. */
static char *verify_project_indexed(cbm_mcp_server_t *srv, cbm_store_t *store,
                                    const char *project) {
    cbm_project_t proj_check = {0};
    int project_rc = cbm_store_get_project(store, project, &proj_check);
    if (project_rc != CBM_STORE_OK) {
        char *err = NULL;
        if (project_rc == CBM_STORE_NOT_FOUND) {
            err = build_project_list_error(srv, "project not indexed — run index_repository first");
        } else {
            record_store_query_failure(srv, project, cbm_store_db_path(store), store,
                                       CBM_STORE_VERIFY_IO_FAILED, "source.query_project_row",
                                       cbm_store_error(store));
            err = build_recorded_store_error(srv);
        }
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        return res;
    }
    cbm_project_free_fields(&proj_check);
    return NULL;
}

static char *handle_get_graph_schema(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(project);
        return not_indexed;
    }

    cbm_schema_info_t schema = {0};
    cbm_store_get_schema(store, project, &schema);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_val *labels = yyjson_mut_arr(doc);
    for (int i = 0; i < schema.node_label_count; i++) {
        yyjson_mut_val *lbl = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, lbl, "label", schema.node_labels[i].label);
        yyjson_mut_obj_add_int(doc, lbl, "count", schema.node_labels[i].count);
        yyjson_mut_val *props = yyjson_mut_arr(doc);
        for (int j = 0; j < schema.node_labels[i].property_count; j++) {
            yyjson_mut_arr_add_str(doc, props, schema.node_labels[i].properties[j]);
        }
        yyjson_mut_obj_add_val(doc, lbl, "properties", props);
        yyjson_mut_arr_add_val(labels, lbl);
    }
    yyjson_mut_obj_add_val(doc, root, "node_labels", labels);

    yyjson_mut_val *types = yyjson_mut_arr(doc);
    for (int i = 0; i < schema.edge_type_count; i++) {
        yyjson_mut_val *typ = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, typ, "type", schema.edge_types[i].type);
        yyjson_mut_obj_add_int(doc, typ, "count", schema.edge_types[i].count);
        yyjson_mut_val *eprops = yyjson_mut_arr(doc);
        for (int j = 0; j < schema.edge_types[i].property_count; j++) {
            yyjson_mut_arr_add_str(doc, eprops, schema.edge_types[i].properties[j]);
        }
        yyjson_mut_obj_add_val(doc, typ, "properties", eprops);
        yyjson_mut_arr_add_val(types, typ);
    }
    yyjson_mut_obj_add_val(doc, root, "edge_types", types);

    /* Check ADR presence */
    cbm_project_t proj_info = {0};
    if (cbm_store_get_project(store, project, &proj_info) == 0 && proj_info.root_path) {
        bool adr_exists = project_has_adr(store, project, proj_info.root_path);
        yyjson_mut_obj_add_bool(doc, root, "adr_present", adr_exists);
        if (!adr_exists) {
            yyjson_mut_obj_add_str(
                doc, root, "adr_hint",
                "No ADR found. Use manage_adr(mode='update') to persist architectural "
                "decisions across sessions. Run get_architecture(aspects=['all']) first.");
        }
        cbm_project_free_fields(&proj_info);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_store_schema_free(&schema);
    free(project);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Validate edge type: uppercase letters + underscore only, max 64 chars. */
static bool validate_edge_type(const char *s) {
    if (!s || strlen(s) > CBM_SZ_64) {
        return false;
    }
    for (const char *c = s; *c; c++) {
        if (!(*c >= 'A' && *c <= 'Z') && *c != '_') {
            return false;
        }
    }
    return true;
}

/* Find the raw properties_json of the traversal edge that touches a hop node,
 * preferring an edge that carries runtime-trace promotion markers so trust is
 * surfaced when a promoted and an unpromoted edge both touch the same node.
 * Returns the borrowed properties_json or NULL when no touching edge records
 * properties. (#333) */
static const char *bfs_edge_props_for_hop(cbm_traverse_result_t *tr, int64_t hop_node_id) {
    const char *first = NULL;
    for (int e = 0; e < tr->edge_count; e++) {
        /* Match either endpoint: outbound traces reach the hop as target,
         * inbound traces reach it as source. */
        if (tr->edges[e].target_id != hop_node_id && tr->edges[e].source_id != hop_node_id) {
            continue;
        }
        const char *pj = tr->edges[e].properties_json;
        if (!pj || pj[0] == '\0') {
            continue;
        }
        if (!first) {
            first = pj;
        }
        /* Prefer the promoted edge if one exists among the touching edges. */
        if (strstr(pj, "\"validated\"") != NULL || strstr(pj, "\"provenance\"") != NULL) {
            return pj;
        }
    }
    return first;
}

/* Parse an edge's raw properties_json and graft runtime-trace promotion
 * provenance (validated / trust tier / measured weight / provenance kind) onto
 * `item`. Returns true iff a provenance field OR an explicit error marker was
 * added. Contract (HONEST invariants 1 & 3):
 *   - NULL/empty properties               -> nothing added, false (absence is honest).
 *   - valid JSON with no promotion marker  -> nothing added, false (an unpromoted
 *                                             edge honestly carries no trust label).
 *   - malformed / non-object JSON          -> explicit "provenance_error" marker,
 *                                             true (never a silent drop).
 * Never invents defaults for absent fields. (#333) */
static bool emit_edge_provenance(yyjson_mut_doc *doc, yyjson_mut_val *item, const char *pj) {
    if (!pj || pj[0] == '\0') {
        return false;
    }
    yyjson_doc *pd = yyjson_read(pj, strlen(pj), 0);
    if (!pd) {
        yyjson_mut_obj_add_str(doc, item, "provenance_error", "malformed edge properties_json");
        return true;
    }
    yyjson_val *root = yyjson_doc_get_root(pd);
    if (!root || !yyjson_is_obj(root)) {
        yyjson_doc_free(pd);
        yyjson_mut_obj_add_str(doc, item, "provenance_error",
                               "edge properties_json is not a JSON object");
        return true;
    }
    bool added = false;
    yyjson_val *v;
    if ((v = yyjson_obj_get(root, "validated")) != NULL && yyjson_is_bool(v)) {
        yyjson_mut_obj_add_bool(doc, item, "validated", yyjson_get_bool(v));
        added = true;
    }
    if ((v = yyjson_obj_get(root, "trust")) != NULL && yyjson_is_str(v)) {
        yyjson_mut_obj_add_strcpy(doc, item, "trust", yyjson_get_str(v));
        added = true;
    }
    if ((v = yyjson_obj_get(root, "weight")) != NULL && yyjson_is_int(v)) {
        yyjson_mut_obj_add_int(doc, item, "weight", yyjson_get_int(v));
        added = true;
    }
    if ((v = yyjson_obj_get(root, "provenance")) != NULL && yyjson_is_str(v)) {
        yyjson_mut_obj_add_strcpy(doc, item, "provenance", yyjson_get_str(v));
        added = true;
    }
    yyjson_doc_free(pd);
    return added;
}

/* Enrich search result with 1-hop connected node names. */
/* Add BFS results to a yyjson array (deduped by name). */
static void enrich_add_bfs(yyjson_mut_doc *doc, yyjson_mut_val *arr, cbm_traverse_result_t *tr) {
    for (int j = 0; j < tr->visited_count; j++) {
        if (tr->visited[j].node.name) {
            yyjson_mut_arr_add_strcpy(doc, arr, tr->visited[j].node.name);
        }
    }
}

/* Append one object per connected node whose connecting edge carries runtime-trace
 * promotion provenance to `arr`, as {name, validated?, trust?, weight?, provenance?}
 * (or {name, provenance_error} for a malformed edge). Nodes reached over an
 * unpromoted edge add nothing here — their name is already in connected_names, and
 * an unpromoted edge honestly carries no trust label. (#333) */
static void enrich_add_bfs_edges(yyjson_mut_doc *doc, yyjson_mut_val *arr,
                                 cbm_traverse_result_t *tr) {
    for (int j = 0; j < tr->visited_count; j++) {
        if (!tr->visited[j].node.name) {
            continue;
        }
        const char *pj = bfs_edge_props_for_hop(tr, tr->visited[j].node.id);
        if (!pj) {
            continue;
        }
        yyjson_mut_val *eo = yyjson_mut_obj(doc);
        if (emit_edge_provenance(doc, eo, pj)) {
            yyjson_mut_obj_add_strcpy(doc, eo, "name", tr->visited[j].node.name);
            yyjson_mut_arr_add_val(arr, eo);
        }
    }
}

/* Enrich search result with 1-hop connected node names (inbound + outbound). */
static void enrich_connected(yyjson_mut_doc *doc, yyjson_mut_val *item, cbm_store_t *store,
                             int64_t node_id, const char *relationship) {
    const char *et[] = {relationship ? relationship : "CALLS"};
    yyjson_mut_val *conn = yyjson_mut_arr(doc);
    yyjson_mut_val *conn_edges = yyjson_mut_arr(doc);

    /* BFS doesn't support "both" — run inbound + outbound separately. */
    cbm_traverse_result_t tr_in = {0};
    cbm_store_bfs(store, node_id, "inbound", et, SKIP_ONE, SKIP_ONE, MCP_DEFAULT_LIMIT, &tr_in);
    enrich_add_bfs(doc, conn, &tr_in);
    enrich_add_bfs_edges(doc, conn_edges, &tr_in);
    cbm_store_traverse_free(&tr_in);

    cbm_traverse_result_t tr_out = {0};
    cbm_store_bfs(store, node_id, "outbound", et, SKIP_ONE, SKIP_ONE, MCP_DEFAULT_LIMIT, &tr_out);
    enrich_add_bfs(doc, conn, &tr_out);
    enrich_add_bfs_edges(doc, conn_edges, &tr_out);
    cbm_store_traverse_free(&tr_out);

    if (yyjson_mut_arr_size(conn) > 0) {
        yyjson_mut_obj_add_val(doc, item, "connected_names", conn);
    }
    /* Only emitted when at least one connecting edge carries promotion provenance;
     * absent otherwise (invariant 1: grounded trust labels, no invented defaults). */
    if (yyjson_mut_arr_size(conn_edges) > 0) {
        yyjson_mut_obj_add_val(doc, item, "connected_edges", conn_edges);
    }
}

/* BM25 query/result column and binding positions. */
enum {
    BM25_COL_ID = 0,
    BM25_COL_ATOM_ID = 1,
    BM25_COL_LABEL = 2,
    BM25_COL_NAME = 3,
    BM25_COL_QN = 4,
    BM25_COL_FILE = 5,
    BM25_COL_START_LINE = 6,
    BM25_COL_END_LINE = 7,
    BM25_COL_START_BYTE = 8,
    BM25_COL_END_BYTE = 9,
    BM25_COL_RANK = 10,
    BM25_BIND_QUERY = 1,
    BM25_BIND_PROJECT = 2,
    BM25_BIND_LIMIT = 3,
    BM25_BIND_OFFSET = 4,
    BM25_BIND_FILE = 6,
    BM25_BIND_LABEL = 7,
    BM25_SQL_AUTO_LEN = -1,
};

static void mcp_add_source_location(yyjson_mut_doc *doc, yyjson_mut_val *item, int start_line,
                                    int end_line, uint64_t start_byte, uint64_t end_byte) {
    yyjson_mut_obj_add_int(doc, item, "start_line", start_line);
    yyjson_mut_obj_add_int(doc, item, "end_line", end_line);
    yyjson_mut_obj_add_uint(doc, item, "start_byte", start_byte);
    yyjson_mut_obj_add_uint(doc, item, "end_byte", end_byte);
}

/* Module-local SQLITE_TRANSIENT wrapper to dodge performance-no-int-to-ptr.
 * See the matching helper in src/store/store.c for the same pattern. */
static sqlite3_destructor_type mcp_sqlite_transient(void) {
    static const volatile intptr_t raw = -1;
    sqlite3_destructor_type dtor = NULL;
    memcpy(&dtor, (const void *)&raw, sizeof(dtor));
    return dtor;
}
#define MCP_SQLITE_TRANSIENT (mcp_sqlite_transient())

static bool bm25_is_token_byte(unsigned char ch) {
    return (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
           (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
           (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') || ch == (unsigned char)'_' ||
           ch >= 0x80;
}

/* Build one exact FTS5 MATCH expression without a hidden query-size cap.
 * ASCII punctuation separates terms; UTF-8 bytes remain together for the
 * unicode61 tokenizer. Every term is quoted so words such as AND/OR/NOT stay
 * literal search terms rather than becoming caller-supplied FTS operators. */
static char *bm25_build_match(const char *query, size_t *out_tokens) {
    if (!query || !out_tokens) {
        return NULL;
    }
    *out_tokens = 0;
    size_t required = 0;
    const unsigned char *p = (const unsigned char *)query;
    while (*p) {
        while (*p && !bm25_is_token_byte(*p)) {
            p++;
        }
        const unsigned char *start = p;
        while (*p && bm25_is_token_byte(*p)) {
            p++;
        }
        size_t token_len = (size_t)(p - start);
        if (token_len == 0) {
            continue;
        }
        size_t separator_len = *out_tokens > 0 ? SLEN(" OR ") : 0;
        if (required > SIZE_MAX - separator_len) {
            return NULL;
        }
        required += separator_len;
        if (required > SIZE_MAX - SLEN("\"\"")) {
            return NULL;
        }
        required += SLEN("\"\"");
        if (required > SIZE_MAX - token_len) {
            return NULL;
        }
        required += token_len;
        (*out_tokens)++;
    }
    if (required == SIZE_MAX) {
        return NULL;
    }

    char *out = malloc(required + SKIP_ONE);
    if (!out) {
        return NULL;
    }
    size_t pos = 0;
    size_t emitted = 0;
    p = (const unsigned char *)query;
    while (*p) {
        while (*p && !bm25_is_token_byte(*p)) {
            p++;
        }
        const unsigned char *start = p;
        while (*p && bm25_is_token_byte(*p)) {
            p++;
        }
        size_t token_len = (size_t)(p - start);
        if (token_len == 0) {
            continue;
        }
        if (emitted > 0) {
            memcpy(out + pos, " OR ", SLEN(" OR "));
            pos += SLEN(" OR ");
        }
        out[pos++] = '"';
        memcpy(out + pos, start, token_len);
        pos += token_len;
        out[pos++] = '"';
        emitted++;
    }
    out[pos] = '\0';
    return out;
}

static char *bm25_file_pattern_like(const char *file_pattern, bool *out_failed) {
    *out_failed = false;
    if (!file_pattern) {
        return NULL;
    }
    size_t pattern_len = strlen(file_pattern);
    if (pattern_len == SIZE_MAX) {
        *out_failed = true;
        return NULL;
    }
    char *like = malloc(pattern_len + SKIP_ONE);
    if (!like) {
        *out_failed = true;
        return NULL;
    }
    size_t like_len = 0;
    for (size_t i = 0; i < pattern_len; i++) {
        if (file_pattern[i] == '*' && i + SKIP_ONE < pattern_len &&
            file_pattern[i + SKIP_ONE] == '*') {
            if (like_len > 0 && like[like_len - SKIP_ONE] == '/') {
                like_len--;
            }
            like[like_len++] = '%';
            i++;
            if (i + SKIP_ONE < pattern_len && file_pattern[i + SKIP_ONE] == '/') {
                i++;
            }
        } else if (file_pattern[i] == '*') {
            like[like_len++] = '%';
        } else if (file_pattern[i] == '?') {
            like[like_len++] = '_';
        } else {
            like[like_len++] = file_pattern[i];
        }
    }
    like[like_len] = '\0';
    if (!strchr(file_pattern, '*') && !strchr(file_pattern, '?')) {
        if (like_len > SIZE_MAX - MCP_SEPARATOR - SKIP_ONE) {
            free(like);
            *out_failed = true;
            return NULL;
        }
        char *contains = malloc(like_len + MCP_SEPARATOR + SKIP_ONE);
        if (!contains) {
            free(like);
            *out_failed = true;
            return NULL;
        }
        contains[0] = '%';
        memcpy(contains + SKIP_ONE, like, like_len);
        contains[like_len + SKIP_ONE] = '%';
        contains[like_len + MCP_SEPARATOR] = '\0';
        free(like);
        like = contains;
    }
    return like;
}

static char *bm25_error_result(const char *code, const char *operation, const char *message,
                               const char *remediation, int sqlite_error, const char *detail) {
    char sqlite_error_text[CBM_SZ_32];
    snprintf(sqlite_error_text, sizeof(sqlite_error_text), "%d", sqlite_error);
    cbm_log_error("mcp.search_graph_bm25_failed", "code", code, "operation", operation,
                  "sqlite_error", sqlite_error_text, "detail", detail ? detail : "", "message",
                  message, "remediation", remediation);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", code);
    yyjson_mut_obj_add_str(doc, root, "operation", operation);
    yyjson_mut_obj_add_str(doc, root, "message", message);
    yyjson_mut_obj_add_str(doc, root, "remediation", remediation);
    if (sqlite_error != SQLITE_OK) {
        yyjson_mut_obj_add_int(doc, root, "sqlite_error", sqlite_error);
    }
    if (detail && detail[0]) {
        yyjson_mut_obj_add_str(doc, root, "detail", detail);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_BM25_SERIALIZATION_FAILED\",\"operation\":"
            "\"serialize_error\",\"message\":\"the BM25 failure diagnostic could not be "
            "serialized\",\"remediation\":\"free memory and retry the same request\"}",
            true);
    }
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

static int bm25_bind_filters(sqlite3_stmt *stmt, const char *fts_query, const char *project,
                             const char *file_like, const char *label) {
    int rc = sqlite3_bind_text(stmt, BM25_BIND_QUERY, fts_query, BM25_SQL_AUTO_LEN,
                               MCP_SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, BM25_BIND_PROJECT, project, BM25_SQL_AUTO_LEN,
                               MCP_SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = file_like ? sqlite3_bind_text(stmt, BM25_BIND_FILE, file_like, BM25_SQL_AUTO_LEN,
                                           MCP_SQLITE_TRANSIENT)
                       : sqlite3_bind_null(stmt, BM25_BIND_FILE);
    }
    if (rc == SQLITE_OK) {
        rc = label ? sqlite3_bind_text(stmt, BM25_BIND_LABEL, label, BM25_SQL_AUTO_LEN,
                                       MCP_SQLITE_TRANSIENT)
                   : sqlite3_bind_null(stmt, BM25_BIND_LABEL);
    }
    return rc;
}

/* Run the one exclusive BM25 full-text query path and return a complete MCP
 * result. No tokenization, FTS, count, filtering, or serialization failure may
 * be reinterpreted as the unrelated regex mode. */
static char *bm25_search(cbm_store_t *store, const char *project, const char *query,
                         const char *label, const char *file_pattern, int limit, int offset) {
    sqlite3 *db = cbm_store_get_db(store);
    if (!db) {
        return bm25_error_result(
            "CBM_SEARCH_BM25_STORE_UNAVAILABLE", "open_query_store",
            "the verified project store has no SQLite query connection",
            "preserve the store and inspect its verification/open diagnostics before retrying",
            SQLITE_OK, "cbm_store_get_db returned NULL");
    }

    size_t token_count = 0;
    char *fts_query = bm25_build_match(query, &token_count);
    if (!fts_query) {
        return bm25_error_result(
            "CBM_SEARCH_BM25_ALLOCATION_FAILED", "build_match_expression",
            "the complete BM25 MATCH expression could not be allocated",
            "free memory or submit a shorter query, then retry; no partial query was executed",
            SQLITE_OK, "MATCH expression size overflow or allocation failure");
    }
    if (token_count == 0) {
        free(fts_query);
        return bm25_error_result("CBM_SEARCH_BM25_QUERY_EMPTY", "build_match_expression",
                                 "query contains no searchable letters, digits, or underscores",
                                 "provide at least one searchable Unicode or ASCII term", SQLITE_OK,
                                 "no FTS5 term was emitted");
    }

    bool file_pattern_failed = false;
    char *file_like = bm25_file_pattern_like(file_pattern, &file_pattern_failed);
    if (file_pattern_failed) {
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_ALLOCATION_FAILED", "build_file_filter",
            "the complete BM25 file-pattern filter could not be allocated",
            "free memory or submit a shorter file_pattern, then retry; no unfiltered query was "
            "executed",
            SQLITE_OK, "file-pattern size overflow or allocation failure");
    }

    /* Count the exact same contracted domain used by the ranked page. The
     * contentless FTS table supplies authoritative matching rowids; all stored
     * node fields and filters come from the joined nodes table. */
    const char *count_sql =
        "SELECT COUNT(*) "
        "FROM nodes_fts "
        "JOIN nodes n ON n.id = nodes_fts.rowid "
        "WHERE nodes_fts MATCH ?1 "
        "  AND n.project = ?2 "
        "  AND ((?7 IS NULL AND "
        "        n.label NOT IN ('File','Folder','Module','Section','Project')) "
        "       OR n.label = ?7) "
        "  AND (?6 IS NULL OR n.file_path LIKE ?6)";
    sqlite3_stmt *count_stmt = NULL;
    int rc = sqlite3_prepare_v2(db, count_sql, BM25_SQL_AUTO_LEN, &count_stmt, NULL);
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        free(file_like);
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_PREPARE_FAILED", "prepare_exact_count",
            "SQLite could not prepare the exact BM25 count query",
            "inspect the persisted FTS5/schema diagnostic and repair the project store before "
            "retrying",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }
    rc = bm25_bind_filters(count_stmt, fts_query, project, file_like, label);
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        sqlite3_finalize(count_stmt);
        free(file_like);
        free(fts_query);
        return bm25_error_result("CBM_SEARCH_BM25_BIND_FAILED", "bind_exact_count",
                                 "SQLite could not bind the complete BM25 count query",
                                 "inspect the SQLite diagnostic and retry the unchanged request",
                                 sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }
    rc = sqlite3_step(count_stmt);
    if (rc != SQLITE_ROW) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        sqlite3_finalize(count_stmt);
        free(file_like);
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_COUNT_FAILED", "execute_exact_count",
            "SQLite did not return the exact BM25 match count",
            "inspect the persisted FTS5/store diagnostic and retry after repairing the store",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }
    sqlite3_int64 total = sqlite3_column_int64(count_stmt, 0);
    rc = sqlite3_finalize(count_stmt);
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        free(file_like);
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_COUNT_FAILED", "finalize_exact_count",
            "SQLite could not finalize the exact BM25 count query",
            "inspect the persisted FTS5/store diagnostic and retry after repairing the store",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }

    /* bm25() is lower-is-better. The authoritative node ID breaks every score
     * tie so OFFSET pages are stable and cannot repeat or omit equal-ranked rows. */
    const char *sql = "SELECT n.id, n.atom_id, n.label, n.name, n.qualified_name, n.file_path, "
                      "       n.start_line, n.end_line, n.start_byte, n.end_byte, "
                      "       (bm25(nodes_fts) "
                      "        - CASE WHEN n.label IN ('Function','Method') THEN 10.0 "
                      "               WHEN n.label = 'Route' THEN 8.0 "
                      "               WHEN n.label IN ('Class','Interface','Type','Enum') THEN 5.0 "
                      "               ELSE 0.0 END) AS rank "
                      "FROM nodes_fts "
                      "JOIN nodes n ON n.id = nodes_fts.rowid "
                      "WHERE nodes_fts MATCH ?1 "
                      "  AND n.project = ?2 "
                      "  AND ((?7 IS NULL AND "
                      "        n.label NOT IN ('File','Folder','Module','Section','Project')) "
                      "       OR n.label = ?7) "
                      "  AND (?6 IS NULL OR n.file_path LIKE ?6) "
                      "ORDER BY rank, n.id "
                      "LIMIT ?3 OFFSET ?4";

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, sql, BM25_SQL_AUTO_LEN, &stmt, NULL);
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        free(file_like);
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_PREPARE_FAILED", "prepare_ranked_page",
            "SQLite could not prepare the ranked BM25 page query",
            "inspect the persisted FTS5/schema diagnostic and repair the project store before "
            "retrying",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }
    rc = bm25_bind_filters(stmt, fts_query, project, file_like, label);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, BM25_BIND_LIMIT, limit);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, BM25_BIND_OFFSET, offset);
    }
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        free(file_like);
        free(fts_query);
        return bm25_error_result("CBM_SEARCH_BM25_BIND_FAILED", "bind_ranked_page",
                                 "SQLite could not bind the complete ranked BM25 page query",
                                 "inspect the SQLite diagnostic and retry the unchanged request",
                                 sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_uint(doc, root, "total", (uint64_t)total);
    yyjson_mut_obj_add_str(doc, root, "search_mode", "bm25");

    yyjson_mut_val *results = yyjson_mut_arr(doc);
    int emitted = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        yyjson_mut_val *item = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, item, "atom_id",
                                  (const char *)sqlite3_column_text(stmt, BM25_COL_ATOM_ID));
        yyjson_mut_obj_add_strcpy(doc, item, "name",
                                  (const char *)sqlite3_column_text(stmt, BM25_COL_NAME));
        yyjson_mut_obj_add_strcpy(doc, item, "qualified_name",
                                  (const char *)sqlite3_column_text(stmt, BM25_COL_QN));
        yyjson_mut_obj_add_strcpy(doc, item, "label",
                                  (const char *)sqlite3_column_text(stmt, BM25_COL_LABEL));
        yyjson_mut_obj_add_strcpy(doc, item, "file_path",
                                  (const char *)sqlite3_column_text(stmt, BM25_COL_FILE));
        mcp_add_source_location(doc, item, sqlite3_column_int(stmt, BM25_COL_START_LINE),
                                sqlite3_column_int(stmt, BM25_COL_END_LINE),
                                (uint64_t)sqlite3_column_int64(stmt, BM25_COL_START_BYTE),
                                (uint64_t)sqlite3_column_int64(stmt, BM25_COL_END_BYTE));
        yyjson_mut_obj_add_real(doc, item, "rank", sqlite3_column_double(stmt, BM25_COL_RANK));
        yyjson_mut_arr_add_val(results, item);
        emitted++;
    }
    if (rc != SQLITE_DONE) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        yyjson_mut_doc_free(doc);
        free(file_like);
        free(fts_query);
        return bm25_error_result(
            "CBM_SEARCH_BM25_EXECUTE_FAILED", "execute_ranked_page",
            "SQLite could not complete the ranked BM25 page query",
            "inspect the persisted FTS5/store diagnostic and retry after repairing the store",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }
    rc = sqlite3_finalize(stmt);
    free(file_like);
    free(fts_query);
    if (rc != SQLITE_OK) {
        int sqlite_error = sqlite3_extended_errcode(db);
        char detail_copy[CBM_SZ_512];
        snprintf(detail_copy, sizeof(detail_copy), "%s", sqlite3_errmsg(db));
        yyjson_mut_doc_free(doc);
        return bm25_error_result(
            "CBM_SEARCH_BM25_EXECUTE_FAILED", "finalize_ranked_page",
            "SQLite could not finalize the ranked BM25 page query",
            "inspect the persisted FTS5/store diagnostic and retry after repairing the store",
            sqlite_error != SQLITE_OK ? sqlite_error : rc, detail_copy);
    }

    yyjson_mut_obj_add_val(doc, root, "results", results);
    yyjson_mut_obj_add_bool(doc, root, "has_more",
                            total > (sqlite3_int64)offset + (sqlite3_int64)emitted);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return bm25_error_result("CBM_SEARCH_BM25_SERIALIZATION_FAILED", "serialize_ranked_page",
                                 "the exact BM25 result could not be serialized",
                                 "free memory and retry; no partial result was returned", SQLITE_OK,
                                 "yyjson_mut_write returned NULL");
    }
    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Forward declaration — defined later. enrich_node_properties parses the
 * node's properties_json and grafts the parsed values onto the result item.
 * It returns the parsed yyjson_doc which must outlive the serialization
 * because yyjson_mut_obj_add_val uses zero-copy strings into that doc. */
static yyjson_doc *enrich_node_properties(yyjson_mut_doc *doc, yyjson_mut_val *obj,
                                          const char *properties_json);

/* Emit the cbm_store_search results as a JSON "results" array on the doc.
 * Property docs created via enrich_node_properties are collected in
 * *out_pdocs (count in *out_pdoc_count) and must be freed by the caller
 * AFTER serializing doc, since yyjson_mut strings are zero-copy pointers
 * into those parsed docs. The caller also frees out_pdocs itself. */
static void emit_search_results(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                const cbm_search_output_t *out, cbm_store_t *store,
                                const char *relationship, bool include_connected, int offset,
                                yyjson_doc ***out_pdocs, int *out_pdoc_count) {
    yyjson_doc **pdocs = out->count > 0 ? malloc((size_t)out->count * sizeof(yyjson_doc *)) : NULL;
    int pdoc_count = 0;
    yyjson_mut_obj_add_int(doc, root, "total", out->total);
    yyjson_mut_val *results = yyjson_mut_arr(doc);
    for (int i = 0; i < out->count; i++) {
        cbm_search_result_t *sr = &out->results[i];
        yyjson_mut_val *item = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, item, "atom_id", sr->node.atom_id ? sr->node.atom_id : "");
        yyjson_mut_obj_add_str(doc, item, "name", sr->node.name ? sr->node.name : "");
        yyjson_mut_obj_add_str(doc, item, "qualified_name",
                               sr->node.qualified_name ? sr->node.qualified_name : "");
        yyjson_mut_obj_add_str(doc, item, "label", sr->node.label ? sr->node.label : "");
        yyjson_mut_obj_add_str(doc, item, "file_path",
                               sr->node.file_path ? sr->node.file_path : "");
        mcp_add_source_location(doc, item, sr->node.start_line, sr->node.end_line,
                                sr->node.start_byte, sr->node.end_byte);
        yyjson_mut_obj_add_int(doc, item, "in_degree", sr->in_degree);
        yyjson_mut_obj_add_int(doc, item, "out_degree", sr->out_degree);
        if (include_connected && sr->node.id > 0) {
            enrich_connected(doc, item, store, sr->node.id, relationship);
        }
        yyjson_doc *pdoc = enrich_node_properties(doc, item, sr->node.properties_json);
        if (pdoc && pdocs) {
            pdocs[pdoc_count++] = pdoc;
        }
        yyjson_mut_arr_add_val(results, item);
    }
    yyjson_mut_obj_add_val(doc, root, "results", results);
    yyjson_mut_obj_add_bool(doc, root, "has_more", out->total > offset + out->count);
    *out_pdocs = pdocs;
    *out_pdoc_count = pdoc_count;
}

/* Extract keyword strings from a yyjson array into `keywords`.  Returns the
 * number of strings copied (capped at `max_out`). */
static int extract_semantic_keywords(yyjson_val *sq_val, const char **keywords, int max_out) {
    int kw_count = (int)yyjson_arr_size(sq_val);
    if (kw_count > max_out) {
        kw_count = max_out;
    }
    size_t kw_idx = 0;
    size_t kw_max = 0;
    yyjson_val *kw_val;
    int ki = 0;
    yyjson_arr_foreach(sq_val, kw_idx, kw_max, kw_val) {
        if (ki < kw_count && yyjson_is_str(kw_val)) {
            keywords[ki++] = yyjson_get_str(kw_val);
        }
    }
    return ki;
}

/* Emit cbm_vector_result_t entries as a "semantic_results" array on the doc. */
static void emit_semantic_results(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                  cbm_vector_result_t *vresults, int vcount) {
    yyjson_mut_val *sem_results = yyjson_mut_arr(doc);
    for (int v = 0; v < vcount; v++) {
        yyjson_mut_val *vitem = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, vitem, "atom_id", vresults[v].atom_id);
        yyjson_mut_obj_add_strcpy(doc, vitem, "name", vresults[v].name);
        yyjson_mut_obj_add_strcpy(doc, vitem, "qualified_name", vresults[v].qualified_name);
        yyjson_mut_obj_add_strcpy(doc, vitem, "label", vresults[v].label);
        yyjson_mut_obj_add_strcpy(doc, vitem, "file_path", vresults[v].file_path);
        mcp_add_source_location(doc, vitem, vresults[v].start_line, vresults[v].end_line,
                                vresults[v].start_byte, vresults[v].end_byte);
        yyjson_mut_obj_add_real(doc, vitem, "score", vresults[v].score);
        yyjson_mut_arr_add_val(sem_results, vitem);
    }
    yyjson_mut_obj_add_val(doc, root, "semantic_results", sem_results);
}

/* Append the semantic_query vector-search results onto the doc.  Returns
 * true if semantic_query was provided as a non-array (type error — caller
 * should surface to the user). */
static bool run_semantic_query(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *args,
                               cbm_store_t *store, const char *project, int limit) {
    enum { MAX_KW_SEARCH = 32 };
    yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
    yyjson_val *args_root = args_doc ? yyjson_doc_get_root(args_doc) : NULL;
    yyjson_val *sq_val = args_root ? yyjson_obj_get(args_root, "semantic_query") : NULL;
    bool type_error = false;
    if (sq_val && !yyjson_is_arr(sq_val)) {
        type_error = true;
    } else if (sq_val && yyjson_arr_size(sq_val) > 0) {
        const char *keywords[MAX_KW_SEARCH];
        int ki = extract_semantic_keywords(sq_val, keywords, MAX_KW_SEARCH);
        cbm_vector_result_t *vresults = NULL;
        int vcount = 0;
        int sem_limit = limit > 0 ? limit : CBM_SZ_16;
        if (cbm_store_vector_search(store, project, keywords, ki, sem_limit, &vresults, &vcount) ==
                CBM_STORE_OK &&
            vcount > 0) {
            emit_semantic_results(doc, root, vresults, vcount);
            cbm_store_free_vector_results(vresults, vcount);
        }
    }
    if (args_doc) {
        yyjson_doc_free(args_doc);
    }
    return type_error;
}

static char *search_graph_argument_error_result(const char *argument, const char *expected,
                                                const char *actual) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
    if (!root) {
        if (doc) {
            yyjson_mut_doc_free(doc);
        }
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_MCP_INVALID_ARGUMENT\",\"message\":\"search_graph arguments do "
            "not conform to the advertised inputSchema\",\"remediation\":\"send a JSON object "
            "whose fields have the advertised JSON types\"}",
            true);
    }

    yyjson_mut_doc_set_root(doc, root);
    char message[CBM_SZ_512];
    snprintf(message, sizeof(message), "search_graph argument '%s' must be %s; received %s",
             argument, expected, actual);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_MCP_INVALID_ARGUMENT");
    yyjson_mut_obj_add_str(doc, root, "message", message);
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "send search_graph arguments that conform to the inputSchema returned "
                           "by tools/list; correct the named field's JSON type and retry");
    yyjson_mut_obj_add_str(doc, root, "argument", argument);
    yyjson_mut_obj_add_str(doc, root, "expected_type", expected);
    yyjson_mut_obj_add_str(doc, root, "actual_type", actual);

    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_MCP_INVALID_ARGUMENT\",\"message\":\"search_graph argument "
            "validation failed and its detailed response could not be serialized\","
            "\"remediation\":\"free memory and retry the same corrected request\"}",
            true);
    }
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

/* Validate every field whose type is declared by search_graph's tools/list
 * inputSchema before resolving a project or opening a store. The generic argument
 * accessors intentionally return their defaults for absent fields, so without this
 * boundary a present value of the wrong JSON type is indistinguishable from absence. */
static char *validate_search_graph_arguments(const char *args) {
    yyjson_doc *doc = args ? yyjson_read(args, strlen(args), 0) : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) {
        const char *actual = root ? yyjson_get_type_desc(root) : "invalid JSON";
        char *result = search_graph_argument_error_result("arguments", "a JSON object", actual);
        if (doc) {
            yyjson_doc_free(doc);
        }
        return result;
    }

    yyjson_val *project = yyjson_obj_get(root, "project");
    if (!project || !yyjson_is_str(project)) {
        const char *actual = project ? yyjson_get_type_desc(project) : "absent";
        char *result = search_graph_argument_error_result("project", "a JSON string", actual);
        yyjson_doc_free(doc);
        return result;
    }

    const char *string_fields[] = {"query",      "label",        "name_pattern",
                                   "qn_pattern", "file_pattern", "relationship"};
    for (size_t i = 0; i < sizeof(string_fields) / sizeof(string_fields[0]); i++) {
        yyjson_val *value = yyjson_obj_get(root, string_fields[i]);
        if (value && !yyjson_is_str(value)) {
            char *result = search_graph_argument_error_result(string_fields[i], "a JSON string",
                                                              yyjson_get_type_desc(value));
            yyjson_doc_free(doc);
            return result;
        }
    }

    const char *integer_fields[] = {"min_degree", "max_degree", "limit", "offset"};
    for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); i++) {
        yyjson_val *value = yyjson_obj_get(root, integer_fields[i]);
        if (value && !yyjson_is_int(value)) {
            char *result = search_graph_argument_error_result(integer_fields[i], "a JSON integer",
                                                              yyjson_get_type_desc(value));
            yyjson_doc_free(doc);
            return result;
        }
    }
    yyjson_val *limit_value = yyjson_obj_get(root, "limit");
    if (limit_value &&
        (yyjson_get_sint(limit_value) <= 0 || yyjson_get_sint(limit_value) > INT_MAX)) {
        char *result = search_graph_argument_error_result(
            "limit", "a JSON integer from 1 through 2147483647", "an out-of-range JSON integer");
        yyjson_doc_free(doc);
        return result;
    }
    yyjson_val *offset_value = yyjson_obj_get(root, "offset");
    if (offset_value &&
        (yyjson_get_sint(offset_value) < 0 || yyjson_get_sint(offset_value) > INT_MAX)) {
        char *result = search_graph_argument_error_result(
            "offset", "a JSON integer from 0 through 2147483647", "an out-of-range JSON integer");
        yyjson_doc_free(doc);
        return result;
    }

    const char *boolean_fields[] = {"exclude_entry_points", "include_connected"};
    for (size_t i = 0; i < sizeof(boolean_fields) / sizeof(boolean_fields[0]); i++) {
        yyjson_val *value = yyjson_obj_get(root, boolean_fields[i]);
        if (value && !yyjson_is_bool(value)) {
            char *result = search_graph_argument_error_result(boolean_fields[i], "a JSON boolean",
                                                              yyjson_get_type_desc(value));
            yyjson_doc_free(doc);
            return result;
        }
    }

    yyjson_val *semantic_query = yyjson_obj_get(root, "semantic_query");
    if (semantic_query && !yyjson_is_arr(semantic_query)) {
        char *result = search_graph_argument_error_result(
            "semantic_query", "an array of JSON strings", yyjson_get_type_desc(semantic_query));
        yyjson_doc_free(doc);
        return result;
    }
    if (semantic_query) {
        size_t index, max;
        yyjson_val *item;
        yyjson_arr_foreach(semantic_query, index, max, item) {
            if (!yyjson_is_str(item)) {
                char argument[CBM_SZ_64];
                snprintf(argument, sizeof(argument), "semantic_query[%zu]", index);
                char *result = search_graph_argument_error_result(argument, "a JSON string",
                                                                  yyjson_get_type_desc(item));
                yyjson_doc_free(doc);
                return result;
            }
        }
    }

    yyjson_val *query_value = yyjson_obj_get(root, "query");
    if (query_value) {
        if (yyjson_get_len(query_value) == 0) {
            char *result = search_graph_argument_error_result("query", "a non-empty JSON string",
                                                              "an empty JSON string");
            yyjson_doc_free(doc);
            return result;
        }
        const char *incompatible_fields[] = {
            "name_pattern", "qn_pattern",           "relationship",      "min_degree",
            "max_degree",   "exclude_entry_points", "include_connected", "semantic_query",
        };
        for (size_t i = 0; i < sizeof(incompatible_fields) / sizeof(incompatible_fields[0]); i++) {
            yyjson_val *value = yyjson_obj_get(root, incompatible_fields[i]);
            if (value) {
                char *result = search_graph_argument_error_result(incompatible_fields[i],
                                                                  "absent when query is provided",
                                                                  yyjson_get_type_desc(value));
                yyjson_doc_free(doc);
                return result;
            }
        }
    }

    yyjson_doc_free(doc);
    return NULL;
}

static char *handle_search_graph(cbm_mcp_server_t *srv, const char *args) {
    char *argument_error = validate_search_graph_arguments(args);
    if (argument_error) {
        return argument_error;
    }

    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(project);
        return not_indexed;
    }

    /* An explicit query selects one exclusive BM25 path. Every failure is
     * returned from that mode; it is never reinterpreted as regex/vector search. */
    char *query = cbm_mcp_get_string_arg(args, "query");
    if (query) {
        int q_limit = cbm_mcp_get_int_arg(args, "limit", CBM_DEFAULT_SEARCH_LIMIT);
        int q_offset = cbm_mcp_get_int_arg(args, "offset", 0);
        char *q_label = cbm_mcp_get_string_arg(args, "label");
        char *q_file_pattern = cbm_mcp_get_string_arg(args, "file_pattern");
        char *result =
            bm25_search(store, project, query, q_label, q_file_pattern, q_limit, q_offset);
        free(q_label);
        free(q_file_pattern);
        free(query);
        free(project);
        return result;
    }
    free(query);

    char *label = cbm_mcp_get_string_arg(args, "label");
    char *name_pattern = cbm_mcp_get_string_arg(args, "name_pattern");
    char *qn_pattern = cbm_mcp_get_string_arg(args, "qn_pattern");
    char *file_pattern = cbm_mcp_get_string_arg(args, "file_pattern");
    char *relationship = cbm_mcp_get_string_arg(args, "relationship");
    bool exclude_entry_points = cbm_mcp_get_bool_arg(args, "exclude_entry_points");
    bool include_connected = cbm_mcp_get_bool_arg(args, "include_connected");
    int limit = cbm_mcp_get_int_arg(args, "limit", CBM_DEFAULT_SEARCH_LIMIT);
    int offset = cbm_mcp_get_int_arg(args, "offset", 0);
    int min_degree = cbm_mcp_get_int_arg(args, "min_degree", CBM_NOT_FOUND);
    int max_degree = cbm_mcp_get_int_arg(args, "max_degree", CBM_NOT_FOUND);

    if (relationship && !validate_edge_type(relationship)) {
        free(project);
        free(label);
        free(name_pattern);
        free(qn_pattern);
        free(file_pattern);
        free(relationship);
        return cbm_mcp_text_result("relationship must be uppercase letters and underscores", true);
    }

    cbm_search_params_t params = {
        .project = project,
        .label = label,
        .name_pattern = name_pattern,
        .qn_pattern = qn_pattern,
        .file_pattern = file_pattern,
        .relationship = relationship,
        .exclude_entry_points = exclude_entry_points,
        .include_connected = include_connected,
        .limit = limit,
        .offset = offset,
        .min_degree = min_degree,
        .max_degree = max_degree,
    };

    cbm_search_output_t out = {0};
    cbm_store_search(store, &params, &out);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_doc **props_docs = NULL;
    int props_doc_count = 0;
    emit_search_results(doc, root, &out, store, relationship, include_connected, offset,
                        &props_docs, &props_doc_count);

    /* Add diagnostic hint when zero results */
    if (out.total == 0) {
        if (name_pattern && label) {
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "No results. Try removing the label filter or broadening the name_pattern regex.");
        } else if (name_pattern) {
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "No nodes match this pattern. Check spelling or try a broader regex.");
        } else if (label) {
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "No nodes with this label. Available labels: Function, Method, Class, "
                "Interface, Route, Variable, Module, Package, File, Folder.");
        }
    }

    bool sq_type_error = run_semantic_query(doc, root, args, store, project, limit);

    if (sq_type_error) {
        for (int pi = 0; pi < props_doc_count; pi++) {
            yyjson_doc_free(props_docs[pi]);
        }
        free(props_docs);
        yyjson_mut_doc_free(doc);
        cbm_store_search_free(&out);
        free(project);
        free(label);
        free(name_pattern);
        free(qn_pattern);
        free(file_pattern);
        free(relationship);
        return cbm_mcp_text_result(
            "semantic_query must be an array of keyword strings, e.g. "
            "[\"send\",\"pubsub\",\"publish\"] — not a single string. Split your query "
            "into individual keywords; each is scored independently via per-keyword "
            "min-cosine.",
            true);
    }

    char *json = yy_doc_to_str(doc);
    /* Property docs are zero-copy referenced by the mut doc — they must
     * outlive yy_doc_to_str. Free them once serialization is complete. */
    for (int pi = 0; pi < props_doc_count; pi++) {
        yyjson_doc_free(props_docs[pi]);
    }
    free(props_docs);
    yyjson_mut_doc_free(doc);
    cbm_store_search_free(&out);

    free(project);
    free(label);
    free(name_pattern);
    free(qn_pattern);
    free(file_pattern);
    free(relationship);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

static char *handle_query_graph(cbm_mcp_server_t *srv, const char *args) {
    char *query = cbm_mcp_get_string_arg(args, "query");
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    int max_rows = cbm_mcp_get_int_arg(args, "max_rows", 0);

    if (!query) {
        free(project);
        return cbm_mcp_text_result("query is required", true);
    }
    if (!store) {
        char *_err = build_no_store_error(srv, project);
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(project);
        free(query);
        return _res;
    }

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(project);
        free(query);
        return not_indexed;
    }

    cbm_cypher_result_t result = {0};
    int rc = cbm_cypher_execute(store, query, project, max_rows, &result);

    if (rc < 0) {
        char *err_msg = result.error ? result.error : "query execution failed";
        char *resp = cbm_mcp_text_result(err_msg, true);
        cbm_cypher_result_free(&result);
        free(query);
        free(project);
        return resp;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    /* columns */
    yyjson_mut_val *cols = yyjson_mut_arr(doc);
    for (int i = 0; i < result.col_count; i++) {
        yyjson_mut_arr_add_str(doc, cols, result.columns[i]);
    }
    yyjson_mut_obj_add_val(doc, root, "columns", cols);

    /* rows */
    yyjson_mut_val *rows = yyjson_mut_arr(doc);
    for (int r = 0; r < result.row_count; r++) {
        yyjson_mut_val *row = yyjson_mut_arr(doc);
        for (int c = 0; c < result.col_count; c++) {
            yyjson_mut_arr_add_str(doc, row, result.rows[r][c]);
        }
        yyjson_mut_arr_add_val(rows, row);
    }
    yyjson_mut_obj_add_val(doc, root, "rows", rows);
    yyjson_mut_obj_add_int(doc, root, "total", result.row_count);

    if (result.row_count == 0) {
        yyjson_mut_obj_add_str(
            doc, root, "hint",
            "Query returned no results. Use get_graph_schema() to see available labels and "
            "edge types.");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_cypher_result_free(&result);
    free(query);
    free(project);

    char *res = cbm_mcp_text_result(json, false);
    free(json);
    return res;
}

static char *handle_index_status(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    if (project) {
        int nodes = cbm_store_count_nodes(store, project);
        int edges = cbm_store_count_edges(store, project);
        yyjson_mut_obj_add_str(doc, root, "project", project);
        yyjson_mut_obj_add_int(doc, root, "nodes", nodes);
        yyjson_mut_obj_add_int(doc, root, "edges", edges);
        yyjson_mut_obj_add_str(doc, root, "status", nodes > 0 ? "ready" : "empty");
        cbm_project_t proj_info = {0};
        if (cbm_store_get_project(store, project, &proj_info) == CBM_STORE_OK) {
            yyjson_mut_obj_add_strcpy(doc, root, "root_path",
                                      proj_info.root_path ? proj_info.root_path : "");
            add_git_context_json(doc, root, proj_info.root_path);
            safe_str_free(&proj_info.name);
            safe_str_free(&proj_info.indexed_at);
            safe_str_free(&proj_info.root_path);
        }
        if (nodes == 0) {
            yyjson_mut_obj_add_str(
                doc, root, "hint",
                "Project is empty. Re-run index_repository(repo_path=...) to populate.");
        }
    } else {
        yyjson_mut_obj_add_str(doc, root, "status", "no_project");
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(project);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* delete_project: just erase the .db file (and WAL/SHM). */
static char *handle_delete_project(cbm_mcp_server_t *srv, const char *args) {
    char *name = get_project_arg(args);
    if (!name) {
        return cbm_mcp_text_result("project is required", true);
    }

    /* Close store if it's the project being deleted */
    if (srv->current_project && strcmp(srv->current_project, name) == 0) {
        if (srv->owns_store && srv->store) {
            cbm_store_close(srv->store);
            srv->store = NULL;
        }
        free(srv->current_project);
        srv->current_project = NULL;
    }

    /* Wait for any in-progress pipeline to finish before deleting */
    cbm_pipeline_lock();

    /* Delete the .db file + WAL/SHM */
    char path[CBM_SZ_1K];
    project_db_path(name, path, sizeof(path));

    char wal[CBM_SZ_1K];
    char shm[CBM_SZ_1K];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);

    /* #430: extended-length-safe existence probe. The old access(path, F_OK)
     * was MAX_PATH-bound, so on a deep store (>260-char db path) the .db file
     * was really present yet this gate reported "not_found" and never reached
     * the cbm_unlink sites below — orphaning the whole .db/-wal/-shm family.
     * cbm_path_exists widens via "\\?\" (GetFileAttributesW) so the probe agrees
     * with the unlink calls that are already long-path-safe (#415). */
    bool exists = cbm_path_exists(path);
    const char *status = "not_found";
    const char *error_detail = NULL;
    bool is_error = false;

    if (exists) {
        int rc = cbm_unlink(path);
        (void)cbm_unlink(wal);
        (void)cbm_unlink(shm);
        if (rc == 0) {
            status = "deleted";
        } else {
            status = "delete_failed";
            error_detail = strerror(errno);
            is_error = true;
        }
    } else {
        is_error = true;
    }

    cbm_pipeline_unlock();

    if (srv->watcher) {
        cbm_watcher_unwatch(srv->watcher, name);
    }

    cbm_mem_collect(); /* return freed pages to OS after closing database */

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "project", name);
    yyjson_mut_obj_add_str(doc, root, "status", status);
    if (error_detail) {
        yyjson_mut_obj_add_str(doc, root, "error", error_detail);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(name);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* Canonical list of valid aspect tokens for get_architecture. Single source
 * of truth for the server-side validation (authoritative); the JSON-Schema
 * enum in the TOOLS entry above is the advisory client-side mirror — update
 * both together when the aspect set changes. */
static const char *VALID_ASPECTS[] = {
    "all",          "overview", "structure",  "dependencies", "routes",    "languages", "packages",
    "entry_points", "hotspots", "boundaries", "layers",       "file_tree", "clusters",  NULL};

static bool aspect_is_valid(const char *name) {
    if (!name) {
        return false;
    }
    for (int i = 0; VALID_ASPECTS[i]; i++) {
        if (strcmp(name, VALID_ASPECTS[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Check if an aspect is requested. NULL aspects = all. The array can contain
 * "all" (everything), "overview" (everything except file_tree — see
 * cbm_store_arch_aspect_in_overview in store.c), or the aspect name itself. */
static bool aspect_wanted(yyjson_doc *aspects_doc, yyjson_val *aspects_arr, const char *name) {
    if (!aspects_arr) {
        return true; /* no filter = all */
    }
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(aspects_arr, &iter);
    yyjson_val *val;
    while ((val = yyjson_arr_iter_next(&iter)) != NULL) {
        const char *s = yyjson_get_str(val);
        if (!s) {
            continue;
        }
        if (strcmp(s, "all") == 0) {
            return true;
        }
        if (strcmp(s, "overview") == 0 && cbm_store_arch_aspect_in_overview(name)) {
            return true;
        }
        if (strcmp(s, name) == 0) {
            return true;
        }
    }
    (void)aspects_doc;
    return false;
}

/* Append cross_repo_links summary to architecture JSON if CROSS_* edges exist. */
static void append_cross_repo_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                      const cbm_schema_info_t *schema) {
    /* Scan edge types for any CROSS_* edges and sum them */
    int cross_total = 0;
    yyjson_mut_val *cr = yyjson_mut_obj(doc);
    static const char *cross_types[] = {"CROSS_HTTP_CALLS",    "CROSS_ASYNC_CALLS",
                                        "CROSS_CHANNEL",       "CROSS_GRPC_CALLS",
                                        "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS"};
    for (int t = 0; t < (int)(sizeof(cross_types) / sizeof(cross_types[0])); t++) {
        for (int i = 0; i < schema->edge_type_count; i++) {
            if (strcmp(schema->edge_types[i].type, cross_types[t]) == 0) {
                yyjson_mut_obj_add_int(doc, cr, cross_types[t], schema->edge_types[i].count);
                cross_total += schema->edge_types[i].count;
                break;
            }
        }
    }
    if (cross_total > 0) {
        yyjson_mut_obj_add_int(doc, cr, "total", cross_total);
        yyjson_mut_obj_add_val(doc, root, "cross_repo_links", cr);
    }
}

static char *handle_get_architecture(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    char *scope_path = cbm_mcp_get_string_arg(args, "path");
    cbm_store_t *store = resolve_store(srv, project);
    REQUIRE_STORE(store, project);

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(project);
        free(scope_path);
        return not_indexed;
    }

    /* Parse aspects array from args */
    yyjson_doc *aspects_doc = NULL;
    yyjson_val *aspects_arr = NULL;
    {
        yyjson_doc *args_doc = yyjson_read(args, strlen(args), 0);
        if (args_doc) {
            yyjson_val *aval = yyjson_obj_get(yyjson_doc_get_root(args_doc), "aspects");
            if (yyjson_is_arr(aval)) {
                aspects_doc = args_doc; /* keep alive */
                aspects_arr = aval;
            } else {
                yyjson_doc_free(args_doc);
            }
        }
    }

    /* Build a C string array from aspects for cbm_store_get_architecture.
     * Strings point into aspects_doc memory so aspects_doc must outlive this array. */
    const char *aspects_strs[MCP_COL_16];
    int aspects_strs_count = 0;
    if (aspects_arr) {
        size_t aspect_idx;
        size_t aspect_max;
        yyjson_val *aspect_val;
        yyjson_arr_foreach(aspects_arr, aspect_idx, aspect_max, aspect_val) {
            const char *s = yyjson_get_str(aspect_val);
            if (s && aspects_strs_count < MCP_COL_16) {
                aspects_strs[aspects_strs_count++] = s;
            }
        }
    }

    /* Server-side validation: reject unknown aspect tokens with an isError
     * result listing the valid values. The JSON-Schema enum is advisory —
     * many MCP clients do not validate arguments against tool schemas — so
     * without this check a typo degraded to a silent near-empty payload. */
    for (int i = 0; i < aspects_strs_count; i++) {
        if (!aspect_is_valid(aspects_strs[i])) {
            char valid_list[CBM_SZ_256];
            size_t off = 0;
            for (int j = 0; VALID_ASPECTS[j] && off < sizeof(valid_list); j++) {
                int n = snprintf(valid_list + off, sizeof(valid_list) - off, "%s%s",
                                 j > 0 ? ", " : "", VALID_ASPECTS[j]);
                if (n < 0) {
                    break;
                }
                off += (size_t)n;
            }
            char msg[CBM_SZ_512];
            snprintf(msg, sizeof(msg), "Unknown aspect '%s'. Valid: %s.", aspects_strs[i],
                     valid_list);
            char *err = cbm_mcp_text_result(msg, true);
            free(project);
            free(scope_path);
            if (aspects_doc) {
                yyjson_doc_free(aspects_doc);
            }
            return err;
        }
    }

    cbm_schema_info_t schema = {0};
    /* Counts-only: this handler renders label/type counts but never property
     * keys, and full key discovery json_each-scans every row (seconds-to-
     * minutes on multi-million-node graphs). */
    cbm_store_get_schema_counts_scoped(store, project, scope_path, &schema);

    cbm_architecture_info_t arch = {0};
    cbm_store_get_architecture(store, project, scope_path,
                               aspects_strs_count > 0 ? aspects_strs : NULL, aspects_strs_count,
                               &arch);

    int node_count = cbm_store_count_nodes_scoped(store, project, scope_path);
    int edge_count = cbm_store_count_edges_scoped(store, project, scope_path);
    char norm_path[CBM_SZ_512];
    bool path_scoped = cbm_store_normalize_arch_path(scope_path, norm_path, sizeof(norm_path));

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    if (project) {
        yyjson_mut_obj_add_str(doc, root, "project", project);
    }
    if (path_scoped) {
        yyjson_mut_obj_add_str(doc, root, "path", norm_path);
        int root_nodes = cbm_store_count_nodes(store, project);
        int root_edges = cbm_store_count_edges(store, project);
        yyjson_mut_obj_add_int(doc, root, "root_total_nodes", root_nodes);
        yyjson_mut_obj_add_int(doc, root, "root_total_edges", root_edges);
        yyjson_mut_obj_add_int(doc, root, "scoped_total_nodes", node_count);
        yyjson_mut_obj_add_int(doc, root, "scoped_total_edges", edge_count);
    }
    yyjson_mut_obj_add_int(doc, root, "total_nodes", node_count);
    yyjson_mut_obj_add_int(doc, root, "total_edges", edge_count);

    /* Node label summary */
    if (aspect_wanted(aspects_doc, aspects_arr, "structure")) {
        yyjson_mut_val *labels = yyjson_mut_arr(doc);
        for (int i = 0; i < schema.node_label_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "label", schema.node_labels[i].label);
            yyjson_mut_obj_add_int(doc, item, "count", schema.node_labels[i].count);
            yyjson_mut_arr_add_val(labels, item);
        }
        yyjson_mut_obj_add_val(doc, root, "node_labels", labels);
    }

    /* Edge type summary */
    if (aspect_wanted(aspects_doc, aspects_arr, "dependencies")) {
        yyjson_mut_val *types = yyjson_mut_arr(doc);
        for (int i = 0; i < schema.edge_type_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "type", schema.edge_types[i].type);
            yyjson_mut_obj_add_int(doc, item, "count", schema.edge_types[i].count);
            yyjson_mut_arr_add_val(types, item);
        }
        yyjson_mut_obj_add_val(doc, root, "edge_types", types);
    }

    /* Relationship patterns */
    if (aspect_wanted(aspects_doc, aspects_arr, "routes") && schema.rel_pattern_count > 0) {
        yyjson_mut_val *pats = yyjson_mut_arr(doc);
        for (int i = 0; i < schema.rel_pattern_count; i++) {
            yyjson_mut_arr_add_str(doc, pats, schema.rel_patterns[i]);
        }
        yyjson_mut_obj_add_val(doc, root, "relationship_patterns", pats);
    }

    /* Languages */
    if (arch.language_count > 0) {
        yyjson_mut_val *langs = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.language_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "language",
                                   arch.languages[i].language ? arch.languages[i].language : "");
            yyjson_mut_obj_add_int(doc, item, "file_count", arch.languages[i].file_count);
            yyjson_mut_arr_add_val(langs, item);
        }
        yyjson_mut_obj_add_val(doc, root, "languages", langs);
    }

    /* Packages */
    if (arch.package_count > 0) {
        yyjson_mut_val *pkgs = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.package_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "name",
                                   arch.packages[i].name ? arch.packages[i].name : "");
            yyjson_mut_obj_add_int(doc, item, "node_count", arch.packages[i].node_count);
            yyjson_mut_obj_add_int(doc, item, "fan_in", arch.packages[i].fan_in);
            yyjson_mut_obj_add_int(doc, item, "fan_out", arch.packages[i].fan_out);
            yyjson_mut_arr_add_val(pkgs, item);
        }
        yyjson_mut_obj_add_val(doc, root, "packages", pkgs);
    }

    /* Entry points */
    if (arch.entry_point_count > 0) {
        yyjson_mut_val *eps = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.entry_point_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "name",
                                   arch.entry_points[i].name ? arch.entry_points[i].name : "");
            yyjson_mut_obj_add_str(
                doc, item, "qualified_name",
                arch.entry_points[i].qualified_name ? arch.entry_points[i].qualified_name : "");
            yyjson_mut_obj_add_str(doc, item, "file",
                                   arch.entry_points[i].file ? arch.entry_points[i].file : "");
            yyjson_mut_arr_add_val(eps, item);
        }
        yyjson_mut_obj_add_val(doc, root, "entry_points", eps);
    }

    /* HTTP routes */
    if (arch.route_count > 0) {
        yyjson_mut_val *routes = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.route_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "method",
                                   arch.routes[i].method ? arch.routes[i].method : "");
            yyjson_mut_obj_add_str(doc, item, "path",
                                   arch.routes[i].path ? arch.routes[i].path : "");
            yyjson_mut_obj_add_str(doc, item, "handler",
                                   arch.routes[i].handler ? arch.routes[i].handler : "");
            yyjson_mut_arr_add_val(routes, item);
        }
        yyjson_mut_obj_add_val(doc, root, "routes", routes);
    }

    /* Hotspots */
    if (arch.hotspot_count > 0) {
        yyjson_mut_val *hotspots = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.hotspot_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "name",
                                   arch.hotspots[i].name ? arch.hotspots[i].name : "");
            yyjson_mut_obj_add_str(doc, item, "qualified_name",
                                   arch.hotspots[i].qualified_name ? arch.hotspots[i].qualified_name
                                                                   : "");
            yyjson_mut_obj_add_int(doc, item, "fan_in", arch.hotspots[i].fan_in);
            yyjson_mut_arr_add_val(hotspots, item);
        }
        yyjson_mut_obj_add_val(doc, root, "hotspots", hotspots);
    }

    /* Cross-package boundaries */
    if (arch.boundary_count > 0) {
        yyjson_mut_val *boundaries = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.boundary_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "from",
                                   arch.boundaries[i].from ? arch.boundaries[i].from : "");
            yyjson_mut_obj_add_str(doc, item, "to",
                                   arch.boundaries[i].to ? arch.boundaries[i].to : "");
            yyjson_mut_obj_add_int(doc, item, "call_count", arch.boundaries[i].call_count);
            yyjson_mut_arr_add_val(boundaries, item);
        }
        yyjson_mut_obj_add_val(doc, root, "boundaries", boundaries);
    }

    /* Cross-service links (HTTP/async between services) */
    if (arch.service_count > 0) {
        yyjson_mut_val *services = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.service_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "from",
                                   arch.services[i].from ? arch.services[i].from : "");
            yyjson_mut_obj_add_str(doc, item, "to", arch.services[i].to ? arch.services[i].to : "");
            yyjson_mut_obj_add_str(doc, item, "type",
                                   arch.services[i].type ? arch.services[i].type : "");
            yyjson_mut_obj_add_int(doc, item, "count", arch.services[i].count);
            yyjson_mut_arr_add_val(services, item);
        }
        yyjson_mut_obj_add_val(doc, root, "services", services);
    }

    /* Package layers */
    if (arch.layer_count > 0) {
        yyjson_mut_val *layers = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.layer_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "name",
                                   arch.layers[i].name ? arch.layers[i].name : "");
            yyjson_mut_obj_add_str(doc, item, "layer",
                                   arch.layers[i].layer ? arch.layers[i].layer : "");
            yyjson_mut_obj_add_str(doc, item, "reason",
                                   arch.layers[i].reason ? arch.layers[i].reason : "");
            yyjson_mut_arr_add_val(layers, item);
        }
        yyjson_mut_obj_add_val(doc, root, "layers", layers);
    }

    /* Clusters (community detection) */
    if (arch.cluster_count > 0) {
        yyjson_mut_val *clusters = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.cluster_count; i++) {
            const cbm_cluster_info_t *c = &arch.clusters[i];
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_int(doc, item, "id", c->id);
            yyjson_mut_obj_add_str(doc, item, "label", c->label ? c->label : "");
            yyjson_mut_obj_add_int(doc, item, "members", c->members);
            yyjson_mut_obj_add_real(doc, item, "cohesion", c->cohesion);
            yyjson_mut_val *top = yyjson_mut_arr(doc);
            for (int j = 0; j < c->top_node_count; j++) {
                yyjson_mut_arr_add_str(doc, top, c->top_nodes[j] ? c->top_nodes[j] : "");
            }
            yyjson_mut_obj_add_val(doc, item, "top_nodes", top);
            yyjson_mut_val *pkgs = yyjson_mut_arr(doc);
            for (int j = 0; j < c->package_count; j++) {
                yyjson_mut_arr_add_str(doc, pkgs, c->packages[j] ? c->packages[j] : "");
            }
            yyjson_mut_obj_add_val(doc, item, "packages", pkgs);
            yyjson_mut_val *etypes = yyjson_mut_arr(doc);
            for (int j = 0; j < c->edge_type_count; j++) {
                yyjson_mut_arr_add_str(doc, etypes, c->edge_types[j] ? c->edge_types[j] : "");
            }
            yyjson_mut_obj_add_val(doc, item, "edge_types", etypes);
            yyjson_mut_arr_add_val(clusters, item);
        }
        yyjson_mut_obj_add_val(doc, root, "clusters", clusters);
    }

    /* File tree */
    if (arch.file_tree_count > 0) {
        yyjson_mut_val *file_tree = yyjson_mut_arr(doc);
        for (int i = 0; i < arch.file_tree_count; i++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "path",
                                   arch.file_tree[i].path ? arch.file_tree[i].path : "");
            yyjson_mut_obj_add_str(doc, item, "type",
                                   arch.file_tree[i].type ? arch.file_tree[i].type : "");
            yyjson_mut_obj_add_int(doc, item, "children", arch.file_tree[i].children);
            yyjson_mut_arr_add_val(file_tree, item);
        }
        yyjson_mut_obj_add_val(doc, root, "file_tree", file_tree);
    }

    append_cross_repo_summary(doc, root, &schema);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_store_architecture_free(&arch);
    cbm_store_schema_free(&schema);
    if (aspects_doc) {
        yyjson_doc_free(aspects_doc);
    }
    free(project);
    free(scope_path);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Resolve edge types from args: explicit array > mode-based > default ("CALLS").
 * Writes types into out_types (max 16). Returns the parsed yyjson_doc if explicit
 * edge_types were found (caller must keep alive until types are consumed), or NULL. */
static yyjson_doc *resolve_trace_edge_types(const char *args, const char *mode,
                                            const char **out_types, int *out_count) {
    static const char *mode_calls[] = {"CALLS"};
    static const char *mode_data_flow[] = {"CALLS", "DATA_FLOWS"};
    static const char *mode_cross_svc[] = {
        "HTTP_CALLS",          "ASYNC_CALLS",       "DATA_FLOWS",    "CALLS",
        "CROSS_HTTP_CALLS",    "CROSS_ASYNC_CALLS", "CROSS_CHANNEL", "CROSS_GRPC_CALLS",
        "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS"};

    *out_count = 0;

    yyjson_doc *et_doc = yyjson_read(args, strlen(args), 0);
    if (et_doc) {
        yyjson_val *et_arr = yyjson_obj_get(yyjson_doc_get_root(et_doc), "edge_types");
        if (et_arr && yyjson_is_arr(et_arr)) {
            size_t idx2;
            size_t max2;
            yyjson_val *val2;
            yyjson_arr_foreach(et_arr, idx2, max2, val2) {
                if (yyjson_is_str(val2) && *out_count < MCP_COL_16) {
                    out_types[(*out_count)++] = yyjson_get_str(val2);
                }
            }
        }
    }

    if (*out_count > 0) {
        return et_doc; /* caller must keep alive — pointers reference doc memory */
    }

    yyjson_doc_free(et_doc); /* no explicit types found, free */

    const char **defaults = mode_calls;
    int n_defaults = SKIP_ONE;
    if (mode && strcmp(mode, "data_flow") == 0) {
        defaults = mode_data_flow;
        n_defaults = MCP_N_DEFAULTS_2;
    } else if (mode && strcmp(mode, "cross_service") == 0) {
        defaults = mode_cross_svc;
        n_defaults = (int)(sizeof(mode_cross_svc) / sizeof(mode_cross_svc[0]));
    }
    for (int i = 0; i < n_defaults; i++) {
        out_types[i] = defaults[i];
    }
    *out_count = n_defaults;
    return NULL;
}

/* Check if a file path looks like a test file. */
static bool is_test_file(const char *path) {
    if (!path) {
        return false;
    }
    return strstr(path, "/test") != NULL || strstr(path, "test_") != NULL ||
           strstr(path, "_test.") != NULL || strstr(path, "/tests/") != NULL ||
           strstr(path, "/spec/") != NULL || strstr(path, ".test.") != NULL;
}

/* Convert BFS traversal results into a yyjson_mut array. */
/* Find the CALLS-edge "args" JSON (the serialized arg expressions) on the edge
 * that leads to the given hop node, so data_flow mode can surface argument
 * expressions (#514). Returns the borrowed substring "[...]" inside the edge's
 * properties_json, with its length, or NULL when no args are recorded. */
static const char *bfs_edge_args_for_hop(cbm_traverse_result_t *tr, int64_t hop_node_id,
                                         size_t *out_len) {
    for (int e = 0; e < tr->edge_count; e++) {
        /* The hop node is the edge endpoint reached from the root side: for an
         * outbound trace it is the target, for inbound it is the source. Match
         * on either so both directions surface their args. */
        if (tr->edges[e].target_id != hop_node_id && tr->edges[e].source_id != hop_node_id) {
            continue;
        }
        const char *pj = tr->edges[e].properties_json;
        if (!pj) {
            continue;
        }
        const char *args = strstr(pj, "\"args\"");
        if (!args) {
            continue;
        }
        const char *open = strchr(args, '[');
        if (!open) {
            continue;
        }
        int depth = 0;
        const char *p = open;
        for (; *p; p++) {
            if (*p == '[') {
                depth++;
            } else if (*p == ']') {
                depth--;
                if (depth == 0) {
                    p++;
                    break;
                }
            }
        }
        *out_len = (size_t)(p - open);
        return open;
    }
    return NULL;
}

static yyjson_mut_val *bfs_to_json_array(yyjson_mut_doc *doc, cbm_traverse_result_t *tr,
                                         bool risk_labels, bool include_tests, bool data_flow) {
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    for (int i = 0; i < tr->visited_count; i++) {
        const char *fp = tr->visited[i].node.file_path;
        bool test = is_test_file(fp);
        if (!include_tests && test) {
            continue;
        }
        yyjson_mut_val *item = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, item, "name",
                               tr->visited[i].node.name ? tr->visited[i].node.name : "");
        yyjson_mut_obj_add_str(
            doc, item, "qualified_name",
            tr->visited[i].node.qualified_name ? tr->visited[i].node.qualified_name : "");
        yyjson_mut_obj_add_int(doc, item, "hop", tr->visited[i].hop);
        if (risk_labels) {
            yyjson_mut_obj_add_str(doc, item, "risk",
                                   cbm_risk_label(cbm_hop_to_risk(tr->visited[i].hop)));
        }
        if (test) {
            yyjson_mut_obj_add_bool(doc, item, "is_test", true);
        }
        /* data_flow mode promises argument expressions at each call site; surface
         * the CALLS edge's serialized args array as a raw JSON value (#514). */
        if (data_flow) {
            size_t alen = 0;
            const char *args = bfs_edge_args_for_hop(tr, tr->visited[i].node.id, &alen);
            if (args && alen > 0) {
                yyjson_mut_val *av = yyjson_mut_rawn(doc, args, alen);
                if (av) {
                    yyjson_mut_obj_add_val(doc, item, "args", av);
                }
            }
        }
        /* Surface runtime-trace promotion provenance (validated / trust / measured
         * weight / provenance kind) of the edge leading to this hop when present;
         * an unpromoted hop's edge adds nothing (invariant 1). The root (hop 0) has
         * no edge leading to it, so it is never labelled from its own outgoing edge. (#333) */
        if (tr->visited[i].hop > 0) {
            emit_edge_provenance(doc, item, bfs_edge_props_for_hop(tr, tr->visited[i].node.id));
        }
        yyjson_mut_arr_add_val(arr, item);
    }
    return arr;
}

static char *snippet_suggestions(const char *input, cbm_node_t *nodes, int count);

/* Rank a candidate for name resolution. The label tier (callable > class-like >
 * module/file) is the primary key; WITHIN a tier the larger definition by line
 * span wins. In practice the .c-over-.h and C-main-over-shell-main preferences
 * come primarily from span (the real definition has the larger body), since the
 * competing matches usually share a tier — no file extension is hardcoded.
 * Consequence: two same-tier candidates with equal span tie and are reported
 * ambiguous (see pick_resolved_node) rather than guessed. */
enum {
    RES_RANK_CALLABLE = 2,     /* Function / Method */
    RES_RANK_OTHER = 1,        /* Class / Struct / etc. */
    RES_RANK_MODULE = 0,       /* Module / File */
    RES_LABEL_WEIGHT = 1000000 /* label tier dominates span */
};
static long node_resolution_score(const cbm_node_t *n) {
    long label_rank = RES_RANK_MODULE;
    if (n->label) {
        if (strcmp(n->label, "Function") == 0 || strcmp(n->label, "Method") == 0) {
            label_rank = RES_RANK_CALLABLE;
        } else if (strcmp(n->label, "Module") != 0 && strcmp(n->label, "File") != 0) {
            label_rank = RES_RANK_OTHER;
        }
    }
    long span = (long)n->end_line - (long)n->start_line;
    if (span < 0) {
        span = 0;
    }
    return label_rank * (long)RES_LABEL_WEIGHT + span;
}

/* A "real" callable definition: a Function/Method node with a non-empty body
 * span (end_line > start_line). A body-less node (start_line == end_line) is an
 * ambient declaration / signature stub — e.g. a TypeScript `.d.ts` declaration
 * — which is a *fragment* of one logical symbol, not a distinct definition. The
 * distinction lets pick_resolved_node union a stub with its real implementation
 * (#546) while still treating two genuinely-different same-named functions as
 * ambiguous rather than conflating their caller sets. */
static bool node_is_real_callable_def(const cbm_node_t *n) {
    if (!n->label) {
        return false;
    }
    if (strcmp(n->label, "Function") != 0 && strcmp(n->label, "Method") != 0) {
        return false;
    }
    return (long)n->end_line - (long)n->start_line > 0;
}

/* Pick the best-resolving node among name matches. Sets *ambiguous when the
 * matches can't be reduced to one logical symbol, so resolution never silently
 * traces (or conflates) the wrong same-named node:
 *   1. the top score is shared by >1 candidate (a genuine rank/span tie), or
 *   2. two or more *real* callable definitions share the name — distinct
 *      implementations, not a definition plus its body-less stub(s).
 * Rule 2 completes rule 1: without it, two same-named functions whose bodies
 * differ in length score differently, dodge the tie, and get their caller sets
 * unioned by bfs_union_same_name (#546) into one confidently-conflated answer.
 * Body-less .d.ts stubs still union with their implementation (#650). */
static int pick_resolved_node(const cbm_node_t *nodes, int count, bool *ambiguous) {
    *ambiguous = false;
    if (count <= 1) {
        return 0;
    }
    int best = 0;
    long best_score = node_resolution_score(&nodes[0]);
    for (int i = 1; i < count; i++) {
        long s = node_resolution_score(&nodes[i]);
        if (s > best_score) {
            best_score = s;
            best = i;
        }
    }
    int top_count = 0;
    int real_def_count = 0;
    for (int i = 0; i < count; i++) {
        if (node_resolution_score(&nodes[i]) == best_score) {
            top_count++;
        }
        if (node_is_real_callable_def(&nodes[i])) {
            real_def_count++;
        }
    }
    if (real_def_count > 1) {
        *ambiguous = true;
    }
    if (top_count > 1) {
        *ambiguous = true;
    }
    return best;
}

/* BFS from EVERY node sharing the resolved name and merge the results, so the
 * caller/callee set is complete even when one logical symbol is represented by
 * more than one graph node — e.g. a real .ts implementation plus an ambient
 * .d.ts stub, whose inbound CALLS edges are otherwise split across the two
 * nodes and silently truncated by tracing only one (#546). visited hops are
 * deduped by node id; edges are concatenated. Ownership of all heap fields
 * transfers into *out, freed by cbm_store_traverse_free. */
static int bfs_union_same_name(cbm_store_t *store, const cbm_node_t *nodes, int node_count,
                               const char *direction, const char **edge_types, int edge_type_count,
                               int depth, cbm_traverse_result_t *out) {
    memset(out, 0, sizeof(*out));
    int vcap = 0, ecap = 0;
    for (int k = 0; k < node_count; k++) {
        cbm_traverse_result_t tr = {0};
        if (cbm_store_bfs(store, nodes[k].id, direction, edge_types, edge_type_count, depth,
                          MCP_BFS_LIMIT, &tr) != CBM_STORE_OK) {
            cbm_store_traverse_free(&tr);
            cbm_store_traverse_free(out);
            return CBM_STORE_ERR;
        }
        for (int i = 0; i < tr.visited_count; i++) {
            bool dup = false;
            for (int j = 0; j < out->visited_count; j++) {
                if (out->visited[j].node.id == tr.visited[i].node.id) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                continue;
            }
            if (!cbm_da_ensure_capacity((void **)&out->visited, &vcap, out->visited_count + 1,
                                        sizeof(*out->visited))) {
                cbm_store_traverse_free(&tr);
                cbm_store_traverse_free(out);
                cbm_log_error(
                    "mcp.trace_union", "code", "CBM_TRACE_ALLOCATION_FAILED", "message",
                    "trace visited-node allocation failed", "remediation",
                    "free memory or narrow the trace, then retry; no partial trace was returned");
                return CBM_STORE_ERR;
            }
            out->visited[out->visited_count++] = tr.visited[i];
            memset(&tr.visited[i], 0, sizeof(tr.visited[i])); /* ownership moved */
        }
        for (int i = 0; i < tr.edge_count; i++) {
            if (!cbm_da_ensure_capacity((void **)&out->edges, &ecap, out->edge_count + 1,
                                        sizeof(*out->edges))) {
                cbm_store_traverse_free(&tr);
                cbm_store_traverse_free(out);
                cbm_log_error(
                    "mcp.trace_union", "code", "CBM_TRACE_ALLOCATION_FAILED", "message",
                    "trace edge allocation failed", "remediation",
                    "free memory or narrow the trace, then retry; no partial trace was returned");
                return CBM_STORE_ERR;
            }
            out->edges[out->edge_count++] = tr.edges[i];
            memset(&tr.edges[i], 0, sizeof(tr.edges[i])); /* ownership moved */
        }
        cbm_store_traverse_free(&tr); /* frees only the un-moved (root + dup) fields */
    }
    return CBM_STORE_OK;
}

/* Clamp a client-supplied traversal depth to the MCP ceiling (cbm_mcp_max_depth),
 * WARN-logging when it does so — never a silent truncation (#887). An unclamped
 * `depth` would drive the shared cbm_store_bfs to an arbitrary hop count. */
static int clamp_mcp_depth(int depth, const char *tool) {
    int cap = cbm_mcp_max_depth();
    if (depth > cap) {
        char req_buf[16];
        char cap_buf[16];
        snprintf(req_buf, sizeof(req_buf), "%d", depth);
        snprintf(cap_buf, sizeof(cap_buf), "%d", cap);
        cbm_log_warn("mcp.depth_capped", "tool", tool, "requested", req_buf, "cap", cap_buf);
        return cap;
    }
    return depth;
}

static char *handle_trace_call_path(cbm_mcp_server_t *srv, const char *args) {
    char *func_name = cbm_mcp_get_string_arg(args, "function_name");
    char *project = get_project_arg(args);
    cbm_store_t *store = resolve_store(srv, project);
    char *direction = cbm_mcp_get_string_arg(args, "direction");
    char *mode = cbm_mcp_get_string_arg(args, "mode");
    char *param_name = cbm_mcp_get_string_arg(args, "parameter_name");
    int depth = cbm_mcp_get_int_arg(args, "depth", MCP_DEFAULT_DEPTH);
    depth = clamp_mcp_depth(depth, "trace_call_path");
    bool risk_labels = cbm_mcp_get_bool_arg(args, "risk_labels");
    bool include_tests = cbm_mcp_get_bool_arg(args, "include_tests");

    if (!func_name) {
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return cbm_mcp_text_result("function_name is required", true);
    }
    if (!store) {
        char *_err = build_no_store_error(srv, project);
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return _res;
    }

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        return not_indexed;
    }

    if (!direction) {
        direction = heap_strdup("both");
    }

    /* Find the node by name. If the bare-name lookup misses, fall back to
     * qualified_name so callers passing a fully-qualified identifier (which
     * the not-found hint actually recommends) hit the same path. The QN
     * lookup uses the same scan_node helper as the bare lookup, so the
     * shallow struct copy below transfers ownership of the strdup'd string
     * fields cleanly and cbm_store_free_nodes will free them. */
    cbm_node_t *nodes = NULL;
    int node_count = 0;
    cbm_store_find_nodes_by_name(store, project, func_name, &nodes, &node_count);

    if (node_count == 0) {
        cbm_node_t qn_node = {0};
        if (cbm_store_find_node_by_qn(store, project, func_name, &qn_node) == CBM_STORE_OK) {
            nodes = malloc(sizeof(cbm_node_t));
            if (nodes) {
                nodes[0] = qn_node;
                node_count = 1;
            } else {
                free_node_contents(&qn_node);
            }
        }
    }

    if (node_count == 0) {
        enum { HINT_BUF_SZ = 512 };
        char hint[HINT_BUF_SZ];
        snprintf(hint, sizeof(hint),
                 "{\"error\":\"function not found\",\"function_name\":\"%s\","
                 "\"hint\":\"Use search_graph(name_pattern=\\\".*%s.*\\\") to find the exact "
                 "name, then pass it to trace_path.\"}",
                 func_name, func_name);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        cbm_store_free_nodes(nodes, 0);
        return cbm_mcp_text_result(hint, true);
    }

    /* Disambiguate same-named matches: prefer the real definition, and report
     * ambiguity (rather than silently tracing nodes[0]) on a genuine tie — e.g.
     * a C main() vs a same-named shell-script main(). */
    bool trace_ambiguous = false;
    int sel = pick_resolved_node(nodes, node_count, &trace_ambiguous);
    if (trace_ambiguous) {
        char *result = snippet_suggestions(func_name, nodes, node_count);
        free(func_name);
        free(project);
        free(direction);
        free(mode);
        free(param_name);
        cbm_store_free_nodes(nodes, node_count);
        return result;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "function", func_name);
    yyjson_mut_obj_add_str(doc, root, "direction", direction);
    if (mode) {
        yyjson_mut_obj_add_str(doc, root, "mode", mode);
    }

    /* Edge types: explicit > mode-based > default */
    const char *edge_types[MCP_COL_16];
    int edge_type_count = 0;
    yyjson_doc *et_doc_keep = resolve_trace_edge_types(args, mode, edge_types, &edge_type_count);

    /* Run BFS for each requested direction.
     * IMPORTANT: yyjson_mut_obj_add_str borrows pointers — we must keep
     * traversal results alive until after yy_doc_to_str serialization. */
    bool do_outbound = strcmp(direction, "outbound") == 0 || strcmp(direction, "both") == 0;
    bool do_inbound = strcmp(direction, "inbound") == 0 || strcmp(direction, "both") == 0;

    cbm_traverse_result_t tr_out = {0};
    cbm_traverse_result_t tr_in = {0};

    bool data_flow = mode && strcmp(mode, "data_flow") == 0;

    (void)sel; /* union across all same-name nodes — see bfs_union_same_name (#546) */

    if (do_outbound) {
        if (bfs_union_same_name(store, nodes, node_count, "outbound", edge_types, edge_type_count,
                                depth, &tr_out) != CBM_STORE_OK) {
            goto trace_failed;
        }
        yyjson_mut_obj_add_val(
            doc, root, "callees",
            bfs_to_json_array(doc, &tr_out, risk_labels, include_tests, data_flow));
    }

    if (do_inbound) {
        if (bfs_union_same_name(store, nodes, node_count, "inbound", edge_types, edge_type_count,
                                depth, &tr_in) != CBM_STORE_OK) {
            goto trace_failed;
        }
        yyjson_mut_obj_add_val(
            doc, root, "callers",
            bfs_to_json_array(doc, &tr_in, risk_labels, include_tests, data_flow));
    }

    /* Serialize BEFORE freeing traversal results (yyjson borrows strings) */
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    /* Now safe to free traversal data */
    if (do_outbound) {
        cbm_store_traverse_free(&tr_out);
    }
    if (do_inbound) {
        cbm_store_traverse_free(&tr_in);
    }

    cbm_store_free_nodes(nodes, node_count);
    free(func_name);
    free(project);
    free(direction);
    free(mode);
    free(param_name);
    if (et_doc_keep) {
        yyjson_doc_free(et_doc_keep);
    }

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;

trace_failed:
    cbm_store_traverse_free(&tr_out);
    cbm_store_traverse_free(&tr_in);
    yyjson_mut_doc_free(doc);
    cbm_store_free_nodes(nodes, node_count);
    free(func_name);
    free(project);
    free(direction);
    free(mode);
    free(param_name);
    if (et_doc_keep) {
        yyjson_doc_free(et_doc_keep);
    }
    return cbm_mcp_text_result(
        "{\"code\":\"CBM_TRACE_FAILED\",\"message\":\"trace traversal failed before a complete "
        "result was assembled\",\"remediation\":\"inspect the CBM store error log, repair the "
        "recorded storage or allocation failure, and retry\"}",
        true);
}

/* ── Helper: free heap fields of a stack-allocated node ────────── */

static void free_node_contents(cbm_node_t *n) {
    safe_str_free(&n->project);
    safe_str_free(&n->label);
    safe_str_free(&n->name);
    safe_str_free(&n->qualified_name);
    safe_str_free(&n->file_path);
    safe_str_free(&n->properties_json);
    memset(n, 0, sizeof(*n));
}

/* ── Helper: read lines [start, end] from a file ─────────────── */

static char *read_file_lines(const char *path, int start, int end) {
    FILE *fp = cbm_fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    size_t cap = CBM_SZ_4K;
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        errno = ENOMEM;
        return NULL;
    }
    size_t len = 0;
    buf[0] = '\0';

    int lineno = SKIP_ONE;
    bool failed = false;
    for (;;) {
        int ch = fgetc(fp);
        if (ch == EOF) {
            if (ferror(fp)) {
                failed = true;
            }
            break;
        }
        if (ch == '\0') {
            errno = EILSEQ;
            failed = true;
            break;
        }
        if (lineno >= start && lineno <= end) {
            if (len + MCP_SEPARATOR > cap) {
                size_t next = cap * PAIR_LEN;
                if (next <= cap) {
                    errno = ENOMEM;
                    failed = true;
                    break;
                }
                char *grown = realloc(buf, next);
                if (!grown) {
                    errno = ENOMEM;
                    failed = true;
                    break;
                }
                buf = grown;
                cap = next;
            }
            buf[len++] = (char)ch;
            buf[len] = '\0';
        }
        if (ch == '\n') {
            if (lineno == end) {
                break;
            }
            if (lineno == INT_MAX) {
                errno = EOVERFLOW;
                failed = true;
                break;
            }
            lineno++;
        }
    }

    if (fclose(fp) != 0) {
        failed = true;
    }
    if (failed || len == 0) {
        free(buf);
        return NULL;
    }
    const unsigned char *cursor = (const unsigned char *)buf;
    while (*cursor) {
        if (*cursor <= 0x7f) {
            cursor++;
            continue;
        }
        int sequence_len = cbm_utf8_sequence_len(cursor);
        if (sequence_len <= 0) {
            free(buf);
            errno = EILSEQ;
            return NULL;
        }
        cursor += sequence_len;
    }
    return buf;
}

/* ── Helper: get project root_path from store ─────────────────── */

static char *get_project_root(cbm_mcp_server_t *srv, const char *project) {
    if (!project) {
        return NULL;
    }
    cbm_store_t *store = resolve_store(srv, project);
    if (!store) {
        return NULL;
    }
    cbm_project_t proj = {0};
    int project_rc = cbm_store_get_project(store, project, &proj);
    if (project_rc != CBM_STORE_OK) {
        if (project_rc != CBM_STORE_NOT_FOUND) {
            record_store_query_failure(srv, project, cbm_store_db_path(store), store,
                                       CBM_STORE_VERIFY_IO_FAILED, "source.query_project_root",
                                       cbm_store_error(store));
        }
        return NULL;
    }
    char *root = heap_strdup(proj.root_path);
    safe_str_free(&proj.name);
    safe_str_free(&proj.indexed_at);
    safe_str_free(&proj.root_path);
    return root;
}

/* ── index_repository ─────────────────────────────────────────── */

/* Handle mode="cross-repo-intelligence" — extract to reduce complexity. */
static char *handle_cross_repo_mode(const char *repo_path, const char *args) {
    char *project = heap_strdup(cbm_project_name_from_path(repo_path));
    if (!project) {
        return cbm_mcp_text_result("cannot derive project name", true);
    }

    yyjson_doc *jdoc = yyjson_read(args, strlen(args), 0);
    yyjson_val *jroot = jdoc ? yyjson_doc_get_root(jdoc) : NULL;
    yyjson_val *tp_arr = jroot ? yyjson_obj_get(jroot, "target_projects") : NULL;

    if (!tp_arr || !yyjson_is_arr(tp_arr) || yyjson_arr_size(tp_arr) == 0) {
        yyjson_doc_free(jdoc);
        free(project);
        return cbm_mcp_text_result(
            "{\"error\":\"target_projects is required for cross-repo-intelligence mode. "
            "Use [\\\"*\\\"] for all projects. Run list_projects to see available.\"}",
            true);
    }

    int tp_count = (int)yyjson_arr_size(tp_arr);
    const char **targets = malloc((size_t)tp_count * sizeof(char *));
    size_t idx;
    size_t max;
    yyjson_val *val;
    int ti = 0;
    yyjson_arr_foreach(tp_arr, idx, max, val) {
        targets[ti++] = yyjson_get_str(val);
    }

    cbm_cross_repo_result_t result = cbm_cross_repo_match(project, targets, tp_count);
    free(targets);
    yyjson_doc_free(jdoc);

    int total = result.http_edges + result.async_edges + result.channel_edges + result.grpc_edges +
                result.graphql_edges + result.trpc_edges;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", "success");
    yyjson_mut_obj_add_str(doc, root, "mode", "cross-repo-intelligence");
    yyjson_mut_obj_add_strcpy(doc, root, "project", project);
    yyjson_mut_obj_add_int(doc, root, "projects_scanned", result.projects_scanned);
    yyjson_mut_obj_add_int(doc, root, "cross_http_calls", result.http_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_async_calls", result.async_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_channel", result.channel_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_grpc_calls", result.grpc_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_graphql_calls", result.graphql_edges);
    yyjson_mut_obj_add_int(doc, root, "cross_trpc_calls", result.trpc_edges);
    yyjson_mut_obj_add_int(doc, root, "total_cross_edges", total);
    yyjson_mut_obj_add_real(doc, root, "elapsed_ms", result.elapsed_ms);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(project);
    char *out = cbm_mcp_text_result(json, false);
    free(json);
    return out;
}

/* Bootstrap from artifact if no local DB exists for this project. */
static void try_artifact_bootstrap(const char *project_name, const char *repo_path) {
    char db_buf[CBM_SZ_1K];
    project_db_path(project_name, db_buf, sizeof(db_buf));
    if (cbm_file_size(db_buf) < 0 && cbm_artifact_exists(repo_path)) {
        cbm_log_info("index.artifact_bootstrap", "project", project_name);
        cbm_artifact_import(repo_path, db_buf);
    }
}

/* Cap on excluded dir paths listed in the response — keep it compact on large
 * repos (node_modules / vendor / etc. can produce many skip points). The full
 * count is still reported via "count" + "truncated". */
enum { INDEX_EXCLUDED_DIR_CAP = 25 };

/* Attach a compact summary of directory subtrees skipped during discovery (#411).
 * Shape: "excluded": {"dirs": [up to 25 rel-paths], "count": <total>, "truncated": <bool>}.
 * No-op when nothing was excluded. excluded_dirs[] is borrowed (copied into doc). */
static void add_excluded_summary(yyjson_mut_doc *doc, yyjson_mut_val *root, char **excluded_dirs,
                                 int excluded_count) {
    if (!excluded_dirs || excluded_count <= 0) {
        return;
    }
    yyjson_mut_val *excluded = yyjson_mut_obj(doc);
    yyjson_mut_val *dirs = yyjson_mut_arr(doc);
    int shown = excluded_count < INDEX_EXCLUDED_DIR_CAP ? excluded_count : INDEX_EXCLUDED_DIR_CAP;
    for (int i = 0; i < shown; i++) {
        if (excluded_dirs[i]) {
            yyjson_mut_arr_add_strcpy(doc, dirs, excluded_dirs[i]);
        }
    }
    yyjson_mut_obj_add_val(doc, excluded, "dirs", dirs);
    yyjson_mut_obj_add_int(doc, excluded, "count", excluded_count);
    yyjson_mut_obj_add_bool(doc, excluded, "truncated", excluded_count > INDEX_EXCLUDED_DIR_CAP);
    yyjson_mut_obj_add_val(doc, root, "excluded", excluded);
}

/* Cap on per-file skips embedded in the JSON response — keep it compact on
 * large repos. The FULL, uncapped list always goes to the per-run logfile;
 * the JSON carries "count" + "truncated" so nothing is silently hidden. */
enum { INDEX_SKIPPED_FILE_CAP = 50 };

/* Attach a summary of per-file skips (Stage 2 / Track B). Always emits a
 * top-level "skipped_count" (0 on clean runs) so consumers can rely on it.
 * When there are skips, also emits:
 *   "skipped": {"files":[{path,reason,phase}..(<=50)], "count":N, "truncated":bool}
 * and, if a per-run logfile was written, "logfile": "<path>".
 * The run status stays "indexed" — a skipped file is the expected handled
 * outcome, not a failure. errs[] is borrowed (copied into doc). */
static void add_skipped_summary(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                const cbm_file_error_t *errs, int count, const char *logfile) {
    yyjson_mut_obj_add_int(doc, root, "skipped_count", count < 0 ? 0 : count);
    if (!errs || count <= 0) {
        return;
    }
    yyjson_mut_val *skipped = yyjson_mut_obj(doc);
    yyjson_mut_val *files = yyjson_mut_arr(doc);
    int shown = count < INDEX_SKIPPED_FILE_CAP ? count : INDEX_SKIPPED_FILE_CAP;
    for (int i = 0; i < shown; i++) {
        yyjson_mut_val *fe = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, fe, "path", errs[i].path ? errs[i].path : "");
        yyjson_mut_obj_add_strcpy(doc, fe, "reason", errs[i].reason ? errs[i].reason : "");
        yyjson_mut_obj_add_strcpy(doc, fe, "phase", errs[i].phase ? errs[i].phase : "");
        yyjson_mut_arr_add_val(files, fe);
    }
    yyjson_mut_obj_add_val(doc, skipped, "files", files);
    yyjson_mut_obj_add_int(doc, skipped, "count", count);
    yyjson_mut_obj_add_bool(doc, skipped, "truncated", count > INDEX_SKIPPED_FILE_CAP);
    yyjson_mut_obj_add_val(doc, root, "skipped", skipped);
    if (logfile && logfile[0]) {
        yyjson_mut_obj_add_strcpy(doc, root, "logfile", logfile);
    }
}

/* Write the FULL (uncapped) skip list to a per-run logfile — ONLY when >=1 file
 * was skipped (no logfile on a clean run). Location:
 *   $CBM_INDEX_LOG (override) else <cache_dir>/logs/<project>-<epoch>.log
 * Returns true and fills out_path on success. */
static bool write_skip_logfile(const char *project, const cbm_file_error_t *errs, int count,
                               char *out_path, size_t out_sz) {
    if (!errs || count <= 0) {
        return false;
    }
    char path[CBM_SZ_1K];
    const char *override = getenv("CBM_INDEX_LOG");
    if (override && override[0]) {
        snprintf(path, sizeof(path), "%s", override);
    } else {
        const char *cdir = cbm_resolve_cache_dir();
        if (!cdir) {
            return false;
        }
        char logdir[CBM_SZ_1K];
        snprintf(logdir, sizeof(logdir), "%s/logs", cdir);
        cbm_mkdir_p(logdir, 0755);
        snprintf(path, sizeof(path), "%s/%s-%lld.log", logdir, project ? project : "index",
                 (long long)time(NULL));
    }
    FILE *f = cbm_fopen(path, "wb");
    if (!f) {
        cbm_log_warn("index.logfile_open_fail", "path", path);
        return false;
    }
    (void)fprintf(f, "# codebase-memory-mcp index skip report\n");
    (void)fprintf(f, "# project=%s skipped=%d\n", project ? project : "", count);
    (void)fprintf(f, "# columns: phase\treason\tpath\n");
    for (int i = 0; i < count; i++) {
        (void)fprintf(f, "%s\t%s\t%s\n", errs[i].phase ? errs[i].phase : "",
                      errs[i].reason ? errs[i].reason : "", errs[i].path ? errs[i].path : "");
    }
    (void)fclose(f);
    if (out_path && out_sz) {
        snprintf(out_path, out_sz, "%s", path);
    }
    return true;
}

static char *build_index_state_mismatch_error(const char *project_name, int expected_nodes,
                                              int expected_edges, int persisted_nodes,
                                              int persisted_edges) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_INDEX_PERSISTED_STATE_MISMATCH\",\"message\":\"persisted graph "
            "counts differ from the completed in-memory graph\",\"remediation\":\"preserve the "
            "database family and inspect the persistence transaction\"}");
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_INDEX_PERSISTED_STATE_MISMATCH");
    yyjson_mut_obj_add_str(doc, root, "message",
                           "index_repository completed extraction but persisted graph readback did "
                           "not exactly match the committed in-memory state");
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "preserve the database, WAL, and SHM together; inspect the persistence "
                           "transaction and retry only after resolving the mismatch");
    yyjson_mut_obj_add_str(doc, root, "project", project_name);
    yyjson_mut_obj_add_int(doc, root, "expected_nodes", expected_nodes);
    yyjson_mut_obj_add_int(doc, root, "expected_edges", expected_edges);
    yyjson_mut_obj_add_int(doc, root, "persisted_nodes", persisted_nodes);
    yyjson_mut_obj_add_int(doc, root, "persisted_edges", persisted_edges);
    yyjson_mut_obj_add_bool(doc, root, "source_family_preserved", true);
    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    return json ? json : heap_strdup("{\"code\":\"CBM_INDEX_PERSISTED_STATE_MISMATCH\"}");
}

/* Build the success portion only after the persisted source of truth has been
 * verified and independently read back. Returns a structured error on failure. */
static char *build_index_success_response(cbm_mcp_server_t *srv, yyjson_mut_doc *doc,
                                          yyjson_mut_val *root, const char *project_name,
                                          const char *repo_path, bool persistence,
                                          cbm_pipeline_t *p, char **excluded_dirs,
                                          int excluded_count, const cbm_file_error_t *file_errors,
                                          int file_error_count, const char *logfile) {
    add_excluded_summary(doc, root, excluded_dirs, excluded_count);
    add_skipped_summary(doc, root, file_errors, file_error_count, logfile);

    int exp_nodes = -1;
    int exp_edges = -1;
    cbm_pipeline_get_committed_counts(p, &exp_nodes, &exp_edges);

    cbm_store_t *store = resolve_store(srv, project_name);
    if (!store) {
        return build_no_store_error(srv, project_name);
    }
    int nodes = cbm_store_count_nodes(store, project_name);
    int edges = cbm_store_count_edges(store, project_name);
    if (nodes < 0 || edges < 0) {
        record_store_query_failure(srv, project_name, cbm_store_db_path(store), store,
                                   CBM_STORE_VERIFY_IO_FAILED, "source.query_persisted_counts",
                                   cbm_store_error(store));
        return build_recorded_store_error(srv);
    }
    if (exp_nodes < 0 || exp_edges < 0 || nodes != exp_nodes || edges != exp_edges) {
        cbm_log_error("dump.verify_failed", "code", "CBM_INDEX_PERSISTED_STATE_MISMATCH", "project",
                      project_name, "message",
                      "persisted node/edge counts differ from the completed in-memory graph",
                      "remediation", "preserve the database family and inspect persistence");
        return build_index_state_mismatch_error(project_name, exp_nodes, exp_edges, nodes, edges);
    }

    yyjson_mut_obj_add_int(doc, root, "nodes", nodes);
    yyjson_mut_obj_add_int(doc, root, "edges", edges);
    yyjson_mut_obj_add_int(doc, root, "expected_nodes", exp_nodes);
    yyjson_mut_obj_add_int(doc, root, "expected_edges", exp_edges);

    /* #727: a reference whose source syntax resolves to several stable atoms in
     * one semantic domain (e.g. `#[cfg]`-gated methods sharing a qualified
     * name) has its edge skipped rather than refusing the whole corpus. The
     * count is always emitted — including 0 — so a consumer can rely on the
     * field and a degraded index can never read as a clean one. */
    uint_least64_t ambiguous_skips = cbm_pipeline_get_ambiguous_reference_skips(p);
    yyjson_mut_obj_add_uint(doc, root, "ambiguous_reference_skips", (uint64_t)ambiguous_skips);
    if (ambiguous_skips > 0) {
        yyjson_mut_obj_add_str(
            doc, root, "ambiguous_reference_hint",
            "Some reference edges were skipped because one qualified name resolved to "
            "multiple stable atoms in the same semantic domain. The graph is complete "
            "except for those edges; see the CBM_NODE_DOMAIN_AMBIGUOUS log entries for "
            "the exact qualified names, candidate atoms, and source locations.");
    }

    /* A source-attribution miss is distinct from same-domain ambiguity: the
     * extractor asserted a callable owner, but its exact stable source atom was
     * absent. The edge is refused rather than silently becoming File-owned. */
    uint_least64_t unresolved_source_skips = cbm_pipeline_get_unresolved_reference_source_skips(p);
    yyjson_mut_obj_add_uint(doc, root, "unresolved_reference_source_skips",
                            (uint64_t)unresolved_source_skips);
    if (unresolved_source_skips > 0) {
        yyjson_mut_obj_add_str(
            doc, root, "unresolved_reference_source_hint",
            "Some reference edges were skipped because their extracted enclosing callable "
            "could not be matched to an exact stable source atom. No edge was re-attributed "
            "to a File node; see CBM_REFERENCE_SOURCE_NOT_FOUND log entries for the exact "
            "operation, qualified name, source path, and line.");
    }

    bool adr_exists = project_has_adr(store, project_name, repo_path);
    yyjson_mut_obj_add_bool(doc, root, "adr_present", adr_exists);
    if (!adr_exists) {
        yyjson_mut_obj_add_str(
            doc, root, "adr_hint",
            "Project indexed. Consider creating an Architecture Decision Record: "
            "explore the codebase with get_architecture(aspects=['all']), then use "
            "manage_adr(mode='update') to persist architectural insights across sessions.");
    }

    bool has_artifact = cbm_artifact_exists(repo_path);
    yyjson_mut_obj_add_bool(doc, root, "artifact_present", has_artifact);
    if (persistence && has_artifact) {
        yyjson_mut_obj_add_str(doc, root, "artifact_hint",
                               "Persistent artifact written to .codebase-memory/graph.db.zst. "
                               "Commit this file to share the index with teammates.");
    }

    return NULL;
}

/* A supervised worker deliberately skips deep graph/server destruction before
 * _Exit, but SQLite is an external resource whose library destructor is part
 * of the on-disk correctness contract.  Close the success-readback store
 * explicitly, then prove that no WAL/SHM state remains.  Never unlink a
 * sidecar here: its presence may belong to a concurrent reader and is therefore
 * a terminal publication error, not cleanup permission. */
static char *finalize_index_worker_store(cbm_mcp_server_t *srv, const char *project_name) {
    if (!cbm_index_worker_active() || !srv || !srv->store || !srv->owns_store) {
        return NULL;
    }
    const char *borrowed_path = cbm_store_db_path(srv->store);
    char *db_path = borrowed_path ? heap_strdup(borrowed_path) : NULL;
    bool path_alloc_failed = borrowed_path && !db_path;
    cbm_store_close(srv->store);
    srv->store = NULL;
    free(srv->current_project);
    srv->current_project = NULL;
    srv->store_last_used = 0;

    const char *code = NULL;
    const char *message = NULL;
    bool wal_present = false;
    bool shm_present = false;
    char *wal_path = NULL;
    char *shm_path = NULL;
    if (path_alloc_failed) {
        code = "CBM_INDEX_WORKER_STORE_PATH_ALLOC_FAILED";
        message = "the worker could not retain the authoritative store path through finalization";
    } else if (db_path) {
        size_t path_len = strlen(db_path);
        if (path_len > SIZE_MAX - 5) {
            code = "CBM_INDEX_WORKER_STORE_PATH_OVERFLOW";
            message = "the worker store path cannot represent WAL and shared-memory members";
        } else {
            wal_path = malloc(path_len + 5);
            shm_path = malloc(path_len + 5);
            if (!wal_path || !shm_path) {
                code = "CBM_INDEX_WORKER_STORE_PATH_ALLOC_FAILED";
                message = "the worker could not allocate authoritative sidecar paths";
            } else {
                snprintf(wal_path, path_len + 5, "%s-wal", db_path);
                snprintf(shm_path, path_len + 5, "%s-shm", db_path);
                wal_present = cbm_path_exists(wal_path);
                shm_present = cbm_path_exists(shm_path);
                if (wal_present || shm_present) {
                    code = "CBM_INDEX_WORKER_STORE_FINALIZE_FAILED";
                    message =
                        "the worker readback store retained WAL or shared-memory state after close";
                }
            }
        }
    }
    if (!code) {
        free(db_path);
        free(wal_path);
        free(shm_path);
        return NULL;
    }

    cbm_log_error("index.worker.store_finalize_failed", "code", code, "project",
                  project_name ? project_name : "", "db_path", db_path ? db_path : "",
                  "wal_present", wal_present ? "true" : "false", "shm_present",
                  shm_present ? "true" : "false", "message", message, "remediation",
                  "close concurrent readers or writers, preserve the database family, and retry");
    yyjson_mut_doc *error_doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *error_root = error_doc ? yyjson_mut_obj(error_doc) : NULL;
    char *error_json = NULL;
    if (error_doc && error_root) {
        yyjson_mut_doc_set_root(error_doc, error_root);
        yyjson_mut_obj_add_strcpy(error_doc, error_root, "code", code);
        yyjson_mut_obj_add_strcpy(error_doc, error_root, "message", message);
        yyjson_mut_obj_add_str(
            error_doc, error_root, "remediation",
            "close concurrent readers or writers, preserve the database family, and retry");
        yyjson_mut_obj_add_strcpy(error_doc, error_root, "project",
                                  project_name ? project_name : "");
        yyjson_mut_obj_add_strcpy(error_doc, error_root, "db_path", db_path ? db_path : "");
        yyjson_mut_obj_add_bool(error_doc, error_root, "wal_present", wal_present);
        yyjson_mut_obj_add_bool(error_doc, error_root, "shm_present", shm_present);
        yyjson_mut_obj_add_bool(error_doc, error_root, "sqlite_publication_started", true);
        error_json = yyjson_mut_write(error_doc, 0, NULL);
    }
    if (error_doc) {
        yyjson_mut_doc_free(error_doc);
    }
    free(db_path);
    free(wal_path);
    free(shm_path);
    return error_json ? error_json
                      : heap_strdup("{\"code\":\"CBM_INDEX_WORKER_STORE_FINALIZE_FAILED\"}");
}

/* Build the response for a worker that crashed/hung/failed without producing a
 * result. The crash is already contained (this process survived); we report it
 * rather than dying. Precise skip-and-continue (quarantine the culprit, index the
 * rest) is layered on in the probe stage. */
#ifdef ASTRO_WORKER_DIAG
/* #282: bound on the worker-response excerpt embedded in the failure JSON. A
 * response is normally a short error result; the tail keeps the terminal error
 * text if something ever writes more. */
enum { CBM_WORKER_RESPONSE_TAIL_MAX = 2048 };

static char *build_worker_failure_response(const char *args, cbm_proc_outcome_t outcome,
                                           int exit_code, const char *worker_response,
                                           const char *worker_log, const char *worker_log_path) {
#else
static char *build_worker_failure_response(const char *args, cbm_proc_outcome_t outcome) {
#endif
    char *repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", "error");
    yyjson_mut_obj_add_str(doc, root, "outcome", cbm_proc_outcome_str(outcome));
    const char *code = outcome == CBM_PROC_HANG    ? "CBM_INDEX_WORKER_HUNG"
                       : outcome == CBM_PROC_CRASH ? "CBM_INDEX_WORKER_CRASHED"
                                                   : "CBM_INDEX_WORKER_FAILED";
    yyjson_mut_obj_add_str(doc, root, "code", code);
    yyjson_mut_obj_add_str(
        doc, root, "message",
        outcome == CBM_PROC_HANG
            ? "the isolated index worker stopped making measurable progress"
            : "the isolated index worker terminated before a complete graph was committed");
    yyjson_mut_obj_add_str(
        doc, root, "remediation",
        "inspect the worker exit code, response tail, persisted log, and source path; fix the "
        "reported root cause before submitting the repository again");
#ifdef ASTRO_WORKER_DIAG
    /* #282: carry the worker's own evidence so a contained failure is
     * attributable from this artifact alone. */
    yyjson_mut_obj_add_int(doc, root, "worker_exit_code", exit_code);
    if (worker_response && worker_response[0]) {
        size_t wr_len = strlen(worker_response);
        const char *wr_tail = wr_len > CBM_WORKER_RESPONSE_TAIL_MAX
                                  ? worker_response + (wr_len - CBM_WORKER_RESPONSE_TAIL_MAX)
                                  : worker_response;
        yyjson_mut_obj_add_strcpy(doc, root, "worker_response_tail", wr_tail);
    }
    if (worker_log && worker_log[0]) {
        /* #282 (attempt 15): the worker's own log tail — panic/abort text —
         * already bounded by the supervisor (CBM_WORKER_LOG_TAIL_MAX). */
        yyjson_mut_obj_add_strcpy(doc, root, "worker_log_tail", worker_log);
    }
    if (worker_log_path && worker_log_path[0]) {
        yyjson_mut_obj_add_strcpy(doc, root, "worker_log_path", worker_log_path);
    }
#endif
    if (repo_path) {
        yyjson_mut_obj_add_strcpy(doc, root, "repo_path", repo_path);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(repo_path);
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

/* Drop the cached store so the next query reopens whatever the worker wrote (each
 * worker is a fresh process that deletes + recreates the .db). NULL-safe: the
 * background watcher path (main.c) has no MCP server / cached store — the child
 * writes the DB and the parent only needs the return code, so there is nothing
 * to invalidate. */
static void supervisor_invalidate_store(cbm_mcp_server_t *srv) {
    if (!srv) {
        return;
    }
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;
}

/* #405: fail-closed structured result for the strict (shadow) supervised index
 * path when the pipeline pass could NOT be run with out-of-process isolation — a
 * spawn failure, an unavailable supervisor, or a clean-but-empty worker exit.
 * Unlike build_worker_failure_response (a CONTAINED crash *after* the child ran),
 * these are pre-run refusals; both carry `outcome` so the Rust caller maps them to
 * a fail-closed {code, message, remediation} without ever touching the vault. */
static char *build_strict_supervised_error(const char *args, const char *outcome,
                                           const char *message) {
    char *repo_path = args ? cbm_mcp_get_string_arg(args, "repo_path") : NULL;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "status", "error");
    yyjson_mut_obj_add_str(doc, root, "outcome", outcome);
    yyjson_mut_obj_add_str(doc, root, "code",
                           strcmp(outcome, "response_missing") == 0
                               ? "CBM_INDEX_WORKER_RESPONSE_MISSING"
                               : "CBM_INDEX_SUPERVISOR_UNAVAILABLE");
    yyjson_mut_obj_add_strcpy(doc, root, "message", message);
    yyjson_mut_obj_add_str(
        doc, root, "remediation",
        "restore isolated worker execution and inspect process-creation diagnostics; do not "
        "rerun in-process or accept a partial graph");
    if (repo_path) {
        yyjson_mut_obj_add_strcpy(doc, root, "repo_path", repo_path);
    }
    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(repo_path);
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

/* A tool execution error is a completed worker result, not a worker crash. The
 * public CLI deliberately exits 1 when its MCP result has isError:true, so the
 * exact process outcome and the independently parsed response envelope must be
 * evaluated together. Only the documented exit code plus a complete MCP text
 * result is accepted. Missing/malformed responses, other exit codes, signals,
 * crashes, kills, and hangs remain supervisor failures. */
static bool supervised_worker_returned_tool_error(const cbm_index_worker_result_t *wr) {
    if (!wr || wr->outcome != CBM_PROC_EXIT_NONZERO || wr->exit_code != SKIP_ONE || !wr->response ||
        !wr->response[0]) {
        return false;
    }
    yyjson_doc *doc = yyjson_read(wr->response, strlen(wr->response), 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *is_error = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "isError") : NULL;
    yyjson_val *content = root && yyjson_is_obj(root) ? yyjson_obj_get(root, "content") : NULL;
    yyjson_val *first = content && yyjson_is_arr(content) && yyjson_arr_size(content) > 0
                            ? yyjson_arr_get_first(content)
                            : NULL;
    yyjson_val *type = first && yyjson_is_obj(first) ? yyjson_obj_get(first, "type") : NULL;
    yyjson_val *text = first && yyjson_is_obj(first) ? yyjson_obj_get(first, "text") : NULL;
    bool valid = is_error && yyjson_is_bool(is_error) && yyjson_get_bool(is_error) && type &&
                 yyjson_is_str(type) && strcmp(yyjson_get_str(type), "text") == 0 && text &&
                 yyjson_is_str(text) && yyjson_get_str(text)[0];
    if (doc) {
        yyjson_doc_free(doc);
    }
    return valid;
}

/* Run index_repository exactly once in an isolated worker. A process or
 * response failure is a terminal structured refusal; the supervisor never
 * retries with a changed corpus and never degrades to in-process execution. */
static char *index_run_supervised(cbm_mcp_server_t *srv, const char *args) {
    supervisor_invalidate_store(srv);

    cbm_index_worker_result_t wr;
    int rc = cbm_index_spawn_worker(args, &wr);
    if (rc != 0 || wr.outcome == CBM_PROC_SPAWN_FAILED) {
        cbm_index_worker_result_free(&wr);
        supervisor_invalidate_store(srv);
        return build_strict_supervised_error(
            args, "spawn_failed",
            "the isolated index worker could not be spawned; no index transaction ran");
    }

    if (wr.outcome == CBM_PROC_CLEAN && wr.response) {
        char *response = wr.response;
        wr.response = NULL;
        cbm_index_worker_result_free(&wr);
        supervisor_invalidate_store(srv);
        return response;
    }

    if (supervised_worker_returned_tool_error(&wr)) {
        char *response = wr.response;
        wr.response = NULL;
        cbm_log_info("index.supervisor.tool_error", "outcome", "exit_nonzero", "exit_code", "1");
        cbm_index_worker_result_free(&wr);
        supervisor_invalidate_store(srv);
        return response;
    }

    supervisor_invalidate_store(srv);
#ifdef ASTRO_WORKER_DIAG
    char *failure = NULL;
    if (wr.outcome == CBM_PROC_CLEAN) {
        failure = build_strict_supervised_error(args, "response_missing",
                                                "the isolated index worker exited cleanly without "
                                                "a complete index_repository response");
    } else {
        failure = build_worker_failure_response(args, wr.outcome, wr.exit_code, wr.response,
                                                wr.log_tail, wr.log_path);
    }
#else
    char *failure =
        wr.outcome == CBM_PROC_CLEAN
            ? build_strict_supervised_error(args, "response_missing",
                                            "the isolated index worker exited cleanly without a "
                                            "complete index_repository response")
            : build_worker_failure_response(args, wr.outcome);
#endif
    cbm_index_worker_result_free(&wr);
    return failure;
}
/* Public entry (see mcp.h): the shadow full-index path (#405) runs the CBM
 * pipeline OUT OF PROCESS and FAILS CLOSED rather than degrading to in-process,
 * so a hard pass abort is contained in the child and the caller refuses before it
 * touches the vault. No row sink is registered on the way in — the child rebuilds
 * nothing for the parent; the parent reads the child's persisted <project>.db. */
char *cbm_mcp_index_repository_supervised_strict(cbm_mcp_server_t *srv, const char *args) {
    if (!args) {
        return build_strict_supervised_error(NULL, "spawn_failed",
                                             "index_repository args are required");
    }
    char *early_repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    if (!early_repo_path) {
        return cbm_mcp_text_result("repo_path is required", true);
    }
    free(early_repo_path);
    if (!cbm_index_supervisor_should_wrap()) {
        /* The shadow path requires out-of-process isolation. Embedders and an
         * already-active worker cannot start another supervisor. */
        return build_strict_supervised_error(
            args, "spawn_failed",
            "the index supervisor is unavailable (host not marked or already running "
            "as an index worker), so the shadow index pass cannot "
            "run with out-of-process crash isolation");
    }
    return index_run_supervised(srv, args);
}

/* Build a minimal {"repo_path": "<root>"} args object (path safely escaped) and
 * run it through index_run_supervised. Shared by the session auto-index (srv
 * present → its cached store is invalidated) and the watcher re-index (srv NULL).
 * Returns the worker's response string (caller frees). NULL is an allocation
 * failure and is never permission to run a different indexing path. */
static char *index_run_supervised_path(cbm_mcp_server_t *srv, const char *root_path) {
    if (!root_path || !root_path[0]) {
        cbm_log_error("index.supervisor.args_failed", "code", "CBM_INDEX_REPO_PATH_REQUIRED",
                      "message", "supervised indexing requires a non-empty repository path",
                      "remediation", "supply the exact readable repository root");
        return NULL;
    }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        cbm_log_error("index.supervisor.args_failed", "code",
                      "CBM_INDEX_SUPERVISOR_ARGS_ALLOC_FAILED", "message",
                      "the supervised index argument document could not be allocated",
                      "remediation", "free memory and retry without changing the corpus");
        return NULL;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    if (!root) {
        yyjson_mut_doc_free(doc);
        cbm_log_error("index.supervisor.args_failed", "code",
                      "CBM_INDEX_SUPERVISOR_ARGS_ALLOC_FAILED", "message",
                      "the supervised index argument object could not be allocated", "remediation",
                      "free memory and retry without changing the corpus");
        return NULL;
    }
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_strcpy(doc, root, "repo_path", root_path);
    char *args = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (!args) {
        cbm_log_error("index.supervisor.args_failed", "code",
                      "CBM_INDEX_SUPERVISOR_ARGS_SERIALIZE_FAILED", "message",
                      "the supervised index arguments could not be serialized", "remediation",
                      "free memory and retry without changing the corpus");
        return NULL;
    }
    char *resp = index_run_supervised(srv, args);
    free(args);
    return resp;
}

/* Public entry (see mcp.h): the watcher re-index in main.c has no MCP server, so
 * it reaches the supervised runner through this srv-less wrapper. */
char *cbm_mcp_index_run_supervised_path(const char *root_path) {
    return index_run_supervised_path(NULL, root_path);
}

bool cbm_path_within_root(const char *root_path, const char *abs_path); /* defined below */

static char *handle_index_repository(cbm_mcp_server_t *srv, const char *args) {
    /* Supervisor gate: a real host runs the index once in an isolated worker.
     * Spawn/process/response failure is terminal; it never authorizes an
     * in-process retry or a changed corpus. */
#ifdef ASTRO_WORKER_DIAG
    /* #282: validate arguments BEFORE supervision. Spawning a worker for
     * trivially-invalid args converts a clean validation error into an
     * anonymous contained-crash report (the worker exits nonzero carrying the
     * real message, which the supervisor used to discard) — and it costs a
     * whole process spawn to say "missing argument". Argument validation is
     * the caller's answer, not a worker's job. */
    {
        char *early_repo_path = cbm_mcp_get_string_arg(args, "repo_path");
        if (!early_repo_path) {
            return cbm_mcp_text_result("repo_path is required", true);
        }
        free(early_repo_path);
    }
#endif
    /* #346: the streaming row sink is an in-process FFI callback into the host's
     * own address space (an embedder installs it via cbm_mcp_server_set_row_sink).
     * A supervised worker is a SEPARATE process that runs a fresh pipeline with no
     * sink registered, so every row it emits is lost to the parent and all
     * row-derived shadow surfaces (provenance/skill_tree/bridges/kernel_context/
     * anomalies) degrade to sqlite_fallback in the host. A function pointer cannot
     * be transported across the process boundary, so when a sink is registered we
     * index IN-PROCESS where the sink lives. This is an explicit, labeled
     * trade-off: the shadow-import path forgoes the supervisor's crash isolation to
     * deliver the real row stream. The Rust sink is fail-closed on malformed bytes
     * (it refuses rather than corrupt), so integrity is not weakened. The
     * watcher/auto-index path indexes with srv==NULL (index_run_supervised) and a
     * plain server carries no sink, so both keep their supervised worker for crash
     * isolation and RSS reclamation (#832/#845). */
    bool row_sink_registered = srv && srv->row_sink_active;
    if (row_sink_registered) {
        cbm_log_info("index.supervisor.inprocess", "reason", "row_sink_registered", "tradeoff",
                     "crash_isolation_forgone_to_deliver_row_stream");
    } else if (cbm_index_supervisor_should_wrap()) {
        char *supervised = index_run_supervised(srv, args);
        if (supervised) {
            return supervised;
        }
        return build_strict_supervised_error(args, "response_missing",
                                             "the isolated index supervisor produced no response "
                                             "and no in-process retry is allowed");
    }

    char *repo_path = cbm_mcp_get_string_arg(args, "repo_path");
    char *mode_str = cbm_mcp_get_string_arg(args, "mode");
    char *name_override = cbm_mcp_get_string_arg(args, "name");
    cbm_normalize_path_sep(repo_path);

    if (!repo_path) {
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result("repo_path is required", true);
    }

    repo_path = canonicalize_repo_path_if_exists(repo_path);
    if (!repo_path) {
        free(mode_str);
        free(name_override);
        return cbm_mcp_text_result(
            "CBM_REPO_PATH_UNRESOLVABLE: repo_path does not resolve to an existing readable "
            "filesystem object; pass an existing repository path",
            true);
    }

    if (cbm_path_is_ephemeral_launcher_root(repo_path)) {
        cbm_log_error("index.ephemeral_project_root", "code", "CBM_EPHEMERAL_PROJECT_ROOT",
                      "repo_path", repo_path, "index_started", "false", "store_created", "false",
                      "remediation", "index the stable canonical repository root", NULL);
        char *error = build_ephemeral_project_root_error(repo_path);
        free(mode_str);
        free(name_override);
        free(repo_path);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }

    /* Optional workspace boundary: when CBM_ALLOWED_ROOT is set (agentic /
     * multi-tenant deployments where repo_path may be influenced by an
     * untrusted caller), refuse to index a path that resolves outside it.
     * Unset by default, so the standard "index the path I gave you" behaviour
     * is unchanged. */
    const char *allowed_root = getenv("CBM_ALLOWED_ROOT");
    if (allowed_root && allowed_root[0] && repo_path &&
        !cbm_path_within_root(allowed_root, repo_path)) {
        free(mode_str);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("repo_path is outside the allowed root", true);
    }

    if (mode_str && strcmp(mode_str, "cross-repo-intelligence") == 0) {
        free(mode_str);
        free(name_override);
        char *result = handle_cross_repo_mode(repo_path, args);
        free(repo_path);
        return result;
    }

    cbm_index_mode_t mode = CBM_MODE_FULL;
    if (mode_str && strcmp(mode_str, "fast") == 0) {
        mode = CBM_MODE_FAST;
    } else if (mode_str && strcmp(mode_str, "moderate") == 0) {
        mode = CBM_MODE_MODERATE;
    }
    free(mode_str);

    bool persistence = cbm_mcp_get_bool_arg(args, "persistence");

    cbm_pipeline_t *p = cbm_pipeline_new(repo_path, NULL, mode);
    if (!p) {
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("failed to create pipeline", true);
    }
    if (cbm_pipeline_set_sink(p, srv->row_sink_active ? &srv->row_sink : NULL) != 0) {
        cbm_pipeline_free(p);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result(
            "CBM_ROW_SINK_INSTALL_FAILED: the complete row-sink descriptor was refused; inspect "
            "the structured native diagnostic and retry",
            true);
    }
    if (name_override && name_override[0] && !cbm_pipeline_set_project_name(p, name_override)) {
        cbm_pipeline_free(p);
        free(name_override);
        free(repo_path);
        return cbm_mcp_text_result("invalid project name", true);
    }
    free(name_override);
    cbm_pipeline_set_persistence(p, persistence);

    char *project_name = heap_strdup(cbm_pipeline_project_name(p));

    /* Bootstrap from artifact if no local DB exists */
    try_artifact_bootstrap(project_name, repo_path);

    /* Close cached store — pipeline will delete + recreate the .db file */
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;

    /* Serialize pipeline runs to prevent concurrent writes.
     * Track active pipeline so signal handler and notifications/cancelled
     * can cancel it mid-run. */
    cbm_pipeline_lock();
    srv->active_pipeline = p;
    int rc = cbm_pipeline_run(p);
    srv->active_pipeline = NULL;
    cbm_pipeline_unlock();

    /* Capture the excluded-subtree list (#411) while the pipeline (which owns
     * the strings) is still alive — the response builder copies them into the
     * JSON doc, so they need only outlive that call, not cbm_pipeline_free. */
    char **excluded_dirs = NULL;
    int excluded_count = 0;
    cbm_pipeline_get_excluded(p, &excluded_dirs, &excluded_count);

    /* Capture the per-file skip list (Stage 2 / Track B) while the pipeline
     * still owns the strings; the response builder copies them into the doc. */
    cbm_file_error_t *file_errors = NULL;
    int file_error_count = 0;
    cbm_pipeline_get_file_errors(p, &file_errors, &file_error_count);

    cbm_mem_collect(); /* return mimalloc pages to OS after large indexing */

    /* Invalidate cached store so next query reopens the fresh database */
    if (srv->owns_store && srv->store) {
        cbm_store_close(srv->store);
        srv->store = NULL;
    }
    free(srv->current_project);
    srv->current_project = NULL;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "project", project_name);

    char *postcondition_error = NULL;
    if (rc == 0) {
        /* Write the per-run logfile ONLY when there were skips (no logfile on a
         * clean run). The FULL list goes to the file; the JSON caps at 50. */
        char logfile_path[CBM_SZ_1K];
        logfile_path[0] = '\0';
        bool has_logfile = write_skip_logfile(project_name, file_errors, file_error_count,
                                              logfile_path, sizeof(logfile_path));
        postcondition_error = build_index_success_response(
            srv, doc, root, project_name, repo_path, persistence, p, excluded_dirs, excluded_count,
            file_errors, file_error_count, has_logfile ? logfile_path : NULL);
        if (!postcondition_error) {
            yyjson_mut_obj_add_str(doc, root, "status", "indexed");
        }
    } else if (rc == CBM_PIPELINE_EMPTY_SOURCE_CORPUS) {
        yyjson_mut_obj_add_str(doc, root, "status", "error");
        yyjson_mut_obj_add_str(doc, root, "code", "CBM_PIPELINE_EMPTY_SOURCE_CORPUS");
        yyjson_mut_obj_add_str(doc, root, "operation", "discover_source_files");
        yyjson_mut_obj_add_str(doc, root, "phase", "discovery");
        yyjson_mut_obj_add_str(doc, root, "path", repo_path);
        yyjson_mut_obj_add_uint(doc, root, "requested", 0);
        yyjson_mut_obj_add_str(
            doc, root, "message",
            "index_repository refused because discovery produced zero non-auxiliary source files");
        yyjson_mut_obj_add_str(
            doc, root, "remediation",
            "add at least one supported readable source file or correct discovery, mode, and "
            "ignore configuration before retrying");
        yyjson_mut_obj_add_bool(doc, root, "sqlite_publication_started", false);
    } else {
        cbm_pipeline_error_t fatal = {0};
        bool has_fatal = cbm_pipeline_get_fatal_error(p, &fatal);
        yyjson_mut_obj_add_str(doc, root, "status", "error");
        yyjson_mut_obj_add_str(doc, root, "code", has_fatal ? fatal.code : "CBM_PIPELINE_FAILED");
        yyjson_mut_obj_add_str(doc, root, "operation",
                               has_fatal ? fatal.operation : "cbm_pipeline_run");
        yyjson_mut_obj_add_str(doc, root, "phase", has_fatal ? fatal.phase : "pipeline");
        yyjson_mut_obj_add_str(doc, root, "path", has_fatal ? fatal.path : repo_path);
        yyjson_mut_obj_add_uint(doc, root, "requested", has_fatal ? fatal.requested : 0);
        yyjson_mut_obj_add_str(doc, root, "message",
                               has_fatal ? fatal.message
                                         : "the authoritative indexing pipeline failed");
        yyjson_mut_obj_add_str(
            doc, root, "remediation",
            has_fatal
                ? fatal.remediation
                : "inspect the preceding structured diagnostics, fix the exact failure, then retry "
                  "the complete corpus");
        yyjson_mut_obj_add_bool(doc, root, "sqlite_publication_started", false);
    }

    char *worker_store_error = finalize_index_worker_store(srv, project_name);
    if (worker_store_error) {
        if (rc == 0 && !postcondition_error) {
            postcondition_error = worker_store_error;
        } else {
            free(worker_store_error);
        }
    }

    bool response_is_error = rc != 0 || postcondition_error != NULL;
    char *json = postcondition_error ? postcondition_error : yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    /* Free the pipeline only after the response doc copied the excluded list.
     * Supervised worker: skip the deep free — the process exits right after
     * handing over the response (main.c fast-exits), and piecemeal-freeing a
     * multi-GB graph before process death costs minutes on kernel-scale repos;
     * the OS reclaims it wholesale at exit. In-process paths still free
     * normally. */
    if (cbm_index_worker_active()) {
        cbm_log_info("index.worker.fast_exit", "skip", "pipeline_free");
    } else {
        cbm_pipeline_free(p);
    }
    free(project_name);
    free(repo_path);

    char *result = cbm_mcp_text_result(json, response_is_error);
    free(json);
    return result;
}

/* ── get_code_snippet ─────────────────────────────────────────── */

/* Copy a node from an array into a heap-allocated standalone node. */
static void copy_node(const cbm_node_t *src, cbm_node_t *dst) {
    dst->id = src->id;
    dst->project = heap_strdup(src->project);
    dst->label = heap_strdup(src->label);
    dst->name = heap_strdup(src->name);
    dst->atom_id = heap_strdup(src->atom_id);
    dst->qualified_name = heap_strdup(src->qualified_name);
    dst->file_path = heap_strdup(src->file_path);
    dst->start_line = src->start_line;
    dst->end_line = src->end_line;
    dst->properties_json = src->properties_json ? heap_strdup(src->properties_json) : NULL;
}

/* Build a JSON suggestions response for ambiguous or fuzzy results. */
static char *snippet_suggestions(const char *input, cbm_node_t *nodes, int count) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_str(doc, root, "status", "ambiguous");
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_NODE_QN_AMBIGUOUS");

    char msg[CBM_SZ_512];
    snprintf(msg, sizeof(msg),
             "%d stable source atoms match \"%s\". Qualified names are non-unique; "
             "pick an atom_id from the candidates below.",
             count, input);
    yyjson_mut_obj_add_str(doc, root, "message", msg);
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "call search_graph if necessary, select the intended stable atom_id, "
                           "and retry get_code_snippet with atom_id instead of qualified_name");

    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    for (int i = 0; i < count; i++) {
        yyjson_mut_val *s = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_str(doc, s, "atom_id", nodes[i].atom_id ? nodes[i].atom_id : "");
        yyjson_mut_obj_add_str(doc, s, "qualified_name",
                               nodes[i].qualified_name ? nodes[i].qualified_name : "");
        yyjson_mut_obj_add_str(doc, s, "name", nodes[i].name ? nodes[i].name : "");
        yyjson_mut_obj_add_str(doc, s, "label", nodes[i].label ? nodes[i].label : "");
        yyjson_mut_obj_add_str(doc, s, "file_path", nodes[i].file_path ? nodes[i].file_path : "");
        yyjson_mut_arr_append(arr, s);
    }
    yyjson_mut_obj_add_val(doc, root, "suggestions", arr);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

/* Enrich a mutable JSON object with key-value pairs from a node's properties_json.
 * Returns the parsed yyjson_doc (caller frees AFTER serialization — zero-copy). */
static yyjson_doc *enrich_node_properties(yyjson_mut_doc *doc, yyjson_mut_val *obj,
                                          const char *properties_json) {
    if (!properties_json || properties_json[0] == '\0') {
        return NULL;
    }
    yyjson_doc *props_doc = yyjson_read(properties_json, strlen(properties_json), 0);
    if (!props_doc) {
        return NULL;
    }
    yyjson_val *props_root = yyjson_doc_get_root(props_doc);
    if (!props_root || !yyjson_is_obj(props_root)) {
        yyjson_doc_free(props_doc);
        return NULL;
    }
    yyjson_obj_iter iter;
    yyjson_obj_iter_init(props_root, &iter);
    yyjson_val *key;
    while ((key = yyjson_obj_iter_next(&iter))) {
        yyjson_val *val = yyjson_obj_iter_get_val(key);
        const char *k = yyjson_get_str(key);
        if (!k) {
            continue;
        }
        if (yyjson_is_str(val)) {
            yyjson_mut_obj_add_str(doc, obj, k, yyjson_get_str(val));
        } else if (yyjson_is_bool(val)) {
            yyjson_mut_obj_add_bool(doc, obj, k, yyjson_get_bool(val));
        } else if (yyjson_is_int(val)) {
            yyjson_mut_obj_add_int(doc, obj, k, yyjson_get_int(val));
        } else if (yyjson_is_real(val)) {
            yyjson_mut_obj_add_real(doc, obj, k, yyjson_get_real(val));
        }
    }
    return props_doc; /* caller frees after serialization */
}

/* Resolve an absolute path from root_path + file_path, verify containment,
 * and read source lines. Sets *out_abs_path (caller frees). Returns source
 * string (caller frees) or NULL if path is invalid/unreadable. */
/* True only when abs_path, after full filesystem resolution (collapsing `..` AND
 * following symlinks/junctions to their real target), stays within root_path. This
 * is the single containment guard every MCP file-read sink must pass before reading
 * a file into a tool response: both the snippet path (resolve_snippet_source) and
 * the search path (attach_result_source) route through it, so a result whose
 * indexed path escapes the project root — via a `..` segment, or a symlink /
 * Windows junction picked up during discovery — is never read back out.
 *
 * #437: both operands are canonicalized through cbm_real_path_final, which on
 * Windows uses GetFinalPathNameByHandleW on an opened handle. That replaces the
 * former MAX_PATH-bound, purely-lexical ANSI _fullpath, which (1) returned NULL on
 * a repo root >260 chars — refusing legitimate reads inside a deep repo (the bug
 * this fixes) — and (2) never resolved reparse points, so a junction under the root
 * pointing outside it, or an 8.3 short-name spelling of the root, would slip a read
 * past the prefix check. Resolving BOTH sides to their real, long-normalized,
 * junction-followed form (the "resolve first, then compare" order — comparing
 * before resolution is the classic bypass, cf. CVE-2022-41722) and comparing them
 * in the same canonical namespace closes both holes. Because both come from the
 * same resolver they share the extended-length "\\?\" prefix and OS-native
 * backslash separators; the compare is case-insensitive per NTFS with a strict
 * separator/NUL boundary so "C:\root2" never matches root "C:\root". Fail-closed:
 * any canonicalization failure (including a non-existent/unopenable path) → false,
 * with no lexical/ANSI fallback. */
bool cbm_path_within_root(const char *root_path, const char *abs_path) {
    if (!root_path || !abs_path) {
        return false;
    }
    char *real_root = cbm_real_path_final(root_path);
    char *real_file = cbm_real_path_final(abs_path);
    bool within = false;
    if (real_root && real_file) {
        size_t root_len = strlen(real_root);
        /* Ignore a trailing separator on the resolved root (e.g. a volume root
         * "\\?\C:\") so the boundary test below is well-defined. */
        while (root_len > 0 &&
               (real_root[root_len - 1] == '\\' || real_root[root_len - 1] == '/')) {
            root_len--;
        }
        if (root_len > 0 &&
#ifdef _WIN32
            /* NTFS is case-insensitive: compare case-folded so a differently-cased
             * spelling of the root cannot look like an escape (and a legitimate
             * differently-cased file is not falsely refused). */
            _strnicmp(real_file, real_root, root_len) == 0 &&
#else
            strncmp(real_file, real_root, root_len) == 0 &&
#endif
            (real_file[root_len] == '\\' || real_file[root_len] == '/' ||
             real_file[root_len] == '\0')) {
            within = true;
        }
    }
    free(real_root);
    free(real_file);
    return within;
}

static char *resolve_snippet_source(const char *root_path, const char *file_path, int start,
                                    int end, char **out_abs_path) {
    *out_abs_path = NULL;
    if (!root_path || !file_path) {
        return NULL;
    }
    size_t apsz = strlen(root_path) + strlen(file_path) + MCP_SEPARATOR;
    char *abs_path = malloc(apsz);
    snprintf(abs_path, apsz, "%s/%s", root_path, file_path);

    *out_abs_path = abs_path;
    if (cbm_path_within_root(root_path, abs_path)) {
        return read_file_lines(abs_path, start, end);
    }
    return NULL;
}

static bool utf8_is_cont(unsigned char c) {
    return (c & 0xC0) == 0x80;
}

static char *sanitize_utf8_lossy(const char *s) {
    enum {
        UTF8_REPLACEMENT_LEN = 3,
        UTF8_THREE_BYTE_LEN = 3,
        UTF8_FOUR_BYTE_LEN = 4,
        UTF8_FOURTH_BYTE = 3,
    };
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    if (len > (((size_t)-1) - SKIP_ONE) / UTF8_REPLACEMENT_LEN) {
        return NULL;
    }
    char *out = malloc(len * UTF8_REPLACEMENT_LEN + SKIP_ONE);
    if (!out) {
        return NULL;
    }

    const unsigned char *p = (const unsigned char *)s;
    const unsigned char *end = p + len;
    unsigned char *dst = (unsigned char *)out;
    while (p < end) {
        unsigned char c = *p;
        size_t n = 0;
        if (c < 0x80) {
            n = 1;
        } else if (c >= 0xC2 && c <= 0xDF && p + 1 < end && utf8_is_cont(p[1])) {
            n = 2;
        } else if (c == 0xE0 && p + 2 < end && p[1] >= 0xA0 && p[1] <= 0xBF && utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c >= 0xE1 && c <= 0xEC && p + 2 < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c == 0xED && p + 2 < end && p[1] >= 0x80 && p[1] <= 0x9F && utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c >= 0xEE && c <= 0xEF && p + 2 < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2])) {
            n = UTF8_THREE_BYTE_LEN;
        } else if (c == 0xF0 && p + UTF8_FOURTH_BYTE < end && p[1] >= 0x90 && p[1] <= 0xBF &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        } else if (c >= 0xF1 && c <= 0xF3 && p + UTF8_FOURTH_BYTE < end && utf8_is_cont(p[1]) &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        } else if (c == 0xF4 && p + UTF8_FOURTH_BYTE < end && p[1] >= 0x80 && p[1] <= 0x8F &&
                   utf8_is_cont(p[2]) && utf8_is_cont(p[UTF8_FOURTH_BYTE])) {
            n = UTF8_FOUR_BYTE_LEN;
        }

        if (n > 0) {
            memcpy(dst, p, n);
            dst += n;
            p += n;
        } else {
            *dst++ = 0xEF;
            *dst++ = 0xBF;
            *dst++ = 0xBD;
            p++;
        }
    }
    *dst = '\0';
    return out;
}

/* Build an enriched snippet response for a resolved node. */
/* Add a string array to a JSON object (no-op if count == 0). */
static void add_string_array(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                             char **strings, int count) {
    if (count <= 0) {
        return;
    }
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    for (int i = 0; i < count; i++) {
        yyjson_mut_arr_add_str(doc, arr, strings[i]);
    }
    yyjson_mut_obj_add_val(doc, obj, key, arr);
}

static char *build_snippet_response(cbm_mcp_server_t *srv, cbm_node_t *node,
                                    const char *match_method, bool include_neighbors,
                                    cbm_node_t *alternatives, int alt_count) {
    char *root_path = get_project_root(srv, node->project);

    int start = node->start_line > 0 ? node->start_line : SKIP_ONE;
    int end = node->end_line > start ? node->end_line : start + SNIPPET_DEFAULT_LINES;
    char *abs_path = NULL;
    char *source = resolve_snippet_source(root_path, node->file_path, start, end, &abs_path);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    yyjson_mut_obj_add_str(doc, root_obj, "atom_id", node->atom_id ? node->atom_id : "");
    yyjson_mut_obj_add_str(doc, root_obj, "name", node->name ? node->name : "");
    yyjson_mut_obj_add_str(doc, root_obj, "qualified_name",
                           node->qualified_name ? node->qualified_name : "");
    yyjson_mut_obj_add_str(doc, root_obj, "label", node->label ? node->label : "");

    const char *display_path = "";
    if (abs_path) {
        display_path = abs_path;
    } else if (node->file_path) {
        display_path = node->file_path;
    }
    yyjson_mut_obj_add_str(doc, root_obj, "file_path", display_path);
    yyjson_mut_obj_add_int(doc, root_obj, "start_line", start);
    yyjson_mut_obj_add_int(doc, root_obj, "end_line", end);

    if (source) {
        char *safe_source = sanitize_utf8_lossy(source);
        if (safe_source) {
            yyjson_mut_obj_add_strcpy(doc, root_obj, "source", safe_source);
            free(safe_source);
        } else {
            yyjson_mut_obj_add_str(doc, root_obj, "source", "(source not available)");
        }
    } else {
        yyjson_mut_obj_add_str(doc, root_obj, "source", "(source not available)");
    }

    /* match_method — omitted for exact matches */
    if (match_method) {
        yyjson_mut_obj_add_str(doc, root_obj, "match_method", match_method);
    }

    /* Enrich with node properties (freed AFTER serialization — zero-copy). */
    yyjson_doc *props_doc = enrich_node_properties(doc, root_obj, node->properties_json);

    /* Caller/callee counts — store already resolved by calling handler */
    cbm_store_t *store = srv->store;
    int in_deg = 0;
    int out_deg = 0;
    cbm_store_node_degree(store, node->id, &in_deg, &out_deg);
    yyjson_mut_obj_add_int(doc, root_obj, "callers", in_deg);
    yyjson_mut_obj_add_int(doc, root_obj, "callees", out_deg);

    char **nb_callers = NULL;
    int nb_caller_count = 0;
    char **nb_callees = NULL;
    int nb_callee_count = 0;
    if (include_neighbors) {
        cbm_store_node_neighbor_names(store, node->id, MCP_DEFAULT_LIMIT, &nb_callers,
                                      &nb_caller_count, &nb_callees, &nb_callee_count);
        add_string_array(doc, root_obj, "caller_names", nb_callers, nb_caller_count);
        add_string_array(doc, root_obj, "callee_names", nb_callees, nb_callee_count);
    }

    /* Alternatives (when auto-resolved from ambiguous) */
    if (alternatives && alt_count > 0) {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);
        for (int i = 0; i < alt_count; i++) {
            yyjson_mut_val *a = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, a, "atom_id",
                                   alternatives[i].atom_id ? alternatives[i].atom_id : "");
            yyjson_mut_obj_add_str(doc, a, "qualified_name",
                                   alternatives[i].qualified_name ? alternatives[i].qualified_name
                                                                  : "");
            yyjson_mut_obj_add_str(doc, a, "file_path",
                                   alternatives[i].file_path ? alternatives[i].file_path : "");
            yyjson_mut_arr_append(arr, a);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "alternatives", arr);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    yyjson_doc_free(props_doc); /* safe if NULL */
    for (int i = 0; i < nb_caller_count; i++) {
        free(nb_callers[i]);
    }
    for (int i = 0; i < nb_callee_count; i++) {
        free(nb_callees[i]);
    }
    free(nb_callers);
    free(nb_callees);
    free(root_path);
    free(abs_path);
    free(source);

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

static char *handle_get_code_snippet(cbm_mcp_server_t *srv, const char *args) {
    char *atom_id = cbm_mcp_get_string_arg(args, "atom_id");
    char *qn = cbm_mcp_get_string_arg(args, "qualified_name");
    char *project = get_project_arg(args);
    bool include_neighbors = cbm_mcp_get_bool_arg(args, "include_neighbors");

    if ((!atom_id && !qn) || (atom_id && qn)) {
        free(atom_id);
        free(qn);
        free(project);
        return cbm_mcp_text_result("exactly one of atom_id or qualified_name is required; prefer "
                                   "atom_id from search_graph",
                                   true);
    }

    cbm_store_t *store = resolve_store(srv, project);
    if (!store) {
        char *_err = build_no_store_error(srv, project);
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        free(atom_id);
        free(qn);
        free(project);
        return _res;
    }

    char *not_indexed = verify_project_indexed(srv, store, project);
    if (not_indexed) {
        free(atom_id);
        free(qn);
        free(project);
        return not_indexed;
    }

    /* Default to current project (same as all other tools) */
    const char *effective_project = project ? project : srv->current_project;

    cbm_node_t node = {0};
    if (atom_id) {
        int atom_rc = cbm_store_find_node_by_atom_id(store, effective_project, atom_id, &node);
        if (atom_rc == CBM_STORE_OK) {
            char *result = build_snippet_response(srv, &node, NULL, include_neighbors, NULL, 0);
            free_node_contents(&node);
            free(atom_id);
            free(project);
            return result;
        }
        char message[CBM_SZ_512];
        snprintf(message, sizeof(message),
                 atom_rc == CBM_STORE_NOT_FOUND ? "atom_id not found in project: %s"
                                                : "atom_id lookup failed; require a canonical "
                                                  "64-character lowercase SHA-256 identity: %s",
                 atom_id);
        free(atom_id);
        free(project);
        return cbm_mcp_text_result(message, true);
    }

    /* Qualified names are display metadata and may resolve only when unique. */
    int rc = cbm_store_find_node_by_qn(store, effective_project, qn, &node);
    if (rc == CBM_STORE_OK) {
        char *result = build_snippet_response(srv, &node, NULL, include_neighbors, NULL, 0);
        free_node_contents(&node);
        free(atom_id);
        free(qn);
        free(project);
        return result;
    }
    if (rc == CBM_STORE_ERR) {
        cbm_node_t *candidates = NULL;
        int candidate_count = 0;
        int candidate_rc = cbm_store_find_nodes_by_qn_suffix(store, effective_project, qn,
                                                             &candidates, &candidate_count);
        if (candidate_rc == CBM_STORE_OK && candidate_count > 1) {
            char *result = snippet_suggestions(qn, candidates, candidate_count);
            cbm_store_free_nodes(candidates, candidate_count);
            free(qn);
            free(project);
            return result;
        }
        cbm_store_free_nodes(candidates, candidate_count);
        char message[CBM_SZ_512];
        snprintf(
            message, sizeof(message),
            "qualified_name lookup failed for \"%s\" while enumerating stable atom candidates; "
            "inspect store logs and rebuild the project if the identity index is invalid",
            qn);
        free(qn);
        free(project);
        return cbm_mcp_text_result(message, true);
    }

    /* Tier 2: Suffix match — handles partial QNs ("main.HandleRequest")
     * and short names ("ProcessOrder") via LIKE '%.X'. */
    cbm_node_t *suffix_nodes = NULL;
    int suffix_count = 0;
    int suffix_rc = cbm_store_find_nodes_by_qn_suffix(store, effective_project, qn, &suffix_nodes,
                                                      &suffix_count);
    if (suffix_rc != CBM_STORE_OK) {
        char message[CBM_SZ_512];
        snprintf(message, sizeof(message), "qualified_name suffix lookup failed for \"%s\"", qn);
        free(qn);
        free(project);
        return cbm_mcp_text_result(message, true);
    }

    if (suffix_count == SKIP_ONE) {
        copy_node(&suffix_nodes[0], &node);
        cbm_store_free_nodes(suffix_nodes, suffix_count);
        char *result = build_snippet_response(srv, &node, "suffix", include_neighbors, NULL, 0);
        free_node_contents(&node);
        free(qn);
        free(project);
        return result;
    }

    if (suffix_count > SKIP_ONE) {
        /* Prefer the real definition (a .c body over a .h declaration, a Function
         * over a Module) so an unambiguous-by-preference match resolves directly
         * instead of forcing a disambiguation round trip; only a genuine tie still
         * returns suggestions. */
        bool snip_ambiguous = false;
        int ssel = pick_resolved_node(suffix_nodes, suffix_count, &snip_ambiguous);
        if (!snip_ambiguous) {
            copy_node(&suffix_nodes[ssel], &node);
            cbm_store_free_nodes(suffix_nodes, suffix_count);
            char *result = build_snippet_response(srv, &node, "suffix", include_neighbors, NULL, 0);
            free_node_contents(&node);
            free(qn);
            free(project);
            return result;
        }
        char *result = snippet_suggestions(qn, suffix_nodes, suffix_count);
        cbm_store_free_nodes(suffix_nodes, suffix_count);
        free(qn);
        free(project);
        return result;
    }

    cbm_store_free_nodes(suffix_nodes, suffix_count);
    free(qn);
    free(project);

    /* Nothing found — guide the caller toward search_graph */
    return cbm_mcp_text_result(
        "symbol not found. Use search_graph(name_pattern=\"...\") first to discover "
        "the exact atom_id, then pass it to get_code_snippet.",
        true);
}

/* ── search_code v2: graph-augmented code search ─────────────── */

/* Intermediate grep match */
typedef struct {
    char *file;
    int line;
    char *content;
} grep_match_t;

/* Deduped result: one per containing graph node */
typedef struct {
    int64_t node_id; /* 0 = raw match (no containing node) */
    char *node_name;
    char *qualified_name;
    char *label;
    char *file;
    int start_line;
    int end_line;
    int in_degree;
    int out_degree;
    int score;
    int *match_lines;
    int match_count;
    int match_cap;
} search_result_t;

typedef struct {
    char operation[CBM_SZ_64];
    char detail[CBM_SZ_512];
} search_response_error_t;

static char *search_operation_error_result(const char *code, const char *message,
                                           const char *remediation,
                                           const search_response_error_t *error) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"error response "
            "allocation failed\",\"remediation\":\"free memory and retry\"}",
            true);
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    if (!root) {
        yyjson_mut_doc_free(doc);
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"error response "
            "allocation failed\",\"remediation\":\"free memory and retry\"}",
            true);
    }
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", code);
    yyjson_mut_obj_add_str(doc, root, "message", message);
    yyjson_mut_obj_add_str(doc, root, "remediation", remediation);
    yyjson_mut_obj_add_str(doc, root, "failed_operation", error->operation);
    yyjson_mut_obj_add_str(doc, root, "detail", error->detail);
    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"error response "
            "serialization failed\",\"remediation\":\"free memory and retry\"}",
            true);
    }
    char *result = cbm_mcp_text_result(json, true);
    free(json);
    return result;
}

/* Score a result for ranking: project source first, vendored last, tests lowest */
enum { SCORE_FUNC = 10, SCORE_ROUTE = 15, SCORE_VENDORED = -50, SCORE_TEST = -5 };
enum { MAX_LINE_SPAN = 999999 };

static int compute_search_score(const search_result_t *r) {
    int score = r->in_degree;
    if (strcmp(r->label, "Function") == 0 || strcmp(r->label, "Method") == 0) {
        score += SCORE_FUNC;
    }
    if (strcmp(r->label, "Route") == 0) {
        score += SCORE_ROUTE;
    }
    if (strstr(r->file, "vendored/") || strstr(r->file, "vendor/") ||
        strstr(r->file, "node_modules/")) {
        score += SCORE_VENDORED;
    }
    /* Penalize test files */
    if (strstr(r->file, "test") || strstr(r->file, "spec") || strstr(r->file, "_test.")) {
        score += SCORE_TEST;
    }
    return score;
}

static int search_result_cmp(const void *a, const void *b) {
    const search_result_t *ra = (const search_result_t *)a;
    const search_result_t *rb = (const search_result_t *)b;
    return rb->score - ra->score; /* descending */
}

/* Build a search command over the exact persisted indexed-file set.  There is
 * deliberately no recursive-filesystem mode: inability to materialize this
 * scope is an error, never permission to search a different corpus. */
static char *build_grep_cmd(bool use_regex, const char *file_pattern, const char *tmpfile,
                            const char *filelist) {
#ifdef _WIN32
    const char *sm = use_regex ? "" : " -SimpleMatch";
    const char *with_filter =
        "powershell -NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'Stop'; "
        "$utf8 = [Text.UTF8Encoding]::new($false, $true); "
        "$pat = [IO.File]::ReadAllText('%s', $utf8); "
        "Get-Content -LiteralPath '%s' -Encoding UTF8 | ForEach-Object { "
        "Select-String -LiteralPath $_ -Pattern $pat%s -ErrorAction Stop } "
        "| Where-Object { $_.Path -like '*%s' } "
        "| ForEach-Object { [ordered]@{path=$_.Path;line=[int64]$_.LineNumber;content=$_.Line} "
        "| ConvertTo-Json -Compress }\"";
    const char *without_filter =
        "powershell -NoProfile -NonInteractive -Command \"$ErrorActionPreference = 'Stop'; "
        "$utf8 = [Text.UTF8Encoding]::new($false, $true); "
        "$pat = [IO.File]::ReadAllText('%s', $utf8); "
        "Get-Content -LiteralPath '%s' -Encoding UTF8 | ForEach-Object { "
        "Select-String -LiteralPath $_ -Pattern $pat%s -ErrorAction Stop } "
        "| ForEach-Object { [ordered]@{path=$_.Path;line=[int64]$_.LineNumber;content=$_.Line} "
        "| ConvertTo-Json -Compress }\"";
    const char *format = file_pattern ? with_filter : without_filter;
    size_t needed = strlen(format) + strlen(tmpfile) + strlen(filelist) + strlen(sm) +
                    (file_pattern ? strlen(file_pattern) : 0) + MCP_SEPARATOR;
    char *cmd = malloc(needed);
    if (!cmd) {
        return NULL;
    }
    if (file_pattern) {
        snprintf(cmd, needed, format, tmpfile, filelist, sm, file_pattern);
    } else {
        snprintf(cmd, needed, format, tmpfile, filelist, sm);
    }
#else
    const char *flag = use_regex ? "-E" : "-F";
    size_t needed = strlen(tmpfile) + strlen(filelist) + strlen(flag) +
                    (file_pattern ? strlen(file_pattern) : 0) + CBM_SZ_256;
    char *cmd = malloc(needed);
    if (!cmd) {
        return NULL;
    }
    if (file_pattern) {
        /* -0: read NUL-separated paths from the filelist so paths containing
         * spaces stay one argument (issue #687). Pairs with the NUL separator
         * written by write_scoped_filelist. */
        snprintf(cmd, needed, "xargs -0 grep -Hn %s --include='%s' -f '%s' < '%s'", flag,
                 file_pattern, tmpfile, filelist);
    } else {
        snprintf(cmd, needed, "xargs -0 grep -Hn %s -f '%s' < '%s'", flag, tmpfile, filelist);
    }
#endif
    return cmd;
}

/* Build deduplicated file list from search results + raw matches. */
static yyjson_mut_val *build_dedup_files_array(yyjson_mut_doc *doc, search_result_t *sr,
                                               int output_count, grep_match_t **raw,
                                               int raw_count) {
    yyjson_mut_val *files_arr = yyjson_mut_arr(doc);
    for (int fi = 0; fi < output_count; fi++) {
        bool dup = false;
        for (int j = 0; j < fi; j++) {
            if (strcmp(sr[j].file, sr[fi].file) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            yyjson_mut_arr_add_str(doc, files_arr, sr[fi].file);
        }
    }
    for (int fi = 0; fi < raw_count; fi++) {
        bool dup = false;
        for (int j = 0; j < output_count; j++) {
            if (strcmp(sr[j].file, raw[fi]->file) == 0) {
                dup = true;
                break;
            }
        }
        for (int j = 0; !dup && j < fi; j++) {
            if (strcmp(raw[j]->file, raw[fi]->file) == 0) {
                dup = true;
            }
        }
        if (!dup) {
            yyjson_mut_arr_add_str(doc, files_arr, raw[fi]->file);
        }
    }
    return files_arr;
}

/* Attach source or context lines to a search result JSON item. */
static bool attach_result_source(yyjson_mut_doc *doc, yyjson_mut_val *item, search_result_t *r,
                                 int mode, int context_lines, const char *root_path,
                                 search_response_error_t *error) {
    enum { MODE_FULL = 1 };
    if (r->start_line <= 0 || r->end_line <= 0) {
        return true;
    }
    if (mode != MODE_FULL && context_lines <= 0) {
        return true;
    }
    size_t root_len = strlen(root_path);
    size_t file_len = strlen(r->file);
    if (root_len > SIZE_MAX - file_len - MCP_SEPARATOR) {
        snprintf(error->operation, sizeof(error->operation), "%s", "response.build_source_path");
        snprintf(error->detail, sizeof(error->detail), "%s",
                 "source path exceeds addressable memory");
        return false;
    }
    size_t abs_len = root_len + file_len + MCP_SEPARATOR;
    char *abs_path = malloc(abs_len);
    if (!abs_path) {
        snprintf(error->operation, sizeof(error->operation), "%s", "response.allocate_source_path");
        snprintf(error->detail, sizeof(error->detail), "source-path allocation failed at %zu bytes",
                 abs_len);
        return false;
    }
    snprintf(abs_path, abs_len, "%s/%s", root_path, r->file);

    /* Containment: a search result whose indexed path resolves outside the
     * project root (a `..` segment, or a symlink/junction that discovery
     * followed) must not be read back into the response. Same guard the
     * snippet path already uses. */
    if (!cbm_path_within_root(root_path, abs_path)) {
        snprintf(error->operation, sizeof(error->operation), "%s", "response.validate_source_path");
        snprintf(error->detail, sizeof(error->detail),
                 "indexed source path resolves outside the project root: %.400s", r->file);
        free(abs_path);
        return false;
    }

    if (mode == MODE_FULL) {
        char *source = read_file_lines(abs_path, r->start_line, r->end_line);
        if (!source) {
            snprintf(error->operation, sizeof(error->operation), "%s", "response.read_source");
            snprintf(error->detail, sizeof(error->detail), "source readback failed for %.360s: %s",
                     abs_path, strerror(errno));
            free(abs_path);
            return false;
        }
        yyjson_mut_obj_add_strcpy(doc, item, "source", source);
        free(source);
    } else if (context_lines > 0 && r->match_count > 0) {
        int ctx_start = r->match_lines[0] - context_lines;
        if (r->match_lines[r->match_count - SKIP_ONE] > INT_MAX - context_lines) {
            snprintf(error->operation, sizeof(error->operation), "%s",
                     "response.compute_context_range");
            snprintf(error->detail, sizeof(error->detail), "%s",
                     "context range exceeds the representable line-number range");
            free(abs_path);
            return false;
        }
        int ctx_end = r->match_lines[r->match_count - SKIP_ONE] + context_lines;
        if (ctx_start < SKIP_ONE) {
            ctx_start = SKIP_ONE;
        }
        char *ctx = read_file_lines(abs_path, ctx_start, ctx_end);
        if (!ctx) {
            snprintf(error->operation, sizeof(error->operation), "%s", "response.read_context");
            snprintf(error->detail, sizeof(error->detail), "context readback failed for %.360s: %s",
                     abs_path, strerror(errno));
            free(abs_path);
            return false;
        }
        yyjson_mut_obj_add_strcpy(doc, item, "context", ctx);
        yyjson_mut_obj_add_int(doc, item, "context_start", ctx_start);
        free(ctx);
    }
    free(abs_path);
    return true;
}

/* Build directory distribution object from search results (top-level dir → count). */
static yyjson_mut_val *build_dir_distribution(yyjson_mut_doc *doc, search_result_t *sr,
                                              int sr_count) {
    yyjson_mut_val *dirs = yyjson_mut_obj(doc);
    if (!dirs) {
        return NULL;
    }
    char **dir_names = sr_count > 0 ? calloc((size_t)sr_count, sizeof(char *)) : NULL;
    int *dir_counts = sr_count > 0 ? calloc((size_t)sr_count, sizeof(int)) : NULL;
    if (sr_count > 0 && (!dir_names || !dir_counts)) {
        free(dir_names);
        free(dir_counts);
        return NULL;
    }
    int dir_n = 0;
    for (int di = 0; di < sr_count; di++) {
        const char *slash = strchr(sr[di].file, '/');
        size_t dlen = slash ? (size_t)(slash - sr[di].file + SKIP_ONE) : strlen(sr[di].file);
        char *top = malloc(dlen + SKIP_ONE);
        if (!top) {
            for (int d = 0; d < dir_n; d++) {
                free(dir_names[d]);
            }
            free(dir_names);
            free(dir_counts);
            return NULL;
        }
        memcpy(top, sr[di].file, dlen);
        top[dlen] = '\0';
        int found = CBM_NOT_FOUND;
        for (int d = 0; d < dir_n; d++) {
            if (strcmp(dir_names[d], top) == 0) {
                found = d;
                break;
            }
        }
        if (found >= 0) {
            dir_counts[found]++;
            free(top);
        } else {
            dir_names[dir_n] = top;
            dir_counts[dir_n] = SKIP_ONE;
            dir_n++;
        }
    }
    for (int d = 0; d < dir_n; d++) {
        yyjson_mut_val *key = yyjson_mut_strcpy(doc, dir_names[d]);
        yyjson_mut_val *val = yyjson_mut_int(doc, dir_counts[d]);
        yyjson_mut_obj_add(dirs, key, val);
        free(dir_names[d]);
    }
    free(dir_names);
    free(dir_counts);
    return dirs;
}

/* Phase 4: assemble JSON output from search results */
static char *assemble_search_output(search_result_t *sr, int sr_count, grep_match_t **raw,
                                    int raw_count, int gm_count, int limit, int mode,
                                    int context_lines, const char *root_path,
                                    bool warn_literal_pipe, uint64_t elapsed_ms) {
    enum { MODE_COMPACT = 0, MODE_FULL = 1, MODE_FILES = 2, SEARCH_SLOW_MS = 5000 };

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"search response "
            "document allocation failed\",\"remediation\":\"free memory and retry the exact "
            "search\"}",
            true);
    }
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    if (!root_obj) {
        yyjson_mut_doc_free(doc);
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"search response "
            "root allocation failed\",\"remediation\":\"free memory and retry the exact "
            "search\"}",
            true);
    }
    yyjson_mut_doc_set_root(doc, root_obj);

    int output_count = sr_count < limit ? sr_count : limit;
    search_response_error_t response_error = {0};

    if (mode == MODE_FILES) {
        yyjson_mut_val *files = build_dedup_files_array(doc, sr, output_count, raw, raw_count);
        if (!files) {
            yyjson_mut_doc_free(doc);
            search_response_error_t allocation_error = {0};
            snprintf(allocation_error.operation, sizeof(allocation_error.operation), "%s",
                     "response.build_file_list");
            snprintf(allocation_error.detail, sizeof(allocation_error.detail), "%s",
                     "file-list response allocation failed");
            return search_operation_error_result(
                "CBM_SEARCH_SERIALIZATION_FAILED", "search response allocation failed",
                "free memory and retry the exact search", &allocation_error);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "files", files);
    } else {
        yyjson_mut_val *results_arr = yyjson_mut_arr(doc);
        for (int ri = 0; ri < output_count; ri++) {
            search_result_t *r = &sr[ri];
            yyjson_mut_val *item = yyjson_mut_obj(doc);

            yyjson_mut_obj_add_str(doc, item, "node", r->node_name);
            yyjson_mut_obj_add_str(doc, item, "qualified_name", r->qualified_name);
            yyjson_mut_obj_add_str(doc, item, "label", r->label);
            yyjson_mut_obj_add_str(doc, item, "file", r->file);
            yyjson_mut_obj_add_int(doc, item, "start_line", r->start_line);
            yyjson_mut_obj_add_int(doc, item, "end_line", r->end_line);
            yyjson_mut_obj_add_int(doc, item, "in_degree", r->in_degree);
            yyjson_mut_obj_add_int(doc, item, "out_degree", r->out_degree);

            yyjson_mut_val *ml = yyjson_mut_arr(doc);
            for (int j = 0; j < r->match_count; j++) {
                yyjson_mut_arr_add_int(doc, ml, r->match_lines[j]);
            }
            yyjson_mut_obj_add_val(doc, item, "match_lines", ml);
            if (!attach_result_source(doc, item, r, mode, context_lines, root_path,
                                      &response_error)) {
                yyjson_mut_doc_free(doc);
                return search_operation_error_result(
                    "CBM_SEARCH_SOURCE_READBACK_FAILED",
                    "search response could not read the exact indexed source bytes",
                    "restore the indexed source revision or re-index it, then retry",
                    &response_error);
            }
            yyjson_mut_arr_add_val(results_arr, item);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "results", results_arr);

        enum { MAX_RAW = 20 };
        yyjson_mut_val *raw_arr = yyjson_mut_arr(doc);
        int raw_output = raw_count < MAX_RAW ? raw_count : MAX_RAW;
        for (int ri = 0; ri < raw_output; ri++) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_str(doc, item, "file", raw[ri]->file);
            yyjson_mut_obj_add_int(doc, item, "line", raw[ri]->line);
            yyjson_mut_obj_add_str(doc, item, "content", raw[ri]->content);
            yyjson_mut_arr_add_val(raw_arr, item);
        }
        yyjson_mut_obj_add_val(doc, root_obj, "raw_matches", raw_arr);
        yyjson_mut_obj_add_bool(doc, root_obj, "raw_matches_truncated", raw_output < raw_count);
    }

    yyjson_mut_val *directories = build_dir_distribution(doc, sr, sr_count);
    if (!directories) {
        yyjson_mut_doc_free(doc);
        search_response_error_t allocation_error = {0};
        snprintf(allocation_error.operation, sizeof(allocation_error.operation), "%s",
                 "response.build_directory_distribution");
        snprintf(allocation_error.detail, sizeof(allocation_error.detail), "%s",
                 "directory-distribution allocation failed");
        return search_operation_error_result(
            "CBM_SEARCH_SERIALIZATION_FAILED", "search response allocation failed",
            "free memory and retry the exact search", &allocation_error);
    }
    yyjson_mut_obj_add_val(doc, root_obj, "directories", directories);

    /* Summary stats */
    yyjson_mut_obj_add_int(doc, root_obj, "total_grep_matches", gm_count);
    yyjson_mut_obj_add_int(doc, root_obj, "total_results", sr_count);
    yyjson_mut_obj_add_int(doc, root_obj, "raw_match_count", raw_count);
    yyjson_mut_obj_add_int(doc, root_obj, "elapsed_ms", (int)elapsed_ms);
    if (sr_count > 0 && gm_count > 0) {
        char ratio[CBM_SZ_32];
        snprintf(ratio, sizeof(ratio), "%.1fx", (double)gm_count / (double)(sr_count + raw_count));
        yyjson_mut_obj_add_strcpy(doc, root_obj, "dedup_ratio", ratio);
    }

    /* Warnings: surface common foot-guns instead of leaving them silent. */
    yyjson_mut_val *warnings = yyjson_mut_arr(doc);
    if (warn_literal_pipe) {
        yyjson_mut_arr_add_strcpy(
            doc, warnings,
            "pattern contains '|' but regex=false, so it is matched literally (not as "
            "alternation). Pass regex=true for 'foo|bar' to mean 'foo OR bar'.");
    }
    if (elapsed_ms >= SEARCH_SLOW_MS) {
        char slow[CBM_SZ_128];
        snprintf(slow, sizeof(slow),
                 "search took %dms (>%ds); narrow file_pattern/path_filter or use a more "
                 "specific pattern",
                 (int)elapsed_ms, SEARCH_SLOW_MS / 1000);
        yyjson_mut_arr_add_strcpy(doc, warnings, slow);
        char ems[CBM_SZ_32];
        snprintf(ems, sizeof(ems), "%d", (int)elapsed_ms);
        cbm_log_warn("search.slow", "elapsed_ms", ems); /* visibility in logs */
    }
    if (yyjson_mut_arr_size(warnings) > 0) {
        yyjson_mut_obj_add_val(doc, root_obj, "warnings", warnings);
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);

    if (!json) {
        return cbm_mcp_text_result(
            "{\"code\":\"CBM_SEARCH_SERIALIZATION_FAILED\",\"message\":\"search response "
            "serialization failed\",\"remediation\":\"free memory and retry the exact "
            "search\"}",
            true);
    }

    char *result = cbm_mcp_text_result(json, false);
    free(json);
    return result;
}

/* Read grep output from fp, parse file:line:content format, apply path filter,
 * and return a dynamically-allocated grep_match_t array. */
/* Strip root path prefix from a file path. */
static const char *strip_root_prefix(const char *path, const char *root, size_t root_len) {
    if (strncmp(path, root, root_len) != 0 || (path[root_len] != '\0' && path[root_len] != '/')) {
        return path;
    }
    const char *p = path + root_len;
    if (*p == '/') {
        p++;
    }
    return p;
}

typedef enum {
    SEARCH_COLLECT_OK = 0,
    SEARCH_COLLECT_IO_FAILED,
    SEARCH_COLLECT_MALFORMED,
    SEARCH_COLLECT_OOM,
} search_collect_status_t;

typedef struct {
    search_collect_status_t status;
    char operation[CBM_SZ_64];
    char detail[CBM_SZ_512];
} search_collect_result_t;

static void free_grep_matches(grep_match_t *matches, int count) {
    if (!matches) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(matches[i].file);
        free(matches[i].content);
    }
    free(matches);
}

/* Read one complete subprocess record without a fixed line buffer.  Returns 1
 * for a record, 0 for clean EOF, and -1 for an explicit I/O/allocation/format
 * failure recorded in result. */
static int read_search_record(FILE *fp, char **buffer, size_t *capacity, size_t *length,
                              search_collect_result_t *result) {
    *length = 0;
    for (;;) {
        int ch = fgetc(fp);
        if (ch == EOF) {
            if (ferror(fp)) {
                result->status = SEARCH_COLLECT_IO_FAILED;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "search.read_process_output");
                snprintf(result->detail, sizeof(result->detail), "output read failed: %s",
                         strerror(errno));
                return CBM_NOT_FOUND;
            }
            if (*length == 0) {
                return 0;
            }
            break;
        }
        if (ch == '\0') {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.parse_process_output");
            snprintf(result->detail, sizeof(result->detail), "%s",
                     "search output contained an embedded NUL byte");
            return CBM_NOT_FOUND;
        }
        if (ch == '\n') {
            break;
        }
        if (*length + MCP_SEPARATOR > *capacity) {
            size_t next = *capacity ? *capacity * PAIR_LEN : CBM_SZ_4K;
            if (next <= *capacity || next > SIZE_MAX - SKIP_ONE) {
                result->status = SEARCH_COLLECT_OOM;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "search.grow_process_record");
                snprintf(result->detail, sizeof(result->detail), "%s",
                         "search output record exceeds addressable memory");
                return CBM_NOT_FOUND;
            }
            char *grown = realloc(*buffer, next);
            if (!grown) {
                result->status = SEARCH_COLLECT_OOM;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "search.grow_process_record");
                snprintf(result->detail, sizeof(result->detail),
                         "record allocation failed at %zu bytes", next);
                return CBM_NOT_FOUND;
            }
            *buffer = grown;
            *capacity = next;
        }
        (*buffer)[(*length)++] = (char)ch;
    }
    if (*length > 0 && (*buffer)[*length - SKIP_ONE] == '\r') {
        (*length)--;
    }
    (*buffer)[*length] = '\0';
    return SKIP_ONE;
}

static int grep_match_file_cmp(const void *left, const void *right) {
    const grep_match_t *a = left;
    const grep_match_t *b = right;
    return strcmp(a->file, b->file);
}

static grep_match_t *collect_grep_matches(FILE *fp, const char *root_path, size_t root_len,
                                          bool has_path_filter, cbm_regex_t *path_regex,
                                          int *out_count, search_collect_result_t *result) {
    memset(result, 0, sizeof(*result));
    *out_count = 0;
    grep_match_t *matches = NULL;
    int count = 0;
    int capacity = 0;
    char *record = NULL;
    size_t record_capacity = 0;
    size_t record_length = 0;

    for (;;) {
        int read_rc = read_search_record(fp, &record, &record_capacity, &record_length, result);
        if (read_rc == 0) {
            break;
        }
        if (read_rc < 0) {
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        if (record_length == 0) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.parse_process_output");
            snprintf(result->detail, sizeof(result->detail),
                     "empty JSON record at output record %d", count + SKIP_ONE);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }

#ifdef _WIN32
        yyjson_doc *doc = yyjson_read(record, record_length, 0);
        yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
        yyjson_val *path_value = root ? yyjson_obj_get(root, "path") : NULL;
        yyjson_val *line_value = root ? yyjson_obj_get(root, "line") : NULL;
        yyjson_val *content_value = root ? yyjson_obj_get(root, "content") : NULL;
        if (!root || !yyjson_is_obj(root) || !path_value || !yyjson_is_str(path_value) ||
            !line_value || !yyjson_is_int(line_value) || !content_value ||
            !yyjson_is_str(content_value)) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.parse_process_output");
            snprintf(result->detail, sizeof(result->detail),
                     "invalid JSON schema at output record %d", count + SKIP_ONE);
            if (doc) {
                yyjson_doc_free(doc);
            }
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        int64_t line_number = yyjson_get_sint(line_value);
        if (line_number <= 0 || line_number > INT_MAX) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.parse_process_output");
            snprintf(result->detail, sizeof(result->detail),
                     "line number out of range at output record %d", count + SKIP_ONE);
            yyjson_doc_free(doc);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        char *path = heap_strdup(yyjson_get_str(path_value));
        char *content = heap_strdup(yyjson_get_str(content_value));
        yyjson_doc_free(doc);
#else
        char *sep1 = strchr(record, ':');
        char *sep2 = sep1 ? strchr(sep1 + SKIP_ONE, ':') : NULL;
        char *endptr = NULL;
        long parsed_line = 0;
        if (sep1 && sep2) {
            *sep1 = '\0';
            *sep2 = '\0';
            errno = 0;
            parsed_line = strtol(sep1 + SKIP_ONE, &endptr, CBM_DECIMAL_BASE);
        }
        if (!sep1 || !sep2 || errno != 0 || !endptr || *endptr != '\0' || parsed_line <= 0 ||
            parsed_line > INT_MAX) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.parse_process_output");
            snprintf(result->detail, sizeof(result->detail), "invalid grep record %d",
                     count + SKIP_ONE);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        int64_t line_number = parsed_line;
        char *path = heap_strdup(record);
        char *content = heap_strdup(sep2 + SKIP_ONE);
#endif
        if (!path || !content) {
            free(path);
            free(content);
            result->status = SEARCH_COLLECT_OOM;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.copy_process_record");
            snprintf(result->detail, sizeof(result->detail),
                     "record allocation failed at output record %d", count + SKIP_ONE);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
#ifdef _WIN32
        cbm_normalize_path_sep(path);
#endif
        const char *relative = strip_root_prefix(path, root_path, root_len);
        if (relative == path || !cbm_path_within_root(root_path, path)) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.validate_process_path");
            snprintf(result->detail, sizeof(result->detail),
                     "search output path is outside the indexed project root: %.400s", path);
            free(path);
            free(content);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        if (has_path_filter && cbm_regexec(path_regex, relative, 0, NULL, 0) != CBM_REG_OK) {
            result->status = SEARCH_COLLECT_MALFORMED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.validate_process_scope");
            snprintf(result->detail, sizeof(result->detail),
                     "search process returned a path excluded by path_filter: %.400s", relative);
            free(path);
            free(content);
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        char *relative_copy = heap_strdup(relative);
        free(path);
        if (!relative_copy) {
            free(content);
            result->status = SEARCH_COLLECT_OOM;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "search.copy_relative_path");
            snprintf(result->detail, sizeof(result->detail), "%s",
                     "relative-path allocation failed");
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        if (count == INT_MAX) {
            free(relative_copy);
            free(content);
            result->status = SEARCH_COLLECT_OOM;
            snprintf(result->operation, sizeof(result->operation), "%s", "search.count_matches");
            snprintf(result->detail, sizeof(result->detail), "%s",
                     "match count exceeds the representable API range");
            free(record);
            free_grep_matches(matches, count);
            return NULL;
        }
        if (count >= capacity) {
            int next = capacity ? capacity * PAIR_LEN : CBM_SZ_64;
            if (next <= capacity || (size_t)next > SIZE_MAX / sizeof(*matches)) {
                free(relative_copy);
                free(content);
                result->status = SEARCH_COLLECT_OOM;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "search.grow_match_set");
                snprintf(result->detail, sizeof(result->detail), "%s",
                         "match-set size exceeds addressable memory");
                free(record);
                free_grep_matches(matches, count);
                return NULL;
            }
            grep_match_t *grown = realloc(matches, (size_t)next * sizeof(*matches));
            if (!grown) {
                free(relative_copy);
                free(content);
                result->status = SEARCH_COLLECT_OOM;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "search.grow_match_set");
                snprintf(result->detail, sizeof(result->detail),
                         "match-set allocation failed at %d records", next);
                free(record);
                free_grep_matches(matches, count);
                return NULL;
            }
            matches = grown;
            capacity = next;
        }
        matches[count].file = relative_copy;
        matches[count].line = (int)line_number;
        matches[count].content = content;
        count++;
    }

    free(record);
    result->status = SEARCH_COLLECT_OK;
    *out_count = count;
    return matches;
}

/* Find the tightest node containing a line in a file. Returns index or -1. */
static int find_tightest_node(cbm_node_t *nodes, int count, int line) {
    int best = CBM_NOT_FOUND;
    int best_span = MAX_LINE_SPAN;
    for (int j = 0; j < count; j++) {
        if (nodes[j].start_line <= line && nodes[j].end_line >= line) {
            int span = nodes[j].end_line - nodes[j].start_line;
            if (span < best_span) {
                best = j;
                best_span = span;
            }
        }
    }
    return best;
}

/* Add a grep hit to the search result set (merge into existing or create new). */
static bool add_search_match_line(search_result_t *result, int line) {
    if (result->match_count >= result->match_cap) {
        int next = result->match_cap ? result->match_cap * PAIR_LEN : 8;
        if (next <= result->match_cap || (size_t)next > SIZE_MAX / sizeof(int)) {
            return false;
        }
        int *grown = realloc(result->match_lines, (size_t)next * sizeof(int));
        if (!grown) {
            return false;
        }
        result->match_lines = grown;
        result->match_cap = next;
    }
    result->match_lines[result->match_count++] = line;
    return true;
}

static bool add_to_search_results(search_result_t **sr, int *sr_count, int *sr_cap, cbm_node_t *n,
                                  int line) {
    for (int j = 0; j < *sr_count; j++) {
        if ((*sr)[j].node_id == n->id) {
            return add_search_match_line(&(*sr)[j], line);
        }
    }
    if (*sr_count >= *sr_cap) {
        int next = *sr_cap ? *sr_cap * PAIR_LEN : CBM_SZ_32;
        if (next <= *sr_cap || (size_t)next > SIZE_MAX / sizeof(search_result_t)) {
            return false;
        }
        search_result_t *grown = realloc(*sr, (size_t)next * sizeof(search_result_t));
        if (!grown) {
            return false;
        }
        memset(grown + *sr_cap, 0, (size_t)(next - *sr_cap) * sizeof(search_result_t));
        *sr = grown;
        *sr_cap = next;
    }
    search_result_t *r = &(*sr)[*sr_count];
    r->node_id = n->id;
    r->node_name = heap_strdup(n->name ? n->name : "");
    r->qualified_name = heap_strdup(n->qualified_name ? n->qualified_name : "");
    r->label = heap_strdup(n->label ? n->label : "");
    r->file = heap_strdup(n->file_path ? n->file_path : "");
    if (!r->node_name || !r->qualified_name || !r->label || !r->file) {
        free(r->node_name);
        free(r->qualified_name);
        free(r->label);
        free(r->file);
        memset(r, 0, sizeof(*r));
        return false;
    }
    r->start_line = n->start_line;
    r->end_line = n->end_line;
    if (!add_search_match_line(r, line)) {
        free(r->node_name);
        free(r->qualified_name);
        free(r->label);
        free(r->file);
        memset(r, 0, sizeof(*r));
        return false;
    }
    (*sr_count)++;
    return true;
}

/* Match a single grep hit to the tightest containing node, then add to sr or raw. */
static bool classify_grep_hit(grep_match_t *hit, cbm_node_t *file_nodes, int file_node_count,
                              search_result_t **sr, int *sr_count, int *sr_cap, grep_match_t ***raw,
                              int *raw_count, int *raw_cap) {
    int best = find_tightest_node(file_nodes, file_node_count, hit->line);
    if (best >= 0) {
        return add_to_search_results(sr, sr_count, sr_cap, &file_nodes[best], hit->line);
    } else {
        if (*raw_count >= *raw_cap) {
            int next = (*raw_cap == 0) ? CBM_SZ_32 : *raw_cap * PAIR_LEN;
            if (next <= *raw_cap || (size_t)next > SIZE_MAX / sizeof(grep_match_t *)) {
                return false;
            }
            grep_match_t **grown = realloc(*raw, (size_t)next * sizeof(grep_match_t *));
            if (!grown) {
                return false;
            }
            *raw = grown;
            *raw_cap = next;
        }
        (*raw)[(*raw_count)++] = hit;
        return true;
    }
}

static void free_search_results(search_result_t *results, int count) {
    if (!results) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(results[i].node_name);
        free(results[i].qualified_name);
        free(results[i].label);
        free(results[i].file);
        free(results[i].match_lines);
    }
    free(results);
}

/* Free a file_nodes array returned from cbm_store_find_nodes_by_file. */
static void free_file_nodes(cbm_node_t *nodes, int count) {
    for (int j = 0; j < count; j++) {
        safe_str_free(&nodes[j].project);
        safe_str_free(&nodes[j].label);
        safe_str_free(&nodes[j].name);
        safe_str_free(&nodes[j].qualified_name);
        safe_str_free(&nodes[j].file_path);
        safe_str_free(&nodes[j].properties_json);
    }
    free(nodes);
}

/* Classify all grep matches file-by-file into search results and raw hits. */
static int classify_all_grep_hits(cbm_mcp_server_t *srv, grep_match_t *gm, int gm_count,
                                  cbm_store_t *store, const char *project, search_result_t **sr,
                                  int *sr_count, int *sr_cap, grep_match_t ***raw, int *raw_count,
                                  int *raw_cap, search_collect_result_t *result) {
    if (!store) {
        result->status = SEARCH_COLLECT_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "enrichment.resolve_store");
        snprintf(result->detail, sizeof(result->detail), "%s",
                 "the verified project store is unavailable during enrichment");
        return CBM_STORE_ERR;
    }
    if (gm_count > SKIP_ONE) {
        qsort(gm, (size_t)gm_count, sizeof(grep_match_t), grep_match_file_cmp);
    }
    int i = 0;
    while (i < gm_count) {
        const char *cur_file = gm[i].file;
        int file_start = i;
        while (i < gm_count && strcmp(gm[i].file, cur_file) == 0) {
            i++;
        }
        cbm_node_t *file_nodes = NULL;
        int file_node_count = 0;
        int query_rc =
            cbm_store_find_nodes_by_file(store, project, cur_file, &file_nodes, &file_node_count);
        if (query_rc != CBM_STORE_OK) {
            record_store_query_failure(
                srv, project, cbm_store_db_path(store), store, CBM_STORE_VERIFY_IO_FAILED,
                "source.query_nodes_for_search_file", cbm_store_error(store));
            result->status = SEARCH_COLLECT_IO_FAILED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "enrichment.query_file_nodes");
            snprintf(result->detail, sizeof(result->detail),
                     "file-node query failed for %.400s: %.80s", cur_file, cbm_store_error(store));
            free_file_nodes(file_nodes, file_node_count);
            return query_rc;
        }
        for (int mi = file_start; mi < i; mi++) {
            if (!classify_grep_hit(&gm[mi], file_nodes, file_node_count, sr, sr_count, sr_cap, raw,
                                   raw_count, raw_cap)) {
                result->status = SEARCH_COLLECT_OOM;
                snprintf(result->operation, sizeof(result->operation), "%s",
                         "enrichment.allocate_results");
                snprintf(result->detail, sizeof(result->detail),
                         "result allocation failed while classifying %.400s:%d", cur_file,
                         gm[mi].line);
                free_file_nodes(file_nodes, file_node_count);
                return CBM_STORE_ERR;
            }
        }
        free_file_nodes(file_nodes, file_node_count);
    }
    return CBM_STORE_OK;
}

typedef enum {
    SEARCH_SCOPE_OK = 0,
    SEARCH_SCOPE_STORE_FAILED,
    SEARCH_SCOPE_EMPTY,
    SEARCH_SCOPE_INVALID_PATH,
    SEARCH_SCOPE_INVALID_SOURCE,
    SEARCH_SCOPE_IO_FAILED,
} search_scope_status_t;

typedef struct {
    search_scope_status_t status;
    char operation[CBM_SZ_64];
    char detail[CBM_SZ_512];
} search_scope_result_t;

static bool validate_utf8_source_file(const char *path, search_scope_result_t *result) {
    FILE *fp = cbm_fopen(path, "rb");
    if (!fp) {
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.open_source");
        snprintf(result->detail, sizeof(result->detail), "source open failed for %.360s: %s", path,
                 strerror(errno));
        return false;
    }
    uint64_t offset = 0;
    bool valid = true;
    for (;;) {
        int first = fgetc(fp);
        if (first == EOF) {
            if (ferror(fp)) {
                result->status = SEARCH_SCOPE_IO_FAILED;
                snprintf(result->operation, sizeof(result->operation), "%s", "scope.read_source");
                snprintf(result->detail, sizeof(result->detail),
                         "source read failed for %.360s at byte %llu: %s", path,
                         (unsigned long long)offset, strerror(errno));
                valid = false;
            }
            break;
        }
        unsigned char sequence[5] = {(unsigned char)first, 0, 0, 0, 0};
        if (sequence[0] == 0) {
            result->status = SEARCH_SCOPE_INVALID_SOURCE;
            snprintf(result->operation, sizeof(result->operation), "%s", "scope.validate_utf8");
            snprintf(result->detail, sizeof(result->detail),
                     "source contains an embedded NUL at byte %llu: %.360s",
                     (unsigned long long)offset, path);
            valid = false;
            break;
        }
        int expected = sequence[0] <= 0x7f   ? 1
                       : sequence[0] <= 0xdf ? 2
                       : sequence[0] <= 0xef ? 3
                                             : 4;
        for (int i = SKIP_ONE; i < expected; i++) {
            int next = fgetc(fp);
            if (next == EOF) {
                valid = false;
                break;
            }
            sequence[i] = (unsigned char)next;
        }
        if (!valid || cbm_utf8_sequence_len(sequence) != expected) {
            result->status = SEARCH_SCOPE_INVALID_SOURCE;
            snprintf(result->operation, sizeof(result->operation), "%s", "scope.validate_utf8");
            snprintf(result->detail, sizeof(result->detail),
                     "source is not valid UTF-8 at byte %llu: %.360s", (unsigned long long)offset,
                     path);
            valid = false;
            break;
        }
        offset += (uint64_t)expected;
    }
    if (fclose(fp) != 0 && valid) {
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.close_source");
        snprintf(result->detail, sizeof(result->detail), "source close failed for %.360s: %s", path,
                 strerror(errno));
        valid = false;
    }
    return valid;
}

/* Write the exact indexed file list for scoped grep.
 * When a path_filter is provided, apply it here — before grep — so large
 * indexed projects do not scan files only for collect_grep_matches to discard
 * them later. The predicate is IDENTICAL to the post-grep filter: the same
 * compiled regex run against the same root-relative path (separators
 * normalized on Windows first), so prefiltering can only skip files whose
 * hits would be dropped anyway — results-preserving by construction.
 * *out_written receives the number of records written (0 = the filter
 * excluded every indexed file). */
static search_scope_status_t write_scoped_filelist(cbm_mcp_server_t *srv, const char *project,
                                                   const char *root_path, const char *filelist,
                                                   bool has_path_filter, cbm_regex_t *path_regex,
                                                   int *out_written,
                                                   search_scope_result_t *result) {
    memset(result, 0, sizeof(*result));
    *out_written = 0;
    cbm_store_t *pre_store = resolve_store(srv, project);
    if (!pre_store) {
        result->status = SEARCH_SCOPE_STORE_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.resolve_store");
        snprintf(result->detail, sizeof(result->detail), "%s",
                 "the verified project store could not be resolved");
        return result->status;
    }
    char **indexed_files = NULL;
    int indexed_count = 0;
    if (cbm_store_list_files(pre_store, project, &indexed_files, &indexed_count) != CBM_STORE_OK) {
        record_store_query_failure(srv, project, cbm_store_db_path(pre_store), pre_store,
                                   CBM_STORE_VERIFY_IO_FAILED, "source.query_indexed_files",
                                   cbm_store_error(pre_store));
        result->status = SEARCH_SCOPE_STORE_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.query_indexed_files");
        snprintf(result->detail, sizeof(result->detail), "%s", cbm_store_error(pre_store));
        return result->status;
    }
    if (indexed_count == 0) {
        free(indexed_files);
        result->status = SEARCH_SCOPE_EMPTY;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.query_indexed_files");
        snprintf(result->detail, sizeof(result->detail), "%s",
                 "the persisted graph contains no indexed source paths");
        return result->status;
    }
    FILE *fl = cbm_fopen(filelist, "wb");
    if (!fl) {
        for (int fi = 0; fi < indexed_count; fi++) {
            free(indexed_files[fi]);
        }
        free(indexed_files);
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.open_filelist");
        snprintf(result->detail, sizeof(result->detail), "filelist open failed: %s",
                 strerror(errno));
        return result->status;
    }

    bool write_ok = true;
    int written = 0;
    for (int fi = 0; fi < indexed_count; fi++) {
        /* A source path never legitimately contains a newline or carriage
         * return. Those bytes are the filelist record separator, so rejecting
         * the complete operation is the only non-lossy response. */
        if (strpbrk(indexed_files[fi], "\r\n") != NULL) {
            result->status = SEARCH_SCOPE_INVALID_PATH;
            snprintf(result->operation, sizeof(result->operation), "%s", "scope.validate_path");
            snprintf(result->detail, sizeof(result->detail),
                     "indexed path contains a forbidden record separator: %s", indexed_files[fi]);
            write_ok = false;
            break;
        }
        if (has_path_filter && path_regex) {
#ifdef _WIN32
            cbm_normalize_path_sep(indexed_files[fi]);
#endif
            if (cbm_regexec(path_regex, indexed_files[fi], 0, NULL, 0) != CBM_REG_OK) {
                continue;
            }
        }
        size_t root_len = strlen(root_path);
        size_t path_len = strlen(indexed_files[fi]);
        if (root_len > SIZE_MAX - path_len - MCP_SEPARATOR) {
            result->status = SEARCH_SCOPE_IO_FAILED;
            snprintf(result->operation, sizeof(result->operation), "%s", "scope.build_source_path");
            snprintf(result->detail, sizeof(result->detail), "%s",
                     "source path exceeds addressable memory");
            write_ok = false;
            break;
        }
        size_t absolute_len = root_len + path_len + MCP_SEPARATOR;
        char *absolute_path = malloc(absolute_len);
        if (!absolute_path) {
            result->status = SEARCH_SCOPE_IO_FAILED;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "scope.allocate_source_path");
            snprintf(result->detail, sizeof(result->detail),
                     "source-path allocation failed at %zu bytes", absolute_len);
            write_ok = false;
            break;
        }
        snprintf(absolute_path, absolute_len, "%s/%s", root_path, indexed_files[fi]);
        if (!cbm_path_within_root(root_path, absolute_path)) {
            result->status = SEARCH_SCOPE_INVALID_PATH;
            snprintf(result->operation, sizeof(result->operation), "%s",
                     "scope.validate_source_path");
            snprintf(result->detail, sizeof(result->detail),
                     "indexed source path resolves outside the project root: %.400s",
                     indexed_files[fi]);
            free(absolute_path);
            write_ok = false;
            break;
        }
        if (!validate_utf8_source_file(absolute_path, result)) {
            free(absolute_path);
            write_ok = false;
            break;
        }
        free(absolute_path);
        write_ok = fwrite(root_path, 1, root_len, fl) == root_len && fputc('/', fl) != EOF &&
                   fwrite(indexed_files[fi], 1, path_len, fl) == path_len;
#ifdef _WIN32
        write_ok = write_ok && fputc('\n', fl) != EOF;
#else
        write_ok = write_ok && fputc('\0', fl) != EOF;
#endif
        if (!write_ok) {
            result->status = SEARCH_SCOPE_IO_FAILED;
            snprintf(result->operation, sizeof(result->operation), "%s", "scope.write_filelist");
            snprintf(result->detail, sizeof(result->detail), "filelist write failed: %s",
                     strerror(errno));
            break;
        }
        written++;
    }
    if (fclose(fl) != 0 && write_ok) {
        write_ok = false;
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "scope.close_filelist");
        snprintf(result->detail, sizeof(result->detail), "filelist close failed: %s",
                 strerror(errno));
    }
    for (int fi = 0; fi < indexed_count; fi++) {
        free(indexed_files[fi]);
    }
    free(indexed_files);
    if (!write_ok) {
        cbm_unlink(filelist);
        return result->status;
    }
    *out_written = written;
    result->status = SEARCH_SCOPE_OK;
    return result->status;
}

static char *build_search_scope_error(const char *code, const search_scope_result_t *scope) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return heap_strdup(
            "{\"code\":\"CBM_SEARCH_SCOPE_FAILED\",\"message\":\"indexed search scope could not "
            "be materialized\",\"remediation\":\"repair the indexed project state and retry\"}");
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "code", code);
    yyjson_mut_obj_add_str(doc, root, "message",
                           "search_code could not materialize the exact persisted indexed-file "
                           "scope and refused to search a different corpus");
    yyjson_mut_obj_add_str(doc, root, "remediation",
                           "repair or re-index the project, resolve the reported scope operation, "
                           "then retry");
    yyjson_mut_obj_add_str(doc, root, "failed_operation", scope->operation);
    yyjson_mut_obj_add_str(doc, root, "detail", scope->detail);
    yyjson_mut_obj_add_bool(doc, root, "recursive_fallback_attempted", false);
    char *json = yyjson_mut_write(doc, 0, NULL);
    yyjson_mut_doc_free(doc);
    return json ? json : heap_strdup("{\"code\":\"CBM_SEARCH_SCOPE_FAILED\"}");
}

typedef enum {
    SEARCH_MODE_COMPACT = 0,
    SEARCH_MODE_FULL = 1,
    SEARCH_MODE_FILES = 2,
} search_mode_t;

static bool parse_search_control_args(const char *args, int *mode, int *limit, int *context,
                                      search_response_error_t *error) {
    *mode = SEARCH_MODE_COMPACT;
    *limit = MCP_DEFAULT_LIMIT;
    *context = 0;
    yyjson_doc *doc = yyjson_read(args, strlen(args), 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) {
        snprintf(error->operation, sizeof(error->operation), "%s", "arguments.parse");
        snprintf(error->detail, sizeof(error->detail), "%s",
                 "search_code arguments are not a valid JSON object");
        if (doc) {
            yyjson_doc_free(doc);
        }
        return false;
    }
    yyjson_val *mode_value = yyjson_obj_get(root, "mode");
    if (mode_value) {
        if (!yyjson_is_str(mode_value)) {
            snprintf(error->operation, sizeof(error->operation), "%s", "arguments.mode");
            snprintf(error->detail, sizeof(error->detail), "%s",
                     "mode must be one of compact, full, or files");
            yyjson_doc_free(doc);
            return false;
        }
        const char *value = yyjson_get_str(mode_value);
        if (strcmp(value, "compact") == 0) {
            *mode = SEARCH_MODE_COMPACT;
        } else if (strcmp(value, "full") == 0) {
            *mode = SEARCH_MODE_FULL;
        } else if (strcmp(value, "files") == 0) {
            *mode = SEARCH_MODE_FILES;
        } else {
            snprintf(error->operation, sizeof(error->operation), "%s", "arguments.mode");
            snprintf(error->detail, sizeof(error->detail), "unsupported search mode: %.400s",
                     value);
            yyjson_doc_free(doc);
            return false;
        }
    }
    const char *names[] = {"limit", "context"};
    int *outputs[] = {limit, context};
    const int minimums[] = {SKIP_ONE, 0};
    for (int i = 0; i < MCP_RETURN_2; i++) {
        yyjson_val *value = yyjson_obj_get(root, names[i]);
        if (!value) {
            continue;
        }
        bool in_range = false;
        uint64_t parsed = 0;
        if (yyjson_is_uint(value)) {
            parsed = yyjson_get_uint(value);
            in_range = parsed <= MCP_MAX_ROWS && parsed >= (uint64_t)minimums[i];
        } else if (yyjson_is_int(value)) {
            int64_t signed_value = yyjson_get_sint(value);
            in_range = signed_value >= minimums[i] && signed_value <= MCP_MAX_ROWS;
            if (in_range) {
                parsed = (uint64_t)signed_value;
            }
        }
        if (!in_range) {
            snprintf(error->operation, sizeof(error->operation), "arguments.%s", names[i]);
            snprintf(error->detail, sizeof(error->detail), "%s must be an integer in [%d,%d]",
                     names[i], minimums[i], MCP_MAX_ROWS);
            yyjson_doc_free(doc);
            return false;
        }
        *outputs[i] = (int)parsed;
    }
    yyjson_doc_free(doc);
    return true;
}

/* Validate shell-safe arguments for search. */
/* Search/grep paths and globs are ALWAYS single-quoted (POSIX sh) or
 * double-/single-quoted (Windows cmd/PowerShell) on the command line, which
 * neutralises '&' — a very common character in real paths (R&D, "Foo & Bar",
 * OneDrive). Accept '&' here while still rejecting every metacharacter that
 * could break out of the quoting (#272). */
static bool validate_search_path_arg(const char *s) {
    if (!s) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '\'':
        case '"':
        case ';':
        case '|':
        case '$':
        case '`':
        case '<':
        case '>':
        case '\n':
        case '\r':
#ifndef _WIN32
        case '\\':
#endif
            return false;
        default:
            break;
        }
    }
    return true;
}

static bool validate_search_args(const char *root_path, const char *file_pattern) {
    if (!validate_search_path_arg(root_path)) {
        return false;
    }
    if (file_pattern && !validate_search_path_arg(file_pattern)) {
        return false;
    }
    return true;
}

/* Write the exact pattern bytes consumed by the search process. */
static search_scope_status_t write_pattern_file(char *tmpfile, int tmpfile_sz, const char *pattern,
                                                search_scope_result_t *result) {
    memset(result, 0, sizeof(*result));
    int path_len = snprintf(tmpfile, (size_t)tmpfile_sz, "%s/cbm_search_XXXXXX", cbm_tmpdir());
    if (path_len < 0 || path_len >= tmpfile_sz) {
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.build_path");
        snprintf(result->detail, sizeof(result->detail), "%s",
                 "pattern temp path exceeds the representable path buffer");
        return result->status;
    }
    int temp_fd = cbm_mkstemp(tmpfile, (size_t)tmpfile_sz);
    if (temp_fd < 0) {
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.create_exclusive");
        snprintf(result->detail, sizeof(result->detail),
                 "exclusive pattern-file creation failed: %s", strerror(errno));
        return result->status;
    }
    FILE *tf = cbm_fdopen(temp_fd, "wb");
    if (!tf) {
        int fdopen_errno = errno;
        (void)cbm_close_fd(temp_fd);
        (void)cbm_unlink(tmpfile);
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.open");
        snprintf(result->detail, sizeof(result->detail), "pattern-file open failed: %s",
                 strerror(fdopen_errno));
        return result->status;
    }
    size_t pattern_len = strlen(pattern);
    bool ok = fwrite(pattern, 1, pattern_len, tf) == pattern_len;
    if (!ok) {
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.write");
        snprintf(result->detail, sizeof(result->detail), "pattern-file write failed: %s",
                 strerror(errno));
    } else if (fflush(tf) != 0) {
        ok = false;
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.flush");
        snprintf(result->detail, sizeof(result->detail), "pattern-file flush failed: %s",
                 strerror(errno));
    }
    if (fclose(tf) != 0 && ok) {
        ok = false;
        result->status = SEARCH_SCOPE_IO_FAILED;
        snprintf(result->operation, sizeof(result->operation), "%s", "pattern.close");
        snprintf(result->detail, sizeof(result->detail), "pattern-file close failed: %s",
                 strerror(errno));
    }
    if (!ok) {
        cbm_unlink(tmpfile);
        return result->status;
    }
    result->status = SEARCH_SCOPE_OK;
    return result->status;
}

typedef enum {
    PATH_FILTER_ABSENT = 0,
    PATH_FILTER_VALID,
    PATH_FILTER_INVALID,
} path_filter_status_t;

static path_filter_status_t compile_path_filter(const char *filter, cbm_regex_t *re,
                                                int *regex_error) {
    *regex_error = CBM_REG_OK;
    if (!filter) {
        return PATH_FILTER_ABSENT;
    }
    *regex_error = cbm_regcomp(re, filter, CBM_REG_EXTENDED | CBM_REG_NOSUB);
    return *regex_error == CBM_REG_OK ? PATH_FILTER_VALID : PATH_FILTER_INVALID;
}

static char *handle_search_code(cbm_mcp_server_t *srv, const char *args) {
    char *pattern = cbm_mcp_get_string_arg(args, "pattern");
    char *project = get_project_arg(args);
    char *file_pattern = cbm_mcp_get_string_arg(args, "file_pattern");
    char *path_filter = cbm_mcp_get_string_arg(args, "path_filter");
    int mode = SEARCH_MODE_COMPACT;
    int limit = MCP_DEFAULT_LIMIT;
    int context_lines = 0;
    bool use_regex = cbm_mcp_get_bool_arg(args, "regex");
    uint64_t search_t0 = cbm_now_ms();
    /* In literal (non-regex) mode a '|' is matched as a byte, not alternation —
     * a common silent 0-match trap; flagged in the result warnings (#282). */
    bool pat_has_pipe = pattern && strchr(pattern, '|') != NULL;

    search_response_error_t argument_error = {0};
    if (!parse_search_control_args(args, &mode, &limit, &context_lines, &argument_error)) {
        free(pattern);
        free(project);
        free(file_pattern);
        free(path_filter);
        return search_operation_error_result(
            "CBM_SEARCH_ARGUMENT_INVALID", "search_code arguments are invalid",
            "correct the reported argument without changing the intended corpus and retry",
            &argument_error);
    }

    if (!pattern) {
        free(project);
        free(file_pattern);
        free(path_filter);
        return cbm_mcp_text_result("pattern is required", true);
    }

    if (strpbrk(pattern, "\r\n") != NULL) {
        search_scope_result_t invalid_pattern = {0};
        snprintf(invalid_pattern.operation, sizeof(invalid_pattern.operation), "%s",
                 "pattern.validate");
        snprintf(invalid_pattern.detail, sizeof(invalid_pattern.detail), "%s",
                 "pattern contains a line separator; search_code accepts one line pattern");
        char *error = build_search_scope_error("CBM_SEARCH_PATTERN_INVALID", &invalid_pattern);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        free(pattern);
        free(project);
        free(file_pattern);
        free(path_filter);
        return result;
    }

    cbm_regex_t path_regex;
    int path_regex_error = CBM_REG_OK;
    path_filter_status_t path_filter_status =
        compile_path_filter(path_filter, &path_regex, &path_regex_error);
    bool has_path_filter = path_filter_status == PATH_FILTER_VALID;
    if (path_filter_status == PATH_FILTER_INVALID) {
        search_scope_result_t invalid_filter = {0};
        snprintf(invalid_filter.operation, sizeof(invalid_filter.operation), "%s",
                 "path_filter.compile");
        snprintf(invalid_filter.detail, sizeof(invalid_filter.detail),
                 "path_filter regex compilation failed with code %d", path_regex_error);
        char *error = build_search_scope_error("CBM_SEARCH_PATH_FILTER_INVALID", &invalid_filter);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        free(pattern);
        free(project);
        free(file_pattern);
        free(path_filter);
        return result;
    }
    free(path_filter);
    path_filter = NULL;

    /* Project is required */
    if (!project) {
        free(pattern);
        free(file_pattern);
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        char *_err = build_missing_project_error();
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        return _res;
    }

    char *root_path = get_project_root(srv, project);
    if (!root_path) {
        char *_err = build_no_store_error(srv, project);
        char *_res = cbm_mcp_text_result(_err, true);
        free(_err);
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(pattern);
        free(project);
        free(file_pattern);
        return _res;
    }

    if (!validate_search_args(root_path, file_pattern)) {
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        return cbm_mcp_text_result("path or file_pattern contains invalid characters", true);
    }

    /* issue #283: when regex=true, a syntactically invalid pattern (e.g. an
     * unclosed group) makes the underlying grep fail, which the handler would
     * otherwise report as an empty result set — indistinguishable from a
     * legitimate no-match. Validate the user's regex up front and return an
     * explicit error so callers can tell "broken pattern" from "no matches". */
    if (use_regex) {
        cbm_regex_t probe;
        if (cbm_regcomp(&probe, pattern, CBM_REG_EXTENDED | CBM_REG_NOSUB) != CBM_REG_OK) {
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            return cbm_mcp_text_result(
                "invalid regex pattern (regex=true): check for unbalanced (), [], or {}", true);
        }
        cbm_regfree(&probe);
    }

    /* ── Phase 0.5: Multi-word → regex conversion ───────────── */
    /* If pattern contains whitespace and is not already a regex, convert to a
     * regex that matches all words in order: "foo bar baz" → "foo.*bar.*baz".
     * This avoids requiring the exact phrase as a contiguous substring. */
    if (!use_regex && strchr(pattern, ' ')) {
        size_t plen = strlen(pattern);
        if (plen > (SIZE_MAX - SKIP_ONE) / 3) {
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t transform_failure = {0};
            snprintf(transform_failure.operation, sizeof(transform_failure.operation), "%s",
                     "pattern.transform_multiword");
            snprintf(transform_failure.detail, sizeof(transform_failure.detail), "%s",
                     "multi-word pattern exceeds addressable memory");
            char *error = build_search_scope_error("CBM_SEARCH_PATTERN_ALLOCATION_FAILED",
                                                   &transform_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        /* Worst case: every char is a space → ".*" between each char */
        char *regex_pat = malloc(plen * 3 + 1);
        if (!regex_pat) {
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t transform_failure = {0};
            snprintf(transform_failure.operation, sizeof(transform_failure.operation), "%s",
                     "pattern.transform_multiword");
            snprintf(transform_failure.detail, sizeof(transform_failure.detail),
                     "multi-word pattern allocation failed at %zu bytes", plen * 3 + SKIP_ONE);
            char *error = build_search_scope_error("CBM_SEARCH_PATTERN_ALLOCATION_FAILED",
                                                   &transform_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        char *dst = regex_pat;
        const char *src = pattern;
        bool in_space = false;
        while (*src) {
            if (*src == ' ' || *src == '\t') {
                if (!in_space) {
                    *dst++ = '.';
                    *dst++ = '*';
                    in_space = true;
                }
            } else {
                /* Escape regex metacharacters from user input */
                if (strchr("\\^$.|?*+()[]{}", *src)) {
                    *dst++ = '\\';
                }
                *dst++ = *src;
                in_space = false;
            }
            src++;
        }
        *dst = '\0';
        free(pattern);
        pattern = regex_pat;
        use_regex = true;
    }

    /* ── Phase 1: Grep scan ──────────────────────────────────── */
    char tmpfile[CBM_SZ_4K];
    search_scope_result_t pattern_file_result;
    if (write_pattern_file(tmpfile, sizeof(tmpfile), pattern, &pattern_file_result) !=
        SEARCH_SCOPE_OK) {
        char *error =
            build_search_scope_error("CBM_SEARCH_PATTERN_FILE_FAILED", &pattern_file_result);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        return result;
    }

    /* Scope search to the exact persisted indexed-file set.  Failure to
     * materialize that set fails closed; recursive filesystem search would be
     * a different corpus and is never an allowed substitute. */
    char filelist[CBM_SZ_4K];
    int filelist_len = snprintf(filelist, sizeof(filelist), "%s.files", tmpfile);
    if (filelist_len < 0 || (size_t)filelist_len >= sizeof(filelist)) {
        cbm_unlink(tmpfile);
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(project);
        free(file_pattern);
        search_scope_result_t path_failure = {0};
        snprintf(path_failure.operation, sizeof(path_failure.operation), "%s",
                 "scope.build_filelist_path");
        snprintf(path_failure.detail, sizeof(path_failure.detail), "%s",
                 "indexed file-list path exceeds the representable path buffer");
        char *error = build_search_scope_error("CBM_SEARCH_SCOPE_IO_FAILED", &path_failure);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }
    int scoped_written = 0;
    search_scope_result_t scope;
    search_scope_status_t scope_status =
        write_scoped_filelist(srv, project, root_path, filelist, has_path_filter,
                              has_path_filter ? &path_regex : NULL, &scoped_written, &scope);
    if (scope_status != SEARCH_SCOPE_OK) {
        cbm_unlink(tmpfile);
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(root_path);
        free(pattern);
        free(file_pattern);
        char *error = NULL;
        if (scope_status == SEARCH_SCOPE_STORE_FAILED) {
            error = build_no_store_error(srv, project);
        } else {
            const char *code =
                scope_status == SEARCH_SCOPE_EMPTY            ? "CBM_SEARCH_INDEX_EMPTY"
                : scope_status == SEARCH_SCOPE_INVALID_PATH   ? "CBM_SEARCH_INDEXED_PATH_INVALID"
                : scope_status == SEARCH_SCOPE_INVALID_SOURCE ? "CBM_SEARCH_SOURCE_ENCODING_INVALID"
                                                              : "CBM_SEARCH_SCOPE_IO_FAILED";
            error = build_search_scope_error(code, &scope);
        }
        free(project);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }

    /* Collect grep matches into array */
    int gm_count = 0;
    grep_match_t *gm = NULL;
    if (scoped_written == 0) {
        /* The path_filter excluded every indexed file — nothing to scan.
         * Skip the grep subprocess: xargs on an empty filelist is
         * platform-dependent (GNU execs grep once with no operands, BSD
         * skips), and the post-grep filter would drop every hit anyway. */
        cbm_unlink(tmpfile);
        cbm_unlink(filelist);
    } else {
        char *cmd = build_grep_cmd(use_regex, file_pattern, tmpfile, filelist);
        if (!cmd) {
            cbm_unlink(tmpfile);
            cbm_unlink(filelist);
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t command_failure = {0};
            snprintf(command_failure.operation, sizeof(command_failure.operation), "%s",
                     "scope.build_search_command");
            snprintf(command_failure.detail, sizeof(command_failure.detail), "%s",
                     "search command allocation failed");
            char *error =
                build_search_scope_error("CBM_SEARCH_ALLOCATION_FAILED", &command_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }

        FILE *fp = cbm_popen(cmd, "r");
        free(cmd);
        if (!fp) {
            cbm_unlink(tmpfile);
            cbm_unlink(filelist);
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t process_failure = {0};
            snprintf(process_failure.operation, sizeof(process_failure.operation), "%s",
                     "scope.start_search_process");
            snprintf(process_failure.detail, sizeof(process_failure.detail),
                     "search process start failed: %s", strerror(errno));
            char *error = build_search_scope_error("CBM_SEARCH_PROCESS_FAILED", &process_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }

        search_collect_result_t collect_result;
        gm = collect_grep_matches(fp, root_path, strlen(root_path), has_path_filter, &path_regex,
                                  &gm_count, &collect_result);
        int search_rc = cbm_pclose(fp);
        cbm_unlink(tmpfile);
        cbm_unlink(filelist);
        if (collect_result.status != SEARCH_COLLECT_OK) {
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t collect_failure = {0};
            snprintf(collect_failure.operation, sizeof(collect_failure.operation), "%s",
                     collect_result.operation);
            snprintf(collect_failure.detail, sizeof(collect_failure.detail), "%s",
                     collect_result.detail);
            const char *code = collect_result.status == SEARCH_COLLECT_OOM
                                   ? "CBM_SEARCH_ALLOCATION_FAILED"
                               : collect_result.status == SEARCH_COLLECT_MALFORMED
                                   ? "CBM_SEARCH_OUTPUT_INVALID"
                                   : "CBM_SEARCH_PROCESS_IO_FAILED";
            char *error = build_search_scope_error(code, &collect_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        if (search_rc != 0) {
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free_grep_matches(gm, gm_count);
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t process_failure = {0};
            process_failure.status = SEARCH_SCOPE_IO_FAILED;
            snprintf(process_failure.operation, sizeof(process_failure.operation), "%s",
                     "scope.execute_search");
            snprintf(process_failure.detail, sizeof(process_failure.detail),
                     "indexed-file search process exited with code %d", search_rc);
            char *error = build_search_scope_error("CBM_SEARCH_PROCESS_FAILED", &process_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
    }

    /* ── Phase 2+3: Block expansion + graph ranking ──────────── */
    /* Sort grep matches by file for contiguous processing.
     * Then: one SQL query per unique file for nodes, one batch query for all degrees. */

    cbm_store_t *store = resolve_store(srv, project);
    if (!store) {
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free_grep_matches(gm, gm_count);
        free(root_path);
        free(pattern);
        free(file_pattern);
        char *error = build_no_store_error(srv, project);
        free(project);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }

    int sr_cap = 0;
    int sr_count = 0;
    search_result_t *sr = NULL;

    int raw_cap = 0;
    int raw_count = 0;
    grep_match_t **raw = NULL;

    search_collect_result_t enrichment_result = {0};
    if (classify_all_grep_hits(srv, gm, gm_count, store, project, &sr, &sr_count, &sr_cap, &raw,
                               &raw_count, &raw_cap, &enrichment_result) != CBM_STORE_OK) {
        if (has_path_filter) {
            cbm_regfree(&path_regex);
        }
        free(raw);
        free_search_results(sr, sr_count);
        free_grep_matches(gm, gm_count);
        free(root_path);
        free(pattern);
        free(file_pattern);
        char *error =
            enrichment_result.status == SEARCH_COLLECT_OOM ? NULL : build_recorded_store_error(srv);
        if (!error) {
            search_scope_result_t allocation_failure = {0};
            snprintf(allocation_failure.operation, sizeof(allocation_failure.operation), "%s",
                     enrichment_result.operation);
            snprintf(allocation_failure.detail, sizeof(allocation_failure.detail), "%s",
                     enrichment_result.detail);
            error = build_search_scope_error("CBM_SEARCH_ALLOCATION_FAILED", &allocation_failure);
        }
        free(project);
        char *result = cbm_mcp_text_result(error, true);
        free(error);
        return result;
    }

    /* Phase 3: batch degree query — ONE query for all results instead of 2×N */
    if (sr_count > 0) {
        int64_t *ids = malloc((size_t)sr_count * sizeof(int64_t));
        int *in_degs = malloc((size_t)sr_count * sizeof(int));
        int *out_degs = malloc((size_t)sr_count * sizeof(int));
        if (!ids || !in_degs || !out_degs) {
            free(ids);
            free(in_degs);
            free(out_degs);
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(raw);
            free_search_results(sr, sr_count);
            free_grep_matches(gm, gm_count);
            free(root_path);
            free(pattern);
            free(project);
            free(file_pattern);
            search_scope_result_t allocation_failure = {0};
            snprintf(allocation_failure.operation, sizeof(allocation_failure.operation), "%s",
                     "enrichment.allocate_degree_batch");
            snprintf(allocation_failure.detail, sizeof(allocation_failure.detail),
                     "degree-array allocation failed for %d results", sr_count);
            char *error =
                build_search_scope_error("CBM_SEARCH_ALLOCATION_FAILED", &allocation_failure);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        for (int j = 0; j < sr_count; j++) {
            ids[j] = sr[j].node_id;
        }
        int degree_rc =
            cbm_store_batch_count_degrees(store, ids, sr_count, "CALLS", in_degs, out_degs);
        if (degree_rc != CBM_STORE_OK) {
            record_store_query_failure(
                srv, project, cbm_store_db_path(store), store, CBM_STORE_VERIFY_IO_FAILED,
                "source.query_search_result_degrees", cbm_store_error(store));
            free(ids);
            free(in_degs);
            free(out_degs);
            if (has_path_filter) {
                cbm_regfree(&path_regex);
            }
            free(raw);
            free_search_results(sr, sr_count);
            free_grep_matches(gm, gm_count);
            free(root_path);
            free(pattern);
            free(file_pattern);
            char *error = build_recorded_store_error(srv);
            free(project);
            char *result = cbm_mcp_text_result(error, true);
            free(error);
            return result;
        }
        for (int j = 0; j < sr_count; j++) {
            sr[j].in_degree = in_degs[j];
            sr[j].out_degree = out_degs[j];
        }
        free(ids);
        free(in_degs);
        free(out_degs);
    }

    /* Compute scores and sort */
    for (int j = 0; j < sr_count; j++) {
        sr[j].score = compute_search_score(&sr[j]);
    }
    if (sr_count > SKIP_ONE) {
        qsort(sr, sr_count, sizeof(search_result_t), search_result_cmp);
    }

    /* ── Phase 4: Context assembly (extracted helper) ─────────── */

    char *result =
        assemble_search_output(sr, sr_count, raw, raw_count, gm_count, limit, mode, context_lines,
                               root_path, pat_has_pipe && !use_regex, cbm_now_ms() - search_t0);
    free_grep_matches(gm, gm_count);
    free_search_results(sr, sr_count);
    free(raw);
    free(root_path);
    free(pattern);
    free(project);
    free(file_pattern);
    if (has_path_filter) {
        cbm_regfree(&path_regex);
    }
    return result;
}

/* ── detect_changes ───────────────────────────────────────────── */

/* Find symbols defined in a file and add them to the impacted array. */
static void detect_add_impacted_symbols(cbm_store_t *store, const char *project, const char *file,
                                        yyjson_mut_doc *doc, yyjson_mut_val *impacted) {
    cbm_node_t *nodes = NULL;
    int ncount = 0;
    cbm_store_find_nodes_by_file(store, project, file, &nodes, &ncount);
    for (int i = 0; i < ncount; i++) {
        if (nodes[i].label && strcmp(nodes[i].label, "File") != 0 &&
            strcmp(nodes[i].label, "Folder") != 0 && strcmp(nodes[i].label, "Project") != 0) {
            yyjson_mut_val *item = yyjson_mut_obj(doc);
            yyjson_mut_obj_add_strcpy(doc, item, "name", nodes[i].name ? nodes[i].name : "");
            yyjson_mut_obj_add_strcpy(doc, item, "label", nodes[i].label);
            yyjson_mut_obj_add_strcpy(doc, item, "file", file);
            yyjson_mut_arr_add_val(impacted, item);
        }
    }
    cbm_store_free_nodes(nodes, ncount);
}

static char *handle_detect_changes(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    char *base_branch = cbm_mcp_get_string_arg(args, "base_branch");
    char *since = cbm_mcp_get_string_arg(args, "since");
    char *scope = cbm_mcp_get_string_arg(args, "scope");
    int depth = cbm_mcp_get_int_arg(args, "depth", MCP_DEFAULT_BFS_DEPTH);
    depth = clamp_mcp_depth(depth, "detect_changes");

    /* scope: "files" = just changed files, "symbols" = files + symbols (default) */
    bool want_symbols = !scope || strcmp(scope, "symbols") == 0 || strcmp(scope, "impact") == 0;

    /* `since` (e.g. "HEAD~10", "v0.5.0") is the documented diff base but was
     * previously parsed and never used: it takes precedence over base_branch.
     * Route it through base_branch so the shared shell-arg validation and the
     * existing `<base>...HEAD` (three-dot) diff apply unchanged — `since` thus
     * adopts the same merge-base semantics base_branch already uses. */
    if (since && since[0]) {
        free(base_branch);
        base_branch = since; /* transfer ownership */
        since = NULL;
    }
    free(since); /* no-op after the swap (since is NULL); frees it otherwise */

    if (!base_branch) {
        base_branch = heap_strdup("main");
    }

    /* Reject shell metacharacters, and a leading '-', in the user-supplied
     * branch name. base_branch is spliced into `git diff --name-only
     * "<base>"...HEAD`; a value starting with '-' would be read by git as an
     * option rather than a ref (e.g. `--output=<path>` writes the diff to an
     * arbitrary file). A real git ref never begins with '-'. */
    if (!cbm_validate_shell_arg(base_branch) || base_branch[0] == '-') {
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("base_branch contains invalid characters", true);
    }

    char *root_path = get_project_root(srv, project);
    if (!root_path) {
        char *err = build_no_store_error(srv, project);
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        free(project);
        free(base_branch);
        free(scope);
        return res;
    }

    if (!validate_search_path_arg(root_path)) {
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result("project path contains invalid characters", true);
    }

    /* Get changed files via git (-C avoids cd + quoting issues on Windows).
     * Three sources are merged:
     *   1. committed changes vs base   (diff <base>...HEAD)
     *   2. unstaged tracked changes    (diff)
     *   3. untracked + staged-new files (status --porcelain) — these are
     *      invisible to `git diff` and were silently missed before, so a
     *      brand-new file never appeared until a manual re-index (#520).
     * status --porcelain prefixes each path with a 2-char code + space
     * ("?? path", "A  path"); the prefix is stripped when parsing below. */
    char cmd[CBM_SZ_2K];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd),
             "git -C \"%s\" diff --name-only \"%s\"...HEAD 2>NUL & "
             "git -C \"%s\" diff --name-only 2>NUL & "
             "git --no-optional-locks -C \"%s\" status --porcelain "
             "--untracked-files=normal 2>NUL",
             root_path, base_branch, root_path, root_path);
#else
    snprintf(cmd, sizeof(cmd),
             "{ git -C '%s' diff --name-only '%s'...HEAD 2>/dev/null; "
             "git -C '%s' diff --name-only 2>/dev/null; "
             "git --no-optional-locks -C '%s' status --porcelain "
             "--untracked-files=normal 2>/dev/null; } | sort -u",
             root_path, base_branch, root_path, root_path);
#endif

    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        char errmsg[CBM_SZ_256];
        snprintf(errmsg, sizeof(errmsg),
                 "git diff failed: cannot execute command (%s). Check that git is installed.",
                 strerror(errno));
        free(root_path);
        free(project);
        free(base_branch);
        free(scope);
        return cbm_mcp_text_result(errmsg, true);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    yyjson_mut_val *changed = yyjson_mut_arr(doc);
    yyjson_mut_val *impacted = yyjson_mut_arr(doc);

    /* resolve_store already called via get_project_root above */
    cbm_store_t *store = srv->store;

    char line[CBM_SZ_1K];
    int file_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }

        /* `git status --porcelain` prefixes each path with a two-character
         * status code and a space ("?? path", "A  path", " M path"). The two
         * `git diff --name-only` sources emit bare paths. Strip the porcelain
         * prefix when present so all three sources yield clean paths; for a
         * rename ("R  old -> new") keep the post-arrow destination path. */
        char *path_line = line;
        if (len > PAIR_LEN && line[PAIR_LEN] == ' ' && strchr(" MADRCU?!", line[0]) &&
            strchr(" MADRCU?!", line[1])) {
            path_line = line + PAIR_LEN + SKIP_ONE;
            char *arrow = strstr(path_line, " -> ");
            if (arrow) {
                enum { ARROW_LEN = 4 }; /* length of " -> " */
                path_line = arrow + ARROW_LEN;
            }
        }
        if (path_line[0] == '\0') {
            continue;
        }

        yyjson_mut_arr_add_strcpy(doc, changed, path_line);
        file_count++;

        if (want_symbols) {
            detect_add_impacted_symbols(store, project, path_line, doc, impacted);
        }
    }
    int git_status = cbm_pclose(fp);

    bool is_error = false;
    if (git_status != 0 && file_count == 0) {
        char hint_buf[CBM_SZ_256];
        snprintf(hint_buf, sizeof(hint_buf),
                 "git diff exited with status %d. Check that branch '%s' exists.", git_status,
                 base_branch);
        yyjson_mut_obj_add_strcpy(doc, root_obj, "hint", hint_buf);
        is_error = true;
    }

    yyjson_mut_obj_add_val(doc, root_obj, "changed_files", changed);
    yyjson_mut_obj_add_int(doc, root_obj, "changed_count", file_count);
    yyjson_mut_obj_add_val(doc, root_obj, "impacted_symbols", impacted);
    yyjson_mut_obj_add_int(doc, root_obj, "depth", depth);

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    free(root_path);
    free(project);
    free(base_branch);
    free(scope);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* ── manage_adr ───────────────────────────────────────────────── */

/* ADR "sections" mode: list markdown headers ('#'-prefixed lines) from the
 * ADR content string. */
static void adr_list_sections_from_content(yyjson_mut_doc *doc, yyjson_mut_val *root_obj,
                                           const char *content) {
    yyjson_mut_val *sections = yyjson_mut_arr(doc);
    const char *p = content;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        while (linelen > 0 && p[linelen - SKIP_ONE] == '\r') {
            linelen--;
        }
        if (linelen > 0 && p[0] == '#') {
            char hdr[CBM_SZ_1K];
            if (linelen >= sizeof(hdr)) {
                linelen = sizeof(hdr) - SKIP_ONE;
            }
            memcpy(hdr, p, linelen);
            hdr[linelen] = '\0';
            yyjson_mut_arr_add_strcpy(doc, sections, hdr);
        }
        if (!eol) {
            break;
        }
        p = eol + SKIP_ONE;
    }
    yyjson_mut_obj_add_val(doc, root_obj, "sections", sections);
}

/* Read the legacy file-based ADR (<root>/.codebase-memory/adr.md), used by
 * older versions. Returns a heap buffer (caller frees) or NULL if missing/
 * empty. Kept only to migrate old ADRs into the store (#256). */
static char *adr_read_legacy_file(const char *root_path) {
    if (!root_path) {
        return NULL;
    }
    char adr_path[CBM_SZ_4K];
    snprintf(adr_path, sizeof(adr_path), "%s/.codebase-memory/adr.md", root_path);
    FILE *fp = cbm_fopen(adr_path, "r");
    if (!fp) {
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) {
        (void)fclose(fp);
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + SKIP_ONE);
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    size_t n = fread(buf, SKIP_ONE, (size_t)sz, fp);
    buf[n] = '\0';
    (void)fclose(fp);
    if (buf[0] == '\0') {
        free(buf);
        return NULL;
    }
    return buf;
}

#define ADR_EMPTY_HINT                                                             \
    "No ADR yet. Create one with manage_adr(mode='update', "                       \
    "content='## PURPOSE\\n...\\n\\n## STACK\\n...\\n\\n## ARCHITECTURE\\n..."     \
    "\\n\\n## PATTERNS\\n...\\n\\n## TRADEOFFS\\n...\\n\\n## PHILOSOPHY\\n...'). " \
    "For guided creation: explore the codebase with get_architecture, "            \
    "then draft and store. Sections: PURPOSE, STACK, ARCHITECTURE, "               \
    "PATTERNS, TRADEOFFS, PHILOSOPHY."

/* #1793: ADR writes must never fail opaquely. Every write/open failure carries
 * the physical DB path, the DB/WAL/SHM presence, the SQLite error code and
 * message, the failing stage, and a concrete remediation hint — so an
 * intermittent Windows write fault is diagnosable from the response alone. */
static void adr_add_family_presence(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                    const char *db_path) {
    if (!db_path) {
        return;
    }
    char wal_path[CBM_SZ_4K];
    char shm_path[CBM_SZ_4K];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", db_path);
    yyjson_mut_obj_add_strcpy(doc, root, "wal_path", wal_path);
    yyjson_mut_obj_add_strcpy(doc, root, "shm_path", shm_path);
    yyjson_mut_obj_add_bool(doc, root, "wal_present", cbm_path_exists(wal_path));
    yyjson_mut_obj_add_bool(doc, root, "shm_present", cbm_path_exists(shm_path));
}

/* Populate the manage_adr result object with a structured write-error diagnostic
 * (the store's error buffer/code were set by cbm_store_adr_store after its
 * bounded transient retries were exhausted). */
static void adr_fill_write_error(yyjson_mut_doc *doc, yyjson_mut_val *root, cbm_store_t *store,
                                 const char *project) {
    const char *db_path = cbm_store_db_path(store);
    int sqlite_err = cbm_store_error_code(store);
    const char *detail = cbm_store_error(store);

    yyjson_mut_obj_add_str(doc, root, "status", "write_error");
    yyjson_mut_obj_add_str(doc, root, "code", "CBM_STORE_ADR_WRITE_FAILED");
    yyjson_mut_obj_add_str(
        doc, root, "message",
        "the ADR upsert into project_summaries failed after bounded transient-fault retries");
    yyjson_mut_obj_add_str(doc, root, "stage", "sqlite.step.write");
    yyjson_mut_obj_add_strcpy(doc, root, "project", project ? project : "");
    yyjson_mut_obj_add_strcpy(doc, root, "db_path",
                              db_path ? db_path : "(embedded/in-memory store)");
    yyjson_mut_obj_add_int(doc, root, "sqlite_error", sqlite_err);
    yyjson_mut_obj_add_strcpy(doc, root, "sqlite_detail", detail ? detail : "");
    if (db_path) {
        yyjson_mut_obj_add_bool(doc, root, "db_present", cbm_path_exists(db_path));
        adr_add_family_presence(doc, root, db_path);
    }
    yyjson_mut_obj_add_str(
        doc, root, "remediation",
        "another MCP session or the UI may hold a write lock on this project DB, or a Windows "
        "AV/Search-indexer scan briefly locked the DB/WAL/SHM family. Ensure a single writer, "
        "exclude the codebase-memory cache directory from real-time AV/indexing, then retry; if "
        "the SQLite error persists, preserve the DB/WAL/SHM family together and inspect them.");
}

static char *handle_manage_adr(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);
    char *mode_str = cbm_mcp_get_string_arg(args, "mode");
    char *content = cbm_mcp_get_string_arg(args, "content");

    if (!mode_str) {
        mode_str = heap_strdup("get");
    }

    /* ADRs are stored in the SQLite store (project_summaries), the SAME
     * backend the UI /api/adr endpoints use — so writes via the MCP tool and
     * the UI are visible to each other (#256). */
    bool owns_mutation_store = false;
    cbm_store_t *store = resolve_mutation_store(srv, project, &owns_mutation_store);
    if (!store) {
        char *err = build_no_store_error(srv, project);
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        free(project);
        free(mode_str);
        free(content);
        return res;
    }

    /* One-time migration: older versions wrote ADRs to a file at
     * <root>/.codebase-memory/adr.md. If the store has no ADR yet but that
     * legacy file exists, import it so nothing is lost on upgrade. */
    cbm_adr_t adr;
    memset(&adr, 0, sizeof(adr));
    bool have_adr = (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK);
    if (!have_adr) {
        cbm_project_t persisted_project = {0};
        char *root_path = NULL;
        if (cbm_store_get_project(store, project, &persisted_project) == CBM_STORE_OK) {
            root_path = heap_strdup(persisted_project.root_path);
        }
        safe_str_free(&persisted_project.name);
        safe_str_free(&persisted_project.indexed_at);
        safe_str_free(&persisted_project.root_path);
        char *legacy = adr_read_legacy_file(root_path);
        free(root_path);
        if (legacy) {
            if (cbm_store_adr_store(store, project, legacy) == CBM_STORE_OK) {
                have_adr = (cbm_store_adr_get(store, project, &adr) == CBM_STORE_OK);
            }
            free(legacy);
        }
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root_obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root_obj);

    bool is_error = false;
    if ((strcmp(mode_str, "update") == 0 || strcmp(mode_str, "store") == 0) && content) {
        if (cbm_store_adr_store(store, project, content) == CBM_STORE_OK) {
            yyjson_mut_obj_add_str(doc, root_obj, "status", "updated");
        } else {
            adr_fill_write_error(doc, root_obj, store, project);
            is_error = true;
        }
    } else if (strcmp(mode_str, "sections") == 0) {
        adr_list_sections_from_content(doc, root_obj, have_adr ? adr.content : NULL);
    } else { /* get */
        if (have_adr && adr.content) {
            yyjson_mut_obj_add_strcpy(doc, root_obj, "content", adr.content);
        } else {
            yyjson_mut_obj_add_str(doc, root_obj, "content", "");
            yyjson_mut_obj_add_str(doc, root_obj, "status", "no_adr");
            yyjson_mut_obj_add_str(doc, root_obj, "adr_hint", ADR_EMPTY_HINT);
        }
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    if (have_adr) {
        cbm_store_adr_free(&adr);
    }
    if (owns_mutation_store) {
        cbm_store_close(store);
    }
    free(project);
    free(mode_str);
    free(content);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* ── ingest_traces ────────────────────────────────────────────── */

/* True when a `traces` array element is a simple {caller, callee, count}
 * record (as opposed to an OTLP ResourceSpans object). */
static bool traces_arr_is_simple(yyjson_val *traces) {
    if (!traces || !yyjson_is_arr(traces) || yyjson_arr_size(traces) == 0) {
        return false;
    }
    yyjson_val *first = yyjson_arr_get_first(traces);
    return first && yyjson_is_obj(first) && yyjson_obj_get(first, "caller") != NULL &&
           yyjson_obj_get(first, "callee") != NULL;
}

/* Collect {caller, callee, count} records from a JSON array. Caller frees. */
static cbm_trace_simple_t *collect_simple(yyjson_val *traces, int *out_n) {
    int n = (int)yyjson_arr_size(traces);
    *out_n = 0;
    if (n <= 0) {
        return NULL;
    }
    cbm_trace_simple_t *recs = calloc((size_t)n, sizeof(*recs));
    if (!recs) {
        return NULL;
    }
    int m = 0;
    size_t idx = 0;
    size_t max = 0;
    yyjson_val *el = NULL;
    yyjson_arr_foreach(traces, idx, max, el) {
        yyjson_val *caller = yyjson_obj_get(el, "caller");
        yyjson_val *callee = yyjson_obj_get(el, "callee");
        if (!caller || !callee || !yyjson_is_str(caller) || !yyjson_is_str(callee)) {
            continue;
        }
        snprintf(recs[m].caller, sizeof(recs[m].caller), "%s", yyjson_get_str(caller));
        snprintf(recs[m].callee, sizeof(recs[m].callee), "%s", yyjson_get_str(callee));
        yyjson_val *count = yyjson_obj_get(el, "count");
        recs[m].count = (count && yyjson_is_int(count)) ? yyjson_get_int(count) : 1;
        m++;
    }
    *out_n = m;
    return recs;
}

static char *handle_ingest_traces(cbm_mcp_server_t *srv, const char *args) {
    char *project = get_project_arg(args);

    bool owns_mutation_store = false;
    cbm_store_t *store = resolve_mutation_store(srv, project, &owns_mutation_store);
    if (!store) {
        char *err = build_no_store_error(srv, project);
        char *res = cbm_mcp_text_result(err, true);
        free(err);
        free(project);
        return res;
    }
    const char *eff_project = project;

    cbm_otlp_batch_t batch = {0};
    cbm_trace_ingest_stats_t stats = {0};
    const char *format = "empty";
    /* Control flow must not depend on strcmp(format, ...): GCC 14 -Wstring-compare
     * proves literal-vs-literal branches constant under -O2 jump threading and
     * -Werror rejects them. `format` is response-payload only. */
    bool is_otlp = false;
    bool is_error = false;
    char *err_detail = NULL;

    yyjson_doc *adoc = yyjson_read(args, strlen(args), 0);
    yyjson_val *aroot = adoc ? yyjson_doc_get_root(adoc) : NULL;

    char *b64 = cbm_mcp_get_string_arg(args, "otlp_protobuf_base64");
    yyjson_val *rspans = aroot ? yyjson_obj_get(aroot, "resourceSpans") : NULL;
    if (!rspans && aroot) {
        rspans = yyjson_obj_get(aroot, "resource_spans");
    }
    yyjson_val *traces = aroot ? yyjson_obj_get(aroot, "traces") : NULL;

    if (b64 && b64[0]) {
        format = "otlp_protobuf";
        is_otlp = true;
        int rc = cbm_otlp_decode_protobuf_base64(b64, &batch);
        if (rc != CBM_OTLP_OK) {
            is_error = true;
            err_detail = heap_strdup("invalid OTLP protobuf (base64 or wire format)");
        }
    } else if (rspans && yyjson_is_arr(rspans)) {
        format = "otlp_json";
        is_otlp = true;
        if (cbm_otlp_decode_json_rspans(rspans, &batch) != CBM_OTLP_OK) {
            is_error = true;
            err_detail = heap_strdup("invalid OTLP/JSON resourceSpans");
        }
    } else if (traces && traces_arr_is_simple(traces)) {
        format = "simple";
        int sn = 0;
        cbm_trace_simple_t *recs = collect_simple(traces, &sn);
        if (recs) {
            cbm_trace_ingest_simple(store, eff_project, recs, sn, &stats);
            free(recs);
        }
    } else if (traces && yyjson_is_arr(traces)) {
        /* Legacy signature: OTLP ResourceSpans carried in the `traces` array. */
        format = "otlp_json";
        is_otlp = true;
        if (cbm_otlp_decode_json_rspans(traces, &batch) != CBM_OTLP_OK) {
            is_error = true;
            err_detail = heap_strdup("invalid OTLP/JSON spans in traces[]");
        }
    }

    /* Ingest OTLP records (protobuf/JSON paths). */
    if (!is_error && is_otlp && batch.record_count >= 0) {
        stats.spans_total = batch.spans_total;
        stats.spans_non_http = batch.spans_non_http;
        cbm_trace_ingest_records(store, eff_project, batch.records, batch.record_count, &stats);
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    /* Preserve the pre-#27 contract's input accounting: report how many trace
     * items the request carried in `traces[]` (0 for OTLP-only requests, whose
     * span counts are surfaced separately below). Emitted on both the ok and
     * error responses so callers can always reconcile received vs. accounted. */
    int traces_received = (traces && yyjson_is_arr(traces)) ? (int)yyjson_arr_size(traces) : 0;
    yyjson_mut_obj_add_int(doc, root, "traces_received", traces_received);

    if (is_error) {
        yyjson_mut_obj_add_str(doc, root, "status", "error");
        yyjson_mut_obj_add_strcpy(doc, root, "code", "otlp_decode_failed");
        yyjson_mut_obj_add_strcpy(doc, root, "message",
                                  err_detail ? err_detail : "trace decode failed");
        yyjson_mut_obj_add_str(doc, root, "remediation",
                               "Send a valid OTLP TracesData batch (protobuf base64 in "
                               "'otlp_protobuf_base64', OTLP/JSON in 'resourceSpans', or "
                               "simple {caller,callee,count} objects in 'traces').");
    } else {
        yyjson_mut_obj_add_str(doc, root, "status", "ok");
        yyjson_mut_obj_add_strcpy(doc, root, "format", format);
        yyjson_mut_obj_add_int(doc, root, "spans_total", stats.spans_total);
        yyjson_mut_obj_add_int(doc, root, "spans_http", stats.spans_http);
        yyjson_mut_obj_add_int(doc, root, "spans_non_http", stats.spans_non_http);
        yyjson_mut_obj_add_int(doc, root, "spans_unmatched", stats.spans_unmatched);
        yyjson_mut_obj_add_int(doc, root, "routes_matched", stats.routes_matched);
        yyjson_mut_obj_add_int(doc, root, "edges_promoted", stats.edges_promoted);
        yyjson_mut_obj_add_int(doc, root, "anchors_written", stats.anchors_written);
        yyjson_mut_obj_add_int(doc, root, "incidents_detected", stats.incidents_detected);
        yyjson_mut_obj_add_int(doc, root, "incidents_resolved", stats.incidents_resolved);
        yyjson_mut_obj_add_int(doc, root, "simple_records", stats.simple_records);
        yyjson_mut_obj_add_int(doc, root, "simple_unmatched", stats.simple_unmatched);
        /* Label the degradation: unmatched observations are surfaced, not dropped. */
        if (stats.spans_unmatched > 0 || stats.simple_unmatched > 0) {
            yyjson_mut_obj_add_str(
                doc, root, "unmatched_note",
                "Some observations matched no indexed route/edge and were counted "
                "(spans_unmatched/simple_unmatched), not silently dropped.");
        }
    }

    char *json = yy_doc_to_str(doc);
    yyjson_mut_doc_free(doc);
    cbm_otlp_batch_free(&batch);
    if (adoc) {
        yyjson_doc_free(adoc);
    }
    free(err_detail);
    free(b64);
    if (owns_mutation_store) {
        cbm_store_close(store);
    }
    free(project);

    char *result = cbm_mcp_text_result(json, is_error);
    free(json);
    return result;
}

/* ── Tool dispatch ────────────────────────────────────────────── */

char *cbm_mcp_handle_tool(cbm_mcp_server_t *srv, const char *tool_name, const char *args_json) {
    if (!tool_name) {
        return cbm_mcp_text_result("missing tool name", true);
    }

    if (strcmp(tool_name, "list_projects") == 0) {
        return handle_list_projects(srv, args_json);
    }
    if (strcmp(tool_name, "get_graph_schema") == 0) {
        return handle_get_graph_schema(srv, args_json);
    }
    if (strcmp(tool_name, "search_graph") == 0) {
        return handle_search_graph(srv, args_json);
    }
    if (strcmp(tool_name, "query_graph") == 0) {
        return handle_query_graph(srv, args_json);
    }
    if (strcmp(tool_name, "index_status") == 0) {
        return handle_index_status(srv, args_json);
    }
    if (strcmp(tool_name, "delete_project") == 0) {
        return handle_delete_project(srv, args_json);
    }
    if (strcmp(tool_name, "trace_path") == 0 || strcmp(tool_name, "trace_call_path") == 0) {
        return handle_trace_call_path(srv, args_json);
    }
    if (strcmp(tool_name, "get_architecture") == 0) {
        return handle_get_architecture(srv, args_json);
    }

    /* Pipeline-dependent tools */
    if (strcmp(tool_name, "index_repository") == 0) {
        return handle_index_repository(srv, args_json);
    }
    if (strcmp(tool_name, "get_code_snippet") == 0) {
        return handle_get_code_snippet(srv, args_json);
    }
    if (strcmp(tool_name, "search_code") == 0) {
        return handle_search_code(srv, args_json);
    }
    if (strcmp(tool_name, "detect_changes") == 0) {
        return handle_detect_changes(srv, args_json);
    }
    if (strcmp(tool_name, "manage_adr") == 0) {
        return handle_manage_adr(srv, args_json);
    }
    if (strcmp(tool_name, "ingest_traces") == 0) {
        return handle_ingest_traces(srv, args_json);
    }
    char msg[CBM_SZ_256];
    snprintf(msg, sizeof(msg), "unknown tool: %s", tool_name);
    return cbm_mcp_text_result(msg, true);
}

/* ── Session detection + auto-index ────────────────────────────── */

/* Detect session root from CWD (fallback: single indexed project from DB). */
static void detect_session(cbm_mcp_server_t *srv) {
    if (srv->session_detected) {
        return;
    }
    srv->session_detected = true;

    /* 1. Try CWD */
    char cwd[CBM_SZ_1K];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        const char *home = cbm_get_home_dir();
        /* Skip useless roots: / and $HOME */
        if (strcmp(cwd, "/") != 0 && (home == NULL || strcmp(cwd, home) != 0)) {
            snprintf(srv->session_root, sizeof(srv->session_root), "%s", cwd);
            cbm_log_info("session.root.cwd", "path", cwd);
        }
    }

    /* Derive project name from path — must match cbm_project_name_from_path
     * used by the pipeline, otherwise session queries look for a .db file
     * that doesn't match the indexed project name. */
    if (srv->session_root[0]) {
        char *pname = cbm_project_name_from_path(srv->session_root);
        if (pname) {
            snprintf(srv->session_project, sizeof(srv->session_project), "%s", pname);
            free(pname);
        }
    }
}

/* auto_watch config: gates background watcher registration (default on).
 * Multi-project users can contain a session to its own project with
 * `config set auto_watch false`. */
static bool auto_watch_enabled(cbm_mcp_server_t *srv) {
    if (!srv->config) {
        return true; /* default on */
    }
    return cbm_config_get_bool(srv->config, CBM_CONFIG_AUTO_WATCH, true);
}

/* Register the session project with the background watcher for ongoing
 * change detection — unless auto_watch is disabled. */
static void register_watcher_if_enabled(cbm_mcp_server_t *srv) {
    if (!srv->watcher || srv->session_project[0] == '\0' || srv->session_root[0] == '\0') {
        return;
    }
    if (!auto_watch_enabled(srv)) {
        cbm_log_info("watcher.register.skipped", "reason", "auto_watch_off", "project",
                     srv->session_project);
        return;
    }
    cbm_watcher_watch(srv->watcher, srv->session_project, srv->session_root);
}

/* Background auto-index thread function */
static void *autoindex_thread(void *arg) {
    cbm_mcp_server_t *srv = (cbm_mcp_server_t *)arg;

    cbm_log_info("autoindex.start", "project", srv->session_project, "path", srv->session_root);

    /* #832: use the supervised worker subprocess. Indexing the whole session in
     * this long-lived server thread ratchets RSS (mimalloc v3 does not reclaim the
     * pages worker threads abandon at exit); running it in a child that exits hands
     * 100% of that memory back to the OS every cycle. A supervisor failure is
     * terminal and never authorizes an in-process retry. */
    if (cbm_index_supervisor_should_wrap()) {
        char *resp = index_run_supervised_path(srv, srv->session_root);
        if (resp) {
            yyjson_doc *response_doc = yyjson_read(resp, strlen(resp), 0);
            yyjson_val *response_root = response_doc ? yyjson_doc_get_root(response_doc) : NULL;
            yyjson_val *is_error = response_root ? yyjson_obj_get(response_root, "isError") : NULL;
            bool succeeded = is_error && yyjson_is_bool(is_error) && !yyjson_get_bool(is_error);
            if (response_doc) {
                yyjson_doc_free(response_doc);
            }
            free(resp);
            if (!succeeded) {
                cbm_log_error("autoindex.err", "code", "CBM_AUTOINDEX_SUPERVISED_FAILED", "project",
                              srv->session_project, "message",
                              "the isolated auto-index did not return a successful MCP result",
                              "remediation",
                              "inspect the supervised worker diagnostics before retrying");
                return NULL;
            }
            cbm_log_info("autoindex.done", "project", srv->session_project, "mode", "supervised");
            /* Register with watcher for ongoing change detection — gated on
             * auto_watch (#849), same as the in-process branch below. A bare
             * `if (srv->watcher)` would register even when the user set
             * `config set auto_watch false`, since srv->watcher is always set. */
            register_watcher_if_enabled(srv);
            return NULL;
        }
        cbm_log_error("autoindex.err", "code", "CBM_AUTOINDEX_SUPERVISOR_NO_RESPONSE", "project",
                      srv->session_project, "message",
                      "the isolated auto-index supervisor produced no response", "remediation",
                      "inspect the supervisor argument/process diagnostics before retrying");
        return NULL;
    }

    cbm_pipeline_t *p = cbm_pipeline_new(srv->session_root, NULL, CBM_MODE_FULL);
    if (!p) {
        cbm_log_warn("autoindex.err", "msg", "pipeline_create_failed");
        return NULL;
    }

    /* Block until any concurrent pipeline finishes */
    cbm_pipeline_lock();
    int rc = cbm_pipeline_run(p);
    cbm_pipeline_unlock();

    cbm_pipeline_free(p);
    cbm_mem_collect(); /* return mimalloc pages to OS after indexing (in-process only) */

    if (rc == 0) {
        cbm_log_info("autoindex.done", "project", srv->session_project);
        register_watcher_if_enabled(srv);
    } else {
        cbm_log_warn("autoindex.err", "msg", "pipeline_run_failed");
    }
    return NULL;
}

/* Start auto-indexing if configured and project not yet indexed. */
static void maybe_auto_index(cbm_mcp_server_t *srv) {
    if (srv->session_root[0] == '\0') {
        return; /* no session root detected */
    }

    /* Check if project already has a DB */
    const char *home = cbm_get_home_dir();
#ifdef ASTRO_ENV_STORE
    /* #241: a resolvable home no longer implies a resolvable store, and "%s" on a
     * NULL cache directory is undefined behaviour. Resolve first, then check. */
    const char *session_cache = cbm_resolve_cache_dir();
    if (home && session_cache) {
#else
    if (home) {
#endif
        char db_check[CBM_SZ_1K];
#ifdef ASTRO_ENV_STORE
        snprintf(db_check, sizeof(db_check), "%s/%s.db", session_cache, srv->session_project);
#else
        snprintf(db_check, sizeof(db_check), "%s/%s.db", cbm_resolve_cache_dir(),
                 srv->session_project);
#endif
        if (cbm_file_size(db_check) >= 0) {
            /* Already indexed → register watcher for change detection */
            cbm_log_info("autoindex.skip", "reason", "already_indexed", "project",
                         srv->session_project);
            register_watcher_if_enabled(srv);
            return;
        }
    }

/* Default file limit for auto-indexing new projects */
#define DEFAULT_AUTO_INDEX_LIMIT 50000

    /* Check auto_index config */
    bool auto_index = false;
    int file_limit = DEFAULT_AUTO_INDEX_LIMIT;
    if (srv->config) {
        auto_index = cbm_config_get_bool(srv->config, CBM_CONFIG_AUTO_INDEX, false);
        file_limit =
            cbm_config_get_int(srv->config, CBM_CONFIG_AUTO_INDEX_LIMIT, DEFAULT_AUTO_INDEX_LIMIT);
    }

    if (!auto_index) {
        cbm_log_info("autoindex.skip", "reason", "disabled", "hint",
                     "run: codebase-memory-mcp config set auto_index true");
        return;
    }

    /* Quick file count check to avoid OOM on massive repos */
    if (!cbm_validate_shell_arg(srv->session_root)) {
        cbm_log_warn("autoindex.skip", "reason", "path contains shell metacharacters");
        return;
    }
    char cmd[CBM_SZ_1K];
    snprintf(cmd, sizeof(cmd), "git -C '%s' ls-files 2>/dev/null | wc -l", srv->session_root);
    FILE *fp = cbm_popen(cmd, "r");
    if (fp) {
        char line[CBM_SZ_64];
        if (fgets(line, sizeof(line), fp)) {
            int count = (int)strtol(line, NULL, CBM_DECIMAL_BASE);
            if (count > file_limit) {
                cbm_log_warn("autoindex.skip", "reason", "too_many_files", "files", line, "limit",
                             CBM_CONFIG_AUTO_INDEX_LIMIT);
                cbm_pclose(fp);
                return;
            }
        }
        cbm_pclose(fp);
    }

    /* Launch auto-index in background */
    if (cbm_thread_create(&srv->autoindex_tid, 0, autoindex_thread, srv) == 0) {
        srv->autoindex_active = true;
    }
}

/* ── Background update check ──────────────────────────────────── */

#define UPDATE_CHECK_URL "https://api.github.com/repos/DeusData/codebase-memory-mcp/releases/latest"

static void *update_check_thread(void *arg) {
    cbm_mcp_server_t *srv = (cbm_mcp_server_t *)arg;

    /* Use curl with 5s timeout to fetch latest release tag */
    FILE *fp = cbm_popen("curl -sf --max-time 5 -H 'Accept: application/vnd.github+json' "
                         "'" UPDATE_CHECK_URL "' 2>/dev/null",
                         "r");
    if (!fp) {
        srv->update_checked = true;
        return NULL;
    }

    char buf[CBM_SZ_4K];
    size_t total = 0;
    while (total < sizeof(buf) - SKIP_ONE) {
        size_t n = fread(buf + total, SKIP_ONE, sizeof(buf) - SKIP_ONE - total, fp);
        if (n == 0) {
            break;
        }
        total += n;
    }
    buf[total] = '\0';
    cbm_pclose(fp);

    /* Parse tag_name from JSON response */
    yyjson_doc *doc = yyjson_read(buf, total, 0);
    if (!doc) {
        srv->update_checked = true;
        return NULL;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *tag = yyjson_obj_get(root, "tag_name");
    const char *tag_str = yyjson_get_str(tag);

    if (tag_str) {
        const char *current = cbm_cli_get_version();
        if (cbm_compare_versions(tag_str, current) > 0) {
            snprintf(srv->update_notice, sizeof(srv->update_notice),
                     "Update available: %s -> %s -- run: codebase-memory-mcp update  |  "
                     "Enjoying codebase-memory-mcp? Please leave a star: "
                     "https://github.com/DeusData/codebase-memory-mcp",
                     current, tag_str);
            cbm_log_info("update.available", "current", current, "latest", tag_str);
        }
    }

    yyjson_doc_free(doc);
    srv->update_checked = true;
    return NULL;
}

static void start_update_check(cbm_mcp_server_t *srv) {
    if (srv->update_checked) {
        return;
    }
    srv->update_checked = true; /* prevent double-launch */
    if (cbm_thread_create(&srv->update_tid, 0, update_check_thread, srv) == 0) {
        srv->update_thread_active = true;
    }
}

/* Prepend update notice to a tool result, then clear it (one-shot). */
static char *inject_update_notice(cbm_mcp_server_t *srv, char *result_json) {
    if (srv->update_notice[0] == '\0') {
        return result_json;
    }

    /* Parse existing result, prepend notice text, rebuild */
    yyjson_doc *doc = yyjson_read(result_json, strlen(result_json), 0);
    if (!doc) {
        return result_json;
    }

    yyjson_mut_doc *mdoc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_val_mut_copy(mdoc, yyjson_doc_get_root(doc));
    yyjson_doc_free(doc);
    if (!root) {
        yyjson_mut_doc_free(mdoc);
        return result_json;
    }
    yyjson_mut_doc_set_root(mdoc, root);

    /* Find the "content" array */
    yyjson_mut_val *content = yyjson_mut_obj_get(root, "content");
    if (content && yyjson_mut_is_arr(content)) {
        /* Prepend a text content item with the update notice */
        yyjson_mut_val *notice_item = yyjson_mut_obj(mdoc);
        yyjson_mut_obj_add_str(mdoc, notice_item, "type", "text");
        yyjson_mut_obj_add_str(mdoc, notice_item, "text", srv->update_notice);
        yyjson_mut_arr_prepend(content, notice_item);
    }

    size_t len;
    char *new_json = yyjson_mut_write(mdoc, YYJSON_WRITE_ALLOW_INVALID_UNICODE, &len);
    yyjson_mut_doc_free(mdoc);

    if (new_json) {
        free(result_json);
        srv->update_notice[0] = '\0'; /* clear — one-shot */
        return new_json;
    }
    return result_json;
}

/* ── Server request handler ───────────────────────────────────── */

char *cbm_mcp_server_handle(cbm_mcp_server_t *srv, const char *line) {
    cbm_jsonrpc_request_t req = {0};
    if (cbm_jsonrpc_parse(line, &req) < 0) {
        return cbm_jsonrpc_format_error(0, JSONRPC_PARSE_ERROR, "Parse error");
    }

    /* Notifications (no id) → handle cancellation, then no response */
    if (!req.has_id) {
        if (req.method && strcmp(req.method, "notifications/cancelled") == 0) {
            if (srv->active_pipeline &&
                cbm_mcp_cancel_request_matches(req.params_raw, srv->active_request_id,
                                               srv->active_request_id_str)) {
                cbm_pipeline_cancel(srv->active_pipeline);
                cbm_log_info("mcp.cancelled", "match", "true");
            }
        }
        cbm_jsonrpc_request_free(&req);
        return NULL;
    }

    struct timespec req_t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &req_t0);
    char *result_json = NULL;
    bool request_logged = false;

    if (strcmp(req.method, "initialize") == 0) {
        result_json = cbm_mcp_initialize_response(req.params_raw);
        start_update_check(srv);
        detect_session(srv);
        maybe_auto_index(srv);
    } else if (strcmp(req.method, "ping") == 0) {
        result_json = heap_strdup("{}");
    } else if (strcmp(req.method, "tools/list") == 0) {
        result_json = cbm_mcp_tools_list_page(req.params_raw);
    } else if (strcmp(req.method, "tools/call") == 0) {
        char *tool_name = req.params_raw ? cbm_mcp_get_tool_name(req.params_raw) : NULL;
        char *tool_args =
            req.params_raw ? cbm_mcp_get_arguments(req.params_raw) : heap_strdup("{}");
        srv->active_request_id = req.id;
        free(srv->active_request_id_str);
        srv->active_request_id_str = req.id_str ? heap_strdup(req.id_str) : NULL;

        struct timespec t0;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
        result_json = cbm_mcp_handle_tool(srv, tool_name, tool_args);
        srv->active_request_id = CBM_NOT_FOUND;
        free(srv->active_request_id_str);
        srv->active_request_id_str = NULL;
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - t0.tv_nsec) / MCP_MS_TO_US);
        bool is_err = (result_json != NULL) && (strstr(result_json, "\"isError\":true") != NULL);
        cbm_diag_record_query(dur_us, is_err);
        long long request_dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                                   ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, tool_name, is_err, request_dur_us);
        request_logged = true;

        result_json = inject_update_notice(srv, result_json);
        free(tool_name);
        free(tool_args);
    } else {
        /* Echo the original id (string or numeric, issue #253) on the error. */
        char err_obj[160];
        snprintf(err_obj, sizeof(err_obj), "{\"code\":%d,\"message\":\"Method not found\"}",
                 JSONRPC_METHOD_NOT_FOUND);
        cbm_jsonrpc_response_t err_resp = {
            .id = req.id,
            .id_str = req.id_str,
            .error_json = err_obj,
        };
        char *err = cbm_jsonrpc_format_response(&err_resp);
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, NULL, true, dur_us);
        cbm_jsonrpc_request_free(&req);
        return err;
    }

    if (!request_logged) {
        struct timespec t1;
        cbm_clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dur_us = ((long long)(t1.tv_sec - req_t0.tv_sec) * MCP_S_TO_US) +
                           ((long long)(t1.tv_nsec - req_t0.tv_nsec) / MCP_MS_TO_US);
        cbm_log_mcp_request(req.method, NULL, false, dur_us);
    }

    cbm_jsonrpc_response_t resp = {
        .id = req.id,
        .id_str = req.id_str,
        .result_json = result_json,
    };
    char *out = cbm_jsonrpc_format_response(&resp);
    free(result_json);
    cbm_jsonrpc_request_free(&req);
    return out;
}

/* Handle a Content-Length-framed message (LSP-style transport).
 * Reads headers, body, processes request, writes framed response. */
static void handle_content_length_frame(cbm_mcp_server_t *srv, FILE *in, FILE *out, char **line,
                                        size_t *cap, int content_len) {
    /* Skip blank line(s) between header and body */
    while (cbm_getline(line, cap, in) > 0) {
        size_t hlen = strlen(*line);
        while (hlen > 0 && ((*line)[hlen - SKIP_ONE] == '\n' || (*line)[hlen - SKIP_ONE] == '\r')) {
            (*line)[--hlen] = '\0';
        }
        if (hlen == 0) {
            break;
        }
    }

    char *body = malloc((size_t)content_len + SKIP_ONE);
    if (!body) {
        return;
    }
    size_t nread = fread(body, SKIP_ONE, (size_t)content_len, in);
    body[nread] = '\0';

    char *resp = cbm_mcp_server_handle(srv, body);
    free(body);

    if (resp) {
        size_t rlen = strlen(resp);
        (void)fprintf(out, "Content-Length: %zu\r\n\r\n%s", rlen, resp);
        (void)fflush(out);
        free(resp);
    }
}

#ifndef _WIN32
/* Unix 3-phase poll: non-blocking fd check, FILE* buffer peek, blocking poll.
 * Returns: 1 = data ready, 0 = timeout (evicted idle stores), -1 = error/EOF. */
static int poll_for_input_unix(cbm_mcp_server_t *srv, int fd, FILE *in) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int pr = poll(&pfd, SKIP_ONE, 0); /* Phase 1: non-blocking */

    if (pr < 0) {
        return CBM_NOT_FOUND;
    }
    if (pr > 0) {
        return SKIP_ONE;
    }

    /* Phase 2: peek FILE* buffer */
    int saved_flags = fcntl(fd, F_GETFL);
    if (saved_flags < 0) {
        /* fcntl failed — fall through to a short blocking poll (see the Phase-3
         * note below on why the interval is bounded, not the full idle timeout) */
        pr = poll(&pfd, SKIP_ONE, MCP_TIMEOUT_MS);
        if (pr < 0) {
            return CBM_NOT_FOUND;
        }
        if (pr == 0) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            return 0;
        }
        return SKIP_ONE;
    }

    (void)fcntl(fd, F_SETFL, saved_flags | O_NONBLOCK);
    int c = fgetc(in);
    (void)fcntl(fd, F_SETFL, saved_flags);

    if (c == EOF) {
        if (feof(in)) {
            return CBM_NOT_FOUND; /* true EOF */
        }
        clearerr(in);
        /* Phase 3: blocking poll, bounded to a SHORT interval (not the full idle
         * timeout). macOS poll()/select() do NOT report POLLIN/POLLHUP when a
         * FIFO's last writer closes — only read() returns 0 there (verified). A
         * 60s poll would therefore leave the server blocked up to a full idle
         * timeout after stdin EOF (a client that closes the pipe would appear to
         * hang). Waking every MCP_TIMEOUT_MS lets the Phase-2 read() above detect
         * the EOF within ~1s. Idle-store eviction (threshold STORE_IDLE_TIMEOUT_S)
         * is idempotent, so checking it on each short tick is harmless. */
        pr = poll(&pfd, SKIP_ONE, MCP_TIMEOUT_MS);
        if (pr < 0) {
            return CBM_NOT_FOUND;
        }
        if (pr == 0) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            return 0;
        }
        return SKIP_ONE;
    }

    (void)ungetc(c, in);
    return SKIP_ONE;
}
#endif

/* ── Event loop ───────────────────────────────────────────────── */

int cbm_mcp_server_run(cbm_mcp_server_t *srv, FILE *in, FILE *out) {
    char *line = NULL;
    size_t cap = 0;
    int fd = cbm_fileno(in);

    for (;;) {
        /* Poll with idle timeout so we can evict unused stores between requests.
         *
         * IMPORTANT: poll() operates on the raw fd, but getline() reads from a
         * buffered FILE*. When a client sends multiple messages in rapid
         * succession, the first getline() call may drain ALL kernel data into
         * libc's internal FILE* buffer. Subsequent poll() calls then see an
         * empty kernel fd and block for STORE_IDLE_TIMEOUT_S seconds even
         * though the next messages are already in the FILE* buffer.
         *
         * Fix (Unix): use a three-phase approach —
         *   Phase 1: non-blocking poll (timeout=0) to check the kernel fd.
         *   Phase 2: if Phase 1 returns 0, peek the FILE* buffer via fgetc/
         *            ungetc to detect data buffered by a prior getline() call.
         *            The fd is temporarily set O_NONBLOCK so fgetc() returns
         *            immediately (EAGAIN → EOF + ferror) instead of blocking
         *            when the FILE* buffer is empty, which would otherwise
         *            bypass the Phase 3 idle eviction timeout.
         *   Phase 3: only if both phases confirm no data, do blocking poll. */
#ifdef _WIN32
        /* Windows: WaitForSingleObject on stdin handle */
        HANDLE hStdin = (HANDLE)_get_osfhandle(fd);
        DWORD wr = WaitForSingleObject(hStdin, STORE_IDLE_TIMEOUT_S * MCP_TIMEOUT_MS);
        if (wr == WAIT_FAILED) {
            break;
        }
        if (wr == WAIT_TIMEOUT) {
            cbm_mcp_server_evict_idle(srv, STORE_IDLE_TIMEOUT_S);
            continue;
        }
#else
        int pr = poll_for_input_unix(srv, fd, in);
        if (pr < 0) {
            break;
        }
        if (pr == 0) {
            continue; /* timeout — idle stores evicted */
        }
#endif

        if (cbm_getline(&line, &cap, in) <= 0) {
            break;
        }

        /* Trim trailing newline/CR */
        size_t len = strlen(line);
        while (len > 0 && (line[len - SKIP_ONE] == '\n' || line[len - SKIP_ONE] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }

        /* Content-Length framing (LSP-style transport) */
        if (strncmp(line, "Content-Length:", SLEN("Content-Length:")) == 0) {
            int content_len = (int)strtol(line + MCP_CONTENT_PREFIX, NULL, CBM_DECIMAL_BASE);
            if (content_len > 0 && content_len <= MCP_DEFAULT_LIMIT * CBM_SZ_1K * CBM_SZ_1K) {
                handle_content_length_frame(srv, in, out, &line, &cap, content_len);
            }
            continue;
        }

        char *resp = cbm_mcp_server_handle(srv, line);
        if (resp) {
            (void)fprintf(out, "%s\n", resp);
            (void)fflush(out);
            free(resp);
        }
    }

    free(line);
    return 0;
}

/* ── cbm_parse_file_uri ──────────────────────────────────────── */

bool cbm_parse_file_uri(const char *uri, char *out_path, int out_size) {
    if (!uri || !out_path || out_size <= 0) {
        if (out_path && out_size > 0) {
            out_path[0] = '\0';
        }
        return false;
    }

    /* Must start with file:// */
    if (strncmp(uri, "file://", SLEN("file://")) != 0) {
        out_path[0] = '\0';
        return false;
    }

    const char *path = uri + MCP_URI_PREFIX;

    /* On Windows, file:///C:/path → /C:/path. Strip leading / before drive letter. */
    if (path[0] == '/' && path[SKIP_ONE] &&
        ((path[SKIP_ONE] >= 'A' && path[SKIP_ONE] <= 'Z') ||
         (path[SKIP_ONE] >= 'a' && path[SKIP_ONE] <= 'z')) &&
        path[PAIR_LEN] == ':') {
        path++; /* skip the leading / */
    }

    snprintf(out_path, out_size, "%s", path);
    return true;
}
