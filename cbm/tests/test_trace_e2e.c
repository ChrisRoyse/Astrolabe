/*
 * test_trace_e2e.c — End-to-end integration FSV for ingest_traces (issue #27).
 *
 * Closes the final #27 DoD item: "static fixture graph + trace batch =>
 * trace_path/search_graph responses now carry Trusted service edges".
 *
 * Unlike test_trace_ingest.c (which drives the ingest core against a store and
 * reads raw rows), this suite drives the FULL MCP JSON-RPC path end to end:
 *   1. seed a static route graph into a live MCP server's real store
 *      (caller --HTTP_CALLS--> Route, handler --HANDLES--> Route,
 *       caller --DATA_FLOWS--> handler) — real persisted rows, no mocks;
 *   2. PRE-INGEST negative: call search_graph + trace_path over JSON-RPC and
 *      prove the runtime service edge (RuntimeAnchor / OBSERVED_TRAFFIC) is
 *      ABSENT, and read the HTTP_CALLS edge row back to prove it is still
 *      Provisional (no validated / Trusted markers);
 *   3. ingest a committed OTLP/JSON golden trace batch through the real
 *      ingest_traces JSON-RPC tool;
 *   4. POST-INGEST positive: the SAME search_graph + trace_path JSON-RPC calls
 *      now surface the RuntimeAnchor node and the OBSERVED_TRAFFIC service edge
 *      the batch promoted, and the HTTP_CALLS edge row is now
 *      validated=true / Trusted / measured-weight.
 *
 * The promotion is proven by the tool responses (anchor + service edge appear
 * only after ingest) plus an independent raw-row readback of the promoted
 * edge — not assumed.
 */
#include "test_framework.h"

#include <mcp/mcp.h>
#include <store/store.h>
#include <string.h>

#include "fixtures/otlp/otlp_golden.h"

#define E2E_PROJECT "trace-e2e"
#define ROUTE_QN "__route__POST__/api/orders"
/* write_runtime_anchor() prefixes "__runtime__" onto the route QN. */
#define ANCHOR_QN "__runtime____route__POST__/api/orders"

/* The tool result is embedded in the JSON-RPC envelope as a JSON *string*, so
 * every '"' inside it is backslash-escaped. Match a fragment against either the
 * raw or the escaped form (mirrors the helper in test_mcp.c). */
static bool response_has_fragment(const char *response, const char *fragment) {
    if (!response || !fragment) {
        return false;
    }
    if (strstr(response, fragment)) {
        return true;
    }
    char escaped[256];
    size_t out = 0;
    for (size_t i = 0; fragment[i] && out + 2 < sizeof(escaped); i++) {
        if (fragment[i] == '"') {
            escaped[out++] = '\\';
        }
        escaped[out++] = fragment[i];
    }
    escaped[out] = '\0';
    return strstr(response, escaped) != NULL;
}

/* Seed a live MCP server's store with a static route graph: a caller
 * (HTTP_CALLS -> route), a handler (HANDLES -> route), and a caller->handler
 * DATA_FLOWS carrying the route QN. Mirrors the extraction output a real repo
 * with one POST /api/orders route + caller would produce. Fills the ids. */
static void seed_route_graph(cbm_store_t *s, int64_t *caller_id, int64_t *handler_id) {
    cbm_store_upsert_project(s, E2E_PROJECT, "/tmp/trace-e2e");

    cbm_node_t caller = {.project = E2E_PROJECT,
                         .label = "Function",
                         .name = "checkout",
                         .qualified_name = "web.checkout",
                         .file_path = "web/checkout.go"};
    int64_t cid = cbm_store_upsert_node(s, &caller);

    cbm_node_t handler = {.project = E2E_PROJECT,
                          .label = "Function",
                          .name = "CreateOrder",
                          .qualified_name = "api.CreateOrder",
                          .file_path = "api/orders.go"};
    int64_t hid = cbm_store_upsert_node(s, &handler);

    cbm_node_t route = {.project = E2E_PROJECT,
                        .label = "Route",
                        .name = "/api/orders",
                        .qualified_name = ROUTE_QN,
                        .properties_json = "{\"method\":\"POST\"}"};
    int64_t rid = cbm_store_upsert_node(s, &route);

    cbm_edge_t http = {.project = E2E_PROJECT,
                       .source_id = cid,
                       .target_id = rid,
                       .type = "HTTP_CALLS",
                       .properties_json = "{\"url_path\":\"/api/orders\",\"method\":\"POST\"}"};
    cbm_store_insert_edge(s, &http);

    cbm_edge_t handles = {.project = E2E_PROJECT,
                          .source_id = hid,
                          .target_id = rid,
                          .type = "HANDLES",
                          .properties_json = "{\"handler\":\"CreateOrder\"}"};
    cbm_store_insert_edge(s, &handles);

    cbm_edge_t flow = {.project = E2E_PROJECT,
                       .source_id = cid,
                       .target_id = hid,
                       .type = "DATA_FLOWS",
                       .properties_json = "{\"route\":\"" ROUTE_QN "\"}"};
    cbm_store_insert_edge(s, &flow);

    if (caller_id) {
        *caller_id = cid;
    }
    if (handler_id) {
        *handler_id = hid;
    }
}

/* search_graph(label="RuntimeAnchor") over the JSON-RPC envelope. */
static char *rpc_search_runtime_anchor(cbm_mcp_server_t *srv) {
    return cbm_mcp_server_handle(
        srv, "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"search_graph\","
             "\"arguments\":{\"project\":\"" E2E_PROJECT "\",\"label\":\"RuntimeAnchor\"}}}");
}

/* trace_path outbound over OBSERVED_TRAFFIC from the handler. */
static char *rpc_trace_observed_traffic(cbm_mcp_server_t *srv) {
    return cbm_mcp_server_handle(
        srv, "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"trace_path\","
             "\"arguments\":{\"project\":\"" E2E_PROJECT "\","
             "\"function_name\":\"CreateOrder\",\"direction\":\"outbound\","
             "\"edge_types\":[\"OBSERVED_TRAFFIC\"]}}}");
}

/* trace_path outbound from `fn` over a single edge type (#333 provenance FSV). */
static char *rpc_trace_edge(cbm_mcp_server_t *srv, const char *fn, const char *edge_type) {
    char req[512];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"trace_path\","
             "\"arguments\":{\"project\":\"" E2E_PROJECT "\","
             "\"function_name\":\"%s\",\"direction\":\"outbound\","
             "\"edge_types\":[\"%s\"]}}}",
             fn, edge_type);
    return cbm_mcp_server_handle(srv, req);
}

/* search_graph(name_pattern=fn, relationship=et, include_connected=true) — surfaces
 * connected_edges with per-edge promotion provenance (#333). */
static char *rpc_search_connected(cbm_mcp_server_t *srv, const char *fn, const char *edge_type) {
    char req[512];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"search_graph\","
             "\"arguments\":{\"project\":\"" E2E_PROJECT "\","
             "\"name_pattern\":\"%s\",\"relationship\":\"%s\",\"include_connected\":true}}}",
             fn, edge_type);
    return cbm_mcp_server_handle(srv, req);
}

/* Ingest the committed OTLP/JSON golden batch through the real ingest_traces
 * JSON-RPC tool. The golden JSON is a full {"resourceSpans":[...]} document; we
 * splice the project field in front of its resourceSpans and wrap it as the
 * tool arguments, then serialize the JSON-RPC envelope. Returns the raw tool
 * response (JSON-RPC result) — caller frees. */
static char *rpc_ingest_golden(cbm_mcp_server_t *srv, const unsigned char *json,
                               unsigned long len) {
    /* args = {"project":"trace-e2e", <golden body minus its leading '{'> */
    size_t args_cap = (size_t)len + 128;
    char *args = malloc(args_cap);
    if (!args) {
        return NULL;
    }
    int an = snprintf(args, args_cap, "{\"project\":\"" E2E_PROJECT "\",%.*s",
                      (int)(len - 1), (const char *)json + 1);
    if (an < 0 || (size_t)an >= args_cap) {
        free(args);
        return NULL;
    }

    size_t req_cap = (size_t)an + 160;
    char *req = malloc(req_cap);
    if (!req) {
        free(args);
        return NULL;
    }
    snprintf(req, req_cap,
             "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\","
             "\"params\":{\"name\":\"ingest_traces\",\"arguments\":%s}}",
             args);
    char *resp = cbm_mcp_server_handle(srv, req);
    free(args);
    free(req);
    return resp;
}

/* Read the HTTP_CALLS edge row (caller -> route) straight from the store and
 * return whether it carries the runtime-trace promotion markers. */
static bool http_calls_is_promoted(cbm_store_t *st, int64_t caller_id) {
    cbm_edge_t *edges = NULL;
    int ec = 0;
    if (cbm_store_find_edges_by_source_type(st, caller_id, "HTTP_CALLS", &edges, &ec) !=
            CBM_STORE_OK ||
        ec < 1 || !edges[0].properties_json) {
        cbm_store_free_edges(edges, ec);
        return false;
    }
    const char *p = edges[0].properties_json;
    bool promoted = strstr(p, "\"validated\":true") != NULL &&
                    strstr(p, "\"trust\":\"Trusted\"") != NULL &&
                    strstr(p, "\"provenance\":\"runtime_trace\"") != NULL;
    cbm_store_free_edges(edges, ec);
    return promoted;
}

TEST(trace_e2e_tools_carry_trusted_service_edges_after_ingest) {
    cbm_mcp_server_t *srv = cbm_mcp_server_new(NULL);
    ASSERT_NOT_NULL(srv);
    cbm_store_t *st = cbm_mcp_server_store(srv);
    ASSERT_NOT_NULL(st);

    int64_t caller_id = 0, handler_id = 0;
    seed_route_graph(st, &caller_id, &handler_id);
    ASSERT_TRUE(caller_id > 0);
    ASSERT_TRUE(handler_id > 0);
    cbm_mcp_server_set_project(srv, E2E_PROJECT);

    /* ── PRE-INGEST NEGATIVE ──────────────────────────────────────────
     * The runtime service edge does not exist yet: search_graph finds no
     * RuntimeAnchor node and trace_path finds no OBSERVED_TRAFFIC callee. */
    char *pre_search = rpc_search_runtime_anchor(srv);
    ASSERT_NOT_NULL(pre_search);
    ASSERT_NULL(strstr(pre_search, ANCHOR_QN));
    ASSERT_NULL(strstr(pre_search, "runtime_anchor"));
    free(pre_search);

    char *pre_trace = rpc_trace_observed_traffic(srv);
    ASSERT_NOT_NULL(pre_trace);
    ASSERT_NULL(strstr(pre_trace, ANCHOR_QN));
    free(pre_trace);

    /* And the HTTP_CALLS edge is still Provisional (no promotion markers). */
    ASSERT_FALSE(http_calls_is_promoted(st, caller_id));

    /* ── INGEST the committed OTLP/JSON golden batch via JSON-RPC ─────── */
    char *ingest = rpc_ingest_golden(srv, orders_healthy_json, orders_healthy_json_len);
    ASSERT_NOT_NULL(ingest);
    ASSERT_TRUE(response_has_fragment(ingest, "\"status\":\"ok\""));
    ASSERT_TRUE(response_has_fragment(ingest, "\"format\":\"otlp_json\""));
    /* routes matched -> at least one edge promoted and the runtime anchor written. */
    ASSERT_FALSE(response_has_fragment(ingest, "\"edges_promoted\":0"));
    ASSERT_FALSE(response_has_fragment(ingest, "\"anchors_written\":0"));
    free(ingest);

    /* ── POST-INGEST POSITIVE ────────────────────────────────────────
     * search_graph now surfaces the promoted runtime service anchor with its
     * runtime-trace evidence, and trace_path now reaches it over the promoted
     * OBSERVED_TRAFFIC service edge. Neither existed before the trace batch. */
    char *post_search = rpc_search_runtime_anchor(srv);
    ASSERT_NOT_NULL(post_search);
    ASSERT_NOT_NULL(strstr(post_search, ANCHOR_QN));
    ASSERT_NOT_NULL(strstr(post_search, "runtime_anchor"));
    ASSERT_NOT_NULL(strstr(post_search, "order-service"));
    ASSERT_NOT_NULL(strstr(post_search, "runtime_trace"));
    free(post_search);

    char *post_trace = rpc_trace_observed_traffic(srv);
    ASSERT_NOT_NULL(post_trace);
    ASSERT_NOT_NULL(strstr(post_trace, ANCHOR_QN));
    free(post_trace);

    /* Independent raw-row FSV: the connectivity the tools now report is Trusted
     * — the HTTP_CALLS edge was promoted validated=true / Trusted / measured. */
    ASSERT_TRUE(http_calls_is_promoted(st, caller_id));

    /* ── #333: the SAME promotion is now readable THROUGH the tool JSON ──────
     * trace_path over the promoted HTTP_CALLS edge surfaces the edge's
     * validated / Trusted / runtime_trace / measured-weight provenance on the
     * route hop — no raw-store access required. */
    char *prov_trace = rpc_trace_edge(srv, "checkout", "HTTP_CALLS");
    ASSERT_NOT_NULL(prov_trace);
    ASSERT_TRUE(response_has_fragment(prov_trace, "\"validated\":true"));
    ASSERT_TRUE(response_has_fragment(prov_trace, "\"trust\":\"Trusted\""));
    ASSERT_TRUE(response_has_fragment(prov_trace, "\"provenance\":\"runtime_trace\""));
    ASSERT_TRUE(response_has_fragment(prov_trace, "\"weight\":"));
    free(prov_trace);

    /* search_graph include_connected surfaces the same provenance on the
     * connected_edges of the caller node reached over the promoted edge. */
    char *prov_search = rpc_search_connected(srv, "checkout", "HTTP_CALLS");
    ASSERT_NOT_NULL(prov_search);
    ASSERT_TRUE(response_has_fragment(prov_search, "connected_edges"));
    ASSERT_TRUE(response_has_fragment(prov_search, "\"validated\":true"));
    ASSERT_TRUE(response_has_fragment(prov_search, "\"trust\":\"Trusted\""));
    ASSERT_TRUE(response_has_fragment(prov_search, "\"provenance\":\"runtime_trace\""));
    free(prov_search);

    cbm_mcp_server_free(srv);
    PASS();
}

/* #333 edge-case triad, asserted THROUGH trace_path tool JSON (not raw rows):
 *   (1) an edge with FULL runtime-trace promotion properties surfaces
 *       validated / trust / weight / provenance on the hop;
 *   (2) an edge with NO properties surfaces NONE of those fields (absence is
 *       honest — no invented defaults);
 *   (3) an edge with unusable properties_json (a valid JSON value that is not an
 *       object) surfaces an explicit "provenance_error" marker (invariant 3 —
 *       never a silent drop). NOTE: a truly *unparseable* properties string cannot
 *       be seeded through cbm_store_insert_edge — the edges.url_path_gen generated
 *       column is indexed (idx_edges_url_path), so json_extract() runs at insert and
 *       aborts on malformed JSON. Such rows only exist in legacy/externally-corrupted
 *       DBs; emit_edge_provenance() routes them to the SAME provenance_error marker
 *       this non-object case proves end to end. */
static void seed_provenance_triad(cbm_store_t *s) {
    cbm_store_upsert_project(s, E2E_PROJECT, "/tmp/trace-e2e");

    cbm_node_t caller = {.project = E2E_PROJECT,
                         .label = "Function",
                         .name = "dispatch",
                         .qualified_name = "svc.dispatch",
                         .file_path = "svc/dispatch.go"};
    int64_t cid = cbm_store_upsert_node(s, &caller);

    cbm_node_t full = {.project = E2E_PROJECT,
                       .label = "Function",
                       .name = "promoted_full",
                       .qualified_name = "svc.promoted_full",
                       .file_path = "svc/full.go"};
    int64_t fid = cbm_store_upsert_node(s, &full);

    cbm_node_t bare = {.project = E2E_PROJECT,
                       .label = "Function",
                       .name = "bare_edge",
                       .qualified_name = "svc.bare_edge",
                       .file_path = "svc/bare.go"};
    int64_t bare_id = cbm_store_upsert_node(s, &bare);

    cbm_node_t broken = {.project = E2E_PROJECT,
                         .label = "Function",
                         .name = "broken_props",
                         .qualified_name = "svc.broken_props",
                         .file_path = "svc/broken.go"};
    int64_t broken_id = cbm_store_upsert_node(s, &broken);

    /* (1) fully promoted edge. */
    cbm_edge_t e_full = {
        .project = E2E_PROJECT,
        .source_id = cid,
        .target_id = fid,
        .type = "CALLS",
        .properties_json = "{\"validated\":true,\"trust\":\"Trusted\","
                           "\"provenance\":\"runtime_trace\",\"weight\":42,\"runtime_count\":42}"};
    cbm_store_insert_edge(s, &e_full);

    /* (2) edge with no properties at all (store defaults to "{}"). */
    cbm_edge_t e_bare = {.project = E2E_PROJECT,
                         .source_id = cid,
                         .target_id = bare_id,
                         .type = "USES",
                         .properties_json = NULL};
    cbm_store_insert_edge(s, &e_bare);

    /* (3) edge with unusable properties: valid JSON that is not an object (a JSON
     * array). Inserts cleanly (json_extract on a non-matching path returns NULL,
     * so the generated url_path_gen column does not abort) yet cannot yield the
     * promoted fields, so the tool must emit an explicit provenance_error. */
    cbm_edge_t e_broken = {.project = E2E_PROJECT,
                           .source_id = cid,
                           .target_id = broken_id,
                           .type = "READS",
                           .properties_json = "[\"validated\",\"trust\"]"};
    cbm_store_insert_edge(s, &e_broken);
}

TEST(trace_e2e_edge_provenance_triad_through_tools) {
    cbm_mcp_server_t *srv = cbm_mcp_server_new(NULL);
    ASSERT_NOT_NULL(srv);
    cbm_store_t *st = cbm_mcp_server_store(srv);
    ASSERT_NOT_NULL(st);

    seed_provenance_triad(st);
    cbm_mcp_server_set_project(srv, E2E_PROJECT);

    /* (1) FULL promotion → all four provenance fields on the hop. */
    char *full = rpc_trace_edge(srv, "dispatch", "CALLS");
    ASSERT_NOT_NULL(full);
    ASSERT_TRUE(response_has_fragment(full, "promoted_full"));
    ASSERT_TRUE(response_has_fragment(full, "\"validated\":true"));
    ASSERT_TRUE(response_has_fragment(full, "\"trust\":\"Trusted\""));
    ASSERT_TRUE(response_has_fragment(full, "\"weight\":42"));
    ASSERT_TRUE(response_has_fragment(full, "\"provenance\":\"runtime_trace\""));
    ASSERT_NULL(strstr(full, "provenance_error"));
    free(full);

    /* (2) NO properties → NONE of the provenance fields, and no error marker. */
    char *bare = rpc_trace_edge(srv, "dispatch", "USES");
    ASSERT_NOT_NULL(bare);
    ASSERT_TRUE(response_has_fragment(bare, "bare_edge"));
    ASSERT_NULL(strstr(bare, "validated"));
    ASSERT_NULL(strstr(bare, "\\\"trust\\\""));
    ASSERT_NULL(strstr(bare, "provenance_error"));
    free(bare);

    /* (3) MALFORMED properties → explicit provenance_error marker, never silent. */
    char *broken = rpc_trace_edge(srv, "dispatch", "READS");
    ASSERT_NOT_NULL(broken);
    ASSERT_TRUE(response_has_fragment(broken, "broken_props"));
    ASSERT_TRUE(response_has_fragment(broken, "provenance_error"));
    ASSERT_NULL(strstr(broken, "\\\"validated\\\":true"));
    free(broken);

    cbm_mcp_server_free(srv);
    PASS();
}

/* Negative-only guard: with NO matching route in the graph, ingesting the same
 * batch promotes nothing, so trace_path/search_graph stay empty of the service
 * edge. Proves the post-ingest positives above are caused by the route match,
 * not by ingestion unconditionally minting anchors. */
TEST(trace_e2e_no_route_no_service_edge) {
    cbm_mcp_server_t *srv = cbm_mcp_server_new(NULL);
    ASSERT_NOT_NULL(srv);
    cbm_store_t *st = cbm_mcp_server_store(srv);
    ASSERT_NOT_NULL(st);

    /* Project with a handler symbol but NO Route/HTTP_CALLS to match. */
    cbm_store_upsert_project(st, E2E_PROJECT, "/tmp/trace-e2e");
    cbm_node_t handler = {.project = E2E_PROJECT,
                          .label = "Function",
                          .name = "CreateOrder",
                          .qualified_name = "api.CreateOrder",
                          .file_path = "api/orders.go"};
    ASSERT_TRUE(cbm_store_upsert_node(st, &handler) > 0);
    cbm_mcp_server_set_project(srv, E2E_PROJECT);

    char *ingest = rpc_ingest_golden(srv, orders_healthy_json, orders_healthy_json_len);
    ASSERT_NOT_NULL(ingest);
    ASSERT_TRUE(response_has_fragment(ingest, "\"status\":\"ok\""));
    /* No route matched -> no promotion, no anchor. */
    ASSERT_TRUE(response_has_fragment(ingest, "\"edges_promoted\":0"));
    ASSERT_TRUE(response_has_fragment(ingest, "\"anchors_written\":0"));
    free(ingest);

    char *search = rpc_search_runtime_anchor(srv);
    ASSERT_NOT_NULL(search);
    ASSERT_NULL(strstr(search, ANCHOR_QN));
    free(search);

    char *trace = rpc_trace_observed_traffic(srv);
    ASSERT_NOT_NULL(trace);
    ASSERT_NULL(strstr(trace, ANCHOR_QN));
    free(trace);

    cbm_mcp_server_free(srv);
    PASS();
}

SUITE(trace_e2e) {
    RUN_TEST(trace_e2e_tools_carry_trusted_service_edges_after_ingest);
    RUN_TEST(trace_e2e_no_route_no_service_edge);
    RUN_TEST(trace_e2e_edge_provenance_triad_through_tools);
}
