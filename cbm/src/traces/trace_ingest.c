/*
 * trace_ingest.c — Runtime-trace ingestion into the code knowledge graph.
 * See trace_ingest.h for the contract.
 */
#include "traces/trace_ingest.h"
#include "traces/traces.h"
#include "store/store.h"
#include "foundation/constants.h"
#include "foundation/str_util.h"
#include "foundation/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Route QN canonicalization — the SAME function the indexing pipeline uses to
 * build __route__ QNs, so trace observations rendezvous with indexed routes.
 * Declared in pipeline_internal.h; forward-declared here to keep this TU light. */
const char *cbm_route_canon_path(const char *in, char *out, size_t out_sz);

enum {
    TI_METHOD_BUF = 16,
    TI_PATH_BUF = 512,
    TI_SVC_BUF = 128,
    TI_HTTP_STATUS_SERVER_ERR = 500,
    TI_DUR_INIT_CAP = 8,
    /* Mirrors pipeline_internal.h TI_ROUTE_QN_SIZE (768): the route QNs we
     * build here must hold the same strings the indexing pipeline produces. */
    TI_ROUTE_QN_SIZE = 768,
};

/* Caller-side edge types that rendezvous into a Route node and are eligible
 * for runtime promotion (issue #27 scope: HTTP_CALLS / CROSS_* + async). */
static const char *const TI_CALLER_EDGE_TYPES[] = {
    "HTTP_CALLS",       "ASYNC_CALLS",        "CROSS_HTTP_CALLS", "CROSS_ASYNC_CALLS",
    "CROSS_GRPC_CALLS", "CROSS_GRAPHQL_CALLS", "CROSS_TRPC_CALLS", "CROSS_CHANNEL",
};

/* ── aggregation ─────────────────────────────────────────────────── */

typedef struct {
    char method[TI_METHOD_BUF];
    char canonpath[TI_PATH_BUF];
    char service[TI_SVC_BUF];
    int64_t count;
    int64_t error_count;
    int64_t *durations;
    int dur_n;
    int dur_cap;
} trace_group_t;

typedef struct {
    trace_group_t *groups;
    int n;
    int cap;
} trace_group_set_t;

static void upper_ascii(char *s) {
    for (; *s; s++) {
        if (*s >= 'a' && *s <= 'z') {
            *s = (char)(*s - ('a' - 'A'));
        }
    }
}

static trace_group_t *group_find_or_add(trace_group_set_t *gs, const char *method,
                                        const char *canonpath) {
    for (int i = 0; i < gs->n; i++) {
        if (strcmp(gs->groups[i].method, method) == 0 &&
            strcmp(gs->groups[i].canonpath, canonpath) == 0) {
            return &gs->groups[i];
        }
    }
    if (gs->n >= gs->cap) {
        int newcap = gs->cap > 0 ? gs->cap * 2 : 8;
        trace_group_t *grown = realloc(gs->groups, (size_t)newcap * sizeof(*grown));
        if (!grown) {
            return NULL;
        }
        gs->groups = grown;
        gs->cap = newcap;
    }
    trace_group_t *g = &gs->groups[gs->n++];
    memset(g, 0, sizeof(*g));
    snprintf(g->method, sizeof(g->method), "%s", method);
    snprintf(g->canonpath, sizeof(g->canonpath), "%s", canonpath);
    return g;
}

static bool group_push_duration(trace_group_t *g, int64_t d) {
    if (g->dur_n >= g->dur_cap) {
        int newcap = g->dur_cap > 0 ? g->dur_cap * 2 : TI_DUR_INIT_CAP;
        int64_t *grown = realloc(g->durations, (size_t)newcap * sizeof(*grown));
        if (!grown) {
            return false;
        }
        g->durations = grown;
        g->dur_cap = newcap;
    }
    g->durations[g->dur_n++] = d;
    return true;
}

static void group_set_free(trace_group_set_t *gs) {
    for (int i = 0; i < gs->n; i++) {
        free(gs->groups[i].durations);
    }
    free(gs->groups);
    gs->groups = NULL;
    gs->n = 0;
    gs->cap = 0;
}

/* ── promotion ───────────────────────────────────────────────────── */

/* json_patch the promotion evidence onto an existing edge (idempotent: the
 * upsert conflict target is (source,target,type), payload is absolute). */
static int promote_edge(cbm_store_t *store, const char *project, int64_t source_id,
                        int64_t target_id, const char *type, const char *patch) {
    cbm_edge_t e = {
        .project = project,
        .source_id = source_id,
        .target_id = target_id,
        .type = type,
        .properties_json = patch,
    };
    return cbm_store_insert_edge(store, &e) > 0 ? 1 : 0;
}

/* Promote every caller-side edge of the given type targeting the route. */
static int promote_caller_edges(cbm_store_t *store, const char *project, int64_t route_id,
                                const char *type, const char *patch) {
    cbm_edge_t *edges = NULL;
    int count = 0;
    if (cbm_store_find_edges_by_target_type(store, route_id, type, &edges, &count) !=
        CBM_STORE_OK) {
        return 0;
    }
    int promoted = 0;
    for (int i = 0; i < count; i++) {
        promoted +=
            promote_edge(store, project, edges[i].source_id, edges[i].target_id, type, patch);
    }
    cbm_store_free_edges(edges, count);
    return promoted;
}

/* Promote DATA_FLOWS edges that flow into a handler and reference this route.
 * DATA_FLOWS carry a "route":"<route_qn>" property (pass_route_nodes.c), so we
 * filter by substring to avoid contaminating a handler's flows for other
 * routes. */
static int promote_handler_data_flows(cbm_store_t *store, const char *project, int64_t handler_id,
                                      const char *route_qn, const char *patch) {
    cbm_edge_t *edges = NULL;
    int count = 0;
    if (cbm_store_find_edges_by_target_type(store, handler_id, "DATA_FLOWS", &edges, &count) !=
        CBM_STORE_OK) {
        return 0;
    }
    int promoted = 0;
    for (int i = 0; i < count; i++) {
        if (edges[i].properties_json && route_qn[0] &&
            strstr(edges[i].properties_json, route_qn) != NULL) {
            promoted += promote_edge(store, project, edges[i].source_id, edges[i].target_id,
                                     "DATA_FLOWS", patch);
        }
    }
    cbm_store_free_edges(edges, count);
    return promoted;
}

/* ── anchors + incidents ─────────────────────────────────────────── */

/* Write the RuntimeAnchor node for a route (absolute values -> idempotent) and
 * an OBSERVED_TRAFFIC edge from every handler symbol. Returns objects written. */
static int write_runtime_anchor(cbm_store_t *store, const char *project, const char *route_qn,
                                const cbm_node_t *route, int64_t count, int64_t error_count,
                                int64_t p99_ns, double error_rate, bool incident,
                                const char *service) {
    char anchor_qn[TI_ROUTE_QN_SIZE];
    snprintf(anchor_qn, sizeof(anchor_qn), "__runtime__%s", route_qn);

    char esc_svc[TI_SVC_BUF * 2];
    char esc_path[TI_PATH_BUF * 2];
    cbm_json_escape(esc_svc, sizeof(esc_svc), service ? service : "");
    cbm_json_escape(esc_path, sizeof(esc_path), route->name ? route->name : "");

    char props[CBM_SZ_1K];
    snprintf(props, sizeof(props),
             "{\"kind\":\"runtime_anchor\",\"service\":\"%s\",\"path\":\"%s\","
             "\"traffic\":%lld,\"error_count\":%lld,\"error_rate\":%.4f,"
             "\"p99_ns\":%lld,\"incident\":%s,\"provenance\":\"runtime_trace\"}",
             esc_svc, esc_path, (long long)count, (long long)error_count, error_rate,
             (long long)p99_ns, incident ? "true" : "false");

    cbm_node_t anchor = {
        .project = project,
        .label = "RuntimeAnchor",
        .name = route->name ? route->name : "",
        .qualified_name = anchor_qn,
        .file_path = "",
        .start_line = 0,
        .end_line = 0,
        .properties_json = props,
    };
    int64_t anchor_id = cbm_store_upsert_node(store, &anchor);
    if (anchor_id <= 0) {
        return 0;
    }
    int written = 1;

    /* route -> anchor (deterministic, upsert -> idempotent). */
    char edge_props[CBM_SZ_128];
    snprintf(edge_props, sizeof(edge_props), "{\"traffic\":%lld}", (long long)count);
    promote_edge(store, project, route->id, anchor_id, "HAS_RUNTIME_ANCHOR", edge_props);

    /* handler symbols get Recurrence occurrences: OBSERVED_TRAFFIC edges. */
    cbm_edge_t *handles = NULL;
    int hcount = 0;
    if (cbm_store_find_edges_by_target_type(store, route->id, "HANDLES", &handles, &hcount) ==
        CBM_STORE_OK) {
        char hprops[CBM_SZ_256];
        snprintf(hprops, sizeof(hprops),
                 "{\"traffic\":%lld,\"error_count\":%lld,\"p99_ns\":%lld,"
                 "\"provenance\":\"runtime_trace\"}",
                 (long long)count, (long long)error_count, (long long)p99_ns);
        for (int i = 0; i < hcount; i++) {
            if (promote_edge(store, project, handles[i].source_id, anchor_id, "OBSERVED_TRAFFIC",
                             hprops)) {
                written++;
            }
        }
        cbm_store_free_edges(handles, hcount);
    }
    return written;
}

/* Create an Incident node labeled onto the route. Only called when incident. */
static int write_incident(cbm_store_t *store, const char *project, const char *route_qn,
                          const cbm_node_t *route, int64_t count, int64_t error_count,
                          double error_rate) {
    const char *severity =
        error_rate >= CBM_INCIDENT_ERROR_RATE_CRITICAL ? "critical" : "high";

    char incident_qn[TI_ROUTE_QN_SIZE];
    snprintf(incident_qn, sizeof(incident_qn), "__incident__%s", route_qn);

    char props[CBM_SZ_512];
    snprintf(props, sizeof(props),
             "{\"kind\":\"incident\",\"severity\":\"%s\",\"status\":\"active\","
             "\"error_rate\":%.4f,\"error_count\":%lld,\"traffic\":%lld,"
             "\"trigger\":\"5xx_spike\",\"provenance\":\"runtime_trace\"}",
             severity, error_rate, (long long)error_count, (long long)count);

    cbm_node_t incident = {
        .project = project,
        .label = "Incident",
        .name = route->name ? route->name : "incident",
        .qualified_name = incident_qn,
        .file_path = "",
        .start_line = 0,
        .end_line = 0,
        .properties_json = props,
    };
    int64_t incident_id = cbm_store_upsert_node(store, &incident);
    if (incident_id <= 0) {
        return 0;
    }
    /* Upsert-by-QN re-activates a previously resolved node (flapping): the props
     * above carry status "active" and overwrite any prior resolved record. */
    char edge_props[CBM_SZ_128];
    snprintf(edge_props, sizeof(edge_props),
             "{\"label\":\"incident\",\"severity\":\"%s\",\"resolved\":false}", severity);
    promote_edge(store, project, route->id, incident_id, "LABELED", edge_props);
    return 1;
}

/* Resolve a latched Incident when a later batch's window shows the route
 * healthy again. Fail-closed lifecycle (issue #323): never a silent deletion —
 * the Incident node is flipped active -> resolved with recovery provenance and
 * the route->incident LABELED edge is patched resolved=true, so the transition
 * is an independently readable ledger entry. Returns 1 iff a transition
 * occurred (an active Incident existed); 0 when there is no incident to clear
 * or it is already resolved (idempotent). Only the caller's healthy-window gate
 * (>= INCIDENT_MIN_REQUESTS, error rate below INCIDENT_ERROR_RATE_HIGH) reaches
 * here, so a below-sample or empty window can never clear a real incident. */
static int resolve_incident(cbm_store_t *store, const char *project, const char *route_qn,
                            const cbm_node_t *route, int64_t count, int64_t error_count,
                            double error_rate) {
    char incident_qn[TI_ROUTE_QN_SIZE];
    snprintf(incident_qn, sizeof(incident_qn), "__incident__%s", route_qn);

    cbm_node_t existing = {0};
    if (cbm_store_find_node_by_qn(store, project, incident_qn, &existing) != CBM_STORE_OK) {
        return 0; /* nothing latched */
    }
    if (existing.properties_json &&
        strstr(existing.properties_json, "\"status\":\"resolved\"") != NULL) {
        cbm_node_free_fields(&existing); /* already resolved -> idempotent no-op */
        return 0;
    }
    /* Preserve the incident's original severity band in the resolution record. */
    const char *severity = (existing.properties_json &&
                            strstr(existing.properties_json, "\"severity\":\"critical\"") != NULL)
                               ? "critical"
                               : "high";
    cbm_node_free_fields(&existing);

    char props[CBM_SZ_512];
    snprintf(props, sizeof(props),
             "{\"kind\":\"incident\",\"severity\":\"%s\",\"status\":\"resolved\","
             "\"error_rate\":%.4f,\"error_count\":%lld,\"traffic\":%lld,"
             "\"trigger\":\"5xx_spike\",\"resolution\":\"recovery\","
             "\"provenance\":\"runtime_trace\"}",
             severity, error_rate, (long long)error_count, (long long)count);

    cbm_node_t incident = {
        .project = project,
        .label = "Incident",
        .name = route->name ? route->name : "incident",
        .qualified_name = incident_qn,
        .file_path = "",
        .start_line = 0,
        .end_line = 0,
        .properties_json = props,
    };
    int64_t incident_id = cbm_store_upsert_node(store, &incident);
    if (incident_id <= 0) {
        return 0;
    }
    char edge_props[CBM_SZ_128];
    snprintf(edge_props, sizeof(edge_props), "{\"resolved\":true,\"resolution\":\"recovery\"}");
    promote_edge(store, project, route->id, incident_id, "LABELED", edge_props);
    return 1;
}

/* ── per-group processing ────────────────────────────────────────── */

static int process_group(cbm_store_t *store, const char *project, trace_group_t *g,
                         cbm_trace_ingest_stats_t *stats) {
    char route_qn[TI_ROUTE_QN_SIZE];
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", g->method, g->canonpath);

    cbm_node_t route = {0};
    int rc = cbm_store_find_node_by_qn(store, project, route_qn, &route);
    if (rc != CBM_STORE_OK) {
        /* Fall back to a method-agnostic (prefix) route registration. */
        snprintf(route_qn, sizeof(route_qn), "__route__ANY__%s", g->canonpath);
        rc = cbm_store_find_node_by_qn(store, project, route_qn, &route);
    }
    if (rc != CBM_STORE_OK) {
        stats->spans_unmatched += (int)g->count;
        return CBM_STORE_OK;
    }

    int64_t p99_ns = cbm_calculate_p99(g->durations, g->dur_n);
    double error_rate = g->count > 0 ? (double)g->error_count / (double)g->count : 0.0;
    /* Incident detection is over the BATCH WINDOW (not cumulative traffic), so a
     * later healthy window can recover a route regardless of its lifetime total.
     * Both bands require a valid sample (>= MIN_REQUESTS) so a 1-request blip can
     * neither raise nor clear an incident. */
    bool incident = (g->count >= CBM_INCIDENT_MIN_REQUESTS &&
                     error_rate >= CBM_INCIDENT_ERROR_RATE_HIGH);
    bool window_healthy = (g->count >= CBM_INCIDENT_MIN_REQUESTS &&
                           error_rate < CBM_INCIDENT_ERROR_RATE_HIGH);

    /* Promotion patch: numbers + fixed tokens only (no escaping needed). */
    char patch[CBM_SZ_512];
    snprintf(patch, sizeof(patch),
             "{\"validated\":true,\"trust\":\"Trusted\",\"provenance\":\"runtime_trace\","
             "\"weight\":%lld,\"runtime_count\":%lld,\"runtime_error_count\":%lld,"
             "\"runtime_p99_ns\":%lld,\"incident\":%s}",
             (long long)g->count, (long long)g->count, (long long)g->error_count,
             (long long)p99_ns, incident ? "true" : "false");

    int promoted = 0;
    for (size_t t = 0; t < sizeof(TI_CALLER_EDGE_TYPES) / sizeof(TI_CALLER_EDGE_TYPES[0]); t++) {
        promoted += promote_caller_edges(store, project, route.id, TI_CALLER_EDGE_TYPES[t], patch);
    }

    /* DATA_FLOWS through the route's handlers (filtered by route QN). */
    cbm_edge_t *handles = NULL;
    int hcount = 0;
    if (cbm_store_find_edges_by_target_type(store, route.id, "HANDLES", &handles, &hcount) ==
        CBM_STORE_OK) {
        for (int i = 0; i < hcount; i++) {
            promoted +=
                promote_handler_data_flows(store, project, handles[i].source_id, route_qn, patch);
        }
        cbm_store_free_edges(handles, hcount);
    }

    stats->routes_matched++;
    stats->edges_promoted += promoted;
    stats->spans_http += (int)g->count;

    stats->anchors_written += write_runtime_anchor(store, project, route_qn, &route, g->count,
                                                   g->error_count, p99_ns, error_rate, incident,
                                                   g->service);
    if (incident) {
        stats->incidents_detected +=
            write_incident(store, project, route_qn, &route, g->count, g->error_count, error_rate);
    } else if (window_healthy) {
        stats->incidents_resolved += resolve_incident(store, project, route_qn, &route, g->count,
                                                       g->error_count, error_rate);
    }

    cbm_node_free_fields(&route);
    return CBM_STORE_OK;
}

/* ── public: OTLP record ingestion ───────────────────────────────── */

int cbm_trace_ingest_records(cbm_store_t *store, const char *project,
                             const cbm_trace_record_t *records, int n,
                             cbm_trace_ingest_stats_t *stats) {
    if (!store || !project || !stats) {
        return CBM_STORE_ERR;
    }
    if (!records || n <= 0) {
        return CBM_STORE_OK;
    }

    trace_group_set_t gs = {0};
    for (int i = 0; i < n; i++) {
        const cbm_trace_record_t *r = &records[i];
        char method[TI_METHOD_BUF];
        snprintf(method, sizeof(method), "%s", r->method[0] ? r->method : "ANY");
        upper_ascii(method);
        char canon[TI_PATH_BUF];
        cbm_route_canon_path(r->path, canon, sizeof(canon));

        trace_group_t *g = group_find_or_add(&gs, method, canon);
        if (!g) {
            group_set_free(&gs);
            return CBM_STORE_ERR;
        }
        g->count++;
        if (r->status_code >= TI_HTTP_STATUS_SERVER_ERR) {
            g->error_count++;
        }
        if (g->service[0] == '\0' && r->service[0] != '\0') {
            snprintf(g->service, sizeof(g->service), "%s", r->service);
        }
        if (r->duration_ns > 0) {
            group_push_duration(g, r->duration_ns);
        }
    }

    int rc = CBM_STORE_OK;
    for (int i = 0; i < gs.n; i++) {
        rc = process_group(store, project, &gs.groups[i], stats);
        if (rc != CBM_STORE_OK) {
            break;
        }
    }

    char b1[CBM_SZ_16];
    char b2[CBM_SZ_16];
    snprintf(b1, sizeof(b1), "%d", stats->routes_matched);
    snprintf(b2, sizeof(b2), "%d", stats->edges_promoted);
    cbm_log_info("traces.ingest", "routes_matched", b1, "edges_promoted", b2);

    group_set_free(&gs);
    return rc;
}

/* ── public: simple {caller, callee, count} ingestion ────────────── */

/* Resolve a symbol name to a node id: exact QN, else unique QN-suffix match. */
static int64_t resolve_symbol(cbm_store_t *store, const char *project, const char *name) {
    cbm_node_t node = {0};
    if (cbm_store_find_node_by_qn(store, project, name, &node) == CBM_STORE_OK) {
        int64_t id = node.id;
        cbm_node_free_fields(&node);
        return id;
    }
    cbm_node_t *nodes = NULL;
    int count = 0;
    int64_t id = 0;
    if (cbm_store_find_nodes_by_qn_suffix(store, project, name, &nodes, &count) == CBM_STORE_OK &&
        count == 1) {
        id = nodes[0].id;
    }
    cbm_store_free_nodes(nodes, count);
    return id;
}

/* Promote any CALLS/HTTP_CALLS/DATA_FLOWS edge from source_id to target_id. */
static int promote_simple_pair(cbm_store_t *store, const char *project, int64_t source_id,
                               int64_t target_id, int64_t count) {
    static const char *const types[] = {"CALLS", "HTTP_CALLS", "DATA_FLOWS"};
    char patch[CBM_SZ_256];
    snprintf(patch, sizeof(patch),
             "{\"validated\":true,\"trust\":\"Trusted\",\"provenance\":\"runtime_trace\","
             "\"weight\":%lld,\"runtime_count\":%lld}",
             (long long)count, (long long)count);

    int promoted = 0;
    for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        cbm_edge_t *edges = NULL;
        int ec = 0;
        if (cbm_store_find_edges_by_source_type(store, source_id, types[t], &edges, &ec) !=
            CBM_STORE_OK) {
            continue;
        }
        for (int i = 0; i < ec; i++) {
            if (edges[i].target_id == target_id) {
                promoted +=
                    promote_edge(store, project, source_id, target_id, types[t], patch);
            }
        }
        cbm_store_free_edges(edges, ec);
    }
    return promoted;
}

int cbm_trace_ingest_simple(cbm_store_t *store, const char *project,
                            const cbm_trace_simple_t *simple, int n,
                            cbm_trace_ingest_stats_t *stats) {
    if (!store || !project || !stats) {
        return CBM_STORE_ERR;
    }
    if (!simple || n <= 0) {
        return CBM_STORE_OK;
    }
    for (int i = 0; i < n; i++) {
        stats->simple_records++;
        int64_t source_id = resolve_symbol(store, project, simple[i].caller);
        int64_t target_id = resolve_symbol(store, project, simple[i].callee);
        if (source_id <= 0 || target_id <= 0) {
            stats->simple_unmatched++;
            continue;
        }
        int promoted = promote_simple_pair(store, project, source_id, target_id, simple[i].count);
        if (promoted == 0) {
            stats->simple_unmatched++;
        } else {
            stats->edges_promoted += promoted;
        }
    }
    return CBM_STORE_OK;
}
