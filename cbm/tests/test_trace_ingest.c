/*
 * test_trace_ingest.c — Full State Verification for ingest_traces (issue #27).
 *
 * Exercises the real ingestion path against a real (in-memory) SQLite store:
 * builds a static route graph, ingests committed OTLP golden batches (protobuf
 * AND JSON) plus the simple {caller,callee,count} format, then INDEPENDENTLY
 * reads back the persisted edge properties, RuntimeAnchor nodes and Incident
 * nodes and compares them to the expected promotions. Covers the edge triad
 * (empty / unmatched-accounting / invalid) and idempotent re-ingestion.
 */
#include "test_framework.h"

#include <store/store.h>
#include <traces/otlp_decode.h>
#include <traces/trace_ingest.h>
#include <yyjson/yyjson.h>
#include <string.h>

#include "fixtures/otlp/otlp_golden.h"

#define ROUTE_QN "__route__POST__/api/orders"
#define ANCHOR_QN "__runtime____route__POST__/api/orders"
#define INCIDENT_QN "__incident____route__POST__/api/orders"

/* Build a store with one POST /api/orders route: a caller (HTTP_CALLS -> route),
 * a handler (HANDLES -> route), and a caller->handler DATA_FLOWS carrying the
 * route QN. Returns the store; route_id/caller_id/handler_id are filled. */
static cbm_store_t *setup_route_graph(int64_t *route_id, int64_t *caller_id, int64_t *handler_id) {
    cbm_store_t *s = cbm_store_open_memory();
    if (!s) {
        return NULL;
    }
    cbm_store_upsert_project(s, "test", "/tmp/test");

    cbm_node_t caller = {.project = "test",
                         .label = "Function",
                         .name = "checkout",
                         .qualified_name = "test.web.checkout",
                         .file_path = "web/checkout.go"};
    int64_t cid = cbm_store_upsert_node(s, &caller);

    cbm_node_t handler = {.project = "test",
                          .label = "Function",
                          .name = "CreateOrder",
                          .qualified_name = "test.api.CreateOrder",
                          .file_path = "api/orders.go"};
    int64_t hid = cbm_store_upsert_node(s, &handler);

    cbm_node_t route = {.project = "test",
                        .label = "Route",
                        .name = "/api/orders",
                        .qualified_name = ROUTE_QN,
                        .properties_json = "{\"method\":\"POST\"}"};
    int64_t rid = cbm_store_upsert_node(s, &route);

    cbm_edge_t http = {.project = "test",
                       .source_id = cid,
                       .target_id = rid,
                       .type = "HTTP_CALLS",
                       .properties_json = "{\"url_path\":\"/api/orders\",\"method\":\"POST\"}"};
    cbm_store_insert_edge(s, &http);

    cbm_edge_t handles = {.project = "test",
                          .source_id = hid,
                          .target_id = rid,
                          .type = "HANDLES",
                          .properties_json = "{\"handler\":\"CreateOrder\"}"};
    cbm_store_insert_edge(s, &handles);

    cbm_edge_t flow = {.project = "test",
                       .source_id = cid,
                       .target_id = hid,
                       .type = "DATA_FLOWS",
                       .properties_json = "{\"route\":\"" ROUTE_QN "\"}"};
    cbm_store_insert_edge(s, &flow);

    if (route_id) {
        *route_id = rid;
    }
    if (caller_id) {
        *caller_id = cid;
    }
    if (handler_id) {
        *handler_id = hid;
    }
    return s;
}

/* Decode a JSON fixture and ingest it. */
static int ingest_json_fixture(cbm_store_t *s, const unsigned char *buf, unsigned long len,
                               cbm_trace_ingest_stats_t *stats) {
    yyjson_doc *doc = yyjson_read((const char *)buf, (size_t)len, 0);
    if (!doc) {
        return -1;
    }
    cbm_otlp_batch_t batch = {0};
    int rc = cbm_otlp_decode_json(yyjson_doc_get_root(doc), &batch);
    if (rc == CBM_OTLP_OK) {
        stats->spans_total = batch.spans_total;
        stats->spans_non_http = batch.spans_non_http;
        cbm_trace_ingest_records(s, "test", batch.records, batch.record_count, stats);
    }
    cbm_otlp_batch_free(&batch);
    yyjson_doc_free(doc);
    return rc;
}

/* Decode a protobuf fixture and ingest it. */
static int ingest_pb_fixture(cbm_store_t *s, const unsigned char *buf, unsigned long len,
                             cbm_trace_ingest_stats_t *stats) {
    cbm_otlp_batch_t batch = {0};
    int rc = cbm_otlp_decode_protobuf(buf, (size_t)len, &batch);
    if (rc == CBM_OTLP_OK) {
        stats->spans_total = batch.spans_total;
        stats->spans_non_http = batch.spans_non_http;
        cbm_trace_ingest_records(s, "test", batch.records, batch.record_count, stats);
    }
    cbm_otlp_batch_free(&batch);
    return rc;
}

/* Read back the sole HTTP_CALLS edge into the route; assert promotion markers. */
static int assert_http_edge_promoted(cbm_store_t *s, int64_t route_id, long long expect_weight) {
    cbm_edge_t *edges = NULL;
    int count = 0;
    int ok = 0;
    if (cbm_store_find_edges_by_target_type(s, route_id, "HTTP_CALLS", &edges, &count) ==
            CBM_STORE_OK &&
        count == 1) {
        const char *p = edges[0].properties_json;
        char w[64];
        snprintf(w, sizeof(w), "\"weight\":%lld", expect_weight);
        ok = p && strstr(p, "\"validated\":true") && strstr(p, "\"trust\":\"Trusted\"") &&
             strstr(p, "\"provenance\":\"runtime_trace\"") && strstr(p, w) &&
             strstr(p, "\"url_path\":\"/api/orders\""); /* original prop preserved */
    }
    cbm_store_free_edges(edges, count);
    return ok;
}

/* ── JSON promotion FSV ──────────────────────────────────────────── */

TEST(trace_ingest_json_promotes) {
    int64_t route_id = 0;
    int64_t handler_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, &handler_id);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(ingest_json_fixture(s, orders_healthy_json, orders_healthy_json_len, &st),
              CBM_OTLP_OK);

    /* Accounting: 8 spans = 6 matched + 1 unmatched(GET) + 1 non-HTTP. */
    ASSERT_EQ(st.spans_total, 8);
    ASSERT_EQ(st.spans_non_http, 1);
    ASSERT_EQ(st.spans_unmatched, 1);
    ASSERT_EQ(st.routes_matched, 1);
    ASSERT_EQ(st.incidents_detected, 0);
    ASSERT_GT(st.edges_promoted, 0);

    /* Promoted HTTP_CALLS edge read back raw from the store. */
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 6));

    /* DATA_FLOWS caller->handler promoted too. */
    cbm_edge_t *df = NULL;
    int dfc = 0;
    ASSERT_EQ(cbm_store_find_edges_by_target_type(s, handler_id, "DATA_FLOWS", &df, &dfc),
              CBM_STORE_OK);
    ASSERT_EQ(dfc, 1);
    ASSERT_TRUE(strstr(df[0].properties_json, "\"validated\":true") != NULL);
    cbm_store_free_edges(df, dfc);

    /* RuntimeAnchor node written with absolute measured evidence. */
    cbm_node_t anchor = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", ANCHOR_QN, &anchor), CBM_STORE_OK);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"traffic\":6") != NULL);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"error_count\":0") != NULL);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"p99_ns\":60000000") != NULL);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"incident\":false") != NULL);
    cbm_node_free_fields(&anchor);

    /* Handler symbol got a Recurrence occurrence (OBSERVED_TRAFFIC edge). */
    cbm_edge_t *obs = NULL;
    int obsc = 0;
    ASSERT_EQ(cbm_store_find_edges_by_source_type(s, handler_id, "OBSERVED_TRAFFIC", &obs, &obsc),
              CBM_STORE_OK);
    ASSERT_EQ(obsc, 1);
    cbm_store_free_edges(obs, obsc);

    /* No Incident node for a healthy batch (negative). */
    cbm_node_t incident = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", INCIDENT_QN, &incident), CBM_STORE_NOT_FOUND);

    cbm_store_close(s);
    PASS();
}

/* ── protobuf matches JSON ───────────────────────────────────────── */

TEST(trace_ingest_protobuf_matches_json) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_healthy_pb, orders_healthy_pb_len, &st), CBM_OTLP_OK);

    ASSERT_EQ(st.spans_total, 8);
    ASSERT_EQ(st.spans_non_http, 1);
    ASSERT_EQ(st.spans_unmatched, 1);
    ASSERT_EQ(st.routes_matched, 1);
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 6));

    cbm_store_close(s);
    PASS();
}

/* ── incident detection (5xx spike) ──────────────────────────────── */

TEST(trace_ingest_incident_on_5xx_spike) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_incident_pb, orders_incident_pb_len, &st), CBM_OTLP_OK);

    /* 8 requests, 6x 500 => error_rate 0.75 => critical incident. */
    ASSERT_EQ(st.routes_matched, 1);
    ASSERT_EQ(st.incidents_detected, 1);

    cbm_node_t incident = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", INCIDENT_QN, &incident), CBM_STORE_OK);
    ASSERT_STR_EQ(incident.label, "Incident");
    ASSERT_TRUE(strstr(incident.properties_json, "\"severity\":\"critical\"") != NULL);
    ASSERT_TRUE(strstr(incident.properties_json, "\"trigger\":\"5xx_spike\"") != NULL);
    cbm_node_free_fields(&incident);

    /* The route is LABELED with the incident. */
    cbm_edge_t *lab = NULL;
    int labc = 0;
    ASSERT_EQ(cbm_store_find_edges_by_source_type(s, route_id, "LABELED", &lab, &labc),
              CBM_STORE_OK);
    ASSERT_EQ(labc, 1);
    cbm_store_free_edges(lab, labc);

    /* Promoted edge carries incident:true. */
    cbm_edge_t *edges = NULL;
    int count = 0;
    ASSERT_EQ(cbm_store_find_edges_by_target_type(s, route_id, "HTTP_CALLS", &edges, &count),
              CBM_STORE_OK);
    ASSERT_EQ(count, 1);
    ASSERT_TRUE(strstr(edges[0].properties_json, "\"incident\":true") != NULL);
    ASSERT_TRUE(strstr(edges[0].properties_json, "\"runtime_error_count\":6") != NULL);
    cbm_store_free_edges(edges, count);

    cbm_store_close(s);
    PASS();
}

/* ── below-threshold: NO incident (negative) ─────────────────────── */

TEST(trace_ingest_below_threshold_no_incident) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_below_threshold_pb, orders_below_threshold_pb_len, &st),
              CBM_OTLP_OK);

    /* 10 requests, 1x 500 => error_rate 0.1 => no incident. */
    ASSERT_EQ(st.routes_matched, 1);
    ASSERT_EQ(st.incidents_detected, 0);

    cbm_node_t incident = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", INCIDENT_QN, &incident), CBM_STORE_NOT_FOUND);

    cbm_store_close(s);
    PASS();
}

/* ── idempotent re-ingestion ─────────────────────────────────────── */

TEST(trace_ingest_idempotent) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st1 = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_healthy_pb, orders_healthy_pb_len, &st1), CBM_OTLP_OK);
    cbm_trace_ingest_stats_t st2 = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_healthy_pb, orders_healthy_pb_len, &st2), CBM_OTLP_OK);

    /* Second pass yields identical promotion accounting (no growth). */
    ASSERT_EQ(st1.edges_promoted, st2.edges_promoted);
    ASSERT_EQ(st1.anchors_written, st2.anchors_written);

    /* Weight is absolute (6), not doubled to 12. */
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 6));

    /* Exactly one HTTP_CALLS edge and one RuntimeAnchor (no duplicates). */
    cbm_edge_t *edges = NULL;
    int count = 0;
    ASSERT_EQ(cbm_store_find_edges_by_target_type(s, route_id, "HTTP_CALLS", &edges, &count),
              CBM_STORE_OK);
    ASSERT_EQ(count, 1);
    cbm_store_free_edges(edges, count);

    cbm_node_t anchor = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", ANCHOR_QN, &anchor), CBM_STORE_OK);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"traffic\":6") != NULL);
    cbm_node_free_fields(&anchor);

    cbm_store_close(s);
    PASS();
}

/* ── simple {caller,callee,count} format ─────────────────────────── */

TEST(trace_ingest_simple_format) {
    int64_t caller_id = 0;
    int64_t handler_id = 0;
    cbm_store_t *s = setup_route_graph(NULL, &caller_id, &handler_id);
    ASSERT_NOT_NULL(s);

    /* Add a direct CALLS edge caller -> handler to promote. */
    cbm_edge_t call = {.project = "test",
                       .source_id = caller_id,
                       .target_id = handler_id,
                       .type = "CALLS",
                       .properties_json = "{}"};
    cbm_store_insert_edge(s, &call);

    cbm_trace_simple_t recs[] = {
        {.caller = "test.web.checkout", .callee = "test.api.CreateOrder", .count = 42},
    };
    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(cbm_trace_ingest_simple(s, "test", recs, 1, &st), CBM_STORE_OK);
    ASSERT_EQ(st.simple_records, 1);
    ASSERT_EQ(st.simple_unmatched, 0);
    ASSERT_GT(st.edges_promoted, 0);

    /* Read back the promoted CALLS edge. */
    cbm_edge_t *edges = NULL;
    int count = 0;
    ASSERT_EQ(cbm_store_find_edges_by_source_type(s, caller_id, "CALLS", &edges, &count),
              CBM_STORE_OK);
    int found = 0;
    for (int i = 0; i < count; i++) {
        if (edges[i].target_id == handler_id &&
            strstr(edges[i].properties_json, "\"trust\":\"Trusted\"") &&
            strstr(edges[i].properties_json, "\"weight\":42")) {
            found = 1;
        }
    }
    cbm_store_free_edges(edges, count);
    ASSERT_TRUE(found);

    cbm_store_close(s);
    PASS();
}

/* ── edge triad: empty + invalid + unmatched-only ────────────────── */

TEST(trace_ingest_empty_input) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);
    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", NULL, 0, &st), CBM_STORE_OK);
    ASSERT_EQ(st.routes_matched, 0);
    ASSERT_EQ(st.edges_promoted, 0);
    cbm_store_close(s);
    PASS();
}

TEST(trace_ingest_invalid_protobuf) {
    cbm_otlp_batch_t b = {0};
    unsigned char junk[] = {0xff, 0xff, 0xff, 0xff};
    ASSERT_EQ(cbm_otlp_decode_protobuf(junk, sizeof(junk), &b), CBM_OTLP_ERR_FORMAT);
    ASSERT_EQ(cbm_otlp_decode_protobuf_base64("!!!!", &b), CBM_OTLP_ERR_FORMAT);
    cbm_otlp_batch_free(&b);
    PASS();
}

TEST(trace_ingest_unmatched_accounted) {
    /* Store has NO matching route -> every HTTP span is counted as unmatched,
     * nothing promoted, nothing silently dropped. */
    cbm_store_t *s = cbm_store_open_memory();
    ASSERT_NOT_NULL(s);
    cbm_store_upsert_project(s, "test", "/tmp/test");

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(ingest_pb_fixture(s, orders_healthy_pb, orders_healthy_pb_len, &st), CBM_OTLP_OK);
    ASSERT_EQ(st.routes_matched, 0);
    ASSERT_EQ(st.edges_promoted, 0);
    /* 6 POST + 1 GET HTTP spans all unmatched; 1 non-HTTP accounted separately. */
    ASSERT_EQ(st.spans_unmatched, 7);
    ASSERT_EQ(st.spans_non_http, 1);

    cbm_store_close(s);
    PASS();
}

/* ── incident lifecycle FSV (issue #323) + cumulative weights (issue #324) ──
 *
 * These tests build HTTP record batches directly (bypassing the OTLP decoder)
 * so a batch's exact request count / error count / route can be dialed in, then
 * INDEPENDENTLY read back the persisted Incident status, LABELED edge, promoted
 * edge weight, RuntimeAnchor traffic and TraceBatch ledger node. Appended after
 * the original #27 suite; nothing above is modified. */

/* Fill `recs` with `total` POST /api/orders records, the first `errors` of them
 * returning 500 (the rest 200). Matches the setup_route_graph POST route. */
static int fill_orders(cbm_trace_record_t *recs, int total, int errors) {
    for (int i = 0; i < total; i++) {
        memset(&recs[i], 0, sizeof(recs[i]));
        snprintf(recs[i].service, sizeof(recs[i].service), "orders-svc");
        snprintf(recs[i].method, sizeof(recs[i].method), "POST");
        snprintf(recs[i].path, sizeof(recs[i].path), "/api/orders");
        recs[i].status_code = (i < errors) ? 500 : 200;
        recs[i].duration_ns = 10000000 + i;
        recs[i].span_kind = 3;
    }
    return total;
}

/* Read back the Incident node's status string ("active"/"resolved"), or NULL. */
static int incident_status_is(cbm_store_t *s, const char *want) {
    cbm_node_t inc = {0};
    int ok = 0;
    if (cbm_store_find_node_by_qn(s, "test", INCIDENT_QN, &inc) == CBM_STORE_OK) {
        char needle[64];
        snprintf(needle, sizeof(needle), "\"status\":\"%s\"", want);
        ok = inc.properties_json && strstr(inc.properties_json, needle) != NULL;
    }
    cbm_node_free_fields(&inc);
    return ok;
}

/* ── #323: incident resolves when a later batch recovers ─────────────── */

TEST(trace_ingest_incident_resolves_on_recovery) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    /* Batch A: 8 requests, 6x 500 => error_rate 0.75 => critical incident. */
    cbm_trace_record_t a[8];
    fill_orders(a, 8, 6);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 8, &sa), CBM_STORE_OK);
    ASSERT_EQ(sa.incidents_detected, 1);
    ASSERT_EQ(sa.incidents_resolved, 0);
    ASSERT_TRUE(incident_status_is(s, "active")); /* before: latched active */

    /* Batch B: 6 healthy requests => valid recovery window => resolved. */
    cbm_trace_record_t b[6];
    fill_orders(b, 6, 0);
    cbm_trace_ingest_stats_t sb = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", b, 6, &sb), CBM_STORE_OK);
    ASSERT_EQ(sb.incidents_detected, 0);
    ASSERT_EQ(sb.incidents_resolved, 1);

    /* After: the SAME node persists, flipped to resolved (never deleted). */
    cbm_node_t inc = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", INCIDENT_QN, &inc), CBM_STORE_OK);
    ASSERT_TRUE(strstr(inc.properties_json, "\"status\":\"resolved\"") != NULL);
    ASSERT_TRUE(strstr(inc.properties_json, "\"resolution\":\"recovery\"") != NULL);
    ASSERT_TRUE(strstr(inc.properties_json, "\"severity\":\"critical\"") != NULL); /* preserved */
    cbm_node_free_fields(&inc);

    /* Ledgered on the route->incident LABELED edge as well. */
    cbm_edge_t *lab = NULL;
    int labc = 0;
    ASSERT_EQ(cbm_store_find_edges_by_source_type(s, route_id, "LABELED", &lab, &labc),
              CBM_STORE_OK);
    ASSERT_EQ(labc, 1);
    ASSERT_TRUE(strstr(lab[0].properties_json, "\"resolved\":true") != NULL);
    cbm_store_free_edges(lab, labc);

    /* Re-applying the recovery batch is idempotent (already resolved => 0). */
    cbm_trace_ingest_stats_t sc = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", b, 6, &sc), CBM_STORE_OK);
    ASSERT_EQ(sc.incidents_resolved, 0);
    ASSERT_TRUE(incident_status_is(s, "resolved"));

    cbm_store_close(s);
    PASS();
}

/* ── #323 edge: empty recovery batch keeps the incident latched ──────── */

TEST(trace_ingest_incident_persists_on_empty_recovery) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_record_t a[8];
    fill_orders(a, 8, 6);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 8, &sa), CBM_STORE_OK);
    ASSERT_TRUE(incident_status_is(s, "active")); /* before */

    /* Empty batch: no window to evaluate => no transition. */
    cbm_trace_ingest_stats_t sb = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", NULL, 0, &sb), CBM_STORE_OK);
    ASSERT_EQ(sb.incidents_resolved, 0);
    ASSERT_TRUE(incident_status_is(s, "active")); /* after: still latched */

    cbm_store_close(s);
    PASS();
}

/* ── #323 edge: route absent from the recovery batch keeps it latched ── */

TEST(trace_ingest_incident_persists_when_route_absent) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_record_t a[8];
    fill_orders(a, 8, 6);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 8, &sa), CBM_STORE_OK);
    ASSERT_TRUE(incident_status_is(s, "active")); /* before */

    /* Recovery batch touches only an UNMATCHED route: the incident route was
     * never observed healthy, so its incident cannot be cleared. */
    cbm_trace_record_t b[6];
    fill_orders(b, 6, 0);
    for (int i = 0; i < 6; i++) {
        snprintf(b[i].path, sizeof(b[i].path), "/api/widgets");
    }
    cbm_trace_ingest_stats_t sb = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", b, 6, &sb), CBM_STORE_OK);
    ASSERT_EQ(sb.routes_matched, 0);
    ASSERT_EQ(sb.incidents_resolved, 0);
    ASSERT_TRUE(incident_status_is(s, "active")); /* after: still latched */

    cbm_store_close(s);
    PASS();
}

/* ── #323 edge: exactly-at-threshold window does NOT resolve ─────────── */

TEST(trace_ingest_at_threshold_no_resolve) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_record_t a[8];
    fill_orders(a, 8, 6);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 8, &sa), CBM_STORE_OK);
    ASSERT_TRUE(incident_status_is(s, "active")); /* before */

    /* 8 requests, 4x 500 => error_rate 0.50 == INCIDENT_ERROR_RATE_HIGH: the
     * band is inclusive, so this is still an incident, never a recovery. */
    cbm_trace_record_t b[8];
    fill_orders(b, 8, 4);
    cbm_trace_ingest_stats_t sb = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", b, 8, &sb), CBM_STORE_OK);
    ASSERT_EQ(sb.incidents_resolved, 0);
    ASSERT_EQ(sb.incidents_detected, 1);
    ASSERT_TRUE(incident_status_is(s, "active")); /* after: still active */

    cbm_store_close(s);
    PASS();
}

/* ── #323 edge: flapping route active -> resolved -> active ──────────── */

TEST(trace_ingest_incident_flapping) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_record_t spike[8];
    fill_orders(spike, 8, 6);
    cbm_trace_record_t healthy[6];
    fill_orders(healthy, 6, 0);

    cbm_trace_ingest_stats_t s1 = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", spike, 8, &s1), CBM_STORE_OK);
    ASSERT_TRUE(incident_status_is(s, "active"));

    cbm_trace_ingest_stats_t s2 = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", healthy, 6, &s2), CBM_STORE_OK);
    ASSERT_EQ(s2.incidents_resolved, 1);
    ASSERT_TRUE(incident_status_is(s, "resolved"));

    /* Re-incident must RE-ACTIVATE the same node, not stay resolved. */
    cbm_trace_ingest_stats_t s3 = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", spike, 8, &s3), CBM_STORE_OK);
    ASSERT_EQ(s3.incidents_detected, 1);
    ASSERT_TRUE(incident_status_is(s, "active")); /* flipped back */

    /* Exactly ONE Incident node exists for the route (no duplicate latch). */
    cbm_node_t *incs = NULL;
    int nincs = 0;
    ASSERT_EQ(cbm_store_find_nodes_by_label(s, "test", "Incident", &incs, &nincs), CBM_STORE_OK);
    ASSERT_EQ(nincs, 1);
    cbm_store_free_nodes(incs, nincs);

    cbm_store_close(s);
    PASS();
}

/* ── #324: edge weights accumulate across distinct batches ───────────── */

TEST(trace_ingest_weights_accumulate_across_batches) {
    int64_t route_id = 0;
    cbm_store_t *s = setup_route_graph(&route_id, NULL, NULL);
    ASSERT_NOT_NULL(s);

    /* Batch A: 4 healthy requests => cumulative traffic 4. */
    cbm_trace_record_t a[4];
    fill_orders(a, 4, 0);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 4, &sa), CBM_STORE_OK);
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 4)); /* before: weight 4 */

    /* Batch B: 5 healthy requests (distinct content) => cumulative 4 + 5 = 9. */
    cbm_trace_record_t b[5];
    fill_orders(b, 5, 0);
    cbm_trace_ingest_stats_t sb = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", b, 5, &sb), CBM_STORE_OK);
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 9)); /* after: hand-computed 9 */

    /* RuntimeAnchor traffic reads back the cumulative total, not a per-batch one. */
    cbm_node_t anchor = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", ANCHOR_QN, &anchor), CBM_STORE_OK);
    ASSERT_TRUE(strstr(anchor.properties_json, "\"traffic\":9") != NULL);
    cbm_node_free_fields(&anchor);

    /* Two distinct TraceBatch ledger entries recorded. */
    cbm_node_t *batches = NULL;
    int nb = 0;
    ASSERT_EQ(cbm_store_find_nodes_by_label(s, "test", "TraceBatch", &batches, &nb), CBM_STORE_OK);
    ASSERT_EQ(nb, 2);
    cbm_store_free_nodes(batches, nb);

    /* Re-ingest batch A verbatim: fingerprint already ledgered => NO double
     * count. Weight stays 9 and no new ledger node is created. */
    cbm_trace_ingest_stats_t sc = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 4, &sc), CBM_STORE_OK);
    ASSERT_TRUE(assert_http_edge_promoted(s, route_id, 9));
    cbm_node_t *batches2 = NULL;
    int nb2 = 0;
    ASSERT_EQ(cbm_store_find_nodes_by_label(s, "test", "TraceBatch", &batches2, &nb2), CBM_STORE_OK);
    ASSERT_EQ(nb2, 2);
    cbm_store_free_nodes(batches2, nb2);

    cbm_store_close(s);
    PASS();
}

/* ── #324 edge: overflow-scale counts saturate, never wrap ───────────── */

TEST(trace_ingest_weight_overflow_saturates) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    /* Pre-seed the RuntimeAnchor near INT64_MAX to simulate long-run traffic
     * (before state: traffic == INT64_MAX - 2). */
    cbm_node_t seed = {.project = "test",
                       .label = "RuntimeAnchor",
                       .name = "/api/orders",
                       .qualified_name = ANCHOR_QN,
                       .file_path = "",
                       .properties_json = "{\"kind\":\"runtime_anchor\","
                                          "\"traffic\":9223372036854775805,\"error_count\":0}"};
    ASSERT_GT(cbm_store_upsert_node(s, &seed), 0);

    /* A distinct batch of 6 healthy requests would push traffic past INT64_MAX. */
    cbm_trace_record_t a[6];
    fill_orders(a, 6, 0);
    cbm_trace_ingest_stats_t sa = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", a, 6, &sa), CBM_STORE_OK);

    /* After: clamped at INT64_MAX (never a negative wrap), degradation labeled. */
    cbm_node_t back = {0};
    ASSERT_EQ(cbm_store_find_node_by_qn(s, "test", ANCHOR_QN, &back), CBM_STORE_OK);
    ASSERT_TRUE(strstr(back.properties_json, "\"traffic\":9223372036854775807") != NULL);
    ASSERT_TRUE(strstr(back.properties_json, "\"saturated\":true") != NULL);
    cbm_node_free_fields(&back);

    cbm_store_close(s);
    PASS();
}

/* ── #324 edge: an empty batch writes no ledger node ─────────────────── */

TEST(trace_ingest_empty_batch_no_ledger) {
    cbm_store_t *s = setup_route_graph(NULL, NULL, NULL);
    ASSERT_NOT_NULL(s);

    cbm_trace_ingest_stats_t st = {0};
    ASSERT_EQ(cbm_trace_ingest_records(s, "test", NULL, 0, &st), CBM_STORE_OK);

    cbm_node_t *batches = NULL;
    int nb = 0;
    ASSERT_EQ(cbm_store_find_nodes_by_label(s, "test", "TraceBatch", &batches, &nb), CBM_STORE_OK);
    ASSERT_EQ(nb, 0); /* nothing measured => nothing ledgered */
    cbm_store_free_nodes(batches, nb);

    cbm_store_close(s);
    PASS();
}

SUITE(trace_ingest) {
    RUN_TEST(trace_ingest_json_promotes);
    RUN_TEST(trace_ingest_protobuf_matches_json);
    RUN_TEST(trace_ingest_incident_on_5xx_spike);
    RUN_TEST(trace_ingest_below_threshold_no_incident);
    RUN_TEST(trace_ingest_idempotent);
    RUN_TEST(trace_ingest_simple_format);
    RUN_TEST(trace_ingest_empty_input);
    RUN_TEST(trace_ingest_invalid_protobuf);
    RUN_TEST(trace_ingest_unmatched_accounted);
    RUN_TEST(trace_ingest_incident_resolves_on_recovery);
    RUN_TEST(trace_ingest_incident_persists_on_empty_recovery);
    RUN_TEST(trace_ingest_incident_persists_when_route_absent);
    RUN_TEST(trace_ingest_at_threshold_no_resolve);
    RUN_TEST(trace_ingest_incident_flapping);
    RUN_TEST(trace_ingest_weights_accumulate_across_batches);
    RUN_TEST(trace_ingest_weight_overflow_saturates);
    RUN_TEST(trace_ingest_empty_batch_no_ledger);
}
