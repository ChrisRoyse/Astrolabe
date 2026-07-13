/*
 * trace_ingest.h — Runtime-trace ingestion into the code knowledge graph.
 *
 * Consumes normalized OTLP records (otlp_decode.h) or CBM's declared simple
 * `{caller, callee, count}` format and, against a real store:
 *
 *   1. Matches HTTP observations to Route nodes by CBM's deterministic route
 *      QN canonicalization (__route__METHOD__/path).
 *   2. Promotes the caller/cross-service edges into that Route (and the
 *      DATA_FLOWS through its handlers): props.validated=true, weight ->
 *      measured request count, trust Provisional -> Trusted, provenance ref.
 *   3. Writes runtime anchors: a RuntimeAnchor node per matched route carrying
 *      traffic/latency/error evidence, plus OBSERVED_TRAFFIC edges from the
 *      handler symbols (Recurrence occurrences).
 *   4. Detects incidents: when the 5xx rate over a route spikes past the
 *      declared threshold, an Incident node is labeled onto the route.
 *
 * Ingestion is idempotent: aggregates are written as absolute measured values
 * keyed by deterministic QN, and edge promotion is a json_patch, so ingesting
 * the same batch twice yields no double-promotion and no duplicate anchors.
 *
 * Every span is accounted: non-HTTP spans and HTTP spans that match no route
 * are counted and surfaced, never silently dropped (HONEST invariant 3).
 */
#ifndef CBM_TRACE_INGEST_H
#define CBM_TRACE_INGEST_H

#include <stdint.h>

#include "store/store.h"
#include "traces/otlp_decode.h"

/* CBM's declared simple ingestion record. */
typedef struct {
    char caller[256];
    char callee[256];
    int64_t count;
} cbm_trace_simple_t;

/* Accumulating ingestion statistics. Callers zero-initialize before the first
 * ingest call in a request and may pass the same struct to several calls. */
typedef struct {
    int spans_total;      /* every span the batch contained (set by caller) */
    int spans_http;       /* HTTP records handed to ingestion */
    int spans_non_http;   /* non-HTTP spans (set by caller from decoder) */
    int spans_unmatched;  /* HTTP records whose route matched no Route node */
    int routes_matched;   /* distinct Route nodes that received promotions */
    int edges_promoted;   /* edge upserts carrying validated/Trusted/weight */
    int anchors_written;  /* RuntimeAnchor nodes + occurrence edges written */
    int incidents_detected; /* Incident nodes labeled */
    int simple_records;   /* {caller,callee,count} records applied */
    int simple_unmatched; /* simple records with no matching edge */
} cbm_trace_ingest_stats_t;

/* Ingestion knobs (documented measurement thresholds, not magic constants). */
/* A route with >= INCIDENT_ERROR_RATE_HIGH of requests returning >=500 over
 * >= INCIDENT_MIN_REQUESTS samples is an incident. Two bands give severity. */
#define CBM_INCIDENT_MIN_REQUESTS 5
#define CBM_INCIDENT_ERROR_RATE_HIGH 0.5
#define CBM_INCIDENT_ERROR_RATE_CRITICAL 0.75

/* Ingest normalized OTLP records into `store` for `project`.
 * Fills routes_matched/edges_promoted/anchors_written/incidents_detected/
 * spans_http/spans_unmatched in *stats (accumulated). Returns CBM_STORE_OK or
 * CBM_STORE_ERR. A NULL/empty record set is success. */
int cbm_trace_ingest_records(cbm_store_t *store, const char *project,
                             const cbm_trace_record_t *records, int n,
                             cbm_trace_ingest_stats_t *stats);

/* Ingest simple {caller, callee, count} records: promote matching CALLS/
 * HTTP_CALLS/DATA_FLOWS edges between the named symbols with identical
 * validated/Trusted/weight semantics. Fills simple_records/simple_unmatched/
 * edges_promoted. */
int cbm_trace_ingest_simple(cbm_store_t *store, const char *project,
                            const cbm_trace_simple_t *simple, int n,
                            cbm_trace_ingest_stats_t *stats);

#endif /* CBM_TRACE_INGEST_H */
