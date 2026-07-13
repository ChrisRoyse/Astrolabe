/*
 * otlp_decode.h — Decode OpenTelemetry OTLP trace batches into normalized
 * HTTP records.
 *
 * Two wire encodings are supported, both matching the canonical
 * opentelemetry-proto `TracesData` message:
 *
 *   - Protobuf   (opentelemetry/proto/trace/v1/trace.proto binary wire format)
 *   - JSON       (proto3 JSON mapping; camelCase or snake_case field names)
 *
 * Both decoders converge on the SAME extraction path: they materialize each
 * span as a `cbm_trace_span_t` and reuse the tested helpers
 * `cbm_extract_service_name` / `cbm_extract_http_info` (traces.h). Callers get
 * a flat array of `cbm_trace_record_t`, one per HTTP span, plus explicit
 * accounting of every span that was seen but not an HTTP span — nothing is
 * silently dropped (HONEST invariant 3).
 */
#ifndef CBM_OTLP_DECODE_H
#define CBM_OTLP_DECODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <yyjson/yyjson.h>

/* One normalized HTTP observation extracted from a server-side span. */
typedef struct {
    char service[128];
    char method[16];
    char path[512];
    int status_code;    /* HTTP status; 0 when the span carried none */
    int64_t duration_ns;
    int span_kind;      /* OTLP SpanKind: 1 internal, 2 server, 3 client, ... */
} cbm_trace_record_t;

/* Result of decoding one OTLP batch. */
typedef struct {
    cbm_trace_record_t *records; /* heap array, record_count entries */
    int record_count;            /* HTTP records extracted */
    int record_cap;
    int spans_total;             /* every span the batch contained */
    int spans_non_http;          /* spans that were not HTTP (accounted) */
} cbm_otlp_batch_t;

/* Decode result codes. */
#define CBM_OTLP_OK 0
#define CBM_OTLP_ERR_ARGS (-1)   /* NULL args */
#define CBM_OTLP_ERR_FORMAT (-2) /* malformed / truncated wire bytes */
#define CBM_OTLP_ERR_OOM (-3)    /* allocation failure */

/* Decode an OTLP/JSON `TracesData` object.
 * `root` must be the JSON object that owns "resourceSpans" (or "resource_spans").
 * Appends decoded records to `out` (which the caller zero-initializes or reuses).
 * Returns CBM_OTLP_OK on success (an empty batch is success), or a negative
 * CBM_OTLP_ERR_* code. On error `out` is left freeable via cbm_otlp_batch_free. */
int cbm_otlp_decode_json(yyjson_val *root, cbm_otlp_batch_t *out);

/* Decode a JSON array of OTLP `ResourceSpans` objects directly (the value of
 * "resourceSpans"). Lets the MCP handler accept OTLP spans carried in the
 * legacy `traces` array as well as a top-level TracesData object. */
int cbm_otlp_decode_json_rspans(yyjson_val *rspans_array, cbm_otlp_batch_t *out);

/* Decode an OTLP protobuf `TracesData` message (`buf`, `len` bytes).
 * Bounds-checked: malformed or truncated input returns CBM_OTLP_ERR_FORMAT
 * rather than over-reading. Appends decoded records to `out`. */
int cbm_otlp_decode_protobuf(const uint8_t *buf, size_t len, cbm_otlp_batch_t *out);

/* Decode a base64-encoded OTLP protobuf `TracesData` message. Returns
 * CBM_OTLP_ERR_FORMAT on invalid base64 or malformed protobuf. */
int cbm_otlp_decode_protobuf_base64(const char *b64, cbm_otlp_batch_t *out);

/* Release a batch's record array. Safe on a zeroed struct. */
void cbm_otlp_batch_free(cbm_otlp_batch_t *b);

/* Append one record to a batch, growing as needed. Returns CBM_OTLP_OK or
 * CBM_OTLP_ERR_OOM. Exposed for the shared span-extraction path and tests. */
int cbm_otlp_batch_push(cbm_otlp_batch_t *out, const cbm_trace_record_t *rec);

#endif /* CBM_OTLP_DECODE_H */
