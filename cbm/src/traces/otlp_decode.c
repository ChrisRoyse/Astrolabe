/*
 * otlp_decode.c — OTLP protobuf + JSON trace decoders.
 *
 * Both paths converge on records_from_span(), which reuses the tested
 * cbm_extract_service_name / cbm_extract_http_info helpers so protobuf and
 * JSON share ONE extraction semantics.
 */
#include "traces/otlp_decode.h"
#include "traces/traces.h"
#include "foundation/constants.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    OTLP_MAX_SPAN_ATTRS = 48,
    OTLP_KEY_BUF = 128,
    OTLP_VAL_BUF = 512,
    OTLP_TIME_BUF = 32,
    OTLP_BATCH_INIT_CAP = 16,
    /* protobuf field numbers (opentelemetry-proto) */
    PB_RS_RESOURCE = 1,   /* ResourceSpans.resource */
    PB_RS_SCOPESPANS = 2, /* ResourceSpans.scope_spans */
    PB_RES_ATTRS = 1,     /* Resource.attributes */
    PB_SS_SPANS = 2,      /* ScopeSpans.spans */
    PB_SPAN_KIND = 6,     /* Span.kind */
    PB_SPAN_START = 7,    /* Span.start_time_unix_nano (fixed64) */
    PB_SPAN_END = 8,      /* Span.end_time_unix_nano (fixed64) */
    PB_SPAN_ATTRS = 9,    /* Span.attributes */
    PB_KV_KEY = 1,        /* KeyValue.key */
    PB_KV_VALUE = 2,      /* KeyValue.value */
    PB_AV_STRING = 1,     /* AnyValue.string_value */
    PB_AV_INT = 3,        /* AnyValue.int_value (varint) */
    PB_TRACESDATA_RS = 1, /* TracesData.resource_spans */
    /* protobuf wire types */
    PB_WT_VARINT = 0,
    PB_WT_64BIT = 1,
    PB_WT_LEN = 2,
    PB_WT_32BIT = 5,
};

/* ── batch helpers ───────────────────────────────────────────────── */

int cbm_otlp_batch_push(cbm_otlp_batch_t *out, const cbm_trace_record_t *rec) {
    if (!out || !rec) {
        return CBM_OTLP_ERR_ARGS;
    }
    if (out->record_count >= out->record_cap) {
        int newcap = out->record_cap > 0 ? out->record_cap * 2 : OTLP_BATCH_INIT_CAP;
        cbm_trace_record_t *grown =
            realloc(out->records, (size_t)newcap * sizeof(*grown));
        if (!grown) {
            return CBM_OTLP_ERR_OOM;
        }
        out->records = grown;
        out->record_cap = newcap;
    }
    out->records[out->record_count++] = *rec;
    return CBM_OTLP_OK;
}

void cbm_otlp_batch_free(cbm_otlp_batch_t *b) {
    if (!b) {
        return;
    }
    free(b->records);
    b->records = NULL;
    b->record_count = 0;
    b->record_cap = 0;
}

/* ── shared span → record extraction ─────────────────────────────── */

/* Build a cbm_trace_span_t from materialized attrs and route it through the
 * tested HTTP extractor. Every span increments spans_total; HTTP spans push a
 * record, non-HTTP spans increment spans_non_http (accounted, never dropped). */
static int records_from_span(const cbm_trace_attr_t *attrs, int nattr, int kind,
                             const char *start, const char *end, const char *service,
                             cbm_otlp_batch_t *out) {
    out->spans_total++;

    cbm_trace_span_t span = {
        .kind = kind,
        .attributes = (cbm_trace_attr_t *)attrs,
        .attr_count = nattr,
        .start_time = start,
        .end_time = end,
    };
    cbm_http_span_info_t info;
    if (!cbm_extract_http_info(&span, service, &info)) {
        out->spans_non_http++;
        return CBM_OTLP_OK;
    }

    cbm_trace_record_t rec;
    memset(&rec, 0, sizeof(rec));
    snprintf(rec.service, sizeof(rec.service), "%s", info.service_name ? info.service_name : "");
    snprintf(rec.method, sizeof(rec.method), "%s", info.method ? info.method : "");
    snprintf(rec.path, sizeof(rec.path), "%s", info.path ? info.path : "");
    rec.status_code =
        info.status_code ? (int)strtol(info.status_code, NULL, CBM_DECIMAL_BASE) : 0;
    rec.duration_ns = info.duration_ns;
    rec.span_kind = info.span_kind;
    return cbm_otlp_batch_push(out, &rec);
}

/* ── JSON decode ─────────────────────────────────────────────────── */

/* Get an object member trying camelCase then snake_case. */
static yyjson_val *obj_get2(yyjson_val *obj, const char *camel, const char *snake) {
    if (!obj || !yyjson_is_obj(obj)) {
        return NULL;
    }
    yyjson_val *v = yyjson_obj_get(obj, camel);
    if (!v && snake) {
        v = yyjson_obj_get(obj, snake);
    }
    return v;
}

/* Coerce an OTLP/JSON AnyValue object into a NUL-terminated string in buf.
 * Handles stringValue and intValue (proto3 JSON encodes int64 as a string, but
 * we also accept a bare JSON number). Returns buf, or "" when no scalar. */
static const char *json_anyvalue_str(yyjson_val *value, char *buf, size_t bufsz) {
    buf[0] = '\0';
    if (!value || !yyjson_is_obj(value)) {
        return buf;
    }
    yyjson_val *s = obj_get2(value, "stringValue", "string_value");
    if (s && yyjson_is_str(s)) {
        snprintf(buf, bufsz, "%s", yyjson_get_str(s));
        return buf;
    }
    yyjson_val *iv = obj_get2(value, "intValue", "int_value");
    if (iv) {
        if (yyjson_is_str(iv)) {
            snprintf(buf, bufsz, "%s", yyjson_get_str(iv));
        } else if (yyjson_is_int(iv)) {
            snprintf(buf, bufsz, "%" PRId64, yyjson_get_sint(iv));
        } else if (yyjson_is_uint(iv)) {
            snprintf(buf, bufsz, "%" PRIu64, yyjson_get_uint(iv));
        }
        return buf;
    }
    return buf;
}

/* Extract service.name from a JSON resource object's attributes array. */
static void json_service_name(yyjson_val *resource, char *buf, size_t bufsz) {
    buf[0] = '\0';
    yyjson_val *attrs = obj_get2(resource, "attributes", "attributes");
    if (!attrs || !yyjson_is_arr(attrs)) {
        return;
    }
    size_t idx = 0;
    size_t max = 0;
    yyjson_val *kv = NULL;
    yyjson_arr_foreach(attrs, idx, max, kv) {
        yyjson_val *key = yyjson_obj_get(kv, "key");
        if (key && yyjson_is_str(key) && strcmp(yyjson_get_str(key), "service.name") == 0) {
            yyjson_val *value = yyjson_obj_get(kv, "value");
            json_anyvalue_str(value, buf, bufsz);
            return;
        }
    }
}

/* Parse span kind: accept an integer or the OTLP enum string. */
static int json_span_kind(yyjson_val *span) {
    yyjson_val *k = obj_get2(span, "kind", "kind");
    if (!k) {
        return 0;
    }
    if (yyjson_is_int(k) || yyjson_is_uint(k)) {
        return (int)yyjson_get_int(k);
    }
    if (yyjson_is_str(k)) {
        const char *s = yyjson_get_str(k);
        if (strcmp(s, "SPAN_KIND_SERVER") == 0) {
            return 2;
        }
        if (strcmp(s, "SPAN_KIND_CLIENT") == 0) {
            return 3;
        }
        if (strcmp(s, "SPAN_KIND_PRODUCER") == 0) {
            return 4;
        }
        if (strcmp(s, "SPAN_KIND_CONSUMER") == 0) {
            return 5;
        }
        return 1; /* internal / unspecified */
    }
    return 0;
}

/* Decode one JSON span. keybufs/valbufs are caller-owned scratch. */
static int json_decode_span(yyjson_val *span, const char *service, cbm_otlp_batch_t *out) {
    cbm_trace_attr_t attrs[OTLP_MAX_SPAN_ATTRS];
    static char valbufs[OTLP_MAX_SPAN_ATTRS][OTLP_VAL_BUF];
    int na = 0;

    yyjson_val *sa = obj_get2(span, "attributes", "attributes");
    if (sa && yyjson_is_arr(sa)) {
        size_t idx = 0;
        size_t max = 0;
        yyjson_val *kv = NULL;
        yyjson_arr_foreach(sa, idx, max, kv) {
            if (na >= OTLP_MAX_SPAN_ATTRS) {
                break;
            }
            yyjson_val *key = yyjson_obj_get(kv, "key");
            if (!key || !yyjson_is_str(key)) {
                continue;
            }
            yyjson_val *value = yyjson_obj_get(kv, "value");
            json_anyvalue_str(value, valbufs[na], OTLP_VAL_BUF);
            attrs[na].key = yyjson_get_str(key);
            attrs[na].string_value = valbufs[na];
            na++;
        }
    }

    char startbuf[OTLP_TIME_BUF] = "0";
    char endbuf[OTLP_TIME_BUF] = "0";
    yyjson_val *st = obj_get2(span, "startTimeUnixNano", "start_time_unix_nano");
    yyjson_val *en = obj_get2(span, "endTimeUnixNano", "end_time_unix_nano");
    if (st) {
        if (yyjson_is_str(st)) {
            snprintf(startbuf, sizeof(startbuf), "%s", yyjson_get_str(st));
        } else if (yyjson_is_uint(st)) {
            snprintf(startbuf, sizeof(startbuf), "%" PRIu64, yyjson_get_uint(st));
        } else if (yyjson_is_int(st)) {
            snprintf(startbuf, sizeof(startbuf), "%" PRId64, yyjson_get_sint(st));
        }
    }
    if (en) {
        if (yyjson_is_str(en)) {
            snprintf(endbuf, sizeof(endbuf), "%s", yyjson_get_str(en));
        } else if (yyjson_is_uint(en)) {
            snprintf(endbuf, sizeof(endbuf), "%" PRIu64, yyjson_get_uint(en));
        } else if (yyjson_is_int(en)) {
            snprintf(endbuf, sizeof(endbuf), "%" PRId64, yyjson_get_sint(en));
        }
    }

    return records_from_span(attrs, na, json_span_kind(span), startbuf, endbuf, service, out);
}

int cbm_otlp_decode_json_rspans(yyjson_val *rspans, cbm_otlp_batch_t *out) {
    if (!out) {
        return CBM_OTLP_ERR_ARGS;
    }
    if (!rspans || !yyjson_is_arr(rspans)) {
        /* Empty / absent resourceSpans is a valid empty batch. */
        return CBM_OTLP_OK;
    }

    size_t ri = 0;
    size_t rmax = 0;
    yyjson_val *rs = NULL;
    yyjson_arr_foreach(rspans, ri, rmax, rs) {
        char service[128];
        json_service_name(obj_get2(rs, "resource", "resource"), service, sizeof(service));

        yyjson_val *sspans = obj_get2(rs, "scopeSpans", "scope_spans");
        if (!sspans || !yyjson_is_arr(sspans)) {
            continue;
        }
        size_t si = 0;
        size_t smax = 0;
        yyjson_val *ss = NULL;
        yyjson_arr_foreach(sspans, si, smax, ss) {
            yyjson_val *spans = obj_get2(ss, "spans", "spans");
            if (!spans || !yyjson_is_arr(spans)) {
                continue;
            }
            size_t pi = 0;
            size_t pmax = 0;
            yyjson_val *span = NULL;
            yyjson_arr_foreach(spans, pi, pmax, span) {
                int rc = json_decode_span(span, service, out);
                if (rc != CBM_OTLP_OK) {
                    return rc;
                }
            }
        }
    }
    return CBM_OTLP_OK;
}

int cbm_otlp_decode_json(yyjson_val *root, cbm_otlp_batch_t *out) {
    if (!root || !out) {
        return CBM_OTLP_ERR_ARGS;
    }
    return cbm_otlp_decode_json_rspans(obj_get2(root, "resourceSpans", "resource_spans"), out);
}

/* ── protobuf decode ─────────────────────────────────────────────── */

static bool pb_read_varint(const uint8_t *buf, size_t len, size_t *pos, uint64_t *out) {
    uint64_t result = 0;
    int shift = 0;
    while (*pos < len) {
        uint8_t b = buf[*pos];
        (*pos)++;
        if (shift < 64) {
            result |= (uint64_t)(b & 0x7F) << shift;
        }
        if ((b & 0x80) == 0) {
            *out = result;
            return true;
        }
        shift += 7;
        if (shift > 70) {
            return false; /* varint too long — malformed */
        }
    }
    return false; /* truncated */
}

static bool pb_read_tag(const uint8_t *buf, size_t len, size_t *pos, uint32_t *field,
                        uint32_t *wt) {
    uint64_t tag = 0;
    if (!pb_read_varint(buf, len, pos, &tag)) {
        return false;
    }
    *field = (uint32_t)(tag >> 3);
    *wt = (uint32_t)(tag & 0x7);
    return true;
}

/* Advance *pos past one field's payload of wire type wt. On a length-delimited
 * field, sets region/region_len to the payload when region != NULL. */
static bool pb_field_bounds(const uint8_t *buf, size_t len, size_t *pos, uint32_t wt,
                            const uint8_t **region, size_t *region_len) {
    switch (wt) {
    case PB_WT_VARINT: {
        uint64_t v = 0;
        return pb_read_varint(buf, len, pos, &v);
    }
    case PB_WT_64BIT:
        if (*pos + 8 > len) {
            return false;
        }
        *pos += 8;
        return true;
    case PB_WT_32BIT:
        if (*pos + 4 > len) {
            return false;
        }
        *pos += 4;
        return true;
    case PB_WT_LEN: {
        uint64_t l = 0;
        if (!pb_read_varint(buf, len, pos, &l)) {
            return false;
        }
        if (l > len - *pos) {
            return false; /* payload runs past buffer */
        }
        if (region) {
            *region = buf + *pos;
            *region_len = (size_t)l;
        }
        *pos += (size_t)l;
        return true;
    }
    default:
        return false; /* unknown wire type (3/4 groups unsupported, deprecated) */
    }
}

/* Read a fixed64 little-endian value at *pos. */
static bool pb_read_fixed64(const uint8_t *buf, size_t len, size_t *pos, uint64_t *out) {
    if (*pos + 8 > len) {
        return false;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)buf[*pos + (size_t)i] << (8 * i);
    }
    *pos += 8;
    *out = v;
    return true;
}

/* Copy a length-delimited protobuf string region into a NUL-terminated buf. */
static void pb_copy_str(const uint8_t *region, size_t region_len, char *buf, size_t bufsz) {
    size_t n = region_len;
    if (n >= bufsz) {
        n = bufsz - 1;
    }
    memcpy(buf, region, n);
    buf[n] = '\0';
}

/* Decode an AnyValue message into a string (string_value or int_value). */
static void pb_decode_anyvalue(const uint8_t *buf, size_t len, char *out, size_t outsz) {
    out[0] = '\0';
    size_t pos = 0;
    while (pos < len) {
        uint32_t field = 0;
        uint32_t wt = 0;
        if (!pb_read_tag(buf, len, &pos, &field, &wt)) {
            return;
        }
        if (field == PB_AV_STRING && wt == PB_WT_LEN) {
            const uint8_t *region = NULL;
            size_t rlen = 0;
            if (!pb_field_bounds(buf, len, &pos, wt, &region, &rlen)) {
                return;
            }
            pb_copy_str(region, rlen, out, outsz);
            return;
        }
        if (field == PB_AV_INT && wt == PB_WT_VARINT) {
            uint64_t v = 0;
            if (!pb_read_varint(buf, len, &pos, &v)) {
                return;
            }
            snprintf(out, outsz, "%" PRId64, (int64_t)v);
            return;
        }
        if (!pb_field_bounds(buf, len, &pos, wt, NULL, NULL)) {
            return;
        }
    }
}

/* Decode a KeyValue message; fill key/val NUL-terminated buffers. */
static void pb_decode_keyvalue(const uint8_t *buf, size_t len, char *key, size_t keysz, char *val,
                               size_t valsz) {
    key[0] = '\0';
    val[0] = '\0';
    size_t pos = 0;
    while (pos < len) {
        uint32_t field = 0;
        uint32_t wt = 0;
        if (!pb_read_tag(buf, len, &pos, &field, &wt)) {
            return;
        }
        const uint8_t *region = NULL;
        size_t rlen = 0;
        if (!pb_field_bounds(buf, len, &pos, wt, &region, &rlen)) {
            return;
        }
        if (field == PB_KV_KEY && wt == PB_WT_LEN) {
            pb_copy_str(region, rlen, key, keysz);
        } else if (field == PB_KV_VALUE && wt == PB_WT_LEN) {
            pb_decode_anyvalue(region, rlen, val, valsz);
        }
    }
}

/* Decode one Span message and route it through records_from_span. */
static int pb_decode_span(const uint8_t *buf, size_t len, const char *service,
                          cbm_otlp_batch_t *out) {
    cbm_trace_attr_t attrs[OTLP_MAX_SPAN_ATTRS];
    static char keybufs[OTLP_MAX_SPAN_ATTRS][OTLP_KEY_BUF];
    static char valbufs[OTLP_MAX_SPAN_ATTRS][OTLP_VAL_BUF];
    int na = 0;
    int kind = 0;
    char startbuf[OTLP_TIME_BUF] = "0";
    char endbuf[OTLP_TIME_BUF] = "0";

    size_t pos = 0;
    while (pos < len) {
        uint32_t field = 0;
        uint32_t wt = 0;
        if (!pb_read_tag(buf, len, &pos, &field, &wt)) {
            return CBM_OTLP_ERR_FORMAT;
        }
        if (field == PB_SPAN_KIND && wt == PB_WT_VARINT) {
            uint64_t v = 0;
            if (!pb_read_varint(buf, len, &pos, &v)) {
                return CBM_OTLP_ERR_FORMAT;
            }
            kind = (int)v;
            continue;
        }
        if (field == PB_SPAN_START && wt == PB_WT_64BIT) {
            uint64_t v = 0;
            if (!pb_read_fixed64(buf, len, &pos, &v)) {
                return CBM_OTLP_ERR_FORMAT;
            }
            snprintf(startbuf, sizeof(startbuf), "%" PRIu64, v);
            continue;
        }
        if (field == PB_SPAN_END && wt == PB_WT_64BIT) {
            uint64_t v = 0;
            if (!pb_read_fixed64(buf, len, &pos, &v)) {
                return CBM_OTLP_ERR_FORMAT;
            }
            snprintf(endbuf, sizeof(endbuf), "%" PRIu64, v);
            continue;
        }
        const uint8_t *region = NULL;
        size_t rlen = 0;
        if (!pb_field_bounds(buf, len, &pos, wt, &region, &rlen)) {
            return CBM_OTLP_ERR_FORMAT;
        }
        if (field == PB_SPAN_ATTRS && wt == PB_WT_LEN && na < OTLP_MAX_SPAN_ATTRS) {
            pb_decode_keyvalue(region, rlen, keybufs[na], OTLP_KEY_BUF, valbufs[na], OTLP_VAL_BUF);
            attrs[na].key = keybufs[na];
            attrs[na].string_value = valbufs[na];
            na++;
        }
    }
    return records_from_span(attrs, na, kind, startbuf, endbuf, service, out);
}

/* Scan a message region for a specific field number and wire type LEN,
 * invoking cb on each matching payload. Returns false on malformed input. */
typedef int (*pb_region_cb)(const uint8_t *region, size_t rlen, void *ud);

static bool pb_foreach_len_field(const uint8_t *buf, size_t len, uint32_t want_field,
                                 pb_region_cb cb, void *ud, int *cb_rc) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t field = 0;
        uint32_t wt = 0;
        if (!pb_read_tag(buf, len, &pos, &field, &wt)) {
            return false;
        }
        const uint8_t *region = NULL;
        size_t rlen = 0;
        if (!pb_field_bounds(buf, len, &pos, wt, &region, &rlen)) {
            return false;
        }
        if (field == want_field && wt == PB_WT_LEN && region) {
            int rc = cb(region, rlen, ud);
            if (rc != CBM_OTLP_OK) {
                *cb_rc = rc;
                return true; /* propagate cb error, stop */
            }
        }
    }
    return true;
}

/* Extract service.name from a Resource message region. */
static int pb_resource_service(const uint8_t *region, size_t rlen, void *ud) {
    char *service = (char *)ud; /* buffer of size 128 */
    char key[OTLP_KEY_BUF];
    char val[OTLP_VAL_BUF];
    pb_decode_keyvalue(region, rlen, key, sizeof(key), val, sizeof(val));
    if (strcmp(key, "service.name") == 0) {
        snprintf(service, 128, "%s", val);
    }
    return CBM_OTLP_OK;
}

typedef struct {
    const char *service;
    cbm_otlp_batch_t *out;
} pb_span_ctx_t;

static int pb_scopespans_span_cb(const uint8_t *region, size_t rlen, void *ud) {
    pb_span_ctx_t *ctx = (pb_span_ctx_t *)ud;
    return pb_decode_span(region, rlen, ctx->service, ctx->out);
}

static int pb_resourcespans_scopespans_cb(const uint8_t *region, size_t rlen, void *ud) {
    /* region is a ScopeSpans message; iterate its spans (field 2). */
    int cb_rc = CBM_OTLP_OK;
    if (!pb_foreach_len_field(region, rlen, PB_SS_SPANS, pb_scopespans_span_cb, ud, &cb_rc)) {
        return CBM_OTLP_ERR_FORMAT;
    }
    return cb_rc;
}

static int pb_decode_resource_spans(const uint8_t *region, size_t rlen, void *ud) {
    cbm_otlp_batch_t *out = (cbm_otlp_batch_t *)ud;
    /* Pass 1: resolve service.name from the resource (order-independent). */
    char service[128] = "";
    int cb_rc = CBM_OTLP_OK;
    /* find resource submessage(s) then its attributes */
    size_t pos = 0;
    while (pos < rlen) {
        uint32_t field = 0;
        uint32_t wt = 0;
        if (!pb_read_tag(region, rlen, &pos, &field, &wt)) {
            return CBM_OTLP_ERR_FORMAT;
        }
        const uint8_t *sub = NULL;
        size_t sublen = 0;
        if (!pb_field_bounds(region, rlen, &pos, wt, &sub, &sublen)) {
            return CBM_OTLP_ERR_FORMAT;
        }
        if (field == PB_RS_RESOURCE && wt == PB_WT_LEN && sub) {
            int rc = CBM_OTLP_OK;
            if (!pb_foreach_len_field(sub, sublen, PB_RES_ATTRS, pb_resource_service, service,
                                      &rc)) {
                return CBM_OTLP_ERR_FORMAT;
            }
        }
    }
    /* Pass 2: decode scope_spans spans with the resolved service. */
    pb_span_ctx_t ctx = {.service = service, .out = out};
    if (!pb_foreach_len_field(region, rlen, PB_RS_SCOPESPANS, pb_resourcespans_scopespans_cb, &ctx,
                              &cb_rc)) {
        return CBM_OTLP_ERR_FORMAT;
    }
    return cb_rc;
}

int cbm_otlp_decode_protobuf(const uint8_t *buf, size_t len, cbm_otlp_batch_t *out) {
    if (!out) {
        return CBM_OTLP_ERR_ARGS;
    }
    if (!buf || len == 0) {
        return CBM_OTLP_OK; /* empty batch */
    }
    int cb_rc = CBM_OTLP_OK;
    if (!pb_foreach_len_field(buf, len, PB_TRACESDATA_RS, pb_decode_resource_spans, out, &cb_rc)) {
        return CBM_OTLP_ERR_FORMAT;
    }
    return cb_rc;
}

/* ── base64 → protobuf ───────────────────────────────────────────── */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

int cbm_otlp_decode_protobuf_base64(const char *b64, cbm_otlp_batch_t *out) {
    if (!out) {
        return CBM_OTLP_ERR_ARGS;
    }
    if (!b64 || b64[0] == '\0') {
        return CBM_OTLP_OK; /* empty batch */
    }
    size_t inlen = strlen(b64);
    uint8_t *buf = malloc(inlen / 4 * 3 + 4);
    if (!buf) {
        return CBM_OTLP_ERR_OOM;
    }
    size_t olen = 0;
    int quad[4];
    int qn = 0;
    for (size_t i = 0; i < inlen; i++) {
        char c = b64[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue; /* padding / whitespace */
        }
        int v = b64_val(c);
        if (v < 0) {
            free(buf);
            return CBM_OTLP_ERR_FORMAT;
        }
        quad[qn++] = v;
        if (qn == 4) {
            buf[olen++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
            buf[olen++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
            buf[olen++] = (uint8_t)((quad[2] << 6) | quad[3]);
            qn = 0;
        }
    }
    if (qn == 3) {
        buf[olen++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
        buf[olen++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
    } else if (qn == 2) {
        buf[olen++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
    } else if (qn == 1) {
        free(buf);
        return CBM_OTLP_ERR_FORMAT; /* stray byte — invalid base64 */
    }
    int rc = cbm_otlp_decode_protobuf(buf, olen, out);
    free(buf);
    return rc;
}
