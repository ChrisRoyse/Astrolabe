#!/usr/bin/env python3
"""
gen_otlp_fixtures.py — Generate committed OTLP golden fixtures for ingest_traces.

Emits, for each logical batch, BOTH encodings of the canonical opentelemetry
`TracesData` message:

  * <name>.json  — proto3 JSON mapping (camelCase), UTF-8 bytes.
  * <name>.pb    — protobuf binary wire format.

and a self-contained C header (otlp_golden.h) embedding every fixture as a byte
array so the trace-ingest test does not depend on the working directory.

The protobuf encoder here hand-writes the real OTLP field numbers / wire types
(opentelemetry/proto/{trace,common,resource}/v1) — the bytes are genuine OTLP,
not a bespoke format. Field map:

  TracesData.resource_spans = 1
  ResourceSpans.resource = 1, .scope_spans = 2
  Resource.attributes = 1
  ScopeSpans.spans = 2
  Span.kind = 6 (varint), .start_time_unix_nano = 7 (fixed64),
       .end_time_unix_nano = 8 (fixed64), .attributes = 9
  KeyValue.key = 1, .value = 2
  AnyValue.string_value = 1, .int_value = 3

Run:  python cbm/tests/fixtures/otlp/gen_otlp_fixtures.py
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


# ── protobuf wire helpers ───────────────────────────────────────────
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field, wt):
    return varint((field << 3) | wt)


def len_delim(field, payload):
    return tag(field, 2) + varint(len(payload)) + payload


def fixed64(field, n):
    return tag(field, 1) + struct.pack("<Q", n)


def varint_field(field, n):
    return tag(field, 0) + varint(n)


def str_field(field, s):
    return len_delim(field, s.encode("utf-8"))


# ── OTLP message builders ───────────────────────────────────────────
def anyvalue_str(s):
    return str_field(1, s)          # AnyValue.string_value


def anyvalue_int(n):
    return varint_field(3, n)       # AnyValue.int_value


def keyvalue(key, value_bytes):
    return str_field(1, key) + len_delim(2, value_bytes)


def kv_str(key, s):
    return keyvalue(key, anyvalue_str(s))


def kv_int(key, n):
    return keyvalue(key, anyvalue_int(n))


def span_pb(sp):
    body = b""
    body += varint_field(6, sp["kind"])
    body += fixed64(7, sp["start"])
    body += fixed64(8, sp["end"])
    for a in sp["attrs"]:
        body += len_delim(9, a)
    return body


def resource_spans_pb(service, spans):
    resource = len_delim(1, kv_str("service.name", service))  # Resource.attributes
    scope_spans = b""
    inner = b""
    for sp in spans:
        inner += len_delim(2, span_pb(sp))                    # ScopeSpans.spans
    scope_spans = len_delim(2, inner)                         # ResourceSpans.scope_spans
    return len_delim(1, resource) + scope_spans               # .resource + .scope_spans


def tracesdata_pb(resource_spans_list):
    out = b""
    for service, spans in resource_spans_list:
        out += len_delim(1, resource_spans_pb(service, spans))  # TracesData.resource_spans
    return out


# ── OTLP JSON builders (proto3 JSON, camelCase) ─────────────────────
def span_attrs_json(sp, status_as_int):
    attrs = []
    for kind, key, val in sp["json_attrs"]:
        if kind == "str":
            attrs.append({"key": key, "value": {"stringValue": val}})
        else:  # int
            if status_as_int:
                attrs.append({"key": key, "value": {"intValue": str(val)}})
            else:
                attrs.append({"key": key, "value": {"stringValue": str(val)}})
    return attrs


def tracesdata_json(resource_spans_list, status_as_int):
    rs = []
    for service, spans in resource_spans_list:
        ss_spans = []
        for sp in spans:
            ss_spans.append({
                "kind": sp["kind"],
                "startTimeUnixNano": str(sp["start"]),
                "endTimeUnixNano": str(sp["end"]),
                "attributes": span_attrs_json(sp, status_as_int),
            })
        rs.append({
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service}}
                ]
            },
            "scopeSpans": [{"spans": ss_spans}],
        })
    return {"resourceSpans": rs}


# ── span construction ───────────────────────────────────────────────
BASE = 1_700_000_000_000_000_000  # arbitrary epoch-nanos base


def http_span(method, route, status, dur_ms):
    """A server-side HTTP span. protobuf uses int status, JSON uses str/int."""
    start = BASE
    end = BASE + dur_ms * 1_000_000
    pb_attrs = [
        kv_str("http.method", method),
        kv_str("http.route", route),
        kv_int("http.status_code", status),
    ]
    json_attrs = [
        ("str", "http.method", method),
        ("str", "http.route", route),
        ("int", "http.status_code", status),
    ]
    return {"kind": 2, "start": start, "end": end,
            "attrs": pb_attrs, "json_attrs": json_attrs}


def db_span():
    """A non-HTTP internal span (must be accounted, not dropped)."""
    return {"kind": 1, "start": BASE, "end": BASE + 5_000_000,
            "attrs": [kv_str("db.system", "postgresql")],
            "json_attrs": [("str", "db.system", "postgresql")]}


# Batch HEALTHY: 6x POST /api/orders 200 (10..60ms), 1x GET /api/unmatched 200,
# 1x non-HTTP span. Expected: route matched, weight 6, no incident,
# spans_non_http=1, spans_unmatched=1.
HEALTHY_SPANS = (
    [http_span("POST", "/api/orders", 200, ms) for ms in (10, 20, 30, 40, 50, 60)]
    + [http_span("GET", "/api/unmatched", 200, 5)]
    + [db_span()]
)

# Batch INCIDENT: 8x POST /api/orders, 6 of them 500 → error_rate 0.75 → critical.
INCIDENT_SPANS = (
    [http_span("POST", "/api/orders", 200, ms) for ms in (12, 24)]
    + [http_span("POST", "/api/orders", 500, ms) for ms in (30, 40, 50, 60, 70, 80)]
)

# Batch BELOW_THRESHOLD: 10x POST /api/orders, 1 of them 500 → error_rate 0.1 → no incident.
BELOW_SPANS = (
    [http_span("POST", "/api/orders", 200, ms) for ms in range(10, 100, 10)]
    + [http_span("POST", "/api/orders", 500, 55)]
)

BATCHES = {
    "orders_healthy": [("order-service", HEALTHY_SPANS)],
    "orders_incident": [("order-service", INCIDENT_SPANS)],
    "orders_below_threshold": [("order-service", BELOW_SPANS)],
}


def c_array(name, data):
    lines = ["static const unsigned char %s[] = {" % name]
    row = "    "
    for i, b in enumerate(data):
        row += "0x%02x," % b
        if (i + 1) % 12 == 0:
            lines.append(row)
            row = "    "
    if row.strip():
        lines.append(row)
    lines.append("};")
    lines.append("static const unsigned long %s_len = %d;" % (name, len(data)))
    return "\n".join(lines)


def main():
    header = [
        "/* otlp_golden.h - GENERATED by gen_otlp_fixtures.py. Do not edit by hand.",
        " * Committed OTLP golden batches (protobuf + JSON) for the trace-ingest test. */",
        "#ifndef CBM_OTLP_GOLDEN_H",
        "#define CBM_OTLP_GOLDEN_H",
        "",
    ]
    for name, rs_list in BATCHES.items():
        # protobuf uses int status; JSON healthy uses str status, others int —
        # this exercises both the string and int AnyValue paths across encodings.
        pb = tracesdata_pb(rs_list)
        status_as_int = (name != "orders_healthy")
        js = json.dumps(tracesdata_json(rs_list, status_as_int),
                        separators=(",", ":")).encode("utf-8")

        with open(os.path.join(HERE, name + ".pb"), "wb") as f:
            f.write(pb)
        with open(os.path.join(HERE, name + ".json"), "wb") as f:
            f.write(js)

        header.append(c_array(name + "_pb", pb))
        header.append(c_array(name + "_json", js))
        header.append("")

    header.append("#endif /* CBM_OTLP_GOLDEN_H */")
    with open(os.path.join(HERE, "otlp_golden.h"), "w", newline="\n") as f:
        f.write("\n".join(header) + "\n")
    print("wrote fixtures + otlp_golden.h to", HERE)


if __name__ == "__main__":
    main()
