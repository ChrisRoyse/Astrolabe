/*
 * pass_calls.c — Resolve function/method calls into CALLS edges.
 *
 * For each discovered file:
 *   1. Re-extract calls (cbm_extract_file)
 *   2. Build per-file import map from IMPORTS edges in graph buffer
 *   3. Resolve each call only from LSP/import/module/qualified-path evidence
 *   4. Create CALLS edges in graph buffer with confidence/strategy properties
 *
 * Depends on: pass_definitions having populated the registry and graph buffer
 */
#include "foundation/constants.h"

enum { PC_RING = 4, PC_RING_MASK = 3, PC_SIG_SCAN = 15, PC_REGEX_GRP = 2 };
/* Byte budget reserved for the ,"line":<int> field (comma + "line" key (7) +
 * colon + up to 10 digits + NUL). Mirrors PP_LINE_MARGIN in pass_parallel.c so
 * the sequential CALLS finalizer reserves identical room as the parallel path
 * (#516). */
enum { CC_LINE_MARGIN = 24 };
/* Confidence for a service-pattern HTTP/ASYNC edge emitted when registry
 * resolution is empty (external, unindexed client library) — see #523. */
#define PC_SVC_PATTERN_CONF 0.5
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h"
#include "pipeline/lsp_resolve.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "foundation/str_util.h"
#include "cbm.h"
#include "service_patterns.h"

#include "foundation/compat_regex.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* True for languages whose module QN derives from the CONTAINING DIRECTORY
 * (Java/Go package). MUST match cbm_lang_module_is_dir() (internal/cbm/helpers.c)
 * so same-module callee resolution keys against the directory-based def-node
 * QNs in the registry. */
static bool pc_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

/* Read entire file into heap-allocated buffer. Caller must free(). */
static char *read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > cbm_max_file_bytes()) { /* generous, env-configurable cap (B4) */
        (void)fclose(f);
        return NULL;
    }

    /* +pad: tree-sitter lexer lookahead reads past EOF; keep it in-bounds */
    enum { CBM_TS_LOOKAHEAD_PAD = 16 };
    char *buf = malloc((size_t)size + CBM_TS_LOOKAHEAD_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, SKIP_ONE, size, f);
    (void)fclose(f);

    if (nread > (size_t)size) {
        nread = (size_t)size;
    }
    memset(buf + nread, 0, CBM_TS_LOOKAHEAD_PAD);
    *out_len = (int)nread;
    return buf;
}

/* Format int for logging. Thread-safe via TLS. */
static const char *itoa_log(int val) {
    static CBM_TLS char bufs[PC_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PC_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

typedef struct {
    int local_only;
    int member_without_type;
    int target_missing;
    int ambiguous;
    int incompatible;
} call_resolution_stats_t;

static void calls_record_unresolved(const cbm_resolution_t *resolution,
                                    call_resolution_stats_t *stats) {
    if (resolution->strategy && strstr(resolution->strategy, "ambiguous")) {
        stats->ambiguous++;
    } else if (resolution->strategy && (strstr(resolution->strategy, "overflow") ||
                                        strstr(resolution->strategy, "invalid"))) {
        stats->incompatible++;
    } else {
        stats->target_missing++;
    }
}

/* Handle a route registration call: create Route node + HANDLES edge. */
static void handle_route_registration(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                      const cbm_gbuf_node_t *source_node, const char *module_qn,
                                      const char **imp_keys, const char **imp_vals, int imp_count) {
    const char *method = cbm_service_pattern_route_method(call->callee_name);
    char route_qn[CBM_ROUTE_QN_SIZE];
    char cpath[CBM_SZ_256];
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", method ? method : "ANY",
             cbm_route_canon_path(call->first_string_arg, cpath, sizeof(cpath)));
    char route_props[CBM_SZ_256];
    snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method ? method : "ANY");
    int64_t route_id = cbm_gbuf_upsert_node(ctx->gbuf, "Route", call->first_string_arg, route_qn,
                                            "", 0, 0, route_props);
    char esc_cn[CBM_SZ_256]; /* sliced source text: escape quotes/newlines */
    char esc_fa[CBM_SZ_256];
    cbm_json_escape(esc_cn, sizeof(esc_cn), call->callee_name);
    cbm_json_escape(esc_fa, sizeof(esc_fa), call->first_string_arg);
    char props[CBM_SZ_512];
    snprintf(props, sizeof(props),
             "{\"callee\":\"%s\",\"url_path\":\"%s\",\"via\":\"route_registration\"}", esc_cn,
             esc_fa);
    cbm_gbuf_insert_edge(ctx->gbuf, source_node->id, route_id, "CALLS", props);
    if (call->second_arg_name != NULL && call->second_arg_name[0] != '\0') {
        cbm_resolution_t hres = cbm_registry_resolve_exact(
            ctx->registry, call->second_arg_name, module_qn, imp_keys, imp_vals, imp_count);
        if (hres.qualified_name != NULL && hres.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *handler = cbm_gbuf_find_by_qn_domain(
                ctx->gbuf, hres.qualified_name, CBM_REF_DOMAIN_CALLABLE, "calls.route_handler");
            if (handler != NULL) {
                char hprops[CBM_SZ_1K]; /* must exceed escaped value + wrapper or snprintf cuts the
                                           closing brace */
                char esc_h[CBM_SZ_512];
                cbm_json_escape(esc_h, sizeof(esc_h), hres.qualified_name);
                snprintf(hprops, sizeof(hprops), "{\"handler\":\"%s\"}", esc_h);
                cbm_gbuf_insert_edge(ctx->gbuf, handler->id, route_id, "HANDLES", hprops);
            }
        }
    }
}

/* Emit an HTTP/async route edge for a service call. */
/* Build route QN and upsert Route node for HTTP/async edge. */
static int64_t create_svc_route_node(cbm_pipeline_ctx_t *ctx, const char *url, cbm_svc_kind_t svc,
                                     const char *method, const char *broker) {
    /* #512: a non-UTF-8 byte in the URL literal must not reach the Route QN raw.
     * The post-merge route_edge_visitor (pass_route_nodes.c) builds its Route QN
     * from the HTTP_CALLS edge's url_path property, which was written through
     * cbm_json_escape (#493) and therefore already carries U+FFFD in place of any
     * bad byte. If this path kept the raw byte in the QN, the two Route nodes
     * would differ in the graph buffer and acquire different source atoms after
     * the #503 dump sanitizer changes one persistence value. Sanitizing the URL
     * to the identical UTF-8-safe form here makes both paths produce the same
     * immutable facts and atom before the dump. */
    char sane_url[CBM_SZ_512];
    cbm_utf8_sanitize(sane_url, sizeof(sane_url), url ? url : "");
    char route_qn[CBM_ROUTE_QN_SIZE];
    const char *prefix;
    char cpath[CBM_SZ_256];
    const char *qpath = sane_url;
    if (svc == CBM_SVC_HTTP) {
        prefix = method ? method : "ANY";
        qpath = cbm_route_canon_path(sane_url, cpath, sizeof(cpath));
    } else {
        prefix = broker ? broker : "async";
    }
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", prefix, qpath);
    /* Properties must be well-formed JSON on every path (#512): the pre-fix code
     * passed the bare method/broker string (e.g. "GET") as the properties column,
     * producing an unparseable Route node — mismatched with the well-formed
     * {"method":...} the route_edge_visitor path emits for the same call. */
    char route_props[CBM_SZ_256];
    if (svc == CBM_SVC_HTTP && method) {
        snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method);
    } else if (svc == CBM_SVC_ASYNC && broker) {
        snprintf(route_props, sizeof(route_props), "{\"broker\":\"%s\"}", broker);
    } else {
        snprintf(route_props, sizeof(route_props), "{}");
    }
    return cbm_gbuf_upsert_node(ctx->gbuf, "Route", sane_url, route_qn, "", 0, 0, route_props);
}

/* Finalize an edge's props and emit it. Mirrors finalize_and_emit() on the
 * parallel path (pass_parallel.c) byte-for-byte so an edge carries identical
 * args + call-site-line evidence regardless of which pipeline produced it —
 * the sequential <50-file path (this file) or the parallel >=50-file path
 * (#514/#516). The base object arrives closed ("...}"); we strip the trailing
 * '}', append ,"args":[...] through the shared serializer (same per-arg caps,
 * same #493 UTF-8-boundary truncation, same buffer-budget cutoff), append
 * ,"line":N for CALLS edges, then restore '}'.
 *
 * Correctness depends on `props` being a CBM_SZ_2K buffer (matching the parallel
 * path's finalize buffer): the args-array truncation budget is bounded by the
 * buffer size, so a smaller buffer would truncate a many-arg call at a different
 * point and break byte-parity. The prior sequential serializer capped each arg
 * through a 512-byte intermediate (`one[512]`) and DROPPED any arg whose escaped
 * expr+value overflowed it wholesale — so a >512-byte string argument vanished on
 * the sequential path while the parallel path kept it capped+truncated (#516). */
static void calls_emit_edge(cbm_gbuf_t *gbuf, int64_t src, int64_t tgt, const char *type,
                            char *props, size_t cap, const CBMCall *call) {
    if (call) {
        size_t len = strlen(props);
        if (len >= SKIP_ONE && props[len - SKIP_ONE] == '}') {
            /* Overwrite the trailing '}'; append_args_json / the line field and
             * the restored '}' rebuild the object from there. */
            size_t pos = cbm_pipeline_append_args_json(props, cap, len - SKIP_ONE, call);
            if (call->start_line > 0 && strcmp(type, "CALLS") == 0 && pos < cap - CC_LINE_MARGIN) {
                int ln = snprintf(props + pos, cap - pos, ",\"line\":%d", call->start_line);
                if (ln > 0) {
                    pos += (size_t)ln;
                }
            }
            if (pos < cap - SKIP_ONE) {
                props[pos] = '}';
                props[pos + SKIP_ONE] = '\0';
            }
        }
    }
    cbm_gbuf_insert_edge(gbuf, src, tgt, type, props);
}

static void emit_http_async_edge(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                 const cbm_gbuf_node_t *source, const cbm_gbuf_node_t *target,
                                 const cbm_resolution_t *res, cbm_svc_kind_t svc,
                                 bool suppress_plain_calls) {
    const char *url_or_topic = call->first_string_arg;
    bool is_url = (url_or_topic && url_or_topic[0] != '\0' &&
                   (url_or_topic[0] == '/' || strstr(url_or_topic, "://") != NULL));
    bool is_topic = (url_or_topic && url_or_topic[0] != '\0' && svc == CBM_SVC_ASYNC &&
                     strlen(url_or_topic) > PAIR_LEN);
    if (!is_url && !is_topic) {
        /* No URL/topic → this is not a real service call; the svc kind was a
         * substring coincidence in the resolved QN (e.g. "SalesforceRestClient"
         * matches the "RestClient" HTTP lib). Emit a plain CALLS edge — unless a
         * weak TS/JS member-call match should be suppressed (#592/#606). */
        if (suppress_plain_calls) {
            return;
        }
        char esc_callee[CBM_SZ_256];
        cbm_json_escape(esc_callee, sizeof(esc_callee), call->callee_name);
        char props[CBM_SZ_2K]; /* 2K: match the parallel finalize buffer so args truncate alike
                                  (#516) */
        snprintf(props, sizeof(props),
                 "{\"callee\":\"%s\",\"confidence\":%.2f,\"strategy\":\"%s\",\"candidates\":%d}",
                 esc_callee, res->confidence, res->strategy ? res->strategy : "unknown",
                 res->candidate_count);
        calls_emit_edge(ctx->gbuf, source->id, target->id, "CALLS", props, sizeof(props), call);
        return;
    }
    const char *edge_type = (svc == CBM_SVC_HTTP) ? "HTTP_CALLS" : "ASYNC_CALLS";
    const char *method =
        (svc == CBM_SVC_HTTP) ? cbm_service_pattern_http_method(call->callee_name) : NULL;
    const char *broker =
        (svc == CBM_SVC_ASYNC) ? cbm_service_pattern_broker(res->qualified_name) : NULL;
    int64_t route_id = create_svc_route_node(ctx, url_or_topic, svc, method, broker);
    char esc_callee[CBM_SZ_256];
    char esc_url[CBM_SZ_256];
    cbm_json_escape(esc_callee, sizeof(esc_callee), call->callee_name);
    cbm_json_escape(esc_url, sizeof(esc_url), url_or_topic);
    char
        props[CBM_SZ_2K]; /* 2K: match the parallel finalize buffer so args truncate alike (#516) */
    snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"url_path\":\"%s\"%s%s%s%s%s}", esc_callee,
             esc_url, method ? ",\"method\":\"" : "", method ? method : "", method ? "\"" : "",
             broker ? ",\"broker\":\"" : "", broker ? broker : "");
    if (broker) {
        size_t plen = strlen(props);
        if (plen > 0 && props[plen - SKIP_ONE] != '}') {
            snprintf(props + plen - 1, sizeof(props) - plen + SKIP_ONE, "\"}");
        }
    }
    calls_emit_edge(ctx->gbuf, source->id, route_id, edge_type, props, sizeof(props), call);
}

/* Classify a resolved call and emit the appropriate edge. */
/* When suppress_plain_calls is true (a TS/JS/TSX weak short-name member-call
 * match, #592/#606), the route/HTTP/ASYNC/CONFIG service classifications below
 * still run — only the plain CALLS fall-through is skipped, so a fabricated
 * project edge is dropped while every service edge stays main-identical. */
static void emit_classified_edge(cbm_pipeline_ctx_t *ctx, const CBMCall *call,
                                 const cbm_gbuf_node_t *source, const cbm_gbuf_node_t *target,
                                 const cbm_resolution_t *res, const char *module_qn,
                                 const char **imp_keys, const char **imp_vals, int imp_count,
                                 bool suppress_plain_calls) {
    cbm_svc_kind_t svc = cbm_service_pattern_match(res->qualified_name);
    if (svc == CBM_SVC_ROUTE_REG && call->first_string_arg && call->first_string_arg[0] == '/') {
        handle_route_registration(ctx, call, source, module_qn, imp_keys, imp_vals, imp_count);
        return;
    }
    if (svc == CBM_SVC_HTTP || svc == CBM_SVC_ASYNC) {
        emit_http_async_edge(ctx, call, source, target, res, svc, suppress_plain_calls);
        return;
    }
    if (svc == CBM_SVC_CONFIG) {
        char esc_c[CBM_SZ_256];
        char esc_k[CBM_SZ_256];
        cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
        cbm_json_escape(esc_k, sizeof(esc_k), call->first_string_arg ? call->first_string_arg : "");
        char props[CBM_SZ_2K]; /* 2K: match the parallel finalize buffer so args truncate alike
                                  (#516) */
        snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"key\":\"%s\",\"confidence\":%.2f}",
                 esc_c, esc_k, res->confidence);
        calls_emit_edge(ctx->gbuf, source->id, target->id, "CONFIGURES", props, sizeof(props),
                        call);
        return;
    }
    if (suppress_plain_calls) {
        return; /* weak TS/JS member-call match with an unresolved receiver (#606) */
    }
    char esc_c2[CBM_SZ_256];
    cbm_json_escape(esc_c2, sizeof(esc_c2), call->callee_name);
    char
        props[CBM_SZ_2K]; /* 2K: match the parallel finalize buffer so args truncate alike (#516) */
    snprintf(props, sizeof(props),
             "{\"callee\":\"%s\",\"confidence\":%.2f,\"strategy\":\"%s\",\"candidates\":%d}",
             esc_c2, res->confidence, res->strategy ? res->strategy : "unknown",
             res->candidate_count);
    calls_emit_edge(ctx->gbuf, source->id, target->id, "CALLS", props, sizeof(props), call);
}

/* Find source node for a call: enclosing function or file node. */
static const cbm_gbuf_node_t *calls_find_source(cbm_pipeline_ctx_t *ctx, const char *rel,
                                                const char *module_qn, const char *enclosing_qn,
                                                int call_line) {
    return cbm_pipeline_find_reference_source(ctx->gbuf, ctx->project_name, rel, module_qn,
                                              enclosing_qn, call_line, "calls.reference_source");
}

/* Resolve one call and emit the appropriate edge. Returns 1 if resolved, 0 if not. */
static int resolve_single_call(cbm_pipeline_ctx_t *ctx, CBMCall *call,
                               const CBMResolvedCallArray *lsp_calls, const char *rel,
                               const char *module_qn, const char **imp_keys, const char **imp_vals,
                               int imp_count, CBMLanguage lang, call_resolution_stats_t *stats) {
    const cbm_gbuf_node_t *source_node =
        calls_find_source(ctx, rel, module_qn, call->enclosing_func_qn, call->start_line);
    if (!source_node) {
        return 0;
    }

    /* LSP-resolved calls take precedence over registry-textual matching.
     * Unique-tail fallbacks are JVM-only (see cbm_pipeline_lsp_allow_tail_match). */
    bool allow_tail = cbm_pipeline_lsp_allow_tail_match(lang);
    const CBMResolvedCall *lsp = cbm_pipeline_find_lsp_resolution(lsp_calls, call, allow_tail);
    if (lsp) {
        const cbm_gbuf_node_t *target_node =
            cbm_pipeline_lsp_target_node(ctx->gbuf, ctx->project_name, lsp->callee_qn, allow_tail);
        if (target_node && source_node->id != target_node->id) {
            cbm_resolution_t res = {0};
            /* Use the gbuf node's QN so downstream edge props show the canonical
             * project-qualified form even when fallback prefixed the project. */
            res.qualified_name = target_node->qualified_name;
            res.confidence = lsp->confidence;
            res.strategy = lsp->strategy;
            res.candidate_count = 1;
            emit_classified_edge(ctx, call, source_node, target_node, &res, module_qn, imp_keys,
                                 imp_vals, imp_count, false);
            return SKIP_ONE;
        }
    }
    if (call->reference.evidence == CBM_REF_EVIDENCE_LOCAL) {
        stats->local_only++;
        return 0;
    }

    /* Service-pattern HTTP/ASYNC client call (`requests.get(url)`): the service
     * signal lives in the callee_name. The registry can mis-resolve such a call
     * to a spurious builtin short-name match (e.g. `requests.get` ->
     * `builtins.dict.get` via "get", strategy unique_name), which is non-empty
     * and not an HTTP pattern, so BOTH the empty-resolution and resolved-QN
     * service checks below miss it and the call is dropped. Detect it on the
     * callee_name FIRST so the HTTP_CALLS/ASYNC_CALLS edge is emitted regardless
     * (target is a synthesized route node, not the unindexed library). (#523) */
    cbm_svc_kind_t csvc = cbm_service_pattern_match(call->callee_name);
    if (csvc == CBM_SVC_HTTP || csvc == CBM_SVC_ASYNC) {
        const char *cu = call->first_string_arg;
        bool chas_url = cu && cu[0] != '\0' &&
                        (cu[0] == '/' || strstr(cu, "://") != NULL ||
                         (csvc == CBM_SVC_ASYNC && strlen(cu) > PAIR_LEN));
        if (chas_url) {
            cbm_resolution_t svc_res = {.qualified_name = call->callee_name,
                                        .confidence = PC_SVC_PATTERN_CONF,
                                        .strategy = "service_pattern",
                                        .candidate_count = 0};
            emit_http_async_edge(ctx, call, source_node, NULL, &svc_res, csvc, false);
            return SKIP_ONE;
        }
    }
    if (call->reference.evidence == CBM_REF_EVIDENCE_MEMBER &&
        !call->reference.resolved_target_qn) {
        if (cbm_service_pattern_route_method(call->callee_name) != NULL && call->first_string_arg &&
            call->first_string_arg[0] == '/') {
            handle_route_registration(ctx, call, source_node, module_qn, imp_keys, imp_vals,
                                      imp_count);
            return SKIP_ONE;
        }
        stats->member_without_type++;
        return 0;
    }

    cbm_resolution_t res =
        call->reference.resolved_target_qn
            ? (cbm_resolution_t){call->reference.resolved_target_qn, "self_member", 1.0, 1}
            : cbm_registry_resolve_exact(ctx->registry, call->callee_name, module_qn, imp_keys,
                                         imp_vals, imp_count);
    if (!res.qualified_name || res.qualified_name[0] == '\0') {
        /* Resolution is empty when the callee belongs to an EXTERNAL client
         * library whose source is not in the indexed tree (e.g. `requests.get`,
         * `httpx.post`) — the import map skips it (no node) and no project symbol
         * matches. The service-pattern signal lives in the RAW callee_name
         * ("requests.get" contains "requests"), so classify on that and emit the
         * HTTP_CALLS/ASYNC_CALLS edge directly (target is a synthesized route
         * node, not the absent library). Without this the call is dropped and
         * cross-repo matching finds no edge to match (#523). The parallel path
         * has the equivalent empty-resolution fallback in resolve_file_calls. */
        cbm_svc_kind_t esvc = cbm_service_pattern_match(call->callee_name);
        if (esvc == CBM_SVC_HTTP || esvc == CBM_SVC_ASYNC) {
            const char *u = call->first_string_arg;
            bool has_url_or_topic = u && u[0] != '\0' &&
                                    (u[0] == '/' || strstr(u, "://") != NULL ||
                                     (esvc == CBM_SVC_ASYNC && strlen(u) > PAIR_LEN));
            if (has_url_or_topic) {
                cbm_resolution_t svc_res = {.qualified_name = call->callee_name,
                                            .confidence = PC_SVC_PATTERN_CONF,
                                            .strategy = "service_pattern",
                                            .candidate_count = 0};
                emit_http_async_edge(ctx, call, source_node, NULL, &svc_res, esvc, false);
                return SKIP_ONE;
            }
        }
        calls_record_unresolved(&res, stats);
        return 0;
    }

    /* Perl call-graph noise guard (#476). Perl has no LSP resolver, so the
     * generic registry chain is the only resolver; for builtins (push/shift/
     * keys/...) and method calls ($obj->m with an unresolved receiver), a *weak*
     * cross-file short-name match to a project sub sharing the name is almost
     * always a false positive. Suppress only those weak matches; KEEP the
     * high-confidence same_module / import_map strategies so a genuine
     * same-file or imported call to a builtin-named sub still resolves. Gated
     * to Perl — other languages are unaffected. */
    if (cbm_perl_suppress_generic_match(lang == CBM_LANG_PERL, call->is_method, call->callee_name,
                                        res.strategy)) {
        return 0;
    }

    /* TS/JS/TSX weak-method suppression (#592/#606). A member call x.foo() only
     * reaches the registry when the TS-LSP could not resolve the receiver type
     * (the LSP block above already returned for type-resolved calls, including
     * the "resolved but target out of gbuf" fall-through). Binding such a call
     * by a weak short-name strategy fabricates an edge (`re.test()` -> a project
     * `test`). Rather than drop it here — which would also skip the service
     * bypasses below and emit_classified_edge's route/HTTP/CONFIG branches —
     * defer to emit_classified_edge and suppress ONLY the plain-CALLS
     * fall-through, so every service edge stays main-identical. res.strategy may
     * be lsp_* here; the helper's explicit drop-list leaves lsp_* untouched. */
    bool is_tsjs =
        lang == CBM_LANG_JAVASCRIPT || lang == CBM_LANG_TYPESCRIPT || lang == CBM_LANG_TSX;
    bool tsjs_drop_plain_call =
        cbm_tsjs_suppress_weak_method_match(is_tsjs, call->is_method, res.strategy);

    /* Service-pattern HTTP/ASYNC calls to an EXTERNAL client library (e.g.
     * `requests.get("/api/orders/{id}")`) resolve to a QN containing the library
     * name ("requests"), but that library is not in the indexed tree so
     * cbm_gbuf_find_by_qn returns NULL. The edge target for such calls is a
     * SYNTHESIZED route node (create_svc_route_node), not the library node, so
     * the missing target must NOT drop the call — otherwise no HTTP_CALLS edge
     * is written and cross-repo matching finds nothing (#523). Emit directly
     * when the call carries a URL/topic first argument. */
    cbm_svc_kind_t svc = cbm_service_pattern_match(res.qualified_name);
    if (svc == CBM_SVC_HTTP || svc == CBM_SVC_ASYNC) {
        const char *u = call->first_string_arg;
        bool has_url_or_topic = u && u[0] != '\0' &&
                                (u[0] == '/' || strstr(u, "://") != NULL ||
                                 (svc == CBM_SVC_ASYNC && strlen(u) > PAIR_LEN));
        if (has_url_or_topic) {
            emit_http_async_edge(ctx, call, source_node, NULL, &res, svc, false);
            return SKIP_ONE;
        }
    }

    const cbm_gbuf_node_t *target_node = cbm_gbuf_find_by_qn_domain(
        ctx->gbuf, res.qualified_name, CBM_REF_DOMAIN_CALLABLE, "calls.call_target");
    if (!target_node || source_node->id == target_node->id) {
        if (!target_node) {
            stats->incompatible++;
        }
        return 0;
    }
    emit_classified_edge(ctx, call, source_node, target_node, &res, module_qn, imp_keys, imp_vals,
                         imp_count, tsjs_drop_plain_call);
    return SKIP_ONE;
}

static CBMFileResult *calls_get_or_extract(cbm_pipeline_ctx_t *ctx, int idx,
                                           const cbm_file_info_t *fi, bool *owned) {
    *owned = false;
    if (ctx->result_cache && ctx->result_cache[idx]) {
        return ctx->result_cache[idx];
    }
    int slen = 0;
    char *src = read_file(fi->path, &slen);
    if (!src) {
        return NULL;
    }
    CBMFileResult *r = cbm_extract_file_at_path_with_rust_edition(
        src, slen, fi->language, ctx->project_name, fi->rel_path, fi->path,
        cbm_pxc_rust_edition_for_file(ctx, fi->rel_path), CBM_EXTRACT_BUDGET, NULL, NULL);
    free(src);
    if (r) {
        *owned = true;
    }
    return r;
}

int cbm_pipeline_pass_calls(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "calls", "files", itoa_log(file_count));

    int total_calls = 0;
    int resolved = 0;
    int unresolved = 0;
    int errors = 0;
    call_resolution_stats_t stats = {0};

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            return CBM_NOT_FOUND;
        }

        const char *rel = files[i].rel_path;
        bool result_owned = false;
        CBMFileResult *result = calls_get_or_extract(ctx, i, &files[i], &result_owned);
        if (!result) {
            errors++;
            continue;
        }

        if (result->calls.count == 0) {
            if (result_owned) {
                cbm_free_result(result);
            }
            continue;
        }

        /* Build import map for this file */
        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        if (cbm_pipeline_import_map_build(ctx->gbuf, ctx->project_name, rel, &imp_keys, &imp_vals,
                                          &imp_count) != 0) {
            if (result_owned) {
                cbm_free_result(result);
            }
            return CBM_NOT_FOUND;
        }

        /* Compute module QN for same-module resolution (directory-based for
         * Java/Go so it matches their def-node QNs in the registry). */
        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, rel,
                                                      pc_module_is_dir(files[i].language));

        /* Resolve each call */
        for (int c = 0; c < result->calls.count; c++) {
            CBMCall *call = &result->calls.items[c];
            if (!call->callee_name) {
                continue;
            }
            total_calls++;
            if (resolve_single_call(ctx, call, &result->resolved_calls, rel, module_qn, imp_keys,
                                    imp_vals, imp_count, files[i].language, &stats)) {
                resolved++;
            } else {
                unresolved++;
            }
        }

        free(module_qn);
        cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
        if (result_owned) {
            cbm_free_result(result);
        }
    }

    cbm_log_info("pass.done", "pass", "calls", "total", itoa_log(total_calls), "resolved",
                 itoa_log(resolved), "unresolved", itoa_log(unresolved), "errors",
                 itoa_log(errors));
    cbm_log_info("reference.resolution.refused", "code", "CBM_REFERENCE_TARGET_REFUSED", "pass",
                 "calls", "local_only", itoa_log(stats.local_only), "member_without_type",
                 itoa_log(stats.member_without_type), "message",
                 "textual call targets without lexical or receiver/type evidence were not emitted");
    cbm_log_info("reference.resolution.unresolved", "code", "CBM_REFERENCE_TARGET_UNRESOLVED",
                 "pass", "calls", "target_missing", itoa_log(stats.target_missing), "ambiguous",
                 itoa_log(stats.ambiguous), "incompatible", itoa_log(stats.incompatible),
                 "remediation", "add exact import, module, qualified-path, or LSP type evidence");

    /* Additional pattern-based edge passes run after normal call resolution */
    return cbm_pipeline_pass_fastapi_depends(ctx, files, file_count);
}

/* ── FastAPI Depends() tracking ──────────────────────────────────── */
/* Scans Python function signatures for Depends(func_ref) patterns and
 * creates CALLS edges from the endpoint to the dependency function.
 * Without this, FastAPI auth/DI functions appear as dead code (in_degree=0). */

/* Extract Python function signature text from source starting at given line. Caller frees. */
static char *extract_py_signature(const char *source, int start_line, int end_line) {
    int sig_end = start_line + PC_SIG_SCAN;
    if (end_line > 0 && sig_end > end_line) {
        sig_end = end_line;
    }
    const char *p = source;
    int line = SKIP_ONE;
    while (*p && line < start_line) {
        if (*p == '\n') {
            line++;
        }
        p++;
    }
    const char *sig_start = p;
    while (*p && line < sig_end) {
        if (*p == '\n') {
            line++;
        }
        p++;
        if (p > sig_start + SKIP_ONE && p[-SKIP_ONE] == ':' && p[-PAIR_LEN] == ')') {
            break;
        }
    }
    size_t sig_len = (size_t)(p - sig_start);
    char *sig = malloc(sig_len + SKIP_ONE);
    if (!sig) {
        return NULL;
    }
    memcpy(sig, sig_start, sig_len);
    sig[sig_len] = '\0';
    return sig;
}

/* Scan one function's signature for Depends(func_ref) and create CALLS edges. */
static int scan_depends_in_sig(cbm_pipeline_ctx_t *ctx, const cbm_regex_t *re, const char *sig,
                               const CBMDefinition *def, const char *module_qn, const char **ik,
                               const char **iv, int ic) {
    int count = 0;
    cbm_regmatch_t match[PC_REGEX_GRP];
    const char *scan = sig;
    while (cbm_regexec(re, scan, PC_REGEX_GRP, match, 0) == 0) {
        int ref_len = match[SKIP_ONE].rm_eo - match[SKIP_ONE].rm_so;
        char func_ref[CBM_SZ_256];
        if (ref_len >= (int)sizeof(func_ref)) {
            ref_len = (int)sizeof(func_ref) - SKIP_ONE;
        }
        memcpy(func_ref, scan + match[SKIP_ONE].rm_so, (size_t)ref_len);
        func_ref[ref_len] = '\0';
        cbm_resolution_t res =
            cbm_registry_resolve_exact(ctx->registry, func_ref, module_qn, ik, iv, ic);
        if (res.qualified_name && res.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *sn = cbm_pipeline_find_definition_node(ctx->gbuf, def, "");
            const cbm_gbuf_node_t *tn = cbm_gbuf_find_by_qn_domain(
                ctx->gbuf, res.qualified_name, CBM_REF_DOMAIN_CALLABLE, "calls.fastapi_dependency");
            if (sn && tn && sn->id != tn->id) {
                cbm_gbuf_insert_edge(ctx->gbuf, sn->id, tn->id, "CALLS",
                                     "{\"confidence\":0.95,\"strategy\":\"fastapi_depends\"}");
                count++;
            }
        }
        scan += match[0].rm_eo;
    }
    return count;
}

static bool is_callable_def(const CBMDefinition *def) {
    return def->qualified_name && def->start_line > 0 && def->label &&
           (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0);
}

static bool file_has_depends_call(const CBMFileResult *result) {
    for (int c = 0; c < result->calls.count; c++) {
        if (result->calls.items[c].callee_name &&
            strcmp(result->calls.items[c].callee_name, "Depends") == 0) {
            return true;
        }
    }
    return false;
}

int cbm_pipeline_pass_fastapi_depends(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                      int file_count) {
    cbm_regex_t depends_re;
    if (cbm_regcomp(&depends_re, "Depends\\(([A-Za-z_][A-Za-z0-9_.]*)", CBM_REG_EXTENDED) != 0) {
        cbm_log_error("pass.fastapi_depends_failed", "code", "CBM_FASTAPI_REGEX_COMPILE_FAILED",
                      "component", "calls.fastapi_depends", "operation", "compile_pattern",
                      "message", "FastAPI dependency pattern could not be compiled", "remediation",
                      "inspect the native regex runtime and retry indexing");
        return CBM_NOT_FOUND;
    }

    int edge_count = 0;
    int status = 0;
    for (int i = 0; i < file_count; i++) {
        if (files[i].language != CBM_LANG_PYTHON) {
            continue;
        }
        if (cbm_pipeline_check_cancel(ctx)) {
            status = CBM_NOT_FOUND;
            break;
        }

        CBMFileResult *result = ctx->result_cache ? ctx->result_cache[i] : NULL;
        if (!result || !file_has_depends_call(result)) {
            continue;
        }

        /* Read source and scan for Depends(func_ref) in function signatures */
        int source_len = 0;
        char *source = read_file(files[i].path, &source_len);
        if (!source) {
            continue;
        }

        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, files[i].rel_path,
                                                      pc_module_is_dir(files[i].language));

        /* Build import map for alias resolution */
        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        if (cbm_pipeline_import_map_build(ctx->gbuf, ctx->project_name, files[i].rel_path,
                                          &imp_keys, &imp_vals, &imp_count) != 0) {
            free(module_qn);
            free(source);
            status = CBM_NOT_FOUND;
            break;
        }

        for (int d = 0; d < result->defs.count; d++) {
            CBMDefinition *def = &result->defs.items[d];
            if (!is_callable_def(def)) {
                continue;
            }

            char *sig = extract_py_signature(source, (int)def->start_line, (int)def->end_line);
            if (!sig) {
                continue;
            }

            edge_count += scan_depends_in_sig(ctx, &depends_re, sig, def, module_qn, imp_keys,
                                              imp_vals, imp_count);
            free(sig);
        }

        free(module_qn);
        cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
        free(source);
    }

    cbm_regfree(&depends_re);
    if (edge_count > 0) {
        cbm_log_info("pass.fastapi_depends", "edges", itoa_log(edge_count));
    }
    return status;
}

/* DLL resolve tracking removed — triggered Windows Defender false positive.
 * See issue #89. */
