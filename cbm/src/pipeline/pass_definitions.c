/*
 * pass_definitions.c — Extract definitions from source files.
 *
 * For each discovered file:
 *   1. Read source content from disk
 *   2. Call cbm_extract_file() to get defs, calls, imports
 *   3. Create Function/Class/Method/Variable/Module nodes in graph buffer
 *   4. Register callables in the function registry
 *   5. Store import maps and call sites for later passes
 *
 * Depends on: extraction layer (cbm.h), graph_buffer, pipeline internals
 */
#include "foundation/constants.h"

enum { PD_RING = 4, PD_RING_MASK = 3, PD_JSON_MARGIN = 10, PD_ESC_SPACE = 2 };
/* Fixed bytes around a serialized JSON field: ,"key":"value" / ,"key":[...]
 * -> comma + 2 key quotes + colon + 2 value quotes (resp. brackets). */
enum { PD_JSON_FIELD_OVERHEAD = 6 };
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/str_util.h" // cbm_json_escape — control chars in string property values (#402)
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "cbm.h"
#include "simhash/minhash.h"
#include "semantic/ast_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Read entire file into heap-allocated buffer. Returns NULL on error.
 * Caller must free(). Sets *out_len to byte count. *out_size receives the
 * on-disk size and *out_status the failure reason, so the caller can attribute
 * a skip to the right phase/reason (read vs oversized) instead of a silent
 * drop. Both out params may be NULL. */
static char *read_file(const char *path, int *out_len, long *out_size,
                       cbm_read_status_t *out_status) {
    if (out_size) {
        *out_size = 0;
    }
    if (out_status) {
        *out_status = CBM_READ_OK;
    }
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        if (out_status) {
            *out_status = CBM_READ_OPEN_FAIL;
        }
        return NULL;
    }

    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (out_size) {
        *out_size = size;
    }

    if (size <= 0) {
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_EMPTY;
        }
        return NULL;
    }
    if (size > cbm_max_file_bytes()) { /* generous, env-configurable cap (B4) */
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_OVERSIZED;
        }
        return NULL;
    }

    /* +16 padding: tree-sitter's lexer peeks a few bytes past the final UTF-8
     * character when computing lookahead, reading beyond the logical end.
     * Over-allocate and zero the tail so that read stays in-bounds (ASan
     * flags it as a heap-buffer-overflow otherwise; harmless but real UB). */
    enum { CBM_TS_LOOKAHEAD_PAD = 16 };
    char *buf = malloc((size_t)size + CBM_TS_LOOKAHEAD_PAD);
    if (!buf) {
        (void)fclose(f);
        if (out_status) {
            *out_status = CBM_READ_OOM;
        }
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

/* Format int to string for logging. Thread-safe via TLS. */
static const char *itoa_log(int val) {
    static CBM_TLS char bufs[PD_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PD_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* U+FFFD ("replacement character") encodes as the three bytes EF BF BD — the
 * largest expansion any single input byte can produce under the UTF-8-safe
 * escaper below. Mirrors str_util.c's UTF8_REPLACEMENT_LEN (#493/#503). */
enum { PD_UTF8_REPL_LEN = 3 };

/* Escaped length of a string value under def_json_emit_value's rules (#511):
 *   - JSON meta-chars (" \ \n \r \t) expand to 2 bytes (backslash + escape)
 *   - other control bytes (< 0x20) degrade to a single space
 *   - ASCII (0x20-0x7F) stays 1 byte
 *   - a valid multi-byte UTF-8 sequence is copied verbatim (its own 2-4 bytes)
 *   - any invalid byte (bad lead/continuation, overlong, surrogate, > U+10FFFF)
 *     becomes U+FFFD (3 bytes)
 * Must stay byte-for-byte in step with def_json_emit_value so the whole-field-
 * or-nothing atomic cap check in the append helpers stays exact. Before #511
 * this walked byte-by-byte and passed raw high bytes straight through, so a
 * non-UTF-8 byte in a decorator/route_path literal reached the properties JSON
 * unescaped and made the vault importer refuse the whole repository. */
static size_t def_json_escaped_len(const char *s) {
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        unsigned char c = *p;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            n += PD_ESC_SPACE;
            p++;
        } else if (c < 0x80) {
            n += SKIP_ONE;
            p++;
        } else {
            int seq = cbm_utf8_sequence_len(p);
            if (seq > 0) {
                n += (size_t)seq;
                p += seq;
            } else {
                n += PD_UTF8_REPL_LEN;
                p++;
            }
        }
    }
    return n;
}

/* Emit the JSON-escaped bytes of `val` into buf at *pos (no key, no surrounding
 * quotes), bounded by bufsize with PD_ESC_SPACE reserved for the caller's
 * closing quote/brace + NUL. Byte-for-byte mirror of def_json_escaped_len so a
 * field whose measured length already fit is emitted whole; the per-branch cap
 * checks are defensive belt-and-braces for that guarantee. UTF-8-safe (#511):
 * valid multi-byte sequences are copied atomically so a truncation can only land
 * on a character boundary, and any invalid byte becomes U+FFFD — the same write
 * contract cbm_json_escape (#493) gives the parser-derived property columns. */
static void def_json_emit_value(char *buf, size_t bufsize, size_t *pos, const char *val) {
    size_t p = *pos;
    for (const unsigned char *s = (const unsigned char *)val; *s;) {
        unsigned char c = *s;
        char esc = 0;
        switch (c) {
        case '"':
            esc = '"';
            break;
        case '\\':
            esc = '\\';
            break;
        case '\n':
            esc = 'n';
            break;
        case '\r':
            esc = 'r';
            break;
        case '\t':
            esc = 't';
            break;
        default:
            break;
        }
        if (esc) {
            if (p + PD_ESC_SPACE > bufsize - PD_ESC_SPACE) {
                break;
            }
            buf[p++] = '\\';
            buf[p++] = esc;
            s++;
        } else if (c < 0x20) {
            /* Other raw control byte (e.g. form feed) is invalid inside a JSON
             * string — degrade to a space, as the pre-#511 escaper did. */
            if (p + SKIP_ONE > bufsize - PD_ESC_SPACE) {
                break;
            }
            buf[p++] = ' ';
            s++;
        } else if (c < 0x80) {
            if (p + SKIP_ONE > bufsize - PD_ESC_SPACE) {
                break;
            }
            buf[p++] = (char)c;
            s++;
        } else {
            int seq = cbm_utf8_sequence_len(s);
            if (seq > 0) {
                if (p + (size_t)seq > bufsize - PD_ESC_SPACE) {
                    break;
                }
                memcpy(buf + p, s, (size_t)seq);
                p += (size_t)seq;
                s += seq;
            } else {
                if (p + PD_UTF8_REPL_LEN > bufsize - PD_ESC_SPACE) {
                    break;
                }
                buf[p++] = (char)0xEF;
                buf[p++] = (char)0xBF;
                buf[p++] = (char)0xBD;
                s++;
            }
        }
    }
    *pos = p;
}

/* Appends are ATOMIC: a field is emitted only if the WHOLE serialized form
 * fits (with PD_ESC_SPACE bytes reserved for the closing '}' + NUL). Cutting a
 * field mid-value produced unterminated strings/arrays — malformed properties
 * JSON that aborts every json_extract()-based consumer downstream (seen on the
 * Linux kernel: 50-param functions truncated at the 2 KB cap). Dropping an
 * oversized optional field whole keeps the JSON valid. */
static void append_json_string(char *buf, size_t bufsize, size_t *pos, const char *key,
                               const char *val) {
    if (!val || val[0] == '\0') {
        return;
    }
    /* ,"key":"<escaped>" — comma + 2 key quotes + colon + 2 value quotes */
    size_t required = strlen(key) + def_json_escaped_len(val) + PD_JSON_FIELD_OVERHEAD;
    if (*pos + required + PD_ESC_SPACE > bufsize) {
        return; /* whole field would not fit — skip it atomically */
    }
    size_t p = *pos;
    int w = snprintf(buf + p, bufsize - p, ",\"%s\":\"", key);
    if (w <= 0 || (size_t)w >= bufsize - p) {
        return;
    }
    p += (size_t)w;
    def_json_emit_value(buf, bufsize, &p, val);
    if (p < bufsize - SKIP_ONE) {
        buf[p++] = '"';
    }
    buf[p] = '\0';
    *pos = p;
}

/* Append a JSON array of strings: ,"key":["a","b","c"]. Atomic like
 * append_json_string: emitted only if the whole array fits. */
static void append_json_str_array(char *buf, size_t bufsize, size_t *pos, const char *key,
                                  const char **arr) {
    if (!arr || !arr[0] || *pos >= bufsize - PD_JSON_MARGIN) {
        return;
    }
    /* ,"key":[ + per item "<escaped>" + separating commas + ] */
    size_t required = strlen(key) + PD_JSON_FIELD_OVERHEAD;
    for (int i = 0; arr[i]; i++) {
        required += def_json_escaped_len(arr[i]) + PD_ESC_SPACE + (i > 0 ? SKIP_ONE : 0);
    }
    if (*pos + required + PD_ESC_SPACE > bufsize) {
        return; /* whole array would not fit — skip it atomically */
    }
    size_t p = *pos;
    int n = snprintf(buf + p, bufsize - p, ",\"%s\":[", key);
    if (n <= 0 || p + (size_t)n >= bufsize - PD_ESC_SPACE) {
        return;
    }
    p += (size_t)n;
    for (int i = 0; arr[i]; i++) {
        if (i > 0 && p < bufsize - SKIP_ONE) {
            buf[p++] = ',';
        }
        if (p < bufsize - SKIP_ONE) {
            buf[p++] = '"';
        }
        /* Full escaping (not just quote/backslash): items like C param types
         * sliced from multi-line declarations carry raw \n/\t bytes, which are
         * invalid inside JSON strings; and decorator/route literals may carry a
         * non-UTF-8 byte that must degrade to U+FFFD (#511). */
        def_json_emit_value(buf, bufsize, &p, arr[i]);
        if (p < bufsize - SKIP_ONE) {
            buf[p++] = '"';
        }
    }
    if (p < bufsize - SKIP_ONE) {
        buf[p++] = ']';
    }
    buf[p] = '\0';
    *pos = p;
}

/* Build properties JSON for a definition node. `callees` is the def's
 * newline-delimited "name\tcount" api-callee list (S4 encoder source) or NULL;
 * the caller aggregates it with cbm_pipeline_build_def_callees. */
static void build_def_props(char *buf, size_t bufsize, const CBMDefinition *def,
                            const char *callees) {
    /* The complexity/loop/recursion metrics are only meaningful for executable
     * units (Function/Method). Emitting them on the millions of Macro/Field/
     * Variable/Class/Enum nodes — where they are always zero — bloats every
     * node's properties (~150 B), inflating RAM, the gbuf merge copy and the
     * dump. Gate the block to functions; other labels keep the lean base. */
    const bool is_fn =
        def->label && (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0);
    int n;
    if (is_fn) {
        n = snprintf(buf, bufsize,
                     "{\"complexity\":%d,\"cognitive\":%d,\"loop_count\":%d,\"loop_depth\":%d,"
                     "\"self_recursive\":%s,\"param_count\":%d,\"max_access_depth\":%d,"
                     "\"linear_scan_in_loop\":%d,\"alloc_in_loop\":%d,\"recursion_in_loop\":%s,"
                     "\"unguarded_recursion\":%s,"
                     "\"lines\":%d,\"is_exported\":%s,\"is_test\":%s,\"is_entry_point\":%s",
                     def->complexity, def->cognitive, def->loop_count, def->loop_depth,
                     def->is_recursive ? "true" : "false", def->param_count, def->max_access_depth,
                     def->linear_scan_in_loop, def->alloc_in_loop,
                     def->recursion_in_loop ? "true" : "false",
                     def->unguarded_recursion ? "true" : "false", def->lines,
                     def->is_exported ? "true" : "false", def->is_test ? "true" : "false",
                     def->is_entry_point ? "true" : "false");
    } else {
        n = snprintf(buf, bufsize,
                     "{\"complexity\":%d,\"lines\":%d,\"is_exported\":%s,\"is_test\":%s,"
                     "\"is_entry_point\":%s",
                     def->complexity, def->lines, def->is_exported ? "true" : "false",
                     def->is_test ? "true" : "false", def->is_entry_point ? "true" : "false");
    }

    if (n <= 0 || (size_t)n >= bufsize) {
        buf[0] = '\0';
        return;
    }
    size_t pos = (size_t)n;
    append_json_string(buf, bufsize, &pos, "docstring", def->docstring);
    append_json_string(buf, bufsize, &pos, "signature", def->signature);
    append_json_string(buf, bufsize, &pos, "return_type", def->return_type);
    append_json_string(buf, bufsize, &pos, "parent_class", def->parent_class);
    append_json_str_array(buf, bufsize, &pos, "decorators", def->decorators);
    append_json_str_array(buf, bufsize, &pos, "base_classes", def->base_classes);
    append_json_str_array(buf, bufsize, &pos, "param_names", def->param_names);
    append_json_str_array(buf, bufsize, &pos, "param_types", def->param_types);
    append_json_string(buf, bufsize, &pos, "route_path", def->route_path);
    append_json_string(buf, bufsize, &pos, "route_method", def->route_method);

    /* MinHash fingerprint — append if present and buffer has room. */
    if (def->fingerprint && def->fingerprint_k > 0 &&
        pos + CBM_MINHASH_HEX_LEN + CBM_MINHASH_JSON_OVERHEAD < bufsize) {
        char fp_hex[CBM_MINHASH_HEX_BUF];
        cbm_minhash_to_hex((const cbm_minhash_t *)def->fingerprint, fp_hex, sizeof(fp_hex));
        append_json_string(buf, bufsize, &pos, "fp", fp_hex);
    }

    /* AST structural profile */
    if (def->structural_profile && pos + CBM_AST_PROFILE_BUF < bufsize) {
        append_json_string(buf, bufsize, &pos, "sp", def->structural_profile);
    }

    /* Body tokens */
    if (def->body_tokens && pos + CBM_SZ_512 < bufsize) {
        append_json_string(buf, bufsize, &pos, "bt", def->body_tokens);
    }

    /* Struct trigrams — panel S1 (struct_trigrams guard slot) encoder source.
     * libcbm already computes this normalised AST node-type trigram list
     * (compute_fingerprint → def->struct_trigrams); serializing it here is what
     * lets the shadow importer measure S1 on a real corpus instead of dropping
     * ASTRO_GUARD_AUTO_SLOT_UNMEASURED for every symbol (#374). The append is
     * atomic, so a body whose trigram list would overflow the buffer emits no
     * "st" and stays honestly unmeasured rather than truncated. */
    append_json_string(buf, bufsize, &pos, "st", def->struct_trigrams);

    /* API callees — panel S4 (api_callees guard slot) encoder source (#374). */
    append_json_string(buf, bufsize, &pos, "callees", callees);

    if (pos < bufsize - SKIP_ONE) {
        buf[pos] = '}';
        buf[pos + SKIP_ONE] = '\0';
    }
}

/* Aggregate the api-callee list for one definition. See the declaration in
 * pipeline_internal.h for the contract. Deduplicates by callee name and counts
 * occurrences; the emitted order is dedup-insertion order (the S4 encoder hashes
 * terms into a sparse sum, so order does not affect the resulting vector). */
int cbm_pipeline_build_def_callees(const CBMCallArray *calls, const char *def_qn,
                                   int def_start_line, int def_end_line, char *buf, int bufsize) {
    if (!buf || bufsize < 1) {
        return 0;
    }
    buf[0] = '\0';
    if (!calls || !calls->items || calls->count <= 0 || !def_qn || !def_qn[0] ||
        def_start_line <= 0 || def_end_line < def_start_line) {
        return 0;
    }
    enum { CBM_DEF_CALLEE_MAX = 512 };
    const char *names[CBM_DEF_CALLEE_MAX];
    int counts[CBM_DEF_CALLEE_MAX];
    int distinct = 0;
    for (int i = 0; i < calls->count; i++) {
        const CBMCall *call = &calls->items[i];
        if (!call->callee_name || !call->callee_name[0]) {
            continue;
        }
        if (!call->enclosing_func_qn || strcmp(call->enclosing_func_qn, def_qn) != 0 ||
            call->start_line < def_start_line || call->start_line > def_end_line) {
            continue;
        }
        int found = -1;
        for (int j = 0; j < distinct; j++) {
            if (strcmp(names[j], call->callee_name) == 0) {
                found = j;
                break;
            }
        }
        if (found >= 0) {
            counts[found]++;
        } else if (distinct < CBM_DEF_CALLEE_MAX) {
            names[distinct] = call->callee_name;
            counts[distinct] = 1;
            distinct++;
        }
    }
    int pos = 0;
    for (int j = 0; j < distinct; j++) {
        char rec[CBM_SZ_512];
        int len = snprintf(rec, sizeof(rec), "%s\t%d\n", names[j], counts[j]);
        if (len <= 0 || (size_t)len >= sizeof(rec)) {
            continue; /* pathologically long callee text — skip this record */
        }
        if (pos + len >= bufsize) {
            break; /* deterministic record-boundary truncation */
        }
        memcpy(buf + pos, rec, (size_t)len);
        pos += len;
    }
    buf[pos] = '\0';
    return pos;
}

const cbm_gbuf_node_t *cbm_pipeline_find_definition_node(const cbm_gbuf_t *gbuf,
                                                         const CBMDefinition *def,
                                                         const char *fallback_rel_path) {
    if (!gbuf || !def || !def->name || !def->qualified_name || !def->source) {
        return NULL;
    }
    return cbm_gbuf_find_source_node(
        gbuf, def->label ? def->label : "Function", def->name, def->qualified_name,
        def->file_path ? def->file_path : fallback_rel_path, (int)def->start_line,
        (int)def->end_line, (const uint8_t *)def->source, (size_t)def->source_len, def->start_byte,
        def->end_byte);
}

/* Process one definition: create node, register, DEFINES + DEFINES_METHOD edges. */
static void process_def(cbm_pipeline_ctx_t *ctx, const CBMCallArray *calls,
                        const CBMDefinition *def, const char *rel) {
    if (!def->qualified_name || !def->name) {
        return;
    }
    /* CBM_SZ_32K holds the existing props plus the up-to-16K struct-trigram list
     * (S1) and the api-callee list (S4); append_json_string drops any field that
     * still would not fit, so the JSON stays valid and the symbol stays honestly
     * unmeasured for that slot rather than truncated (#374). */
    char props[CBM_SZ_32K];
    char callees[CBM_SZ_8K];
    cbm_pipeline_build_def_callees(calls, def->qualified_name, (int)def->start_line,
                                   (int)def->end_line, callees, (int)sizeof(callees));
    build_def_props(props, sizeof(props), def, callees);
    int64_t node_id = cbm_gbuf_upsert_source_node(
        ctx->gbuf, def->label ? def->label : "Function", def->name, def->qualified_name,
        def->file_path ? def->file_path : rel, (int)def->start_line, (int)def->end_line,
        (const uint8_t *)def->source, (size_t)def->source_len, def->start_byte, def->end_byte,
        props);
    /* The code registry is a semantic-reference index, not a catalog of every
     * graph fact. Config/data Variable atoms remain in the graph but cannot be
     * selected as code callees/usages. KEEP IN SYNC with pass_parallel.c and
     * pipeline_incremental.c. */
    if (node_id > 0 && cbm_pipeline_definition_is_registry_symbol(
                           def->label, def->file_path ? def->file_path : rel)) {
        (void)cbm_registry_add(ctx->registry, def->name, def->qualified_name, def->label);
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    if (file_node && node_id > 0) {
        cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, node_id, "DEFINES", "{}");
    }
    free(file_qn);
    if (def->parent_class && def->label && strcmp(def->label, "Method") == 0) {
        const cbm_gbuf_node_t *parent = cbm_gbuf_find_by_qn_location(
            ctx->gbuf, def->parent_class, def->file_path ? def->file_path : rel,
            (int)def->start_line);
        if (parent && node_id > 0) {
            cbm_gbuf_insert_edge(ctx->gbuf, parent->id, node_id, "DEFINES_METHOD", "{}");
        }
    }
}

/* Create Channel nodes + EMITS / LISTENS_ON edges for one file's channels.
 * Mirrors the parallel path in cbm_build_registry_from_cache — keep in sync. */
/* Find the source node for a channel edge: enclosing function or file node. */
static const cbm_gbuf_node_t *find_channel_source(cbm_pipeline_ctx_t *ctx, const CBMChannel *ch,
                                                  const char *rel) {
    const cbm_gbuf_node_t *node = NULL;
    if (ch->enclosing_func_qn && ch->enclosing_func_qn[0]) {
        node = ch->start_line > 0 ? cbm_gbuf_find_by_qn_location(ctx->gbuf, ch->enclosing_func_qn,
                                                                 rel, ch->start_line)
                                  : cbm_gbuf_find_by_qn(ctx->gbuf, ch->enclosing_func_qn);
    }
    if (!node) {
        char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
        node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
        free(file_qn);
    }
    return node;
}

static void create_channel_edges_for_file(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                          const char *rel) {
    for (int j = 0; j < result->channels.count; j++) {
        const CBMChannel *ch = &result->channels.items[j];
        if (!ch->channel_name || !ch->channel_name[0]) {
            continue;
        }
        char channel_qn[CBM_SZ_512];
        snprintf(channel_qn, sizeof(channel_qn), "__channel__%s__%s",
                 ch->transport ? ch->transport : "unknown", ch->channel_name);
        char esc_cn[CBM_SZ_256];
        cbm_json_escape(esc_cn, sizeof(esc_cn), ch->channel_name); /* #402: control chars */
        char channel_props[CBM_SZ_512];
        snprintf(channel_props, sizeof(channel_props), "{\"transport\":\"%s\",\"name\":\"%s\"}",
                 ch->transport ? ch->transport : "unknown", esc_cn);
        int64_t channel_id = cbm_gbuf_upsert_node(ctx->gbuf, "Channel", ch->channel_name,
                                                  channel_qn, "", 0, 0, channel_props);

        const cbm_gbuf_node_t *src_node = find_channel_source(ctx, ch, rel);
        if (src_node && channel_id > 0) {
            const char *edge_type = ch->direction == CBM_CHANNEL_EMIT ? "EMITS" : "LISTENS_ON";
            char edge_props[CBM_SZ_128];
            snprintf(edge_props, sizeof(edge_props), "{\"transport\":\"%s\"}",
                     ch->transport ? ch->transport : "unknown");
            cbm_gbuf_insert_edge(ctx->gbuf, src_node->id, channel_id, edge_type, edge_props);
        }
    }
}

/* Create CONFIGURES edges for one file's env accesses.  extract_env_accesses.c
 * records every os.Getenv / process.env / Environment.GetEnvironmentVariable
 * style access into result->env_accesses.  We materialize one EnvVar node per
 * env key and link the enclosing function (or the file node) CONFIGURES-> it,
 * so environment-driven configuration is visible even when the accessor is a
 * stdlib symbol that never resolves to an in-graph callee. */
static int create_env_configures_for_file(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                          const char *rel) {
    int count = 0;
    char *file_qn = NULL;
    const cbm_gbuf_node_t *file_node = NULL;
    for (int j = 0; j < result->env_accesses.count; j++) {
        const CBMEnvAccess *ea = &result->env_accesses.items[j];
        if (!ea->env_key || !ea->env_key[0]) {
            continue;
        }
        char env_qn[CBM_SZ_512];
        snprintf(env_qn, sizeof(env_qn), "__env__%s", ea->env_key);
        char esc_ek[CBM_SZ_256];
        cbm_json_escape(esc_ek, sizeof(esc_ek), ea->env_key); /* #402: control chars */
        char env_props[CBM_SZ_512];
        snprintf(env_props, sizeof(env_props), "{\"env_key\":\"%s\"}", esc_ek);
        int64_t env_id =
            cbm_gbuf_upsert_node(ctx->gbuf, "EnvVar", ea->env_key, env_qn, "", 0, 0, env_props);
        if (env_id <= 0) {
            continue;
        }
        const cbm_gbuf_node_t *src = NULL;
        if (ea->enclosing_func_qn && ea->enclosing_func_qn[0]) {
            src = ea->start_line > 0 ? cbm_gbuf_find_by_qn_location(
                                           ctx->gbuf, ea->enclosing_func_qn, rel, ea->start_line)
                                     : cbm_gbuf_find_by_qn(ctx->gbuf, ea->enclosing_func_qn);
        }
        if (!src) {
            if (!file_qn) {
                file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
                file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
            }
            src = file_node;
        }
        if (src && src->id != env_id) {
            cbm_gbuf_insert_edge(ctx->gbuf, src->id, env_id, "CONFIGURES",
                                 "{\"strategy\":\"env_access\"}");
            count++;
        }
    }
    free(file_qn);
    return count;
}

/* Create IMPORTS edges for one file's imports.  Mirrors the resolution
 * logic in pass_parallel.c register_and_link_def — keep the two in sync. */
static int create_import_edges_for_file(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                        const char *rel, CBMHashTable *namespace_map) {
    int count = 0;
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *source_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    if (!source_node) {
        free(file_qn);
        return 0;
    }
    for (int j = 0; j < result->imports.count; j++) {
        const CBMImport *imp = &result->imports.items[j];
        if (!imp->module_path) {
            continue;
        }
        const cbm_gbuf_node_t *target =
            cbm_pipeline_resolve_import_node(ctx, rel, file_qn, imp, namespace_map);
        if (target && target->id != source_node->id) {
            char *imp_props = cbm_pipeline_import_edge_properties(ctx, rel, imp);
            if (!imp_props) {
                break;
            }
            cbm_gbuf_insert_edge(ctx->gbuf, source_node->id, target->id, "IMPORTS", imp_props);
            free(imp_props);
            count++;
        }
    }
    free(file_qn);
    return count;
}

int cbm_pipeline_pass_definitions(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                  int file_count) {
    cbm_log_info("pass.start", "pass", "definitions", "files", itoa_log(file_count));

    /* #229/#273: `file_count` is a signed count fed unchecked into
     * calloc((size_t)file_count, ...) twice below — the local_cache allocation
     * and the namespace-map `rels` allocation. A negative count (a caller
     * contract violation or an upstream integer wraparound) casts to an enormous
     * size_t: GCC 14 sees the (size_t)file_count range include [INT_MIN..-1] and
     * trips -Walloc-size-larger-than on native MinGW, and such a count really would
     * request an absurd allocation. Refuse a negative count and fail closed with a
     * {code, message, remediation} log record; an empty file set (file_count == 0)
     * stays valid and flows through as a no-op. The early return narrows file_count
     * to [0, INT_MAX] for both allocations. Unconditional (#273): the fix ships in
     * libcbm.a too, instead of being masked by a blanket -Wno-alloc-size-larger-than. */
    if (file_count < 0) {
        cbm_log_error("pass.definitions.file_count", "code", "CBM_E_DEFS_FILE_COUNT_RANGE",
                      "message", "definitions pass received a negative file_count", "remediation",
                      "pass a non-negative file_count; a negative value indicates a "
                      "caller contract violation or an integer overflow upstream");
        return CBM_NOT_FOUND;
    }

    /* Ensure extraction library is initialized */
    if (cbm_init() != 0) {
        cbm_log_error("pass.definitions.init_failed", "code", "CBM_ALLOCATOR_INIT_FAILED",
                      "message", "the extraction allocator contract could not be initialized",
                      "remediation", "inspect allocator.bind_failed and restart the process");
        return CBM_NOT_FOUND;
    }

    /* Defensive: a prior pipeline run may have left a thread-local parser whose
     * lexer holds pointers into a slab that has since been reclaimed. Drop it
     * here so the first cbm_extract_file below recreates a fresh parser. */
    cbm_destroy_thread_parser();

    int total_defs = 0;
    int total_calls = 0;
    int total_imports = 0;
    int errors = 0;

    /* Sequential pass must extract all defs (which create Module/Function/...
     * nodes) BEFORE resolving imports — otherwise a workspace import in the
     * first file processed can't find the target Module node, because the
     * target file's defs haven't been extracted yet. Result cache is
     * required for this two-phase ordering. */
    CBMFileResult **local_cache = ctx->result_cache;
    bool owns_local_cache = false;
    if (!local_cache) {
        local_cache = (CBMFileResult **)calloc((size_t)file_count, sizeof(CBMFileResult *));
        owns_local_cache = (local_cache != NULL);
    }
    if (file_count > 0 && !local_cache) {
        return cbm_pipeline_reject_file_failures(ctx->pipeline, files, file_count, NULL,
                                                 "sequential_cache");
    }

    /* Phase 1: extract every file and create def-derived nodes (Modules,
     * Functions, ...) so any file's IMPORTS can resolve against the
     * complete in-memory graph in Phase 2. */
    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            return CBM_NOT_FOUND;
        }

        const char *path = files[i].path;
        const char *rel = files[i].rel_path;
        CBMLanguage lang = files[i].language;

        /* Read source file */
        int source_len = 0;
        long file_size = 0;
        cbm_read_status_t rst = CBM_READ_OK;
        char *source = read_file(path, &source_len, &file_size, &rst);
        if (!source) {
            errors++;
            if (rst == CBM_READ_OVERSIZED) {
                /* Never a silent drop: record the oversized terminal failure
                 * with its declared and observed sizes. */
                long cap = cbm_max_file_bytes();
                char reason[96];
                snprintf(reason, sizeof(reason), "oversized (%lld MB > %lld MB)",
                         (long long)(file_size / (CBM_SZ_1K * CBM_SZ_1K)),
                         (long long)(cap / (CBM_SZ_1K * CBM_SZ_1K)));
                cbm_pipeline_add_file_error(ctx->pipeline, rel, reason, "oversized");
                cbm_log_warn("index.file_oversized", "path", rel, "size_mb",
                             itoa_log((int)(file_size / (CBM_SZ_1K * CBM_SZ_1K))), "cap_mb",
                             itoa_log((int)(cap / (CBM_SZ_1K * CBM_SZ_1K))));
            } else if (rst == CBM_READ_OPEN_FAIL || rst == CBM_READ_OOM) {
                cbm_pipeline_add_file_error(ctx->pipeline, rel, "read failed", "read");
            }
            /* CBM_READ_EMPTY: benign 0-byte file — nothing to index, not reported. */
            continue;
        }

        /* Extract */
        CBMFileResult *result =
            cbm_extract_file(source, source_len, lang, ctx->project_name, rel, CBM_EXTRACT_BUDGET,
                             NULL, NULL /* no extra defines or include paths */
            );
        free(source);

        if (!result) {
            errors++;
            cbm_pipeline_add_file_error(ctx->pipeline, rel, "extract failed", "extract");
            continue;
        }
        /* Preserve the extractor's exact first failure in the pipeline's
         * diagnostic inventory. The extraction barrier below rejects the whole
         * corpus before later passes or publication. */
        if (result->has_error) {
            cbm_pipeline_add_file_error(ctx->pipeline, rel,
                                        result->error_msg ? result->error_msg : "extract failed",
                                        "extract");
            errors++;
        }

        /* Create nodes for each definition */
        for (int d = 0; d < result->defs.count; d++) {
            process_def(ctx, &result->calls, &result->defs.items[d], rel);
            total_defs++;
        }

        /* Store calls for pass_calls (we save them in the extraction results
         * for now — a future optimization would batch these) */
        total_calls += result->calls.count;

        if (local_cache) {
            local_cache[i] = result;
        } else {
            /* Cache unavailable: imports for this file can still only
             * resolve to defs already in the graph, but the file's
             * own defs are now persisted before the lookup. No namespace
             * map is available without the cache (single-file scope). */
            total_imports += create_import_edges_for_file(ctx, result, rel, NULL);
            create_channel_edges_for_file(ctx, result, rel);
            create_env_configures_for_file(ctx, result, rel);
            cbm_free_result(result);
        }
    }

    /* Authoritative extraction is an all-files barrier. A result carrying
     * has_error (or a discovered file that could not be read/extracted) makes
     * the whole pass fail before imports, later passes, or publication can see
     * a partial graph. */
    int extraction_rc = cbm_pipeline_reject_file_failures(ctx->pipeline, files, file_count,
                                                          local_cache, "sequential_extract");
    if (extraction_rc != 0) {
        if (owns_local_cache) {
            for (int i = 0; i < file_count; i++) {
                cbm_free_result(local_cache[i]);
            }
            free(local_cache);
        }
        return extraction_rc;
    }

    /* Phase 2: now that all extraction results are cached and Module
     * nodes for every file are in the graph, walk the cache again to
     * create IMPORTS / channel edges. Imports resolve against the full
     * project graph. */
    if (local_cache) {
        /* Build a namespace/package → File-QN map so that namespace imports
         * (C# `using`, Java/Kotlin `import`, PHP `use`) resolve to the file
         * that declares the namespace. */
        const char **rels = (const char **)calloc((size_t)file_count, sizeof(char *));
        if (!rels && file_count > 0) {
            cbm_log_error("definitions.namespace_failed", "code", "CBM_NAMESPACE_RELS_ALLOC_FAILED",
                          "component", "definitions.namespace_map", "operation", "rels_alloc",
                          "key", "", "message", "namespace input list could not be allocated",
                          "remediation", "free memory or reduce repository size, then retry");
            if (owns_local_cache) {
                for (int i = 0; i < file_count; i++) {
                    cbm_free_result(local_cache[i]);
                }
                free(local_cache);
            }
            return CBM_NOT_FOUND;
        }
        for (int i = 0; i < file_count; i++) {
            rels[i] = files[i].rel_path;
        }
        CBMHashTable *namespace_map = NULL;
        int namespace_rc = cbm_pipeline_namespace_map_build(ctx->project_name, local_cache, rels,
                                                            file_count, &namespace_map);
        free(rels);
        if (namespace_rc != 0) {
            if (owns_local_cache) {
                for (int i = 0; i < file_count; i++) {
                    cbm_free_result(local_cache[i]);
                }
                free(local_cache);
            }
            return namespace_rc;
        }
        for (int i = 0; i < file_count; i++) {
            if (cbm_pipeline_check_cancel(ctx)) {
                break;
            }
            CBMFileResult *result = local_cache[i];
            if (!result) {
                continue;
            }
            total_imports +=
                create_import_edges_for_file(ctx, result, files[i].rel_path, namespace_map);
            create_channel_edges_for_file(ctx, result, files[i].rel_path);
            create_env_configures_for_file(ctx, result, files[i].rel_path);
        }
        cbm_pipeline_namespace_map_free(namespace_map);
        if (owns_local_cache) {
            for (int i = 0; i < file_count; i++) {
                if (local_cache[i]) {
                    cbm_free_result(local_cache[i]);
                }
            }
            free(local_cache);
        }
    }

    cbm_log_info("pass.done", "pass", "definitions", "defs", itoa_log(total_defs), "calls",
                 itoa_log(total_calls), "imports", itoa_log(total_imports), "errors",
                 itoa_log(errors));
    return cbm_registry_failed(ctx->registry) ? CBM_NOT_FOUND : 0;
}
