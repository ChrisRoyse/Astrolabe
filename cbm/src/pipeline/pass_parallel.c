/*
 * pass_parallel.c — Three-phase parallel pipeline.
 *
 * Phase 3A: Parallel extract + create definition nodes (per-worker gbufs)
 * Phase 3B: Serial registry build + edge creation from cached results
 * Phase 4:  Parallel call/usage/semantic resolution (per-worker edge bufs)
 *
 * Each file is read and parsed ONCE (Phase 3A). The CBMFileResult is cached
 * and reused for resolution (Phase 4), eliminating 3x redundant I/O + parsing.
 *
 * Depends on: worker_pool, graph_buffer (shared IDs + merge), extraction (cbm.h)
 */
#include "foundation/constants.h"
#include "foundation/worker_progress.h"

enum {
    PP_RING = 4,
    PP_RING_MASK = 3,
    PP_JSON_MARGIN = 10,
    PP_ESC_SPACE = 2,
    /* Byte length of the U+FFFD replacement char (EF BF BD) an invalid UTF-8
     * byte degrades to in emitted JSON (#578). */
    PP_UTF8_REPL_LEN = 3,
    /* Fixed bytes around a serialized JSON field: ,"key":"value" / ,"key":[...]
     * -> comma + 2 key quotes + colon + 2 value quotes (resp. brackets). */
    PP_JSON_FIELD_OVERHEAD = 6,
    PP_ARGS_MARGIN = 20,
    /* ,"line":<int> -> comma + key (7) + colon + up to 10 digits + NUL. */
    PP_LINE_MARGIN = 24,
    PP_LOG_THRESH = 24,
    PP_LOG_INTERVAL = 10,
    PP_TIMER_THRESH = 1000,
    /* Extraction memory back-pressure: when the process is over its RSS budget,
     * a worker reclaims + naps before pulling another file so peers can finish
     * and return pages. Bounded spins avoid deadlock when the resident graph
     * itself is near budget (then proceed with a soft overshoot). */
    PP_BACKPRESSURE_MAX_SPINS = 40,
    PP_BACKPRESSURE_NAP_NS = 3000000, /* 3 ms */
};
#define PP_NSEC_PER_SEC 1000000000ULL
#define PP_USEC_PER_MS 1000000ULL
#define PP_HALF_CONF 0.5

/* Source bytes live once in the hash-bound pipeline source slab. File atoms,
 * extraction, and cross-file resolution borrow that same immutable storage;
 * no retention cap, duplicate copy, disk reread, or missing-source degradation
 * exists on this path. */
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h" /* cbm_pxc_* helpers for fused cross-file LSP */
#include "lsp/rust_cargo.h"
#include "pipeline/lsp_resolve.h"
#include "helpers.h" /* cbm_kind_in_set_free_cache — per-worker-thread cache teardown */
#include "pipeline/worker_pool.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "graph_buffer/graph_buffer.h"
#include "service_patterns.h"
#include "foundation/platform.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/slab_alloc.h"
#include "foundation/mem.h"
#include "foundation/str_util.h"
#include "foundation/profile.h"
#include "foundation/compat_regex.h"
#include "foundation/limits.h"
#include "cbm.h"
#include "simhash/minhash.h"
#include "semantic/ast_profile.h"

#include <stdatomic.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Back-pressure nap-cycle counter (test observability): each execution of the
 * over-budget collect+nap gate counts one cycle. Lets tests assert the gate does
 * not re-pay the full nap tax on every file pull when napping cannot reclaim
 * memory (the resident floor, not in-flight transients, holds the budget). */
static _Atomic long g_bp_nap_cycles = 0;

long cbm_pp_bp_nap_cycles(void) {
    return atomic_load_explicit(&g_bp_nap_cycles, memory_order_relaxed);
}

void cbm_pp_bp_nap_cycles_reset(void) {
    atomic_store_explicit(&g_bp_nap_cycles, 0, memory_order_relaxed);
}

static const char *parallel_dispatch_mode_name(cbm_parallel_dispatch_mode_t mode) {
    switch (mode) {
    case CBM_PARALLEL_DISPATCH_MODE_NOOP:
        return "noop";
    case CBM_PARALLEL_DISPATCH_MODE_SERIAL:
        return "serial";
    case CBM_PARALLEL_DISPATCH_MODE_PARALLEL:
        return "parallel";
    }
    return "unknown";
}

static void record_worker_pool_dispatch(cbm_pipeline_t *pipeline,
                                        const cbm_parallel_for_result_t *result) {
    if (!pipeline || !result) {
        return;
    }
    cbm_pipeline_record_parallel_dispatch(
        pipeline, result->operation ? result->operation : "parallel",
        parallel_dispatch_mode_name(result->mode), result->code ? result->code : "",
        result->item_count, result->requested_workers, result->admitted_workers,
        result->created_workers, result->failed_worker_index, result->error_domain,
        result->error_code);
}

static uint64_t extract_now_ns(void) {
    struct timespec ts;
    cbm_clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * PP_NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}

/* ── Helpers (duplicated from pass files — kept static for isolation) ── */

static const char *itoa_log(int val) {
    static CBM_TLS char bufs[PP_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PP_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Append a JSON-escaped string value at *pos, UTF-8-strict (#578).
 *
 * This is the node-properties writer for the parallel (tree-sitter / Rust) path.
 * A raw invalid UTF-8 byte in source metadata — e.g. 0xC0 inside a Rust doc
 * comment — must NOT reach nodes.properties raw: the vault importer fails the
 * whole repo closed on an invalid-UTF-8 properties cell. So this mirrors the
 * pass_definitions.c writer: quote/backslash/\n/\r/\t are backslash-escaped,
 * other C0 control bytes degrade to a space (invalid bare inside a JSON string),
 * a valid multi-byte UTF-8 sequence is copied atomically (so a buffer-cap
 * truncation can only land on a character boundary), and any invalid byte (bad
 * lead/continuation, overlong, surrogate, out of range) becomes U+FFFD. The
 * emitted JSON is therefore always valid UTF-8. *pos is advanced. */
static void pp_json_emit_value(char *buf, size_t bufsize, size_t *pos, const char *val) {
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
            if (p + PP_ESC_SPACE > bufsize - PP_ESC_SPACE) {
                break;
            }
            buf[p++] = '\\';
            buf[p++] = esc;
            s++;
        } else if (c < 0x20) {
            /* Other raw control byte (e.g. form feed) is invalid bare inside a
             * JSON string — degrade to a space. */
            if (p + SKIP_ONE > bufsize - PP_ESC_SPACE) {
                break;
            }
            buf[p++] = ' ';
            s++;
        } else if (c < 0x80) {
            if (p + SKIP_ONE > bufsize - PP_ESC_SPACE) {
                break;
            }
            buf[p++] = (char)c;
            s++;
        } else {
            int seq = cbm_utf8_sequence_len(s);
            if (seq > 0) {
                if (p + (size_t)seq > bufsize - PP_ESC_SPACE) {
                    break;
                }
                memcpy(buf + p, s, (size_t)seq);
                p += (size_t)seq;
                s += seq;
            } else {
                if (p + PP_UTF8_REPL_LEN > bufsize - PP_ESC_SPACE) {
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

/* Escaped length of a string under pp_json_emit_value's rules (#578): escaped
 * characters expand to 2 bytes, an invalid UTF-8 byte expands to the 3-byte
 * U+FFFD replacement, a valid multi-byte sequence keeps its length, everything
 * else stays 1. Used only for the atomic whole-field fit budget. */
static size_t pp_json_escaped_len(const char *src) {
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p;) {
        unsigned char c = *p;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            n += PP_ESC_SPACE;
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
                n += PP_UTF8_REPL_LEN;
                p++;
            }
        }
    }
    return n;
}

/* Appends are ATOMIC: a field is emitted only if the WHOLE serialized form
 * fits (with PP_ESC_SPACE bytes reserved for the closing '}' + NUL). Cutting a
 * field mid-value produced unterminated strings/arrays — malformed properties
 * JSON that aborts every json_extract()-based consumer downstream (seen on the
 * Linux kernel: 50-param functions truncated at the 2 KB cap). Dropping an
 * oversized optional field whole keeps the JSON valid. Twin of
 * pass_definitions.c — keep both in sync. */
static void append_json_string(char *buf, size_t bufsize, size_t *pos, const char *key,
                               const char *val) {
    if (!val || val[0] == '\0') {
        return;
    }
    size_t required = strlen(key) + pp_json_escaped_len(val) + PP_JSON_FIELD_OVERHEAD;
    if (*pos + required + PP_ESC_SPACE > bufsize) {
        return; /* whole field would not fit — skip it atomically */
    }
    size_t p = *pos;
    int w = snprintf(buf + p, bufsize - p, ",\"%s\":\"", key);
    if (w <= 0 || (size_t)w >= bufsize - p) {
        return;
    }
    p += (size_t)w;
    pp_json_emit_value(buf, bufsize, &p, val);
    if (p < bufsize - SKIP_ONE) {
        buf[p++] = '"';
    }
    buf[p] = '\0';
    *pos = p;
}

static void append_json_u64(char *buf, size_t bufsize, size_t *pos, const char *key,
                            uint64_t value) {
    char field[CBM_SZ_128];
    int written = snprintf(field, sizeof(field), ",\"%s\":%llu", key,
                           (unsigned long long)value);
    if (written <= 0 || (size_t)written >= sizeof(field) ||
        *pos + (size_t)written + PP_ESC_SPACE > bufsize) {
        return;
    }
    memcpy(buf + *pos, field, (size_t)written);
    *pos += (size_t)written;
    buf[*pos] = '\0';
}

/* Append a JSON array of strings: ,"key":["a","b","c"]. Atomic like
 * append_json_string: emitted only if the whole array fits. */
static void append_json_str_array(char *buf, size_t bufsize, size_t *pos, const char *key,
                                  const char **arr) {
    if (!arr || !arr[0] || *pos >= bufsize - PP_JSON_MARGIN) {
        return;
    }
    /* ,"key":[ + per item "<escaped>" + separating commas + ] */
    size_t required = strlen(key) + PP_JSON_FIELD_OVERHEAD;
    for (int i = 0; arr[i]; i++) {
        required += pp_json_escaped_len(arr[i]) + PP_ESC_SPACE + (i > 0 ? SKIP_ONE : 0);
    }
    if (*pos + required + PP_ESC_SPACE > bufsize) {
        return; /* whole array would not fit — skip it atomically */
    }
    size_t p = *pos;
    int n = snprintf(buf + p, bufsize - p, ",\"%s\":[", key);
    if (n <= 0 || p + (size_t)n >= bufsize - PP_ESC_SPACE) {
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
         * invalid inside JSON strings; and raw invalid UTF-8 bytes must degrade
         * to U+FFFD (#578) so the properties cell stays valid UTF-8. */
        pp_json_emit_value(buf, bufsize, &p, arr[i]);
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

static void build_def_props(char *buf, size_t bufsize, const CBMDefinition *def,
                            const char *callees) {
    /* Complexity/loop/recursion metrics are meaningful only for Function/Method.
     * Gate the block so the millions of Macro/Field/Variable/Class/Enum nodes
     * keep a lean properties blob (lossless — those fields are always zero for
     * non-functions). Cuts RAM, gbuf-merge copy and dump volume. Mirrors
     * pass_definitions.c::build_def_props — keep both in sync. */
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
    append_json_string(buf, bufsize, &pos, "structured_path", def->structured_path);
    if (def->structured_path) {
        append_json_u64(buf, bufsize, &pos, "structured_occurrence_count",
                        def->structured_occurrence_count);
        append_json_string(buf, bufsize, &pos, "structured_occurrence_sha256",
                           def->structured_occurrence_sha256);
        append_json_u64(buf, bufsize, &pos, "structured_first_start_byte",
                        def->structured_first_start_byte);
        append_json_u64(buf, bufsize, &pos, "structured_first_end_byte",
                        def->structured_first_end_byte);
        append_json_u64(buf, bufsize, &pos, "structured_last_start_byte",
                        def->structured_last_start_byte);
        append_json_u64(buf, bufsize, &pos, "structured_last_end_byte",
                        def->structured_last_end_byte);
        append_json_string(buf, bufsize, &pos, "structured_classification",
                           def->structured_classification);
        append_json_string(buf, bufsize, &pos, "structured_classification_provenance",
                           def->structured_classification_provenance);
    }

    /* MinHash fingerprint — append if present and buffer has room.
     * Hex-encoded K=64 uint32 = 512 chars + key/quotes ≈ 520 chars. */
    if (def->fingerprint && def->fingerprint_k > 0 &&
        pos + CBM_MINHASH_HEX_LEN + CBM_MINHASH_JSON_OVERHEAD < bufsize) {
        char fp_hex[CBM_MINHASH_HEX_BUF];
        cbm_minhash_to_hex((const cbm_minhash_t *)def->fingerprint, fp_hex, sizeof(fp_hex));
        append_json_string(buf, bufsize, &pos, "fp", fp_hex);
    }

    /* AST structural profile — append if present and buffer has room. */
    if (def->structural_profile && pos + CBM_AST_PROFILE_BUF < bufsize) {
        append_json_string(buf, bufsize, &pos, "sp", def->structural_profile);
    }

    /* Body tokens — raw identifiers from function body AST for semantic search. */
    if (def->body_tokens && pos + CBM_SZ_512 < bufsize) {
        append_json_string(buf, bufsize, &pos, "bt", def->body_tokens);
    }

    /* Struct trigrams (panel S1) + api callees (panel S4) encoder sources (#374).
     * Keep in sync with pass_definitions.c::build_def_props. */
    append_json_string(buf, bufsize, &pos, "st", def->struct_trigrams);
    append_json_string(buf, bufsize, &pos, "callees", callees);

    if (pos < bufsize - SKIP_ONE) {
        buf[pos] = '}';
        buf[pos + SKIP_ONE] = '\0';
    }
}

/* True for languages whose module QN derives from the CONTAINING DIRECTORY
 * (Java/Go package). MUST match cbm_lang_module_is_dir() (internal/cbm/helpers.c)
 * and pxc_module_is_dir() (pass_lsp_cross.c) so same-module callee resolution
 * keys against the directory-based def-node QNs in the registry. */
static bool pp_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

static bool is_checked_exception(const char *name) {
    if (!name) {
        return false;
    }
    if (strstr(name, "Error") || strstr(name, "Panic") || strstr(name, "error") ||
        strstr(name, "panic")) {
        return false;
    }
    return true;
}

static const cbm_gbuf_node_t *resolve_as_type(const cbm_registry_t *reg, const cbm_gbuf_t *gbuf,
                                              const char *name, const char *module_qn,
                                              const char **imp_keys, const char **imp_vals,
                                              int imp_count, const char *operation,
                                              cbm_resolution_t *out_resolution) {
    cbm_resolution_t res =
        cbm_registry_resolve_exact(reg, name, module_qn, imp_keys, imp_vals, imp_count);
    if (out_resolution) {
        *out_resolution = res;
    }
    if (!res.qualified_name || res.qualified_name[0] == '\0') {
        return NULL;
    }
    return cbm_gbuf_find_by_qn_domain(gbuf, res.qualified_name, CBM_REF_DOMAIN_TYPE, operation);
}

static void extract_decorator_func(const char *dec, char *out, size_t outsz) {
    out[0] = '\0';
    if (!dec) {
        return;
    }
    const char *start = dec;
    if (*start == '@') {
        start++;
    }
    const char *paren = strchr(start, '(');
    size_t len = paren ? (size_t)(paren - start) : strlen(start);
    if (len == 0 || len >= outsz) {
        return;
    }
    memcpy(out, start, len);
    out[len] = '\0';
}

/* ── File sort for tail-latency reduction ────────────────────────── */

typedef struct {
    int idx;
    int64_t size;
} file_sort_entry_t;

static int compare_by_size_desc(const void *a, const void *b) {
    const file_sort_entry_t *fa = a;
    const file_sort_entry_t *fb = b;
    if (fb->size > fa->size) {
        return SKIP_ONE;
    }
    if (fb->size < fa->size) {
        return CBM_NOT_FOUND;
    }
    return 0;
}

/* ── Phase 3A: Parallel Extract ──────────────────────────────────── */

#define CBM_CACHE_LINE CBM_SZ_128

typedef struct __attribute__((aligned(CBM_CACHE_LINE))) {
    cbm_gbuf_t *local_gbuf;
    int nodes_created;
    int errors;
    uint_least64_t parse_recovery_diagnostics;
    char _pad[CBM_CACHE_LINE - sizeof(cbm_gbuf_t *) - (PP_ESC_SPACE * sizeof(int)) -
              sizeof(uint_least64_t)];
} extract_worker_state_t;

typedef struct {
    const cbm_file_info_t *files;
    file_sort_entry_t *sorted;
    int file_count;
    const char *project_name;
    const char *repo_path;
    const CBMCargoManifest *rust_manifest;
    const cbm_compile_context_index_t *compile_contexts;

    extract_worker_state_t *workers;
    int max_workers;
    _Atomic int next_worker_id;

    CBMFileResult **result_cache;
    _Atomic int64_t *shared_ids;
    _Atomic int *cancelled;
    _Atomic int next_file_idx;

    const cbm_source_slab_t *source_slab; /* hash-bound immutable source bytes */

    /* Back-pressure futility latch: set when a full collect+nap cycle ended
     * still over budget — the resident floor (graph + retained sources), not
     * in-flight transients, holds the memory, so napping cannot reclaim it.
     * While set, pulls skip the nap (the designed soft overshoot); the cheap
     * over-budget probe re-arms the gate once RSS drains under budget. */
    _Atomic int bp_futile;

    /* Measured pre-parse admission. The largest captured file calibrates the
     * exact source-to-live-memory amplification alone. Subsequent workers must
     * reserve that measured amount against both this process's remaining
     * budget and the machine's currently available physical memory before they
     * may read or parse a file. This prevents the largest-first initial burst
     * and keeps concurrent Astrolabe projects from each assuming they own the
     * same total-RAM fraction. */
    cbm_mutex_t admission_mu;
    cbm_cond_t admission_cv;
    bool admission_calibrating;
    bool admission_calibrated;
    bool admission_failed;
    /* Exact next size-sorted source permitted to establish the generation's
     * memory amplification. Content defects advance this cursor by one; every
     * other worker waits, so calibration choice is schedule-independent. */
    int admission_calibration_sort_pos;
    size_t admission_exclusive_amplification;
    size_t admission_active_reserved_bytes;
    size_t admission_peak_reserved_bytes;
    int admission_active_files;
    _Atomic int admission_waits;
    _Atomic uint64_t retained_arena_bytes;
    _Atomic uint64_t retained_array_bytes;
    cbm_pipeline_t *pipeline;
} extract_ctx_t;

typedef struct {
    size_t source_bytes;
    size_t reserved_bytes;
    size_t rss_before;
    bool calibration;
    bool held;
} extract_admission_t;

/* Insert one definition node (and its route if present) into the local gbuf. */
static void insert_def_into_gbuf(extract_worker_state_t *ws, const cbm_file_info_t *fi,
                                 const CBMCallArray *calls, CBMDefinition *def,
                                 const uint8_t *file_source, size_t file_source_len) {
    /* CBM_SZ_32K: room for the struct-trigram (S1) + api-callee (S4) encoder
     * sources alongside the existing props (#374). Keep in sync with
     * pass_definitions.c::process_def. */
    char props[CBM_SZ_32K];
    char callees[CBM_SZ_8K];
    cbm_pipeline_build_def_callees(calls, def->qualified_name, (int)def->start_line,
                                   (int)def->end_line, callees, (int)sizeof(callees));
    build_def_props(props, sizeof(props), def, callees);
    const uint8_t *atom_source = (const uint8_t *)def->source;
    size_t atom_source_len = (size_t)def->source_len;
    bool source_is_slab = def->end_byte > def->start_byte &&
                          (size_t)def->end_byte <= file_source_len && file_source;
    if (source_is_slab) {
        atom_source = file_source + def->start_byte;
        atom_source_len = (size_t)(def->end_byte - def->start_byte);
    }
    int64_t func_id =
        source_is_slab
            ? cbm_gbuf_upsert_source_node_borrowed(
                  ws->local_gbuf, def->label ? def->label : "Function", def->name,
                  def->qualified_name, def->file_path ? def->file_path : fi->rel_path,
                  (int)def->start_line, (int)def->end_line, atom_source, atom_source_len,
                  def->start_byte, def->end_byte, props)
            : cbm_gbuf_upsert_source_node(
                  ws->local_gbuf, def->label ? def->label : "Function", def->name,
                  def->qualified_name, def->file_path ? def->file_path : fi->rel_path,
                  (int)def->start_line, (int)def->end_line, atom_source, atom_source_len,
                  def->start_byte, def->end_byte, props);
    if (func_id > 0) {
        ws->nodes_created++;
    } else {
        ws->errors++;
    }
    if (def->route_path && def->route_path[0] != '\0') {
        const char *rm = def->route_method ? def->route_method : "ANY";
        char route_qn[CBM_ROUTE_QN_SIZE];
        char cpath[CBM_SZ_256];
        snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", rm,
                 cbm_route_canon_path(def->route_path, cpath, sizeof(cpath)));
        char rprops[CBM_SZ_256];
        snprintf(rprops, sizeof(rprops), "{\"method\":\"%s\",\"source\":\"decorator\"}", rm);
        int64_t route_id =
            cbm_gbuf_upsert_node(ws->local_gbuf, "Route", def->route_path, route_qn,
                                 def->file_path ? def->file_path : fi->rel_path, 0, 0, rprops);
        char hprops[CBM_SZ_512];
        char esc_h[CBM_SZ_512];
        cbm_json_escape(esc_h, sizeof(esc_h), def->qualified_name);
        snprintf(hprops, sizeof(hprops), "{\"handler\":\"%s\"}", esc_h);
        cbm_gbuf_insert_edge(ws->local_gbuf, func_id, route_id, "HANDLES", hprops);
    }
}

static void insert_diagnostic_into_gbuf(extract_worker_state_t *ws, const cbm_file_info_t *fi,
                                        const char *project_name, const CBMParseDiagnostic *diag,
                                        const uint8_t *file_source, size_t file_source_len) {
    if (!diag || !diag->code || !diag->node_type) {
        return;
    }
    char *file_qn = cbm_pipeline_fqn_compute(project_name, fi->rel_path, "__file__");
    if (!file_qn) {
        ws->errors++;
        return;
    }
    char qn[CBM_SZ_2K];
    int qn_len = snprintf(qn, sizeof(qn), "%s.__parse_diagnostic__.%s.%u.%u.%s", file_qn,
                          diag->code, diag->start_byte, diag->end_byte, diag->node_type);
    free(file_qn);
    if (qn_len <= 0 || (size_t)qn_len >= sizeof(qn)) {
        ws->errors++;
        return;
    }
    char operation[CBM_SZ_256], node_type[CBM_SZ_256], message[CBM_SZ_512], remediation[CBM_SZ_512];
    cbm_json_escape(operation, sizeof(operation), diag->operation ? diag->operation : "parse");
    cbm_json_escape(node_type, sizeof(node_type), diag->node_type);
    cbm_json_escape(message, sizeof(message), diag->message ? diag->message : "parse degradation");
    cbm_json_escape(remediation, sizeof(remediation),
                    diag->remediation ? diag->remediation : "inspect the exact source span");
    char props[CBM_SZ_2K];
    snprintf(props, sizeof(props),
             "{\"code\":\"%s\",\"operation\":\"%s\",\"node_type\":\"%s\","
             "\"message\":\"%s\",\"remediation\":\"%s\",\"start_byte\":%u,"
             "\"end_byte\":%u,\"missing\":%s}",
             diag->code, operation, node_type, message, remediation, diag->start_byte,
             diag->end_byte, diag->is_missing ? "true" : "false");
    const uint8_t *atom_source = (const uint8_t *)diag->source;
    size_t atom_source_len = (size_t)diag->source_len;
    bool source_is_slab = diag->end_byte > diag->start_byte &&
                          (size_t)diag->end_byte <= file_source_len && file_source;
    if (source_is_slab) {
        atom_source = file_source + diag->start_byte;
        atom_source_len = (size_t)(diag->end_byte - diag->start_byte);
    }
    int64_t node_id =
        source_is_slab
            ? cbm_gbuf_upsert_source_node_borrowed(
                  ws->local_gbuf, "ParseDiagnostic", diag->code, qn, fi->rel_path,
                  (int)diag->start_line, (int)diag->end_line, atom_source, atom_source_len,
                  diag->start_byte, diag->end_byte, props)
            : cbm_gbuf_upsert_source_node(
                  ws->local_gbuf, "ParseDiagnostic", diag->code, qn, fi->rel_path,
                  (int)diag->start_line, (int)diag->end_line, atom_source, atom_source_len,
                  diag->start_byte, diag->end_byte, props);
    if (node_id > 0) {
        ws->nodes_created++;
    } else {
        ws->errors++;
    }
}

static void log_extract_fail(int pos, uint64_t ms, const char *path) {
    if (pos < PP_LOG_THRESH) {
        cbm_log_warn("parallel.extract.file.fail", "pos", itoa_log(pos), "elapsed_ms",
                     itoa_log((int)ms), "path", path);
    }
}

static void log_extract_done(int pos, uint64_t ms, int defs, const char *path) {
    if (pos < PP_LOG_THRESH || ms > PP_TIMER_THRESH) {
        cbm_log_info("parallel.extract.file.done", "pos", itoa_log(pos), "elapsed_ms",
                     itoa_log((int)ms), "defs", itoa_log(defs), "path", path);
    }
}

static size_t extract_admission_source_bytes(const cbm_file_info_t *file) {
    if (!file || file->size <= 0) {
        return 1;
    }
    if ((uint64_t)file->size > (uint64_t)SIZE_MAX) {
        return SIZE_MAX;
    }
    return (size_t)file->size;
}

static bool extract_admission_multiply(size_t left, size_t right, size_t *out) {
    if (!out || left == 0 || right == 0 || left > SIZE_MAX / right) {
        return false;
    }
    *out = left * right;
    return true;
}

static void extract_admission_log_refusal(const cbm_file_info_t *file, const char *code,
                                          size_t requested, size_t process_headroom,
                                          size_t machine_available) {
    char requested_buf[CBM_SZ_32];
    char process_buf[CBM_SZ_32];
    char machine_buf[CBM_SZ_32];
    snprintf(requested_buf, sizeof(requested_buf), "%zu", requested);
    snprintf(process_buf, sizeof(process_buf), "%zu", process_headroom);
    snprintf(machine_buf, sizeof(machine_buf), "%zu", machine_available);
    cbm_log_error("parallel.extract.admission.refused", "code", code, "path",
                  file && file->rel_path ? file->rel_path : "", "requested_bytes", requested_buf,
                  "process_headroom_bytes", process_buf, "machine_available_bytes", machine_buf,
                  "message", "the complete source cannot be admitted within measured memory",
                  "remediation",
                  "close competing memory-intensive work or increase the declared memory budget, "
                  "then retry the complete unchanged corpus");
}

static bool extract_admission_acquire(extract_ctx_t *ec, int sort_pos,
                                      const cbm_file_info_t *file, extract_admission_t *token) {
    if (!ec || !file || !token) {
        return false;
    }
    memset(token, 0, sizeof(*token));
    token->source_bytes = extract_admission_source_bytes(file);

    cbm_mutex_lock(&ec->admission_mu);
    for (;;) {
        if (ec->admission_failed ||
            atomic_load_explicit(ec->cancelled, memory_order_relaxed)) {
            cbm_mutex_unlock(&ec->admission_mu);
            return false;
        }

        size_t budget = cbm_mem_budget();
        size_t rss = cbm_mem_rss();
        size_t machine_available = cbm_mem_available();
        size_t process_headroom = budget > rss ? budget - rss : 0;
        if (budget == 0 || machine_available == 0) {
            ec->admission_failed = true;
            extract_admission_log_refusal(file, "CBM_EXTRACTION_MEMORY_STATE_UNAVAILABLE",
                                          token->source_bytes, process_headroom,
                                          machine_available);
            cbm_cond_broadcast(&ec->admission_cv);
            cbm_mutex_unlock(&ec->admission_mu);
            return false;
        }

        if (!ec->admission_calibrated) {
            if (sort_pos == ec->admission_calibration_sort_pos &&
                !ec->admission_calibrating && ec->admission_active_files == 0) {
                if (token->source_bytes > process_headroom ||
                    token->source_bytes > machine_available) {
                    ec->admission_failed = true;
                    extract_admission_log_refusal(
                        file, "CBM_EXTRACTION_CALIBRATION_ADMISSION_REFUSED", token->source_bytes,
                        process_headroom, machine_available);
                    cbm_cond_broadcast(&ec->admission_cv);
                    cbm_mutex_unlock(&ec->admission_mu);
                    return false;
                }
                ec->admission_calibrating = true;
                ec->admission_active_files = 1;
                ec->admission_active_reserved_bytes = token->source_bytes;
                ec->admission_peak_reserved_bytes = token->source_bytes;
                token->reserved_bytes = token->source_bytes;
                token->rss_before = rss;
                token->calibration = true;
                token->held = true;
                cbm_mutex_unlock(&ec->admission_mu);
                return true;
            }
            atomic_fetch_add_explicit(&ec->admission_waits, 1, memory_order_relaxed);
            cbm_cond_wait(&ec->admission_cv, &ec->admission_mu);
            continue;
        }

        size_t estimate = 0;
        if (!extract_admission_multiply(token->source_bytes,
                                        ec->admission_exclusive_amplification,
                                        &estimate)) {
            ec->admission_failed = true;
            extract_admission_log_refusal(file, "CBM_EXTRACTION_MEMORY_ESTIMATE_OVERFLOW",
                                          SIZE_MAX, process_headroom, machine_available);
            cbm_cond_broadcast(&ec->admission_cv);
            cbm_mutex_unlock(&ec->admission_mu);
            return false;
        }
        size_t headroom = process_headroom < machine_available ? process_headroom : machine_available;
        bool reserve_fits = estimate <= headroom &&
                            ec->admission_active_reserved_bytes <= headroom - estimate;
        if (reserve_fits) {
            ec->admission_active_reserved_bytes += estimate;
            if (ec->admission_active_reserved_bytes > ec->admission_peak_reserved_bytes) {
                ec->admission_peak_reserved_bytes = ec->admission_active_reserved_bytes;
            }
            ec->admission_active_files++;
            token->reserved_bytes = estimate;
            token->rss_before = rss;
            token->held = true;
            cbm_mutex_unlock(&ec->admission_mu);
            return true;
        }

        if (ec->admission_active_files == 0) {
            ec->admission_failed = true;
            extract_admission_log_refusal(file, "CBM_EXTRACTION_MEMORY_ADMISSION_REFUSED", estimate,
                                          process_headroom, machine_available);
            cbm_cond_broadcast(&ec->admission_cv);
            cbm_mutex_unlock(&ec->admission_mu);
            return false;
        }
        atomic_fetch_add_explicit(&ec->admission_waits, 1, memory_order_relaxed);
        cbm_cond_wait(&ec->admission_cv, &ec->admission_mu);
    }
}

static size_t extract_admission_ratio(size_t observed_bytes, size_t source_bytes) {
    if (source_bytes == 0 || observed_bytes == 0) {
        return 1;
    }
    size_t quotient = observed_bytes / source_bytes;
    size_t remainder = observed_bytes % source_bytes;
    if (remainder != 0 && quotient < SIZE_MAX) {
        quotient++;
    }
    return quotient > 0 ? quotient : 1;
}

static void extract_admission_release(extract_ctx_t *ec, extract_admission_t *token,
                                      const cbm_file_info_t *file, size_t parse_rss,
                                      size_t retained_bytes, bool extraction_succeeded,
                                      const CBMExtractionError *extraction_error) {
    if (!ec || !token || !token->held) {
        return;
    }
    cbm_mutex_lock(&ec->admission_mu);
    if (token->reserved_bytes > ec->admission_active_reserved_bytes ||
        ec->admission_active_files <= 0) {
        ec->admission_failed = true;
        cbm_log_error("parallel.extract.admission.invariant", "code",
                      "CBM_EXTRACTION_MEMORY_RESERVATION_INVARIANT", "message",
                      "the extraction memory reservation accounting became inconsistent",
                      "remediation", "inspect the exact admission acquire/release pair and retry");
    } else {
        ec->admission_active_reserved_bytes -= token->reserved_bytes;
        ec->admission_active_files--;
    }

    if (token->calibration) {
        size_t observed_growth =
            parse_rss > token->rss_before ? parse_rss - token->rss_before : 0;
        bool content_defect = extraction_error &&
                              extraction_error->outcome_class ==
                                  CBM_EXTRACTION_OUTCOME_CONTENT_DEFECT;
        if (!extraction_succeeded && content_defect) {
            /* A source-local defect cannot establish a trustworthy memory
             * amplification, but it also cannot abort the corpus. Advance to
             * exactly the next immutable size/path-sorted file. Allowing an
             * arbitrary waiter here would leak worker scheduling into policy. */
            if (ec->admission_calibration_sort_pos < ec->file_count) {
                ec->admission_calibration_sort_pos++;
            }
            char next_position[CBM_SZ_32];
            snprintf(next_position, sizeof(next_position), "%d",
                     ec->admission_calibration_sort_pos);
            cbm_log_warn("parallel.extract.admission.calibration_source_isolated", "code",
                         extraction_error->code, "path",
                         file && file->rel_path ? file->rel_path : "", "next_sort_position",
                         next_position, "message",
                         "the deterministic calibration source was isolated as a content defect",
                         "remediation",
                         "inspect the persisted ContentDefect; the next size-ordered source will "
                         "calibrate memory admission");
        } else if (!extraction_succeeded) {
            ec->admission_failed = true;
            const char *cause_code = extraction_error && extraction_error->code
                                         ? extraction_error->code
                                         : "CBM_EXTRACTION_FAILED";
            cbm_log_error(
                "parallel.extract.admission.calibration_failed", "code",
                "CBM_EXTRACTION_MEMORY_CALIBRATION_SOURCE_FAILED", "cause_code", cause_code,
                "path", file && file->rel_path ? file->rel_path : "", "message",
                "the exclusive calibration source did not complete authoritative extraction",
                "remediation",
                "fix the exact causal extraction failure; a partial or timed-out parse can never "
                "publish a memory amplification");
            cbm_pipeline_record_fatal_error(
                ec->pipeline, "CBM_EXTRACTION_MEMORY_CALIBRATION_SOURCE_FAILED",
                "calibrate_extraction_memory", "parallel_extract",
                file && file->rel_path ? file->rel_path : "", token->source_bytes,
                "the exclusive calibration source did not complete authoritative extraction",
                "inspect the causal parser.budget.refused record, fix that failure, and retry the "
                "complete unchanged corpus");
        } else if (!ec->admission_failed && observed_growth > SIZE_MAX - retained_bytes) {
            ec->admission_failed = true;
            cbm_log_error(
                "parallel.extract.admission.calibration_failed", "code",
                "CBM_EXTRACTION_MEMORY_CALIBRATION_OVERFLOW", "message",
                "the exclusive parse growth and retained fact ownership exceed addressable memory",
                "remediation",
                "preserve the exact extraction diagnostics and retry the complete unchanged corpus");
        } else if (!ec->admission_failed) {
            /* This is the only attributable process-RSS sample in the generation:
             * every peer is held while the largest file calibrates. Include the
             * retained fact copy because fact compaction can overlap the parsed
             * result before phase-local ownership is retired. Process-wide RSS
             * observations made while peers run are deliberately never divided by
             * one file's size: that charges peer/graph growth to an unrelated file
             * and can poison the generation with an unbounded amplification. */
            size_t observed = observed_growth + retained_bytes;
            ec->admission_exclusive_amplification =
                extract_admission_ratio(observed, token->source_bytes);
            ec->admission_calibrated = true;
            char source_buf[CBM_SZ_32];
            char observed_buf[CBM_SZ_32];
            char factor_buf[CBM_SZ_32];
            snprintf(source_buf, sizeof(source_buf), "%zu", token->source_bytes);
            snprintf(observed_buf, sizeof(observed_buf), "%zu", observed);
            snprintf(factor_buf, sizeof(factor_buf), "%zu",
                     ec->admission_exclusive_amplification);
            cbm_log_info("parallel.extract.admission.calibrated", "source_bytes", source_buf,
                         "observed_bytes", observed_buf, "amplification", factor_buf);
        }
        ec->admission_calibrating = false;
    }
    token->held = false;
    cbm_cond_broadcast(&ec->admission_cv);
    cbm_mutex_unlock(&ec->admission_mu);
}

static void extract_worker(int worker_id, void *ctx_ptr) {
    extract_ctx_t *ec = ctx_ptr;
    extract_worker_state_t *ws = &ec->workers[worker_id];

    /* Lazy gbuf creation */
    if (!ws->local_gbuf) {
        ws->local_gbuf = cbm_gbuf_new_shared_ids(ec->project_name, ec->repo_path, ec->shared_ids);
    }

    /* Pull files from shared atomic counter */
    while (SKIP_ONE) {
        int sort_pos =
            atomic_fetch_add_explicit(&ec->next_file_idx, SKIP_ONE, memory_order_relaxed);
        if (sort_pos >= ec->file_count) {
            break;
        }
        if (atomic_load_explicit(ec->cancelled, memory_order_relaxed)) {
            break;
        }

        /* Memory back-pressure (large repos): if the process is over its RSS
         * budget, reclaim this thread's freed pages and nap so peer workers can
         * finish their current file and return memory before this worker adds
         * another parse working set. Caps the concurrent extraction transient
         * near the budget instead of letting all workers parse their biggest
         * files at once. Self-disabling when the budget is unset (tests) or RSS
         * is under budget; bounded spins avoid deadlock when the resident graph
         * is itself near budget (then proceed with a soft overshoot).
         *
         * Futility latch: when a FULL nap cycle ends still over budget, the
         * resident floor — not transients — holds the memory; napping again on
         * the next pull cannot reclaim it and only idles workers (linux kernel:
         * one full cycle per pull ≈ 390 s at 79% avg CPU). Latch bp_futile and
         * proceed with the soft overshoot; the over-budget probe below re-arms
         * the gate as soon as RSS drains under budget. */
        if (cbm_mem_budget() > 0) {
            bool over = cbm_mem_over_budget();
            bool futile = atomic_load_explicit(&ec->bp_futile, memory_order_relaxed) != 0;
            if (over && !futile) {
                cbm_mem_collect();
                atomic_fetch_add_explicit(&g_bp_nap_cycles, SKIP_ONE, memory_order_relaxed);
                int bp = 0;
                for (; bp < PP_BACKPRESSURE_MAX_SPINS && cbm_mem_over_budget() &&
                       !atomic_load_explicit(ec->cancelled, memory_order_relaxed);
                     bp++) {
                    struct timespec nap = {0, PP_BACKPRESSURE_NAP_NS};
                    cbm_nanosleep(&nap, NULL);
                }
                if (bp == PP_BACKPRESSURE_MAX_SPINS && cbm_mem_over_budget()) {
                    /* Log only the 0→1 transition: all workers race into the
                     * gate before anyone latches, so a plain store would WARN
                     * once per worker (12 lines per latch event). */
                    if (atomic_exchange_explicit(&ec->bp_futile, 1, memory_order_relaxed) == 0) {
                        cbm_log_warn("mem.backpressure.futile", "action", "soft_overshoot");
                    }
                }
            } else if (!over && futile) {
                atomic_store_explicit(&ec->bp_futile, 0, memory_order_relaxed);
            }
        }

        int file_idx = ec->sorted[sort_pos].idx;
        const cbm_file_info_t *fi = &ec->files[file_idx];

        extract_admission_t admission;
        if (!extract_admission_acquire(ec, sort_pos, fi, &admission)) {
            cbm_pipeline_record_fatal_error(
                ec->pipeline, "CBM_EXTRACTION_MEMORY_ADMISSION_REFUSED",
                "acquire_extraction_memory", "parallel_extract", fi->rel_path,
                extract_admission_source_bytes(fi),
                "the complete source file could not be admitted within measured memory",
                "close competing memory-intensive work or increase the declared memory budget, "
                "then retry the unchanged corpus");
            atomic_store_explicit(ec->cancelled, 1, memory_order_relaxed);
            ws->errors++;
            break;
        }

        /* Borrow the one verified immutable source entry. Extraction is never
         * permitted to reopen the snapshot or manufacture a substitute. */
        size_t source_size = 0;
        const uint8_t *source_bytes = NULL;
        if (cbm_pipeline_borrow_source(ec->pipeline, ec->source_slab, fi, "parallel_extract_source",
                                       &source_bytes, &source_size) != 0) {
            ws->errors++;
            atomic_store_explicit(ec->cancelled, 1, memory_order_relaxed);
            extract_admission_release(ec, &admission, fi, cbm_mem_rss(), 0, false, NULL);
            break;
        }
        int source_len = (int)source_size;
        const char *source = (const char *)source_bytes;
        if (source_len == 0) {
            extract_admission_release(ec, &admission, fi, cbm_mem_rss(), 0, true, NULL);
            if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_PARALLEL_EXTRACT,
                                                "parallel_extract",
                                                (uint64_t)ec->file_count) != 0) {
                ws->errors++;
                atomic_store_explicit(ec->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_pipeline_record_fatal_error(
                    ec->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
                    "publish_parallel_extract_progress", "parallel_extract",
                    fi->rel_path ? fi->rel_path : "", (size_t)sort_pos,
                    "the completed extraction unit could not advance semantic progress",
                    "preserve the worker workspace, repair the progress stream, and retry the "
                    "unchanged repository");
                break;
            }
            continue;
        }

        /* Per-file start log: shows which file each worker is processing.
         * Critical for diagnosing stuck workers on large vendored files. */
        if (sort_pos < PP_LOG_THRESH) { /* first 2 rounds of workers = most interesting */
            cbm_log_info("parallel.extract.file.start", "pos", itoa_log(sort_pos), "size_kb",
                         itoa_log(source_len / CBM_SZ_1K), "path", fi->rel_path);
        }

        uint64_t file_t0 = extract_now_ns();

        const char *rust_edition = cbm_cargo_edition_for_path(ec->rust_manifest, fi->rel_path);
        CBMFileResult *result = cbm_extract_file_at_path_with_metadata_borrow_source(
            source, source_len, fi->language, ec->project_name, fi->rel_path, fi->path,
            rust_edition, cbm_cargo_is_crate_root(ec->rust_manifest, fi->rel_path),
            fi->structured_classification[0] ? fi->structured_classification : NULL,
            fi->structured_classification_provenance[0]
                ? fi->structured_classification_provenance
                : NULL,
            cbm_parse_budget_micros(source_size), NULL, NULL,
            cbm_compile_context_for_file(ec->compile_contexts, fi->rel_path));

        /* Read the live process source of truth while the parse tree and parser
         * allocations are still resident. The exclusive first file uses this
         * observation to calibrate the source-to-memory admission ratio. */
        size_t parse_rss = cbm_mem_rss();

        uint64_t file_elapsed_ms = (extract_now_ns() - file_t0) / PP_USEC_PER_MS;

        if (!result) {
            log_extract_fail(sort_pos, file_elapsed_ms, fi->rel_path);
            ws->errors++;
            cbm_pipeline_record_fatal_error(
                ec->pipeline, "CBM_EXTRACTION_RESULT_ALLOC_FAILED", "allocate_file_result",
                "parallel_extract", fi->rel_path, sizeof(CBMFileResult),
                "the authoritative per-file extraction result could not be allocated",
                "free memory or reduce concurrent extraction workers, then retry the unchanged "
                "corpus");
            atomic_store_explicit(ec->cancelled, 1, memory_order_relaxed);
            cbm_destroy_thread_parser();
            cbm_slab_reclaim();
            cbm_mem_collect();
            extract_admission_release(ec, &admission, fi, parse_rss, 0, false, NULL);
            break;
        }

        size_t extracted_arena_bytes = result->arena.total_alloc;

        /* The parse tree is the final tree-sitter-owned consumer. Replace the
         * extraction arena immediately with an exact deep copy of its published
         * facts, borrowing only hash-bound source spans. This retires parser/LSP
         * scopes, type graphs, token workspaces, and other phase-local arena
         * state per file instead of retaining their whole-corpus sum. */
        cbm_free_tree(result);
        if (!cbm_file_result_compact_facts(result, source, source_len)) {
            cbm_file_result_set_error(
                result, "CBM_EXTRACTION_FACT_COMPACTION_FAILED", "compact_file_facts",
                "result_fact_compaction", extracted_arena_bytes,
                "the completed extraction could not retire phase-local ownership",
                "inspect the exact arena failure and retry the complete unchanged corpus");
        }
        size_t result_arena_bytes = result->arena.total_alloc;
        size_t result_array_bytes = cbm_file_result_array_bytes(result);
        atomic_fetch_add_explicit(&ec->retained_arena_bytes, (uint64_t)result_arena_bytes,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&ec->retained_array_bytes, (uint64_t)result_array_bytes,
                                  memory_order_relaxed);
        {
            char source_text[32];
            char parse_rss_text[32];
            char extracted_arena_text[32];
            char arena_text[32];
            char arrays_text[32];
            char reserved_text[32];
            char elapsed_text[32];
            snprintf(source_text, sizeof(source_text), "%zu", source_size);
            snprintf(parse_rss_text, sizeof(parse_rss_text), "%zu", parse_rss);
            snprintf(extracted_arena_text, sizeof(extracted_arena_text), "%zu",
                     extracted_arena_bytes);
            snprintf(arena_text, sizeof(arena_text), "%zu", result_arena_bytes);
            snprintf(arrays_text, sizeof(arrays_text), "%zu", result_array_bytes);
            snprintf(reserved_text, sizeof(reserved_text), "%zu", admission.reserved_bytes);
            snprintf(elapsed_text, sizeof(elapsed_text), "%llu",
                     (unsigned long long)file_elapsed_ms);
            cbm_log_info("parallel.extract.file.memory", "path", fi->rel_path ? fi->rel_path : "",
                         "source_bytes", source_text, "parse_rss_bytes", parse_rss_text,
                         "extracted_arena_bytes", extracted_arena_text,
                         "retained_arena_bytes", arena_text, "retained_array_bytes", arrays_text,
                         "reserved_bytes", reserved_text, "elapsed_ms", elapsed_text);
        }
        log_extract_done(sort_pos, file_elapsed_ms, result->defs.count, fi->rel_path);

        /* The deterministic post-merge barrier owns classification and durable
         * recording. Keeping a second worker-order copy would make outcome order
         * scheduling-dependent and would double-count content defects. */
        if (result->has_error) {
            ws->errors++;
        }

        /* Create definition nodes in local gbuf */
        for (int d = 0; d < result->defs.count; d++) {
            CBMDefinition *def = &result->defs.items[d];
            if (def->qualified_name && def->name) {
                insert_def_into_gbuf(ws, fi, &result->calls, def, source_bytes, source_size);
            }
        }
        for (int d = 0; d < result->diagnostics.count; d++) {
            insert_diagnostic_into_gbuf(ws, fi, ec->project_name,
                                        &result->diagnostics.items[d], source_bytes, source_size);
        }
        ws->parse_recovery_diagnostics += (uint_least64_t)result->diagnostics.count;

        /* Cache the exact fact-only result for Phase 3B and Phase 4. */
        ec->result_cache[file_idx] = result;

        /* Progress logging: log every 10 files (atomic read, no contention) */
        if ((sort_pos + SKIP_ONE) % PP_LOG_INTERVAL == 0 || sort_pos + SKIP_ONE == ec->file_count) {
            cbm_log_info("parallel.extract.progress", "done", itoa_log(sort_pos + SKIP_ONE),
                         "total", itoa_log(ec->file_count));
        }

        /* Reclaim all slab + tier2 memory between files.
         *
         * After cbm_free_tree(result), all tree nodes are on free lists.
         * We then destroy the parser (frees its internal allocations too),
         * leaving ZERO live slab/tier2 pointers. At that point, we can
         * safely munmap/free every page, bounding peak memory per-file
         * instead of accumulating across all 644 files.
         *
         * get_thread_parser() in cbm_extract_file will create a fresh
         * parser for the next file — cost is microseconds vs seconds
         * for parsing. This prevents unbounded memory accumulation and works
         * identically on macOS, Linux, and Windows. */
        cbm_destroy_thread_parser();
        cbm_slab_reclaim();
        cbm_mem_collect();
        extract_admission_release(ec, &admission, fi, parse_rss,
                                  result_arena_bytes + result_array_bytes,
                                  !result->has_error, &result->error);
        if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_PARALLEL_EXTRACT,
                                            "parallel_extract", (uint64_t)ec->file_count) != 0) {
            ws->errors++;
            atomic_store_explicit(ec->cancelled, SKIP_ONE, memory_order_relaxed);
            cbm_pipeline_record_fatal_error(
                ec->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
                "publish_parallel_extract_progress", "parallel_extract",
                fi->rel_path ? fi->rel_path : "", (size_t)sort_pos,
                "the completed extraction unit could not advance semantic progress",
                "preserve the worker workspace, repair the progress stream, and retry the "
                "unchanged repository");
            break;
        }
    }

    /* Final cleanup (parser already destroyed in loop, just slab state) */
    cbm_slab_destroy_thread();
    cbm_kind_in_set_free_cache(); /* free this worker thread's node-type bitset cache */
}

static int build_captured_pkgmap(cbm_pipeline_ctx_t *ctx) {
    CBMHashTable *captured_pkgmap = NULL;
    if (cbm_pkgmap_build_from_files_checked(ctx->pipeline, ctx->all_files, ctx->all_file_count,
                                            ctx->project_name, &captured_pkgmap) != 0) {
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_set_pkgmap(captured_pkgmap);
    return 0;
}

static void log_extract_mem_stats(int worker_count) {
    if (cbm_mem_budget() > 0) {
        size_t mb = (size_t)CBM_SZ_1K * CBM_SZ_1K;
        cbm_log_info("parallel.extract.mem", "rss_mb", itoa_log((int)(cbm_mem_rss() / mb)),
                     "peak_mb", itoa_log((int)(cbm_mem_peak_rss() / mb)), "budget_mb",
                     itoa_log((int)(cbm_mem_budget() / mb)), "per_worker_mb",
                     itoa_log((int)(cbm_mem_worker_budget(worker_count) / mb)));
    }
}

void cbm_parallel_rebase_shared_ids(const cbm_gbuf_t *main_gbuf, _Atomic int64_t *shared_ids,
                                    const char *phase) {
    int64_t main_next_id = cbm_gbuf_next_id(main_gbuf);
    int64_t shared_before = atomic_load_explicit(shared_ids, memory_order_relaxed);
    int64_t shared_observed = shared_before;
    while (shared_observed < main_next_id &&
           !atomic_compare_exchange_weak_explicit(shared_ids, &shared_observed, main_next_id,
                                                  memory_order_relaxed, memory_order_relaxed)) {}
    int64_t shared_after = atomic_load_explicit(shared_ids, memory_order_relaxed);
    if (shared_after > shared_before) {
        char shared_before_buf[CBM_SZ_32];
        char main_next_buf[CBM_SZ_32];
        char shared_after_buf[CBM_SZ_32];
        snprintf(shared_before_buf, sizeof(shared_before_buf), "%lld", (long long)shared_before);
        snprintf(main_next_buf, sizeof(main_next_buf), "%lld", (long long)main_next_id);
        snprintf(shared_after_buf, sizeof(shared_after_buf), "%lld", (long long)shared_after);
        cbm_log_info("parallel.id_ceiling_rebased", "code", "CBM_GRAPH_ID_SEQUENCE_REBASED",
                     "phase", phase, "shared_before", shared_before_buf, "main_next_id",
                     main_next_buf, "shared_after", shared_after_buf);
    }
}

static int reject_invalid_parallel_worker_count(const char *operation, int worker_count) {
    cbm_log_error("parallel.worker_count_invalid", "code", "CBM_WORKER_COUNT_INVALID",
                  "operation", operation ? operation : "parallel", "worker_count",
                  itoa_log(worker_count), "message", "worker-count argument is invalid",
                  "remediation",
                  "pass a positive worker count; when derived from CBM_WORKERS, set it to an "
                  "integer from 1 through 256 or remove it");
    return CBM_NOT_FOUND;
}

static int validate_parallel_source_bindings(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                             int file_count, const char *operation) {
    if (!ctx || !files || file_count < 0) {
        if (ctx && ctx->pipeline) {
            cbm_pipeline_record_fatal_error(
                ctx->pipeline, "CBM_SOURCE_SLAB_CONSUMER_ARGUMENT_INVALID", operation,
                "source_slab", "", file_count < 0 ? (size_t)(-(int64_t)file_count) : 0,
                "the parallel source consumer received an invalid context, file view, or count",
                "repair the parallel dispatch contract before retrying the unchanged generation");
        } else {
            cbm_log_error(
                "source_slab.consumer_refused", "code", "CBM_SOURCE_SLAB_CONSUMER_ARGUMENT_INVALID",
                "operation", operation ? operation : "validate_parallel_source_bindings", "message",
                "the parallel source consumer received an invalid context, file view, or count",
                "remediation",
                "repair the parallel dispatch contract before retrying the unchanged generation");
        }
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        const uint8_t *source = NULL;
        size_t source_len = 0;
        if (cbm_pipeline_borrow_source(ctx->pipeline, ctx->source_slab, &files[i], operation,
                                       &source, &source_len) != 0) {
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

int cbm_parallel_extract(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count) {
    if (file_count == 0) {
        return 0;
    }
    if (validate_parallel_source_bindings(ctx, files, file_count,
                                          "validate_parallel_extract_sources") != 0) {
        return CBM_NOT_FOUND;
    }
    if (worker_count <= 0) {
        return reject_invalid_parallel_worker_count("parallel_extract", worker_count);
    }

    cbm_log_info("parallel.extract.start", "files", itoa_log(file_count), "workers",
                 itoa_log(worker_count));
    cbm_log_info("parallel.extract.source_slab", "files", itoa_log(ctx->source_slab->file_count),
                 "sha256", ctx->source_slab->sha256);
    {
        const cbm_parse_budget_policy_t *policy = cbm_parse_budget_policy();
        char base_text[32], throughput_text[32], stall_text[32], balance_text[32], max_text[32];
        snprintf(base_text, sizeof(base_text), "%llu",
                 (unsigned long long)policy->base_micros);
        snprintf(throughput_text, sizeof(throughput_text), "%llu",
                 (unsigned long long)policy->minimum_forward_bytes_per_second);
        snprintf(stall_text, sizeof(stall_text), "%llu",
                 (unsigned long long)policy->forward_stall_micros);
        snprintf(balance_text, sizeof(balance_text), "%llu",
                 (unsigned long long)policy->final_balance_micros);
        snprintf(max_text, sizeof(max_text), "%llu",
                 (unsigned long long)policy->maximum_total_micros);
        cbm_log_info("parser.budget.policy", "registry_version", policy->registry_version,
                     "measurement_source", policy->measurement_source, "base_micros", base_text,
                     "minimum_forward_bytes_per_second", throughput_text,
                     "forward_stall_micros", stall_text, "final_balance_micros", balance_text,
                     "maximum_total_micros", max_text, "fallback", "none");
    }

    /* Log per-worker memory budget */
    if (cbm_mem_budget() > 0) {
        size_t worker_budget = cbm_mem_worker_budget(worker_count);
        cbm_log_info("parallel.mem.budget", "total_mb",
                     itoa_log((int)(cbm_mem_budget() / ((size_t)CBM_SZ_1K * CBM_SZ_1K))),
                     "per_worker_mb",
                     itoa_log((int)(worker_budget / ((size_t)CBM_SZ_1K * CBM_SZ_1K))));
    }

    /* Sub-phase: Ensure extraction library is initialized */
    CBM_PROF_START(t_init);
    if (cbm_init() != 0) {
        cbm_log_error("parallel.init_failed", "code", "CBM_ALLOCATOR_INIT_FAILED", "message",
                      "the extraction allocator contract could not be initialized", "remediation",
                      "inspect allocator.bind_failed and restart the process");
        return CBM_NOT_FOUND;
    }

    /* Tree-sitter's process-global allocator is installed at cbm_alloc_init()
     * before any parser exists. This idempotent call preserves direct callers
     * that reach the parallel pass without going through main(), but it must not
     * publish a new allocator generation after sequential requests have already
     * created parser objects. */
    cbm_slab_install();
    CBM_PROF_END("parallel_extract", "1_init_libs", t_init);

    /* Sub-phase: Sort files by descending size for tail-latency reduction */
    CBM_PROF_START(t_sort);
    file_sort_entry_t *sorted = malloc((size_t)file_count * sizeof(file_sort_entry_t));
    if (!sorted) {
        cbm_pipeline_record_fatal_error(
            ctx->pipeline, "CBM_EXTRACTION_SORT_ALLOC_FAILED", "allocate_file_sort",
            "parallel_extract", ctx->repo_path,
            (size_t)file_count * sizeof(file_sort_entry_t),
            "the deterministic extraction schedule could not be allocated",
            "free memory or reduce concurrent repository work, then retry the unchanged corpus");
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        sorted[i].idx = i;
        sorted[i].size = files[i].size;
    }
    qsort(sorted, file_count, sizeof(file_sort_entry_t), compare_by_size_desc);
    CBM_PROF_END_N("parallel_extract", "2_sort_files", t_sort, file_count);

    /* Allocate per-worker state (cache-line aligned via posix_memalign) */
    extract_worker_state_t *workers = NULL;
    if (cbm_aligned_alloc((void **)&workers, CBM_CACHE_LINE,
                          (size_t)worker_count * sizeof(extract_worker_state_t)) != 0) {
        cbm_pipeline_record_fatal_error(
            ctx->pipeline, "CBM_EXTRACTION_WORKER_STATE_ALLOC_FAILED", "allocate_worker_state",
            "parallel_extract", ctx->repo_path,
            (size_t)worker_count * sizeof(extract_worker_state_t),
            "the bounded extraction worker state could not be allocated",
            "free memory or reduce concurrent repository work, then retry the unchanged corpus");
        free(sorted);
        return CBM_NOT_FOUND;
    }
    memset(workers, 0, (size_t)worker_count * sizeof(extract_worker_state_t));

    extract_ctx_t ec = {
        .files = files,
        .sorted = sorted,
        .file_count = file_count,
        .project_name = ctx->project_name,
        .repo_path = ctx->repo_path,
        .rust_manifest = ctx->rust_manifest,
        .compile_contexts = ctx->compile_contexts,
        .workers = workers,
        .max_workers = worker_count,
        .result_cache = result_cache,
        .shared_ids = shared_ids,
        .cancelled = ctx->cancelled,
        .source_slab = ctx->source_slab,
        .pipeline = ctx->pipeline,
    };
    atomic_init(&ec.next_worker_id, 0);
    atomic_init(&ec.next_file_idx, 0);
    atomic_init(&ec.bp_futile, 0);
    atomic_init(&ec.admission_waits, 0);
    atomic_init(&ec.retained_arena_bytes, 0);
    atomic_init(&ec.retained_array_bytes, 0);
    cbm_mutex_init(&ec.admission_mu);
    cbm_cond_init(&ec.admission_cv);

    /* Sub-phase: Dispatch workers (parse + extract per file, PARALLEL) */
    CBM_PROF_START(t_dispatch);
    cbm_parallel_for_opts_t parallel_opts = {
        .max_workers = worker_count,
        .force_pthreads = false,
        .operation = "parallel_extract",
    };
    cbm_parallel_for_result_t dispatch_result = {0};
    int dispatch_rc =
        cbm_parallel_for(worker_count, extract_worker, &ec, parallel_opts, &dispatch_result);
    record_worker_pool_dispatch(ctx ? ctx->pipeline : NULL, &dispatch_result);
    CBM_PROF_END_N("parallel_extract", "3_dispatch_workers_parallel", t_dispatch, file_count);
    cbm_cond_destroy(&ec.admission_cv);
    cbm_mutex_destroy(&ec.admission_mu);
    if (dispatch_rc != 0) {
        for (int i = 0; i < worker_count; i++) {
            if (workers[i].local_gbuf) {
                cbm_gbuf_free(workers[i].local_gbuf);
            }
        }
        cbm_aligned_free(workers);
        free(sorted);
        return CBM_NOT_FOUND;
    }

    /* Sub-phase: Merge all local gbufs into main gbuf (SEQUENTIAL, gbuf not thread-safe) */
    CBM_PROF_START(t_merge);
    int total_nodes = 0;
    int total_errors = 0;
    for (int i = 0; i < worker_count; i++) {
        if (workers[i].local_gbuf) {
            cbm_gbuf_merge(ctx->gbuf, workers[i].local_gbuf);
            total_nodes += workers[i].nodes_created;
            total_errors += workers[i].errors;
            cbm_pipeline_add_parse_recovery_diagnostics(ctx->pipeline,
                                                        workers[i].parse_recovery_diagnostics);
            cbm_gbuf_free(workers[i].local_gbuf);
        }
    }
    CBM_PROF_END_N("parallel_extract", "4_merge_gbufs_seq", t_merge, total_nodes);
    cbm_parallel_rebase_shared_ids(ctx->gbuf, shared_ids, "parallel_extract.merge");

    int extraction_rc = cbm_pipeline_reject_file_failures(ctx->pipeline, files, file_count,
                                                          result_cache, "parallel_extract");
    if (extraction_rc != 0) {
        cbm_aligned_free(workers);
        free(sorted);
        return extraction_rc;
    }

    int pkgmap_rc = build_captured_pkgmap(ctx);
    cbm_parallel_rebase_shared_ids(ctx->gbuf, shared_ids, "parallel_extract.package_map");

    cbm_aligned_free(workers);
    free(sorted);

    if (pkgmap_rc != 0) {
        return CBM_NOT_FOUND;
    }

    if (atomic_load(ctx->cancelled)) {
        return CBM_NOT_FOUND;
    }

    log_extract_mem_stats(worker_count);

    {
        char amplification[CBM_SZ_32];
        char peak_reserved[CBM_SZ_32];
        char waits[CBM_SZ_32];
        snprintf(amplification, sizeof(amplification), "%zu",
                 ec.admission_exclusive_amplification);
        snprintf(peak_reserved, sizeof(peak_reserved), "%zu",
                 ec.admission_peak_reserved_bytes);
        snprintf(waits, sizeof(waits), "%d",
                 atomic_load_explicit(&ec.admission_waits, memory_order_relaxed));
        cbm_log_info("parallel.extract.admission", "exclusive_amplification", amplification,
                     "peak_reserved_bytes", peak_reserved, "waits", waits, "failed",
                     ec.admission_failed ? "true" : "false");
    }

    {
        char source_slab_bytes[CBM_SZ_32];
        char arena_bytes[CBM_SZ_32];
        char array_bytes[CBM_SZ_32];
        snprintf(source_slab_bytes, sizeof(source_slab_bytes), "%zu",
                 ctx->source_slab->allocated_bytes);
        snprintf(arena_bytes, sizeof(arena_bytes), "%llu",
                 (unsigned long long)atomic_load_explicit(&ec.retained_arena_bytes,
                                                          memory_order_relaxed));
        snprintf(array_bytes, sizeof(array_bytes), "%llu",
                 (unsigned long long)atomic_load_explicit(&ec.retained_array_bytes,
                                                          memory_order_relaxed));
        cbm_log_info("parallel.extract.retained", "source_slab_bytes", source_slab_bytes,
                     "result_arena_bytes", arena_bytes, "result_array_bytes", array_bytes);
    }

    cbm_log_info("parallel.extract.done", "nodes", itoa_log(total_nodes), "errors",
                 itoa_log(total_errors));
    return 0;
}

/* ── Phase 3B: Serial Registry Build ─────────────────────────────── */

/* Register one definition and create DEFINES + DEFINES_METHOD edges. Returns edge count. */
static int register_and_link_def(cbm_pipeline_ctx_t *ctx, const CBMDefinition *def, const char *rel,
                                 int *reg_entries) {
    int edges = 0;
    if (!def->name || !def->qualified_name || !def->label) {
        return 0;
    }
    /* Code-reference symbols only. Config/data keys remain graph atoms but do
     * not enter textual code resolution. KEEP IN SYNC with the sequential and
     * incremental paths. */
    if (cbm_pipeline_definition_is_registry_symbol(def->label,
                                                   def->file_path ? def->file_path : rel)) {
        if (cbm_registry_add(ctx->registry, def->name, def->qualified_name, def->label)) {
            (*reg_entries)++;
        }
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    const cbm_gbuf_node_t *def_node = cbm_pipeline_find_definition_node(ctx->gbuf, def, rel);
    if (file_node && def_node) {
        cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, def_node->id, "DEFINES", "{}");
        edges++;
    }
    free(file_qn);
    if (def->parent_class && strcmp(def->label, "Method") == 0) {
        /* KEEP IN SYNC with pass_definitions.c: the method's own parse-time byte
         * discriminates same-named parents that share one physical line (#1022). */
        const cbm_gbuf_node_t *parent = cbm_gbuf_find_by_qn_location(
            ctx->gbuf, def->parent_class, def->file_path ? def->file_path : rel,
            (int)def->start_line, (uint64_t)def->start_byte, def->end_byte > def->start_byte);
        if (parent && def_node) {
            cbm_gbuf_insert_edge(ctx->gbuf, parent->id, def_node->id, "DEFINES_METHOD", "{}");
        }
    }
    return edges;
}

static int link_diagnostic(cbm_pipeline_ctx_t *ctx, const CBMParseDiagnostic *diag,
                           const char *rel) {
    if (!diag || !diag->code || !diag->node_type) {
        return 0;
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    if (!file_qn) {
        return 0;
    }
    char qn[CBM_SZ_2K];
    int qn_len = snprintf(qn, sizeof(qn), "%s.__parse_diagnostic__.%s.%u.%u.%s", file_qn,
                          diag->code, diag->start_byte, diag->end_byte, diag->node_type);
    const cbm_gbuf_node_t *file_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    const cbm_gbuf_node_t *diag_node =
        (qn_len > 0 && (size_t)qn_len < sizeof(qn)) ? cbm_gbuf_find_by_qn(ctx->gbuf, qn) : NULL;
    int linked = 0;
    if (file_node && diag_node) {
        cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, diag_node->id, "HAS_DIAGNOSTIC", "{}");
        linked = 1;
    }
    free(file_qn);
    return linked;
}

/* Create IMPORTS edges for one file's imports (parallel path). */
static int create_imports_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                const cbm_file_info_t *file, CBMHashTable *namespace_map) {
    const char *rel = file ? file->rel_path : NULL;
    int count = 0;
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel, "__file__");
    const cbm_gbuf_node_t *source_node = cbm_gbuf_find_by_qn(ctx->gbuf, file_qn);
    if (!source_node) {
        free(file_qn);
        return 0;
    }
    for (int j = 0; j < result->imports.count; j++) {
        CBMImport *imp = &result->imports.items[j];
        if (!imp->module_path) {
            continue;
        }
        const cbm_gbuf_node_t *target =
            cbm_pipeline_resolve_import_node(ctx, file, file_qn, imp, (size_t)j, namespace_map);
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

/* Find channel source node (enclosing function or file). */
static const cbm_gbuf_node_t *find_channel_src(cbm_pipeline_ctx_t *ctx, const CBMChannel *ch,
                                               const char *rel, const char *module_qn) {
    return cbm_pipeline_find_reference_source(ctx->gbuf, ctx->project_name, rel, module_qn,
                                              ch->enclosing_func_qn, ch->start_line,
                                              "parallel.channel_source");
}

/* Create Channel nodes + EMITS/LISTENS_ON edges for one file. */
static void create_channel_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                                 const char *rel, const char *module_qn) {
    for (int j = 0; j < result->channels.count; j++) {
        CBMChannel *ch = &result->channels.items[j];
        if (!ch->channel_name || !ch->channel_name[0]) {
            continue;
        }
        char channel_qn[CBM_SZ_512];
        snprintf(channel_qn, sizeof(channel_qn), "__channel__%s__%s",
                 ch->transport ? ch->transport : "unknown", ch->channel_name);
        char channel_props[CBM_SZ_512];
        snprintf(channel_props, sizeof(channel_props), "{\"transport\":\"%s\"}",
                 ch->transport ? ch->transport : "unknown");
        int64_t channel_id = cbm_gbuf_upsert_node(ctx->gbuf, "Channel", ch->channel_name,
                                                  channel_qn, "", 0, 0, channel_props);
        const cbm_gbuf_node_t *src_node = find_channel_src(ctx, ch, rel, module_qn);
        if (src_node && channel_id > 0) {
            const char *edge_type = ch->direction == CBM_CHANNEL_EMIT ? "EMITS" : "LISTENS_ON";
            char edge_props[CBM_SZ_128];
            snprintf(edge_props, sizeof(edge_props), "{\"transport\":\"%s\"}",
                     ch->transport ? ch->transport : "unknown");
            cbm_gbuf_insert_edge(ctx->gbuf, src_node->id, channel_id, edge_type, edge_props);
        }
    }
}

static int advance_registry_progress(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *file,
                                     int index, int file_count) {
    if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_REGISTRY, "registry",
                                        (uint64_t)file_count) == 0) {
        return 0;
    }
    cbm_pipeline_record_fatal_error(
        ctx ? ctx->pipeline : NULL, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
        "publish_registry_progress", "registry",
        file && file->rel_path ? file->rel_path : "", (size_t)index,
        "the completed registry file unit could not advance semantic progress",
        "preserve the worker workspace, repair the progress stream, and retry the unchanged "
        "repository");
    return CBM_NOT_FOUND;
}

int cbm_build_registry_from_cache(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                  int file_count, CBMFileResult **result_cache) {
    cbm_log_info("parallel.registry.start", "files", itoa_log(file_count));

    int reg_entries = 0;
    int defines_edges = 0;
    int imports_edges = 0;
    int diagnostic_edges = 0;

    /* Namespace/package → File-QN map for namespace imports (C# `using`,
     * Java/Kotlin `import`, PHP `use`). Built from the full result cache so
     * every declaring file is visible regardless of loop order. */
    const char **rels = (const char **)calloc((size_t)file_count, sizeof(char *));
    if (!rels && file_count > 0) {
        cbm_log_error("parallel.registry_failed", "code", "CBM_NAMESPACE_RELS_ALLOC_FAILED",
                      "component", "parallel.namespace_map", "operation", "rels_alloc", "key", "",
                      "message", "namespace input list could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        rels[i] = files[i].rel_path;
    }
    CBMHashTable *namespace_map = NULL;
    int namespace_rc = cbm_pipeline_namespace_map_build(ctx, ctx->project_name, result_cache, rels,
                                                        file_count, &namespace_map);
    free(rels);
    if (namespace_rc != 0) {
        return namespace_rc;
    }

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            cbm_pipeline_namespace_map_free(namespace_map);
            return CBM_NOT_FOUND;
        }

        CBMFileResult *result = result_cache[i];
        if (!result) {
            if (advance_registry_progress(ctx, &files[i], i, file_count) != 0) {
                cbm_pipeline_namespace_map_free(namespace_map);
                return CBM_NOT_FOUND;
            }
            continue;
        }

        const char *rel = files[i].rel_path;

        if (cbm_pipeline_enrich_structured_file(ctx, &files[i], result) != 0) {
            cbm_pipeline_namespace_map_free(namespace_map);
            return CBM_NOT_FOUND;
        }

        /* Register callable symbols + DEFINES/DEFINES_METHOD edges */
        for (int d = 0; d < result->defs.count; d++) {
            defines_edges += register_and_link_def(ctx, &result->defs.items[d], rel, &reg_entries);
            if (cbm_registry_failed(ctx->registry)) {
                cbm_pipeline_namespace_map_free(namespace_map);
                return CBM_NOT_FOUND;
            }
        }
        for (int d = 0; d < result->diagnostics.count; d++) {
            diagnostic_edges += link_diagnostic(ctx, &result->diagnostics.items[d], rel);
        }

        imports_edges += create_imports_edges(ctx, result, &files[i], namespace_map);
        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, rel,
                                                      pp_module_is_dir(files[i].language));
        create_channel_edges(ctx, result, rel, module_qn);
        free(module_qn);
        if (advance_registry_progress(ctx, &files[i], i, file_count) != 0) {
            cbm_pipeline_namespace_map_free(namespace_map);
            return CBM_NOT_FOUND;
        }
    }

    cbm_pipeline_namespace_map_free(namespace_map);

    cbm_log_info("parallel.registry.done", "entries", itoa_log(reg_entries), "defines",
                 itoa_log(defines_edges), "imports", itoa_log(imports_edges), "diagnostics",
                 itoa_log(diagnostic_edges));
    return 0;
}

/* ── Phase 4: Parallel Resolution ────────────────────────────────── */

typedef struct __attribute__((aligned(CBM_CACHE_LINE))) {
    cbm_gbuf_t *local_edge_buf;
    int calls_resolved;
    int usages_resolved;
    int semantic_resolved;
    int errors;
    /* Subset of calls_resolved that were attributed via the LSP-override
     * path (cbm_pipeline_find_lsp_resolution hit) rather than the
     * registry's textual matcher. Surfaced in the parallel.resolve.done
     * log line so divergence between pipelines becomes observable. */
    int lsp_overrides;
    int reference_local_only;
    int reference_member_without_type;
    int reference_target_missing;
    int reference_ambiguous;
    int reference_incompatible;
    char _pad[CBM_CACHE_LINE - sizeof(cbm_gbuf_t *) - ((PP_RING + 6) * sizeof(int))];
} resolve_worker_state_t;

typedef struct {
    const cbm_file_info_t *files;
    int file_count;
    const cbm_source_slab_t *source_slab;
    const cbm_compile_context_index_t *compile_contexts;
    const char *project_name;
    const char *repo_path;

    resolve_worker_state_t *workers;
    int max_workers;

    CBMFileResult **result_cache;
    const cbm_gbuf_t *main_gbuf;    /* READ-ONLY during Phase 4 */
    const cbm_registry_t *registry; /* READ-ONLY during Phase 4 */
    /* Back-pointer used only to retain a terminal diagnostic (#1004). Recording
     * elects exactly one writer atomically, so workers may call it concurrently. */
    cbm_pipeline_t *pipeline;
    _Atomic int64_t *shared_ids;
    _Atomic int *cancelled;
    _Atomic int next_file_idx;

    /* Cross-file LSP inputs — pre-built once by the caller in pipeline.c
     * and shared read-only by usage across workers (typed non-const to
     * match the existing cbm_run_X_lsp_cross callee signatures the
     * worker forwards them to). NULL/0 → cross-LSP no-ops. */
    CBMLSPDef *all_defs;
    int def_count;
    char *const *def_modules; /* per-file module QN; def_modules[i] for files[i] */
    /* Optional inverted index for per-file def filtering (gopls pattern).
     * When non-NULL, the fused worker calls cbm_pxc_filter_defs_for_file
     * to shrink the def array passed to the LSP from O(all_defs) to
     * O(relevant_defs). NULL → each file sees the full all_defs[]. */
    struct CBMModuleDefIndex *module_def_index;
    /* Tier 2 full: pre-built per-language registries (project-wide,
     * finalized, READ-ONLY). When non-NULL for a lang, the worker uses
     * cbm_run_X_lsp_cross_with_registry — skip per-file build entirely.
     * Stored as CBMCrossLspRegistries* (typedef from pass_lsp_cross.h). */
    CBMCrossLspRegistries *cross_registries;
    const CBMCargoManifest *rust_manifest;

    /* Counters for parallel.resolve.lsp_cross_done summary. */
    _Atomic int lsp_cross_processed;

    /* Per-sub-phase timing (ns aggregated across workers) — surfaces
     * exactly where parallel_resolve's wall time is spent so we stop
     * guessing about hot paths. Logged once at the end of
     * cbm_parallel_resolve. */
    _Atomic uint64_t time_ns_import_map;
    _Atomic uint64_t time_ns_cross_lsp;
    _Atomic uint64_t time_ns_calls;
    _Atomic uint64_t time_ns_usages;
    _Atomic uint64_t time_ns_throws;
    _Atomic uint64_t time_ns_rw;
    _Atomic uint64_t time_ns_semantic;
    /* Whole-iteration timer — captures everything from atomic file_idx
     * pickup through cleanup. If this >> sum of sub-phases, the
     * unmeasured cost is either in skip-eligibility checks, gbuf
     * setup, or — most likely — workers waiting on the
     * cbm_parallel_for synchronization barrier at the end. */
    _Atomic uint64_t time_ns_total_loop;
    _Atomic int total_files_visited;
    /* Sub-breakdowns inside resolve_file_calls — finds the 553µs-per-
     * iteration hot path that the high-level resolve_calls counter
     * doesn't pinpoint. */
    _Atomic uint64_t time_ns_rc_lsp_lookup; /* lsp_idx + fallback scan */
    _Atomic uint64_t time_ns_rc_resolve;    /* lsp_target_node OR registry_resolve */
    _Atomic uint64_t time_ns_rc_target;     /* gbuf_find_by_qn for target */
    _Atomic uint64_t time_ns_rc_emit;       /* emit_service_edge */
    _Atomic uint64_t time_ns_rc_source;     /* find_source_node */

    /* Exact project-wide inner resolver work. The denominator is derived once
     * from the immutable extraction results before parallel dispatch; workers
     * advance only after an item actually completes. Cross-LSP dispatch owns
     * the rows it dynamically appends, while the immutable pre-dispatch prefix
     * remains individually counted. O(1) live state keeps the liveness protocol
     * independent of repository file count. */
    uint64_t resolve_items_total;
    _Atomic uint64_t resolve_items_completed;
    _Atomic uint64_t resolve_dynamic_lsp_items;
    _Atomic uint64_t resolve_progress_last_attempt_ms;
    _Atomic int resolve_progress_failed;
} resolve_ctx_t;

static bool resolve_cross_lsp_eligible(const resolve_ctx_t *rc, const CBMFileResult *result,
                                       CBMLanguage lang) {
    bool jvm_cross_lsp = lang == CBM_LANG_JAVA || lang == CBM_LANG_KOTLIN;
    return rc->all_defs && rc->def_count > 0 && cbm_pxc_has_cross_lsp(lang) &&
           result->calls.count > 0 &&
           (jvm_cross_lsp || result->resolved_calls.count < result->calls.count);
}

static bool resolve_count_add(uint64_t *total, uint64_t count) {
    if (count > UINT64_MAX - *total) {
        return false;
    }
    *total += count;
    return true;
}

static bool resolve_atomic_count_add(_Atomic uint64_t *total, uint64_t count) {
    uint64_t current = atomic_load_explicit(total, memory_order_relaxed);
    for (;;) {
        if (count > UINT64_MAX - current) {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(total, &current, current + count,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            return true;
        }
    }
}

static bool resolve_count_strings(uint64_t *total, const char *const *items) {
    if (!items) {
        return true;
    }
    for (size_t i = 0; items[i]; i++) {
        if (!resolve_count_add(total, 1)) {
            return false;
        }
    }
    return true;
}

static int resolve_measure_items(const resolve_ctx_t *rc, uint64_t *measured) {
    uint64_t total = 0;
    for (int file_idx = 0; file_idx < rc->file_count; file_idx++) {
        CBMFileResult *result = rc->result_cache[file_idx];
        if (!result) {
            continue;
        }
        if (result->calls.count < 0 || result->resolved_calls.count < 0 ||
            result->usages.count < 0 || result->throws.count < 0 || result->rw.count < 0 ||
            result->defs.count < 0 || result->impl_traits.count < 0) {
            return CBM_NOT_FOUND;
        }
        uint64_t fixed = (uint64_t)result->calls.count + (uint64_t)result->usages.count +
                         (uint64_t)result->throws.count + (uint64_t)result->rw.count +
                         (uint64_t)result->defs.count + (uint64_t)result->impl_traits.count;
        if (result->calls.count > 0 && result->resolved_calls.count > 0) {
            if (!resolve_count_add(&fixed, (uint64_t)result->resolved_calls.count)) {
                return CBM_NOT_FOUND;
            }
        }
        if (resolve_cross_lsp_eligible(rc, result, rc->files[file_idx].language) &&
            !resolve_count_add(&fixed, 1)) {
            return CBM_NOT_FOUND;
        }
        if (!resolve_count_add(&total, fixed)) {
            return CBM_NOT_FOUND;
        }
        for (int def_idx = 0; def_idx < result->defs.count; def_idx++) {
            CBMDefinition *def = &result->defs.items[def_idx];
            if (!def->qualified_name ||
                !cbm_pipeline_find_definition_node(rc->main_gbuf, def, "")) {
                continue;
            }
            if (!resolve_count_strings(&total, def->base_classes) ||
                !resolve_count_strings(&total, def->decorators)) {
                return CBM_NOT_FOUND;
            }
        }
    }
    *measured = total;
    return 0;
}

static int resolve_recount_items(const resolve_ctx_t *rc, uint64_t dynamic_lsp_items,
                                 uint64_t cross_lsp_units, uint64_t *recounted) {
    uint64_t total = 0;
    for (int file_idx = 0; file_idx < rc->file_count; file_idx++) {
        CBMFileResult *result = rc->result_cache[file_idx];
        if (!result) {
            continue;
        }
        if (result->calls.count < 0 || result->resolved_calls.count < 0 ||
            result->usages.count < 0 || result->throws.count < 0 || result->rw.count < 0 ||
            result->defs.count < 0 || result->impl_traits.count < 0) {
            return CBM_NOT_FOUND;
        }
        uint64_t fixed = (uint64_t)result->calls.count + (uint64_t)result->usages.count +
                         (uint64_t)result->throws.count + (uint64_t)result->rw.count +
                         (uint64_t)result->defs.count + (uint64_t)result->impl_traits.count;
        if (result->calls.count > 0 && result->resolved_calls.count > 0 &&
            !resolve_count_add(&fixed, (uint64_t)result->resolved_calls.count)) {
            return CBM_NOT_FOUND;
        }
        if (!resolve_count_add(&total, fixed)) {
            return CBM_NOT_FOUND;
        }
        for (int def_idx = 0; def_idx < result->defs.count; def_idx++) {
            CBMDefinition *def = &result->defs.items[def_idx];
            if (!def->qualified_name ||
                !cbm_pipeline_find_definition_node(rc->main_gbuf, def, "")) {
                continue;
            }
            if (!resolve_count_strings(&total, def->base_classes) ||
                !resolve_count_strings(&total, def->decorators)) {
                return CBM_NOT_FOUND;
            }
        }
    }
    if (dynamic_lsp_items > total) {
        return CBM_NOT_FOUND;
    }
    total -= dynamic_lsp_items;
    if (!resolve_count_add(&total, cross_lsp_units)) {
        return CBM_NOT_FOUND;
    }
    *recounted = total;
    return 0;
}

static void resolve_progress_item_done(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                       const char *rel, const char *phase, size_t item_index) {
    if (rc->resolve_items_total == 0 ||
        atomic_load_explicit(&rc->resolve_progress_failed, memory_order_relaxed)) {
        return;
    }
    uint64_t completed =
        atomic_fetch_add_explicit(&rc->resolve_items_completed, 1, memory_order_relaxed) + 1;
    uint64_t now_ms = cbm_now_ms();
    uint64_t previous =
        atomic_load_explicit(&rc->resolve_progress_last_attempt_ms, memory_order_relaxed);
    bool terminal = completed == rc->resolve_items_total;
    if (!terminal && now_ms >= previous &&
        now_ms - previous < CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS) {
        return;
    }
    if (!terminal &&
        !atomic_compare_exchange_strong_explicit(&rc->resolve_progress_last_attempt_ms, &previous,
                                                 now_ms, memory_order_relaxed,
                                                 memory_order_relaxed)) {
        return;
    }
    if (terminal) {
        atomic_store_explicit(&rc->resolve_progress_last_attempt_ms, now_ms,
                              memory_order_relaxed);
    }
    if (completed <= rc->resolve_items_total &&
        cbm_worker_progress_observe_step(
            CBM_WORKER_PROGRESS_STAGE_RESOLVE, "resolve", (uint64_t)rc->file_count, 2,
            "resolver_items", completed, rc->resolve_items_total) == 0) {
        return;
    }
    if (atomic_exchange_explicit(&rc->resolve_progress_failed, 1, memory_order_relaxed) == 0) {
        ws->errors++;
        atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
        cbm_pipeline_record_fatal_error(
            rc->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
            "publish_parallel_resolve_inner_progress", phase, rel ? rel : "", item_index,
            "completed inner resolver work could not advance the exact semantic cursor",
            "preserve the worker workspace, repair the progress stream, and retry the unchanged "
            "repository");
    }
}

static void resolve_initial_lsp_item_done(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                          const char *rel, int completed,
                                          int initial_resolved_call_count) {
    if (completed <= initial_resolved_call_count) {
        resolve_progress_item_done(rc, ws, rel, "lsp_index", (size_t)(completed - 1));
    }
}

static void log_resolve_phase_slow(const char *rel, const char *phase, int items,
                                   uint64_t elapsed_ns) {
    uint64_t elapsed_ms = elapsed_ns / PP_USEC_PER_MS;
    if (elapsed_ms < CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS) {
        return;
    }
    char elapsed[32];
    char count[32];
    snprintf(elapsed, sizeof(elapsed), "%llu", (unsigned long long)elapsed_ms);
    snprintf(count, sizeof(count), "%d", items);
    cbm_log_info("parallel.resolve.phase_slow", "path", rel ? rel : "", "phase", phase,
                 "items", count, "elapsed_ms", elapsed);
}

/* Minimum buffer space needed per arg JSON object */
#define CBM_ARG_JSON_GUARD CBM_SZ_32

/* Append arg data as JSON to edge properties: ,"args":[{"i":0,"e":"x","v":"val"},...]
 * Returns new position in buffer. */
/* Sanitize expression string for JSON (in-place). */
static void sanitize_expr(char *expr_buf, const char *expr) {
    if (expr) {
        snprintf(expr_buf, 128, "%.*s", 120, expr);
        for (char *p = expr_buf; *p; p++) {
            if (*p == '"') {
                *p = '\'';
            }
            if (*p == '\n' || *p == '\r') {
                *p = ' ';
            }
        }
    } else {
        expr_buf[0] = '\0';
    }
}

/* Format one call arg as JSON. Returns snprintf result. */
static int format_call_arg(char *buf, size_t bufsize, const CBMCallArg *a, const char *expr) {
    char esc_k[CBM_SZ_128];
    char esc_e[CBM_SZ_128];
    char esc_v[CBM_SZ_128];
    cbm_json_escape(esc_e, sizeof(esc_e), expr);
    if (a->keyword && a->value) {
        cbm_json_escape(esc_k, sizeof(esc_k), a->keyword);
        cbm_json_escape(esc_v, sizeof(esc_v), a->value);
        return snprintf(buf, bufsize, "{\"i\":%d,\"k\":\"%s\",\"e\":\"%s\",\"v\":\"%s\"}", a->index,
                        esc_k, esc_e, esc_v);
    }
    if (a->keyword) {
        cbm_json_escape(esc_k, sizeof(esc_k), a->keyword);
        return snprintf(buf, bufsize, "{\"i\":%d,\"k\":\"%s\",\"e\":\"%s\"}", a->index, esc_k,
                        esc_e);
    }
    if (a->value) {
        cbm_json_escape(esc_v, sizeof(esc_v), a->value);
        return snprintf(buf, bufsize, "{\"i\":%d,\"e\":\"%s\",\"v\":\"%s\"}", a->index, esc_e,
                        esc_v);
    }
    return snprintf(buf, bufsize, "{\"i\":%d,\"e\":\"%s\"}", a->index, esc_e);
}

/* Exposed (non-static) so the sequential CALLS finalizer (pass_calls.c, the
 * <50-file path) serializes args through this exact code — same per-arg caps,
 * same #493 UTF-8-boundary truncation, same keyword handling, same buffer-budget
 * cutoff — so both pipelines emit byte-identical "args" arrays (#516). */
size_t cbm_pipeline_append_args_json(char *buf, size_t bufsize, size_t pos, const CBMCall *call) {
    if (call->preprocess_context_id && pos < bufsize - PP_ARGS_MARGIN) {
        char escaped_context[CBM_SZ_256];
        cbm_json_escape(escaped_context, sizeof(escaped_context), call->preprocess_context_id);
        int context_len = snprintf(buf + pos, bufsize - pos,
                                   ",\"preprocess_context_id\":\"%s\"", escaped_context);
        if (context_len <= 0 || (size_t)context_len >= bufsize - pos) {
            return pos;
        }
        pos += (size_t)context_len;
    }
    if (call->arg_count == 0 || pos >= bufsize - PP_ARGS_MARGIN) {
        return pos;
    }
    int n = snprintf(buf + pos, bufsize - pos, ",\"args\":[");
    if (n <= 0) {
        return pos;
    }
    pos += (size_t)n;
    for (int i = 0; i < call->arg_count && pos < bufsize - CBM_ARG_JSON_GUARD; i++) {
        const CBMCallArg *a = &call->args[i];
        size_t mark = pos; /* rollback point (before the separator) */
        if (i > 0 && pos < bufsize - SKIP_ONE) {
            buf[pos++] = ',';
        }
        char expr_buf[CBM_SZ_128];
        sanitize_expr(expr_buf, a->expr);
        n = format_call_arg(buf + pos, bufsize - pos, a, expr_buf);
        /* snprintf returns the UNtruncated length: if the arg did not fully
         * fit, advancing pos by n would push it past buf and the buf[pos]
         * writes below would overflow. Drop the arg whole (atomic field —
         * keeps the array valid) and stop appending. */
        if (n <= 0 || (size_t)n >= bufsize - pos) {
            pos = mark;
            break;
        }
        pos += (size_t)n;
    }
    if (pos < bufsize - SKIP_ONE) {
        buf[pos++] = ']';
    }
    buf[pos] = '\0';
    return pos;
}

/* Scan call args for a URL-like route path and handler reference. */
static bool is_path_keyword(const char *keyword) {
    static const char *path_keywords[] = {"prefix",     "path",     "route", "pattern",
                                          "url",        "endpoint", "rule",  "mount_path",
                                          "route_path", "url_path", NULL};
    for (const char **kw = path_keywords; *kw; kw++) {
        if (strcmp(keyword, *kw) == 0) {
            return true;
        }
    }
    return false;
}

static const char *find_route_path_in_args(const CBMCall *call, const char **out_handler) {
    *out_handler = NULL;
    /* 1. First string arg starting with / */
    if (call->first_string_arg && call->first_string_arg[0] == '/') {
        *out_handler = call->second_arg_name;
        return call->first_string_arg;
    }
    /* 2. Keyword args (prefix=, path=, route=, etc.) */
    const char *found = NULL;
    for (int ai = 0; ai < call->arg_count && !found; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        const char *val = ca->value ? ca->value : ca->expr;
        if (!val || val[0] != '/') {
            continue;
        }
        if ((ca->keyword && is_path_keyword(ca->keyword)) || (!ca->keyword && ca->index == 0)) {
            found = val;
        }
    }
    if (!found) {
        return NULL;
    }
    /* 3. Handler: first identifier arg that's not a path/keyword */
    for (int ai = 0; ai < call->arg_count; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        if (!ca->expr || ca->expr[0] == '/' || ca->expr[0] == '"' || ca->expr[0] == '\'') {
            continue;
        }
        if (ca->keyword && (strcmp(ca->keyword, "prefix") == 0 ||
                            strcmp(ca->keyword, "name") == 0 || strcmp(ca->keyword, "tags") == 0)) {
            continue;
        }
        *out_handler = ca->expr;
        break;
    }
    return found;
}

/* Build props JSON, append args, close brace, emit edge. */
static void finalize_and_emit(cbm_gbuf_t *gbuf, int64_t src_id, int64_t tgt_id,
                              const char *edge_type, char *props, int n, const CBMCall *call) {
    if (n > 0 && (size_t)n < CBM_SZ_2K - PP_ESC_SPACE) {
        size_t pos = cbm_pipeline_append_args_json(props, CBM_SZ_2K, (size_t)n, call);
        if (call->start_line > 0 && strcmp(edge_type, "CALLS") == 0 &&
            pos < CBM_SZ_2K - PP_LINE_MARGIN) {
            int ln = snprintf(props + pos, CBM_SZ_2K - pos, ",\"line\":%d", call->start_line);
            if (ln > 0) {
                pos += (size_t)ln;
            }
        }
        if (pos < CBM_SZ_2K - SKIP_ONE) {
            props[pos] = '}';
            props[pos + SKIP_ONE] = '\0';
        }
    }
    cbm_gbuf_insert_edge(gbuf, src_id, tgt_id, edge_type, props);
}

/* Build Route node QN and properties for HTTP/async service edges. */
static int64_t build_service_route(cbm_gbuf_t *gbuf, const char *arg, const char *method,
                                   const char *broker, cbm_svc_kind_t svc) {
    char route_qn[CBM_ROUTE_QN_SIZE];
    const char *prefix;
    char cpath[CBM_SZ_256];
    const char *qpath = arg;
    if (svc == CBM_SVC_HTTP) {
        prefix = method ? method : "ANY";
        qpath = cbm_route_canon_path(arg, cpath, sizeof(cpath));
    } else {
        prefix = broker ? broker : "async";
    }
    snprintf(route_qn, sizeof(route_qn), "__route__%s__%s", prefix, qpath);
    char route_props[CBM_SZ_256];
    if (method) {
        snprintf(route_props, sizeof(route_props), "{\"method\":\"%s\"}", method);
    } else if (broker) {
        snprintf(route_props, sizeof(route_props), "{\"broker\":\"%s\"}", broker);
    } else {
        snprintf(route_props, sizeof(route_props), "{}");
    }
    return cbm_gbuf_upsert_node(gbuf, "Route", arg, route_qn, "", 0, 0, route_props);
}

/* Emit HTTP_CALLS or ASYNC_CALLS edge via Route node. */
static void emit_http_async_service_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                         const CBMCall *call, const cbm_resolution_t *res,
                                         cbm_svc_kind_t svc, const char *arg) {
    const char *edge_type = (svc == CBM_SVC_HTTP) ? "HTTP_CALLS" : "ASYNC_CALLS";
    const char *method =
        (svc == CBM_SVC_HTTP) ? cbm_service_pattern_http_method(call->callee_name) : NULL;
    const char *broker =
        (svc == CBM_SVC_ASYNC) ? cbm_service_pattern_broker(res->qualified_name) : NULL;

    int64_t route_id = build_service_route(gbuf, arg, method, broker, svc);

    char esc_c[CBM_SZ_256];
    char esc_a[CBM_SZ_256];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    cbm_json_escape(esc_a, sizeof(esc_a), arg);
    char props[CBM_SZ_2K];
    int n = snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"url_path\":\"%s\"", esc_c, esc_a);
    if (method) {
        n += snprintf(props + n, sizeof(props) - (size_t)n, ",\"method\":\"%s\"", method);
    }
    if (broker) {
        n += snprintf(props + n, sizeof(props) - (size_t)n, ",\"broker\":\"%s\"", broker);
    }
    finalize_and_emit(gbuf, source->id, route_id, edge_type, props, n, call);
}

/* Emit CONFIGURES edge. */
static void emit_config_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                             const cbm_gbuf_node_t *target, const CBMCall *call,
                             const cbm_resolution_t *res, const char *arg) {
    /* emit_service_edge may be reached with target==NULL on the HTTP/ASYNC
     * external-client bypass (#523); a CONFIGURES edge needs a real target, so
     * never deref a NULL target here. */
    if (!target) {
        return;
    }
    char esc_c[CBM_SZ_256];
    char esc_k[CBM_SZ_256];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    cbm_json_escape(esc_k, sizeof(esc_k), arg ? arg : "");
    char props[CBM_SZ_2K];
    int n = snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"key\":\"%s\",\"confidence\":%.2f",
                     esc_c, esc_k, res->confidence);
    finalize_and_emit(gbuf, source->id, target->id, "CONFIGURES", props, n, call);
}

/* Emit normal CALLS edge. */
static void emit_normal_calls_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                   const cbm_gbuf_node_t *target, const CBMCall *call,
                                   const cbm_resolution_t *res) {
    /* A CALLS edge needs a real target; the HTTP/ASYNC external-client bypass
     * (#523) can reach emit_service_edge with target==NULL, so guard the deref. */
    if (!target) {
        return;
    }
    char esc_c[CBM_SZ_256];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    char props[CBM_SZ_2K];
    int n = snprintf(props, sizeof(props),
                     "{\"callee\":\"%s\",\"confidence\":%.2f,\"strategy\":\"%s\",\"candidates\":%d",
                     esc_c, res->confidence, res->strategy ? res->strategy : "unknown",
                     res->candidate_count);
    finalize_and_emit(gbuf, source->id, target->id, "CALLS", props, n, call);
}

/* Classify a resolved call by library identity and emit the appropriate edge. */
/* Create Route node + CALLS + HANDLES edges for a route registration call. */
static void emit_route_registration(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                                    const CBMCall *call, const char *route_path,
                                    const char *handler_ref, const char *module_qn,
                                    const cbm_registry_t *registry, const cbm_gbuf_t *main_gbuf,
                                    const char **ik, const char **iv, int ic) {
    const char *method = cbm_service_pattern_route_method(call->callee_name);
    char rqn[CBM_ROUTE_QN_SIZE];
    char cpath[CBM_SZ_256];
    snprintf(rqn, sizeof(rqn), "__route__%s__%s", method ? method : "ANY",
             cbm_route_canon_path(route_path, cpath, sizeof(cpath)));
    char rp[CBM_SZ_256];
    snprintf(rp, sizeof(rp), "{\"method\":\"%s\"}", method ? method : "ANY");
    int64_t rid = cbm_gbuf_upsert_node(gbuf, "Route", route_path, rqn, "", 0, 0, rp);
    char esc_cn[CBM_SZ_256]; /* sliced source text: escape quotes/newlines */
    char esc_rp[CBM_SZ_512];
    cbm_json_escape(esc_cn, sizeof(esc_cn), call->callee_name);
    cbm_json_escape(esc_rp, sizeof(esc_rp), route_path);
    char props[CBM_SZ_1K];
    snprintf(props, sizeof(props),
             "{\"callee\":\"%s\",\"url_path\":\"%s\",\"via\":\"route_registration\"}", esc_cn,
             esc_rp);
    cbm_gbuf_insert_edge(gbuf, source->id, rid, "CALLS", props);
    if (handler_ref && handler_ref[0] != '\0') {
        cbm_resolution_t hres =
            cbm_registry_resolve_exact(registry, handler_ref, module_qn, ik, iv, ic);
        if (hres.qualified_name && hres.qualified_name[0] != '\0') {
            const cbm_gbuf_node_t *h = cbm_gbuf_find_by_qn_domain(
                main_gbuf, hres.qualified_name, CBM_REF_DOMAIN_CALLABLE, "parallel.route_handler");
            if (h) {
                char hp[CBM_SZ_1K]; /* must exceed escaped value + wrapper or snprintf cuts the
                                       closing brace */
                char esc_h2[CBM_SZ_512];
                cbm_json_escape(esc_h2, sizeof(esc_h2), hres.qualified_name);
                snprintf(hp, sizeof(hp), "{\"handler\":\"%s\"}", esc_h2);
                cbm_gbuf_insert_edge(gbuf, h->id, rid, "HANDLES", hp);
            }
        }
    }
}

/* Reject regex metacharacters, spaces, double-slashes in URL candidates. */
static bool is_junk_url(const char *s) {
    for (int i = 0; s[i]; i++) {
        char ch = s[i];
        if (ch == '\\' || ch == '^' || ch == '$' || ch == '*' || ch == '+' || ch == '(' ||
            ch == ')' || ch == '[' || ch == ']' || ch == '|' || ch == ' ') {
            return true;
        }
        if (ch == '/' && i > 0 && s[i - SKIP_ONE] == '/') {
            return true;
        }
    }
    return false;
}

/* Normalize a template literal URL and reject junk patterns.
 * Returns true if norm contains a valid API path. */
static bool normalize_url_arg(const char *url, char *norm, int norm_sz) {
    int ni = 0;
    const char *p = url;
    if (*p == '`' || *p == '"' || *p == '\'') {
        p++;
    }
    if (*p != '/') {
        return false;
    }
    while (*p && ni < norm_sz - PAIR_LEN) {
        if (*p == '$' && *(p + SKIP_ONE) == '{') {
            norm[ni++] = ':';
            p += PAIR_LEN;
            while (*p && *p != '}' && ni < norm_sz - PAIR_LEN) {
                norm[ni++] = *p++;
            }
            if (*p == '}') {
                p++;
            }
        } else if (*p == '`' || *p == '"' || *p == '\'' || *p == '?') {
            break;
        } else {
            norm[ni++] = *p++;
        }
    }
    norm[ni] = '\0';
    enum { MIN_URL_LEN = 4 };
    if (ni < MIN_URL_LEN || !strchr(norm + SKIP_ONE, '/')) {
        return false;
    }
    return !is_junk_url(norm);
}

/* Detect API paths in call arguments and create HTTP_CALLS edges. */
static void detect_url_in_args(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                               const CBMCall *call) {
    for (int ai = 0; ai < call->arg_count; ai++) {
        const CBMCallArg *ca = &call->args[ai];
        const char *url = ca->value ? ca->value : ca->expr;
        if (!url || (url[0] != '/' && url[0] != '`')) {
            continue;
        }
        char norm[CBM_SZ_256];
        if (!normalize_url_arg(url, norm, (int)sizeof(norm))) {
            continue;
        }
        char route_qn[CBM_ROUTE_QN_SIZE];
        char cpath[CBM_SZ_256];
        snprintf(route_qn, sizeof(route_qn), "__route__ANY__%s",
                 cbm_route_canon_path(norm, cpath, sizeof(cpath)));
        int64_t route_id = cbm_gbuf_upsert_node(gbuf, "Route", norm, route_qn, "", 0, 0,
                                                "{\"source\":\"arg_url\"}");
        char esc_c[CBM_SZ_256];
        char esc_n[CBM_SZ_256];
        cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
        cbm_json_escape(esc_n, sizeof(esc_n), norm);
        char eprops[CBM_SZ_512];
        snprintf(eprops, sizeof(eprops),
                 "{\"callee\":\"%s\",\"url_path\":\"%s\",\"via\":\"arg_url\"}", esc_c, esc_n);
        cbm_gbuf_insert_edge(gbuf, source->id, route_id, "HTTP_CALLS", eprops);
        break;
    }
}

/* Extract gRPC service and method from a callee name.
 * Handles patterns like: pb.NewFooServiceClient(conn).GetBar → Foo/GetBar
 * Also: FooServiceGrpc.newBlockingStub(ch).getBar → FooService/getBar */
bool extract_grpc_service_method(const char *callee, char *service, size_t srv_sz, char *method,
                                 size_t meth_sz) {
    service[0] = '\0';
    method[0] = '\0';
    if (!callee) {
        return false;
    }
    /* Find last dot to split service.Method */
    const char *last_dot = strrchr(callee, '.');
    if (!last_dot || !last_dot[SKIP_ONE]) {
        return false;
    }
    snprintf(method, meth_sz, "%s", last_dot + SKIP_ONE);

    /* Extract service name: everything before the last dot, stripped of prefixes/suffixes */
    size_t prefix_len = (size_t)(last_dot - callee);
    char raw[CBM_SZ_256];
    if (prefix_len >= sizeof(raw)) {
        prefix_len = sizeof(raw) - SKIP_ONE;
    }
    memcpy(raw, callee, prefix_len);
    raw[prefix_len] = '\0';

    /* Strip common prefixes: pb.New, New, pb. */
    const char *s = raw;
    if (strncmp(s, "pb.New", CBM_SZ_6) == 0) {
        s += CBM_SZ_6;
    } else if (strncmp(s, "pb.", CBM_SZ_3) == 0 || strncmp(s, "New", CBM_SZ_3) == 0) {
        s += CBM_SZ_3;
    }

    /* Strip the generated-stub/client suffix, preserving the canonical
     * proto-declared service name. The proto service is `<X>Service`; the
     * generated client is `<X>ServiceClient` / `<X>ServiceGrpc`, so we strip
     * only the trailing stub/client token (Client/Stub/Grpc/…), NOT "Service"
     * itself — stripping "ServiceClient" yielded `<X>` and broke cross-repo
     * matching against the `<X>Service` declared name (#294). Longest tokens
     * first so e.g. BlockingStub wins over Stub.
     *
     * A match also serves as the gRPC stub-type signal: we ONLY emit a Route
     * when a recognized suffix is actually present. Without this gate the
     * fallback turned ordinary receiver vars (`_provider.GetGroup`,
     * `_builder.AddSomeService`) into phantom `__grpc__provider/...` Routes
     * that correspond to no .proto anywhere (#294). */
    snprintf(service, srv_sz, "%s", s);
    size_t slen = strlen(service);
    static const char *const suffixes[] = {"BlockingStub", "FutureStub", "AsyncStub",
                                           "AsyncClient",  "Servicer",   "Client",
                                           "Stub",         "Grpc",       NULL};
    bool stripped = false;
    for (const char *const *sfx = suffixes; *sfx; sfx++) {
        size_t flen = strlen(*sfx);
        if (slen > flen && strcmp(service + slen - flen, *sfx) == 0) {
            service[slen - flen] = '\0';
            stripped = true;
            break;
        }
    }

    return stripped && service[0] && method[0];
}

/* Emit GRPC_CALLS edge via gRPC Route node. */
static void emit_grpc_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                           const cbm_resolution_t *res) {
    char service[CBM_SZ_256];
    char method[CBM_SZ_256];
    /* Try callee_name first (e.g., "pb.NewCartServiceClient.GetCart") */
    if (!extract_grpc_service_method(call->callee_name, service, sizeof(service), method,
                                     sizeof(method))) {
        /* Fallback: try the resolved QN for Go chained calls.
         * Go pattern: pb.NewCartServiceClient(conn).GetCart(ctx, req)
         * callee_name = "GetCart", QN = "...CartServiceClient.GetCart"
         * The QN contains the full ServiceClient.Method pattern. */
        if (!res->qualified_name ||
            !extract_grpc_service_method(res->qualified_name, service, sizeof(service), method,
                                         sizeof(method))) {
            return;
        }
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__grpc__%s/%s", service, method);

    char route_name[CBM_SZ_256];
    snprintf(route_name, sizeof(route_name), "%s/%s", service, method);

    int64_t route_id = cbm_gbuf_upsert_node(gbuf, "Route", route_name, route_qn, "", 0, 0,
                                            "{\"source\":\"grpc\"}");

    /* service/method are parsed out of the callee QN: escape UTF-8-strict so a
     * bad byte can't corrupt the GRPC_CALLS edges.properties cell and make the
     * vault importer refuse the repo (#528). callee was already escaped. */
    char esc_c[CBM_SZ_256];
    char esc_svc[CBM_SZ_256 * 3];
    char esc_mth[CBM_SZ_256 * 3];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    cbm_json_escape(esc_svc, (int)sizeof(esc_svc), service);
    cbm_json_escape(esc_mth, (int)sizeof(esc_mth), method);
    char props[CBM_SZ_1K];
    snprintf(props, sizeof(props),
             "{\"callee\":\"%s\",\"service\":\"%s\",\"method\":\"%s\",\"confidence\":%.2f}", esc_c,
             esc_svc, esc_mth, res->confidence);
    cbm_gbuf_insert_edge(gbuf, source->id, route_id, "GRPC_CALLS", props);
}

/* Emit GRAPHQL_CALLS edge. Extract operation from first string arg if available. */
static void emit_graphql_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                              const cbm_resolution_t *res) {
    const char *op = call->first_string_arg;
    if (!op || !op[0]) {
        op = call->callee_name;
    }
    /* Try to extract a query/mutation name from the operation string */
    char op_name[CBM_SZ_256];
    snprintf(op_name, sizeof(op_name), "%s", op);
    /* Trim leading whitespace and "query "/"mutation " prefix */
    const char *p = op_name;
    while (*p == ' ' || *p == '\t' || *p == '\n') {
        p++;
    }
    if (strncmp(p, "query ", CBM_SZ_6) == 0) {
        p += CBM_SZ_6;
    } else if (strncmp(p, "mutation ", CBM_SZ_8) == 0) {
        p += CBM_SZ_8;
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__graphql__%s", p);

    int64_t route_id =
        cbm_gbuf_upsert_node(gbuf, "Route", p, route_qn, "", 0, 0, "{\"source\":\"graphql\"}");

    char esc_c[CBM_SZ_256];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    char props[CBM_SZ_1K];
    snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"operation\":\"%s\",\"confidence\":%.2f}",
             esc_c, p, res->confidence);
    cbm_gbuf_insert_edge(gbuf, source->id, route_id, "GRAPHQL_CALLS", props);
}

/* Emit TRPC_CALLS edge. Extract procedure path from callee chain. */
static void emit_trpc_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source, const CBMCall *call,
                           const cbm_resolution_t *res) {
    /* tRPC calls: trpc.user.getById.query() → extract "user.getById" */
    const char *callee = call->callee_name;
    if (!callee) {
        return;
    }
    /* Strip trailing .query/.mutate/.subscribe */
    char proc[CBM_SZ_256];
    snprintf(proc, sizeof(proc), "%s", callee);
    char *last_dot = strrchr(proc, '.');
    if (last_dot && (strcmp(last_dot, ".query") == 0 || strcmp(last_dot, ".mutate") == 0 ||
                     strcmp(last_dot, ".subscribe") == 0 || strcmp(last_dot, ".useQuery") == 0 ||
                     strcmp(last_dot, ".useMutation") == 0)) {
        *last_dot = '\0';
    }
    /* Strip leading trpc. */
    const char *p = proc;
    if (strncmp(p, "trpc.", CBM_SZ_5) == 0) {
        p += CBM_SZ_5;
    }

    char route_qn[CBM_SZ_512];
    snprintf(route_qn, sizeof(route_qn), "__trpc__%s", p);

    int64_t route_id =
        cbm_gbuf_upsert_node(gbuf, "Route", p, route_qn, "", 0, 0, "{\"source\":\"trpc\"}");

    char esc_c[CBM_SZ_256];
    cbm_json_escape(esc_c, sizeof(esc_c), call->callee_name);
    char props[CBM_SZ_1K];
    snprintf(props, sizeof(props), "{\"callee\":\"%s\",\"procedure\":\"%s\",\"confidence\":%.2f}",
             esc_c, p, res->confidence);
    cbm_gbuf_insert_edge(gbuf, source->id, route_id, "TRPC_CALLS", props);
}

/* When suppress_plain_calls is true (a TS/JS/TSX weak short-name member-call
 * match, #592/#606), every service classification below still runs — only the
 * plain CALLS fall-through (emit_normal_calls_edge) is skipped. detect_url_in_args
 * and the HTTP/ASYNC/gRPC/GraphQL/tRPC/CONFIG/route branches are unaffected, so
 * a verb-suffix HTTP client (api.patch('/x')), broker, or route registration
 * keeps its edge; only the fabricated project CALLS edge is dropped. */
static void emit_service_edge(cbm_gbuf_t *gbuf, const cbm_gbuf_node_t *source,
                              const cbm_gbuf_node_t *target, const CBMCall *call,
                              const cbm_resolution_t *res, const char *module_qn,
                              const cbm_registry_t *registry, const cbm_gbuf_t *main_gbuf,
                              const char **imp_keys, const char **imp_vals, int imp_count,
                              bool suppress_plain_calls) {
    cbm_svc_kind_t svc = cbm_service_pattern_match(res->qualified_name);
    const char *arg = call->first_string_arg;

    /* Also detect route registration by callee name suffix alone (handles unresolved
     * local variables like app.include_router where QN resolution fails). */
    if (svc == CBM_SVC_NONE && cbm_service_pattern_route_method(call->callee_name) != NULL) {
        svc = CBM_SVC_ROUTE_REG;
    }

    /* Detect gRPC stub method calls by resolved QN.
     * Go pattern: pb.NewCartServiceClient(conn).GetCart(ctx, req)
     * Tree-sitter extracts GetCart as the callee, which resolves to the
     * generated pb interface method (QN contains "ServiceClient"). */
    if (svc == CBM_SVC_NONE && res->qualified_name) {
        if (strstr(res->qualified_name, "ServiceClient") != NULL ||
            strstr(res->qualified_name, "ServiceGrpc") != NULL ||
            strstr(res->qualified_name, "Servicer") != NULL) {
            svc = CBM_SVC_GRPC;
        }
    }

    if (svc == CBM_SVC_ROUTE_REG) {
        const char *handler_ref = NULL;
        const char *route_path = find_route_path_in_args(call, &handler_ref);
        if (route_path) {
            emit_route_registration(gbuf, source, call, route_path, handler_ref, module_qn,
                                    registry, main_gbuf, imp_keys, imp_vals, imp_count);
            return;
        }
        /* No path found — fall through to normal CALLS edge */
    }

    bool has_url = (arg && arg[0] != '\0' && (arg[0] == '/' || strstr(arg, "://") != NULL));
    bool has_topic = (arg && arg[0] != '\0' && svc == CBM_SVC_ASYNC && strlen(arg) > PP_ESC_SPACE);

    if ((svc == CBM_SVC_HTTP || svc == CBM_SVC_ASYNC) && (has_url || has_topic)) {
        emit_http_async_service_edge(gbuf, source, call, res, svc, arg);
    } else if (svc == CBM_SVC_GRPC) {
        emit_grpc_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_GRAPHQL) {
        emit_graphql_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_TRPC) {
        emit_trpc_edge(gbuf, source, call, res);
    } else if (svc == CBM_SVC_CONFIG) {
        emit_config_edge(gbuf, source, target, call, res, arg);
    } else if (!suppress_plain_calls) {
        emit_normal_calls_edge(gbuf, source, target, call, res);
    }

    detect_url_in_args(gbuf, source, call);
}

/* Find the source node for an edge: enclosing function or file node. */
static const cbm_gbuf_node_t *find_source_node(const cbm_gbuf_t *gbuf, const char *project,
                                               const char *rel, const char *module_qn,
                                               const char *enclosing_qn, int call_line,
                                               const char *operation) {
    return cbm_pipeline_find_reference_source(gbuf, project, rel, module_qn, enclosing_qn,
                                              call_line, operation);
}

/* Free a strdup'd key stored in the per-file lsp_idx hash table. */
static void lsp_idx_free_key(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    free((char *)key);
}

static char *lsp_idx_key_alloc(const char *context_id, const char *caller_qn,
                               const char *callee_leaf) {
    if (!caller_qn || !callee_leaf) {
        return NULL;
    }
    size_t context_len = context_id ? strlen(context_id) : 0;
    size_t caller_len = strlen(caller_qn);
    size_t leaf_len = strlen(callee_leaf);
    if (context_len > SIZE_MAX - caller_len - leaf_len - 3) {
        return NULL;
    }
    size_t len = context_len + caller_len + leaf_len + 3;
    char *key = malloc(len);
    if (!key) {
        return NULL;
    }
    memcpy(key, context_id ? context_id : "", context_len);
    key[context_len] = '|';
    memcpy(key + context_len + 1, caller_qn, caller_len);
    key[context_len + caller_len + 1] = '|';
    memcpy(key + context_len + caller_len + 2, callee_leaf, leaf_len + 1);
    return key;
}

static void parallel_record_unresolved(resolve_worker_state_t *worker,
                                       const cbm_resolution_t *resolution) {
    if (resolution->strategy && strstr(resolution->strategy, "ambiguous")) {
        worker->reference_ambiguous++;
    } else if (resolution->strategy && (strstr(resolution->strategy, "overflow") ||
                                        strstr(resolution->strategy, "invalid"))) {
        worker->reference_incompatible++;
    } else {
        worker->reference_target_missing++;
    }
}

/* Resolve calls for one file and emit CALLS/HTTP_CALLS/ASYNC_CALLS edges. */
static void resolve_file_calls(resolve_ctx_t *rc, resolve_worker_state_t *ws, CBMFileResult *result,
                               const char *rel, const char *module_qn, const char **imp_keys,
                               const char **imp_vals, int imp_count, CBMLanguage lang,
                               int initial_resolved_call_count) {
    if (initial_resolved_call_count < 0 ||
        initial_resolved_call_count > result->resolved_calls.count) {
        cbm_log_error(
            "parallel.resolve_failed", "code", "CBM_RESOLVE_LSP_PREFIX_INVALID", "component",
            "parallel.resolve.progress", "operation", "validate_lsp_prefix", "path",
            rel ? rel : "", "message",
            "the immutable resolved-call prefix is outside the post-dispatch array bounds",
            "remediation",
            "preserve the generation and inspect cross-LSP mutation of resolved-call rows");
        ws->errors++;
        atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
        return;
    }
    /* Build a per-file hash index of resolved_calls keyed by
     * "caller_qn|callee_short" for O(1) lookup. cbm_pipeline_find_lsp_
     * resolution would otherwise do an O(N) linear scan over
     * resolved_calls for EACH of result->calls.count calls — the
     * dominant cost in parallel_resolve on kubernetes (~50s of pure
     * scanning). On insert, keep the highest-confidence entry per key
     * (matches the original "best" tie-break). Skip the build entirely
     * when there are no calls (nothing to look up) or no resolved
     * entries (lookups would all miss). */
    CBMHashTable *lsp_idx = NULL;
    if (result->calls.count > 0 && result->resolved_calls.count > 0) {
        lsp_idx = cbm_ht_create((uint32_t)result->resolved_calls.count * 2u + 16u);
        if (!lsp_idx) {
            cbm_log_error("parallel.resolve_failed", "code", "CBM_LSP_INDEX_ALLOC_FAILED",
                          "component", "parallel.lsp_idx", "operation", "create", "key", rel,
                          "message", "per-file resolved-call index could not be allocated",
                          "remediation", "free memory or reduce repository size, then retry");
            ws->errors++;
            return;
        }
        for (int i = 0;
             i < result->resolved_calls.count &&
             !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
             i++, resolve_initial_lsp_item_done(rc, ws, rel, i,
                                                initial_resolved_call_count)) {
            CBMResolvedCall *rc_e = &result->resolved_calls.items[i];
            if (!rc_e->caller_qn || !rc_e->callee_qn ||
                rc_e->confidence < CBM_LSP_CONFIDENCE_FLOOR) {
                continue;
            }
            const char *short_name = strrchr(rc_e->callee_qn, '.');
            short_name = short_name ? short_name + 1 : rc_e->callee_qn;
            char *key = lsp_idx_key_alloc(rc_e->preprocess_context_id, rc_e->caller_qn,
                                          short_name);
            if (!key) {
                cbm_log_error("parallel.resolve_failed", "code", "CBM_LSP_INDEX_KEY_ALLOC_FAILED",
                              "component", "parallel.lsp_idx", "operation", "key", "key",
                              rc_e->caller_qn, "message",
                              "resolved-call index key could not be allocated", "remediation",
                              "free memory or reduce repository size, then retry");
                cbm_ht_foreach(lsp_idx, lsp_idx_free_key, NULL);
                cbm_ht_free(lsp_idx);
                ws->errors++;
                return;
            }
            CBMResolvedCall *existing = (CBMResolvedCall *)cbm_ht_get(lsp_idx, key);
            if (!existing) {
                if (!cbm_ht_set_checked(lsp_idx, key, rc_e, NULL)) {
                    cbm_log_error("parallel.resolve_failed", "code", "CBM_LSP_INDEX_INSERT_FAILED",
                                  "component", "parallel.lsp_idx", "operation", "insert", "key",
                                  key, "message", "resolved-call index could not retain an entry",
                                  "remediation",
                                  "free memory or reduce repository size, then retry");
                    free(key);
                    cbm_ht_foreach(lsp_idx, lsp_idx_free_key, NULL);
                    cbm_ht_free(lsp_idx);
                    ws->errors++;
                    return;
                }
            } else if (rc_e->confidence > existing->confidence) {
                /* Update value; reuse stored key pointer to avoid leak. */
                const char *skey = cbm_ht_get_key(lsp_idx, key);
                free(key);
                if (!skey || !cbm_ht_set_checked(lsp_idx, skey, rc_e, NULL)) {
                    cbm_log_error("parallel.resolve_failed", "code", "CBM_LSP_INDEX_UPDATE_FAILED",
                                  "component", "parallel.lsp_idx", "operation", "update", "key",
                                  skey ? skey : "", "message",
                                  "resolved-call index could not update an entry", "remediation",
                                  "free memory or reduce repository size, then retry");
                    cbm_ht_foreach(lsp_idx, lsp_idx_free_key, NULL);
                    cbm_ht_free(lsp_idx);
                    ws->errors++;
                    return;
                }
            } else {
                free(key);
            }
        }
    }

    for (int c = 0;
         c < result->calls.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         c++, resolve_progress_item_done(rc, ws, rel, "calls", (size_t)c)) {
        CBMCall *call = &result->calls.items[c];
        if (!call->callee_name) {
            continue;
        }
        bool has_compile_context = call->preprocess_context_id != NULL;
        if (has_compile_context &&
            !cbm_compile_context_id_exists(rc->compile_contexts,
                                           call->preprocess_context_id)) {
            cbm_log_error(
                "parallel.resolve_failed", "code", "CBM_COMPILE_CONTEXT_ID_UNKNOWN",
                "component", "parallel.compile_context", "operation", "resolve_call", "key",
                call->preprocess_context_id, "message",
                "a mapped C-family call references no immutable compiler context", "remediation",
                "preserve the generation and rebuild its complete compile-context index");
            ws->errors++;
            atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
            break;
        }
        uint64_t _rc_t0 = extract_now_ns();
        const cbm_gbuf_node_t *source_node = find_source_node(
            rc->main_gbuf, rc->project_name, rel, module_qn, call->enclosing_func_qn,
            call->start_line, "parallel.calls.reference_source");
        atomic_fetch_add_explicit(&rc->time_ns_rc_source, extract_now_ns() - _rc_t0,
                                  memory_order_relaxed);
        if (!source_node) {
            continue;
        }

        /* LSP-resolved calls take precedence over registry textual matching.
         * Same helper + same CBM_LSP_CONFIDENCE_FLOOR as the sequential
         * pipeline (pass_calls.c) — both paths must admit the same set of
         * LSP overrides so a project doesn't get different attributions
         * depending on whether parallel mode kicked in. Unique-tail
         * fallbacks are JVM-only (see cbm_pipeline_lsp_allow_tail_match). */
        bool allow_tail = cbm_pipeline_lsp_allow_tail_match(lang);
        cbm_resolution_t res = {0};
        const CBMResolvedCall *lsp = NULL;
        _rc_t0 = extract_now_ns();
        if (lsp_idx && call->enclosing_func_qn) {
            const char *call_leaf = cbm_pipeline_call_callee_leaf(call->callee_name);
            if (call_leaf) {
                char *lookup_key = lsp_idx_key_alloc(call->preprocess_context_id,
                                                     call->enclosing_func_qn, call_leaf);
                if (!lookup_key) {
                    cbm_log_error("parallel.resolve_failed", "code",
                                  "CBM_LSP_INDEX_KEY_ALLOC_FAILED", "component", "parallel.lsp_idx",
                                  "operation", "lookup_key", "key", call->enclosing_func_qn,
                                  "message", "resolved-call lookup key could not be allocated",
                                  "remediation",
                                  "free memory or reduce repository size, then retry");
                    ws->errors++;
                    break;
                }
                lsp = (const CBMResolvedCall *)cbm_ht_get(lsp_idx, lookup_key);
                free(lookup_key);
            }
        }
        atomic_fetch_add_explicit(&rc->time_ns_rc_lsp_lookup, extract_now_ns() - _rc_t0,
                                  memory_order_relaxed);
        _rc_t0 = extract_now_ns();
        const cbm_gbuf_node_t *lsp_target = NULL;
        if (lsp) {
            /* Canonicalise to the gbuf node's QN so res.qualified_name matches
             * the gbuf even when the cross-file fallback had to prefix the
             * project name. If neither lookup hits, leave res.qualified_name
             * empty — the LSP was confident but its target isn't in the gbuf
             * (external/unindexed), so drop the edge rather than fall back to
             * the registry resolver, matching prior single-lookup semantics. */
            lsp_target = cbm_pipeline_lsp_target_node(rc->main_gbuf, rc->project_name,
                                                      lsp->callee_qn, allow_tail);
            if (has_compile_context && lsp_target &&
                cbm_compile_context_target_visible(rc->compile_contexts,
                                                   call->preprocess_context_id,
                                                   lsp_target->file_path) != SKIP_ONE) {
                lsp_target = NULL;
            }
            if (lsp_target) {
                res.qualified_name = lsp_target->qualified_name;
                res.strategy = lsp->strategy ? lsp->strategy : "lsp_override";
                res.confidence = (double)lsp->confidence;
                res.candidate_count = 1;
                ws->lsp_overrides++;
            }
        }
        if (!lsp_target && call->reference.resolved_target_qn) {
            res = (cbm_resolution_t){call->reference.resolved_target_qn, "self_member", 1.0, 1};
        } else if (!lsp_target && has_compile_context) {
            res = cbm_compile_context_resolve_call(
                rc->compile_contexts, rc->registry, rc->main_gbuf,
                call->preprocess_context_id, call->callee_name, lsp ? lsp->callee_qn : NULL,
                module_qn, call->reference.evidence == CBM_REF_EVIDENCE_QUALIFIED_PATH);
            if (lsp && res.qualified_name) {
                ws->lsp_overrides++;
            }
        } else if (!lsp_target) {
            res = cbm_registry_resolve_exact(rc->registry, call->callee_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        }
        atomic_fetch_add_explicit(&rc->time_ns_rc_resolve, extract_now_ns() - _rc_t0,
                                  memory_order_relaxed);
        bool lsp_authoritative = lsp_target || (has_compile_context && lsp && res.qualified_name);
        if (!lsp_authoritative && call->reference.evidence == CBM_REF_EVIDENCE_LOCAL) {
            ws->reference_local_only++;
            continue;
        }

        /* Perl call-graph noise guard (#476), mirroring the sequential pass
         * (pass_calls.c). Perl has no LSP resolver; for builtins (push/shift/
         * keys/...) and method calls ($obj->m, unresolved receiver), suppress
         * only WEAK cross-file short-name matches and keep the high-confidence
         * same_module / import_map strategies so a genuine same-file or
         * imported call to a builtin-named sub still resolves. Gated to Perl —
         * other languages are unaffected. */
        if (cbm_perl_suppress_generic_match(lang == CBM_LANG_PERL, call->is_method,
                                            call->callee_name, res.strategy)) {
            continue;
        }

        /* TS/JS/TSX weak-method suppression (#592/#606). The receiver-aware guard
         * must NOT drop this call here: doing so would also skip the #523
         * callee-name service bypass below, emit_service_edge's route/gRPC/config
         * branches, and its unconditional detect_url_in_args (which classifies
         * verb-suffix HTTP clients like api.patch('/x')). Instead, defer to the
         * emit path and suppress ONLY the plain-CALLS fall-through
         * (emit_normal_calls_edge), so every service edge stays main-identical by
         * construction. res.strategy may carry an lsp_* value here (LSP-resolved
         * calls keep res through this point); the helper's EXPLICIT drop-list
         * leaves lsp_ts_method / lsp_cross untouched. See #606 direction. */
        bool is_tsjs =
            lang == CBM_LANG_JAVASCRIPT || lang == CBM_LANG_TYPESCRIPT || lang == CBM_LANG_TSX;
        bool tsjs_drop_plain_call =
            cbm_tsjs_suppress_weak_method_match(is_tsjs, call->is_method, res.strategy);

        /* Service-pattern HTTP/ASYNC client call (`requests.get(url)`): the
         * service signal lives in the callee_name. The registry can mis-resolve
         * it to a spurious builtin short-name match (`requests.get` ->
         * `builtins.dict.get` via "get"), which is non-empty and not an HTTP
         * pattern, so the resolved-QN service checks below miss it and the call
         * is dropped. Detect it on the callee_name FIRST so the HTTP_CALLS/
         * ASYNC_CALLS edge is emitted regardless (target is a synthesized route
         * node, not the unindexed library). Mirrors pass_calls.c. (#523) */
        cbm_svc_kind_t csvc = cbm_service_pattern_match(call->callee_name);
        if (csvc == CBM_SVC_HTTP || csvc == CBM_SVC_ASYNC) {
            const char *cu = call->first_string_arg;
            bool chas_url = cu && cu[0] != '\0' &&
                            (cu[0] == '/' || strstr(cu, "://") != NULL ||
                             (csvc == CBM_SVC_ASYNC && strlen(cu) > PP_ESC_SPACE));
            if (chas_url) {
                cbm_resolution_t svc_res = {.qualified_name = call->callee_name,
                                            .confidence = PP_HALF_CONF,
                                            .strategy = "service_pattern"};
                emit_service_edge(ws->local_edge_buf, source_node, source_node, call, &svc_res,
                                  module_qn, rc->registry, rc->main_gbuf, imp_keys, imp_vals,
                                  imp_count, false);
                continue;
            }
        }
        if (!lsp_authoritative && call->reference.evidence == CBM_REF_EVIDENCE_MEMBER &&
            !call->reference.resolved_target_qn) {
            if (cbm_service_pattern_route_method(call->callee_name) != NULL &&
                call->first_string_arg && call->first_string_arg[0] == '/') {
                cbm_resolution_t route_resolution = {
                    .qualified_name = call->callee_name,
                    .confidence = PP_HALF_CONF,
                    .strategy = "route_syntax",
                };
                emit_service_edge(ws->local_edge_buf, source_node, source_node, call,
                                  &route_resolution, module_qn, rc->registry, rc->main_gbuf,
                                  imp_keys, imp_vals, imp_count, false);
                ws->calls_resolved++;
            } else {
                ws->reference_member_without_type++;
            }
            continue;
        }

        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            if (cbm_service_pattern_route_method(call->callee_name) != NULL) {
                cbm_resolution_t fake_res = {.qualified_name = call->callee_name,
                                             .confidence = PP_HALF_CONF,
                                             .strategy = "callee_suffix"};
                emit_service_edge(ws->local_edge_buf, source_node, source_node, call, &fake_res,
                                  module_qn, rc->registry, rc->main_gbuf, imp_keys, imp_vals,
                                  imp_count, false);
            }
            parallel_record_unresolved(ws, &res);
            continue;
        }
        /* Reuse lsp_target as target_node when LSP resolved — avoids a
         * second cbm_gbuf_find_by_qn lookup. */
        _rc_t0 = extract_now_ns();
        const cbm_gbuf_node_t *target_node;
        if (lsp_target && res.qualified_name == lsp_target->qualified_name) {
            target_node = lsp_target;
        } else {
            target_node = cbm_gbuf_find_by_qn_domain(
                rc->main_gbuf, res.qualified_name, CBM_REF_DOMAIN_CALLABLE, "parallel.call_target");
        }
        if (has_compile_context && target_node &&
            cbm_compile_context_target_visible(rc->compile_contexts,
                                               call->preprocess_context_id,
                                               target_node->file_path) != SKIP_ONE) {
            target_node = NULL;
        }
        atomic_fetch_add_explicit(&rc->time_ns_rc_target, extract_now_ns() - _rc_t0,
                                  memory_order_relaxed);
        if (!target_node || source_node->id == target_node->id) {
            /* HTTP/ASYNC calls to an EXTERNAL client library (`requests.get(url)`)
             * resolve to an unindexed QN (target_node == NULL), but their edge
             * target is a synthesized route node, not the library — emit them
             * anyway so cross-repo matching has an HTTP_CALLS edge to work with
             * (#523). Mirrors the sequential resolve_single_call bypass. */
            cbm_svc_kind_t psvc = cbm_service_pattern_match(res.qualified_name);
            if ((psvc == CBM_SVC_HTTP || psvc == CBM_SVC_ASYNC) && !target_node) {
                const char *u = call->first_string_arg;
                bool url_or_topic = u && u[0] != '\0' &&
                                    (u[0] == '/' || strstr(u, "://") != NULL ||
                                     (psvc == CBM_SVC_ASYNC && strlen(u) > PP_ESC_SPACE));
                if (url_or_topic) {
                    emit_service_edge(ws->local_edge_buf, source_node, NULL, call, &res, module_qn,
                                      rc->registry, rc->main_gbuf, imp_keys, imp_vals, imp_count,
                                      false);
                    ws->calls_resolved++;
                }
            }
            if (!target_node && psvc != CBM_SVC_HTTP && psvc != CBM_SVC_ASYNC) {
                ws->reference_incompatible++;
            }
            continue;
        }
        _rc_t0 = extract_now_ns();
        emit_service_edge(ws->local_edge_buf, source_node, target_node, call, &res, module_qn,
                          rc->registry, rc->main_gbuf, imp_keys, imp_vals, imp_count,
                          tsjs_drop_plain_call);
        atomic_fetch_add_explicit(&rc->time_ns_rc_emit, extract_now_ns() - _rc_t0,
                                  memory_order_relaxed);
        ws->calls_resolved++;
    }
    if (lsp_idx) {
        cbm_ht_foreach(lsp_idx, lsp_idx_free_key, NULL);
        cbm_ht_free(lsp_idx);
    }
}

/* Resolve usages for one file. */
static void resolve_file_usages(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                CBMFileResult *result, const char *rel, const char *module_qn,
                                const char **imp_keys, const char **imp_vals, int imp_count) {
    for (int u = 0;
         u < result->usages.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         u++, resolve_progress_item_done(rc, ws, rel, "usages", (size_t)u)) {
        CBMUsage *usage = &result->usages.items[u];
        if (!usage->ref_name) {
            continue;
        }
        if (usage->reference.evidence == CBM_REF_EVIDENCE_LOCAL) {
            ws->reference_local_only++;
            continue;
        }
        if (usage->reference.evidence == CBM_REF_EVIDENCE_MEMBER &&
            !usage->reference.resolved_target_qn) {
            ws->reference_member_without_type++;
            continue;
        }
        const cbm_gbuf_node_t *src = find_source_node(
            rc->main_gbuf, rc->project_name, rel, module_qn, usage->enclosing_func_qn,
            usage->start_line, "parallel.usages.reference_source");
        if (!src) {
            continue;
        }
        cbm_resolution_t res =
            usage->reference.resolved_target_qn
                ? (cbm_resolution_t){usage->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(rc->registry, usage->ref_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            parallel_record_unresolved(ws, &res);
            continue;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn_domain(
            rc->main_gbuf, res.qualified_name, usage->target_domain, "parallel.reference_target");
        if (!tgt || src->id == tgt->id) {
            if (!tgt) {
                ws->reference_incompatible++;
            }
            continue;
        }
        char uprops[CBM_SZ_256];
        char esc_ref[CBM_SZ_256]; /* sliced source text: escape quotes/newlines */
        cbm_json_escape(esc_ref, sizeof(esc_ref), usage->ref_name);
        snprintf(uprops, sizeof(uprops), "{\"callee\":\"%s\"}", esc_ref);
        cbm_gbuf_insert_edge(ws->local_edge_buf, src->id, tgt->id, "USAGE", uprops);
        ws->usages_resolved++;
    }
}

/* Resolve throws/raises for one file. */
static void resolve_file_throws(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                CBMFileResult *result, const char *rel, const char *module_qn,
                                const char **imp_keys, const char **imp_vals, int imp_count) {
    for (int t = 0;
         t < result->throws.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         t++, resolve_progress_item_done(rc, ws, rel, "throws", (size_t)t)) {
        CBMThrow *thr = &result->throws.items[t];
        if (!thr->exception_name || !thr->enclosing_func_qn) {
            continue;
        }
        if (thr->reference.evidence == CBM_REF_EVIDENCE_LOCAL) {
            ws->reference_local_only++;
            continue;
        }
        if (thr->reference.evidence == CBM_REF_EVIDENCE_MEMBER &&
            !thr->reference.resolved_target_qn) {
            ws->reference_member_without_type++;
            continue;
        }
        const cbm_gbuf_node_t *src = find_source_node(
            rc->main_gbuf, rc->project_name, rel, module_qn, thr->enclosing_func_qn,
            thr->start_line, "parallel.throws.reference_source");
        if (!src) {
            continue;
        }
        const char *edge_type = is_checked_exception(thr->exception_name) ? "THROWS" : "RAISES";
        cbm_resolution_t res =
            thr->reference.resolved_target_qn
                ? (cbm_resolution_t){thr->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(rc->registry, thr->exception_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            parallel_record_unresolved(ws, &res);
            continue;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn_domain(
            rc->main_gbuf, res.qualified_name, CBM_REF_DOMAIN_TYPE, "parallel.exception_type");
        if (!tgt || src->id == tgt->id) {
            if (!tgt) {
                ws->reference_incompatible++;
            }
            continue;
        }
        cbm_gbuf_insert_edge(ws->local_edge_buf, src->id, tgt->id, edge_type, "{}");
    }
}

/* Resolve reads/writes for one file. */
static void resolve_file_rw(resolve_ctx_t *rc, resolve_worker_state_t *ws, CBMFileResult *result,
                            const char *rel, const char *module_qn, const char **imp_keys,
                            const char **imp_vals, int imp_count) {
    for (int r = 0;
         r < result->rw.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         r++, resolve_progress_item_done(rc, ws, rel, "read_write", (size_t)r)) {
        CBMReadWrite *rw = &result->rw.items[r];
        if (!rw->var_name) {
            continue;
        }
        if (rw->reference.evidence == CBM_REF_EVIDENCE_LOCAL) {
            ws->reference_local_only++;
            continue;
        }
        if (rw->reference.evidence == CBM_REF_EVIDENCE_MEMBER &&
            !rw->reference.resolved_target_qn) {
            ws->reference_member_without_type++;
            continue;
        }
        const cbm_gbuf_node_t *src =
            find_source_node(rc->main_gbuf, rc->project_name, rel, module_qn, rw->enclosing_func_qn,
                             rw->start_line, "parallel.read_write.reference_source");
        if (!src) {
            continue;
        }
        cbm_resolution_t res =
            rw->reference.resolved_target_qn
                ? (cbm_resolution_t){rw->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(rc->registry, rw->var_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            parallel_record_unresolved(ws, &res);
            continue;
        }
        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn_domain(
            rc->main_gbuf, res.qualified_name, CBM_REF_DOMAIN_VALUE, "parallel.read_write_target");
        if (!tgt || src->id == tgt->id) {
            if (!tgt) {
                ws->reference_incompatible++;
            }
            continue;
        }
        const char *etype = rw->is_write ? "WRITES" : "READS";
        cbm_gbuf_insert_edge(ws->local_edge_buf, src->id, tgt->id, etype, "{}");
    }
}

/* Resolve base_classes → INHERITS edges for one definition. */
static void resolve_def_inherits(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                 const CBMDefinition *def, const cbm_gbuf_node_t *node,
                                 const char *rel, const char *mq, const char **ik,
                                 const char **iv, int ic) {
    if (!def->base_classes) {
        return;
    }
    for (int b = 0;
         def->base_classes[b] &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         b++, resolve_progress_item_done(rc, ws, rel, "base_class", (size_t)b)) {
        cbm_resolution_t resolution = {0};
        const cbm_gbuf_node_t *bn =
            resolve_as_type(rc->registry, rc->main_gbuf, def->base_classes[b], mq, ik, iv, ic,
                            "parallel.base_type", &resolution);
        if (!bn) {
            if (resolution.qualified_name && resolution.qualified_name[0]) {
                ws->reference_incompatible++;
            } else {
                parallel_record_unresolved(ws, &resolution);
            }
            continue;
        }
        if (bn && node->id != bn->id) {
            const char *edge_type = strcmp(bn->label, "Interface") == 0 ? "IMPLEMENTS" : "INHERITS";
            cbm_gbuf_insert_edge(ws->local_edge_buf, node->id, bn->id, edge_type, "{}");
            ws->semantic_resolved++;
        }
    }
}

/* Resolve decorators → DECORATES edges for one definition. */
static void resolve_def_decorators(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                   const CBMDefinition *def, const cbm_gbuf_node_t *node,
                                   const char *rel, const char *mq, const char **ik,
                                   const char **iv, int ic) {
    if (!def->decorators) {
        return;
    }
    for (int dc = 0;
         def->decorators[dc] &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         dc++, resolve_progress_item_done(rc, ws, rel, "decorator", (size_t)dc)) {
        char fn[CBM_SZ_256];
        extract_decorator_func(def->decorators[dc], fn, sizeof(fn));
        if (fn[0] == '\0') {
            continue;
        }
        cbm_resolution_t res = cbm_registry_resolve_exact(rc->registry, fn, mq, ik, iv, ic);
        if ((!res.qualified_name || res.qualified_name[0] == '\0') && !strchr(fn, '.')) {
            /* C# attributes are referenced by their short name (`[Log]`) but
             * declared with an `Attribute` suffix (`class LogAttribute`). */
            char with_suffix[CBM_SZ_256];
            int wn = snprintf(with_suffix, sizeof(with_suffix), "%sAttribute", fn);
            if (wn > 0 && (size_t)wn < sizeof(with_suffix)) {
                res = cbm_registry_resolve_exact(rc->registry, with_suffix, mq, ik, iv, ic);
            }
        }
        const cbm_gbuf_node_t *dn = NULL;
        if (res.qualified_name && res.qualified_name[0] != '\0') {
            dn = cbm_gbuf_find_by_qn_domain(rc->main_gbuf, res.qualified_name,
                                            CBM_REF_DOMAIN_CALLABLE, "parallel.decorator");
            if (!dn) {
                ws->reference_incompatible++;
            }
        } else {
            parallel_record_unresolved(ws, &res);
        }
        int64_t dn_id = 0;
        if (dn) {
            dn_id = dn->id;
        } else {
            /* External/stdlib decorator (Rust `#[derive(Debug)]`, Swift
             * `@discardableResult`, Scala `@deprecated`, Python `@cache`,
             * Java `@Override`, ...): no local symbol resolves.  Materialise a
             * synthetic "Decorator" node so the DECORATES relation is recorded.
             * The node is created in the per-worker local_edge_buf (shared-ID
             * gbuf); the sequential merge dedupes by QN across workers, so all
             * uses of the same decorator name collapse to one node project-wide
             * and the edge target IDs are remapped consistently. */
            char syn_qn[CBM_SZ_512];
            snprintf(syn_qn, sizeof(syn_qn), "<decorator:%s>", fn);
            dn_id =
                cbm_gbuf_upsert_node(ws->local_edge_buf, "Decorator", fn, syn_qn, "", 0, 0, "{}");
        }
        if (dn_id != 0 && node->id != dn_id) {
            /* Decorator SOURCE TEXT can contain quotes and raw newlines
             * (e.g. @register.tag("block"), multi-line @override_settings) —
             * interpolating it raw produced malformed properties JSON that
             * aborts every json_extract consumer (django: 3826 such edges). */
            char esc_dec[CBM_SZ_256];
            cbm_json_escape(esc_dec, sizeof(esc_dec), def->decorators[dc]);
            char dp[CBM_SZ_512];
            snprintf(dp, sizeof(dp), "{\"decorator\":\"%s\"}", esc_dec);
            cbm_gbuf_insert_edge(ws->local_edge_buf, node->id, dn_id, "DECORATES", dp);
            /* Ensure a reference-style edge exists so the decorator appears in queries
             * without being misclassified as a real call by downstream passes. */
            cbm_gbuf_insert_edge(ws->local_edge_buf, node->id, dn_id, "USAGE", "{}");
            ws->semantic_resolved++;
        }
    }
}

/* Resolve INHERITS + DECORATES + IMPLEMENTS for one file. */
static void resolve_file_semantic(resolve_ctx_t *rc, resolve_worker_state_t *ws,
                                  CBMFileResult *result, const char *rel, const char *module_qn,
                                  const char **imp_keys, const char **imp_vals, int imp_count) {
    for (int d = 0;
         d < result->defs.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         d++, resolve_progress_item_done(rc, ws, rel, "definition", (size_t)d)) {
        CBMDefinition *def = &result->defs.items[d];
        if (!def->qualified_name) {
            continue;
        }
        const cbm_gbuf_node_t *node = cbm_pipeline_find_definition_node(rc->main_gbuf, def, "");
        if (!node) {
            continue;
        }
        resolve_def_inherits(rc, ws, def, node, rel, module_qn, imp_keys, imp_vals, imp_count);
        resolve_def_decorators(rc, ws, def, node, rel, module_qn, imp_keys, imp_vals, imp_count);
    }
    for (int t = 0;
         t < result->impl_traits.count &&
         !atomic_load_explicit(rc->cancelled, memory_order_relaxed);
         t++, resolve_progress_item_done(rc, ws, rel, "impl_trait", (size_t)t)) {
        CBMImplTrait *it = &result->impl_traits.items[t];
        if (!it->trait_name || !it->struct_name) {
            continue;
        }
        cbm_resolution_t trait_resolution = {0};
        cbm_resolution_t receiver_resolution = {0};
        const cbm_gbuf_node_t *tn =
            resolve_as_type(rc->registry, rc->main_gbuf, it->trait_name, module_qn, imp_keys,
                            imp_vals, imp_count, "parallel.impl_trait", &trait_resolution);
        const cbm_gbuf_node_t *sn =
            resolve_as_type(rc->registry, rc->main_gbuf, it->struct_name, module_qn, imp_keys,
                            imp_vals, imp_count, "parallel.impl_receiver", &receiver_resolution);
        if (!tn || !sn) {
            if (!tn) {
                if (trait_resolution.qualified_name && trait_resolution.qualified_name[0]) {
                    ws->reference_incompatible++;
                } else {
                    parallel_record_unresolved(ws, &trait_resolution);
                }
            }
            if (!sn) {
                if (receiver_resolution.qualified_name && receiver_resolution.qualified_name[0]) {
                    ws->reference_incompatible++;
                } else {
                    parallel_record_unresolved(ws, &receiver_resolution);
                }
            }
            continue;
        }
        if (tn && sn && tn->id != sn->id) {
            cbm_gbuf_insert_edge(ws->local_edge_buf, sn->id, tn->id, "IMPLEMENTS", "{}");
            ws->semantic_resolved++;
        }
    }
}

static void resolve_worker(int worker_id, void *ctx_ptr) {
    resolve_ctx_t *rc = ctx_ptr;
    resolve_worker_state_t *ws = &rc->workers[worker_id];

    if (!ws->local_edge_buf) {
        ws->local_edge_buf =
            cbm_gbuf_new_shared_ids(rc->project_name, rc->repo_path, rc->shared_ids);
        if (!ws->local_edge_buf) {
            cbm_log_error("parallel.resolve.failed", "code", "CBM_RESOLVE_GRAPH_ALLOC_FAILED",
                          "component", "parallel.resolve.worker_graph", "operation", "allocate",
                          "message", "resolve worker graph allocation failed", "remediation",
                          "free memory or reduce repository size, then retry");
            ws->errors++;
            atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
            return;
        }
    }

    /* Per-worker service-pattern result cache. The same resolved QN
     * (e.g. "fmt.Errorf", "context.Context.Done") appears in many
     * call edges across many files within a project — caching turns
     * cbm_service_pattern_match's 6 × 30 × strstr scan into one hash
     * lookup after the first miss for each QN. Scoped to the worker's
     * lifetime in the parallel_resolve phase. */
    if (!cbm_service_pattern_cache_begin()) {
        ws->errors++;
        return;
    }

    while (SKIP_ONE) {
        int file_idx =
            atomic_fetch_add_explicit(&rc->next_file_idx, SKIP_ONE, memory_order_relaxed);
        if (file_idx >= rc->file_count) {
            break;
        }
        if (atomic_load_explicit(rc->cancelled, memory_order_relaxed)) {
            break;
        }

        uint64_t _loop_t0 = extract_now_ns();

        CBMFileResult *result = rc->result_cache[file_idx];
        if (!result) {
            atomic_fetch_add_explicit(&rc->time_ns_total_loop, extract_now_ns() - _loop_t0,
                                      memory_order_relaxed);
            if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_RESOLVE, "resolve",
                                                (uint64_t)rc->file_count) != 0) {
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_pipeline_record_fatal_error(
                    rc->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
                    "publish_parallel_resolve_progress", "resolve",
                    rc->files[file_idx].rel_path ? rc->files[file_idx].rel_path : "",
                    (size_t)file_idx,
                    "the completed empty-result resolution unit could not advance semantic "
                    "progress",
                    "preserve the worker workspace, repair the progress stream, and retry the "
                    "unchanged repository");
            }
            continue;
        }
        atomic_fetch_add_explicit(&rc->total_files_visited, 1, memory_order_relaxed);

        CBMLanguage lang = rc->files[file_idx].language;
        const char *rel = rc->files[file_idx].rel_path;

        /* Cross-file LSP is a per-file tree-sitter re-parse + AST walk +
         * registry lookups — ~50-150ms per file. It can ONLY find calls
         * that exist in the AST. If the per-file extract found zero calls,
         * cross-LSP will too: the AST is the same. For non-JVM languages,
         * skip when per-file LSP already produced at least as many resolved
         * entries as textual calls. Java/Kotlin per-file LSP can fill the
         * count with constructors or same-file calls while a mixed-source-root
         * Java↔Kotlin call remains unresolved, so JVM callers run whenever
         * calls exist. */
        bool cross_lsp_eligible = resolve_cross_lsp_eligible(rc, result, lang);
        int initial_resolved_call_count =
            result->calls.count > 0 ? result->resolved_calls.count : 0;

        /* Skip files with nothing else to resolve and no cross-LSP work. */
        if (result->calls.count == 0 && result->usages.count == 0 && result->throws.count == 0 &&
            result->rw.count == 0 && result->defs.count == 0 && result->impl_traits.count == 0 &&
            !cross_lsp_eligible) {
            if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_RESOLVE, "resolve",
                                                (uint64_t)rc->file_count) != 0) {
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_pipeline_record_fatal_error(
                    rc->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
                    "publish_parallel_resolve_progress", "resolve", rel ? rel : "",
                    (size_t)file_idx,
                    "the completed no-op resolution unit could not advance semantic progress",
                    "preserve the worker workspace, repair the progress stream, and retry the "
                    "unchanged repository");
            }
            continue;
        }

        /* Build import map ONCE (read-only access to main_gbuf). The
         * same imp_keys/imp_vals feed both the fused cross-file LSP
         * step below AND the resolve_file_* chain — no duplicate build. */
        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        uint64_t _imp_t0 = extract_now_ns();
        int import_map_status = cbm_pipeline_import_map_build(
            rc->pipeline, rc->main_gbuf, rc->project_name, rel, &imp_keys, &imp_vals, &imp_count);
        atomic_fetch_add_explicit(&rc->time_ns_import_map, extract_now_ns() - _imp_t0,
                                  memory_order_relaxed);
        if (import_map_status != 0) {
            ws->errors++;
            atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
            break;
        }

        /* Per-file is_import_reachable memoization. Spans all 5 resolve
         * sub-passes (calls/usages/throws/rw/semantic) which all flow
         * through cbm_registry_resolve. Same callee_name appears in
         * many call sites — first eval pays the strstr cost, repeats
         * are O(1) hash. Imports are constant within a file so the
         * cache is sound; invalidated at file exit. */
        cbm_registry_reach_cache_begin(result->calls.count + result->usages.count + 64);

        /* Per-file import-map prefix → module-qn hash. resolve_import_map
         * was doing O(imports) linear strcmp per call; with this it
         * becomes O(1). Keys/values borrowed from imp_keys/imp_vals
         * which outlive this scope. */
        cbm_registry_import_map_cache_begin(imp_keys, imp_vals, imp_count);

        /* THE BIG ONE: per-file cache of cbm_registry_resolve results.
         * Same callee_name in multiple call sites resolves identically
         * within a file (module_qn is fixed) — first call walks the
         * strategy chain, repeats are O(1). On K8s this targets the
         * 98.7% hot spot in resolve_file_calls (881 of 893s CPU). */
        cbm_registry_resolve_cache_begin(result->calls.count + result->usages.count + 64);
        if (cbm_registry_cache_failed()) {
            ws->errors++;
            cbm_registry_reach_cache_end();
            cbm_registry_import_map_cache_end();
            cbm_registry_resolve_cache_end();
            cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
            continue;
        }

        char *module_qn =
            cbm_pipeline_fqn_module_dir(rc->project_name, rel, pp_module_is_dir(lang));
        if (!module_qn) {
            cbm_log_error("parallel.resolve.failed", "code", "CBM_RESOLVE_MODULE_ALLOC_FAILED",
                          "component", "parallel.resolve.module", "operation", "qualify", "path",
                          rel ? rel : "", "message", "module identity allocation failed",
                          "remediation", "free memory or reduce repository size, then retry");
            ws->errors++;
            atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
            cbm_registry_reach_cache_end();
            cbm_registry_import_map_cache_end();
            cbm_registry_resolve_cache_end();
            cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
            break;
        }

        /* ── Cross-file LSP (FUSED) ─────────────────────────────
         * Runs BEFORE resolve_file_calls so its additions to
         * result->resolved_calls are picked up by
         * cbm_pipeline_find_lsp_resolution when calls become CALLS
         * edges. It borrows the exact same hash-bound source slab entry used
         * by File atom creation and extraction. A missing or malformed entry
         * is a terminal generation error; source is never reread or degraded.
         *
         * Slab reclaim afterward: the LSP re-parses via tree-sitter,
         * which allocates through this worker's TLS slab. Reclaiming
         * here keeps the slab high-water bounded as the resolve phase
         * walks across thousands of files in a single worker thread. */
        if (cross_lsp_eligible) {
            size_t lsp_source_size = 0;
            const uint8_t *lsp_source_bytes = NULL;
            if (cbm_pipeline_borrow_source(rc->pipeline, rc->source_slab, &rc->files[file_idx],
                                           "parallel_cross_lsp_source", &lsp_source_bytes,
                                           &lsp_source_size) != 0) {
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_registry_reach_cache_end();
                cbm_registry_import_map_cache_end();
                cbm_registry_resolve_cache_end();
                free(module_qn);
                cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
                break;
            }
            if (lsp_source_size == 0) {
                cbm_pipeline_record_fatal_error(
                    rc->pipeline, "CBM_RESOLVE_EMPTY_SOURCE_INCONSISTENT",
                    "parallel_cross_lsp_source", "parallel_resolve", rel, 0,
                    "a cross-LSP-eligible extraction result is bound to an exact empty source",
                    "preserve the generation and repair extraction/source eligibility before "
                    "retrying");
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_registry_reach_cache_end();
                cbm_registry_import_map_cache_end();
                cbm_registry_resolve_cache_end();
                free(module_qn);
                cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
                break;
            }
            const char *lsp_source = (const char *)lsp_source_bytes;
            int lsp_source_len = (int)lsp_source_size;
            const char *def_module = rc->def_modules ? rc->def_modules[file_idx] : module_qn;

            uint64_t lsp_t0 = extract_now_ns();

            /* Shared per-file dispatch: module-def filtering and shared
             * registries preserve the complete cross-file semantics. */
            int lsp_status = cbm_pxc_dispatch_file(
                lang, result, lsp_source, lsp_source_len, rel, def_module, rc->cross_registries,
                rc->module_def_index, rc->all_defs, rc->def_count, imp_keys, imp_vals, imp_count,
                rc->rust_manifest);
            /* Contract: destroy the thread parser before slab allocator reclaim. */
            cbm_destroy_thread_parser();
            cbm_slab_reclaim();
            uint64_t lsp_elapsed_ns = extract_now_ns() - lsp_t0;
            atomic_fetch_add_explicit(&rc->time_ns_cross_lsp, lsp_elapsed_ns,
                                      memory_order_relaxed);
            uint64_t lsp_elapsed_ms = lsp_elapsed_ns / PP_USEC_PER_MS;
            if (lsp_elapsed_ms > PP_TIMER_THRESH) {
                cbm_log_info("parallel.resolve.lsp_cross.slow", "elapsed_ms",
                             itoa_log((int)lsp_elapsed_ms), "path", rel);
            }
            atomic_fetch_add_explicit(&rc->lsp_cross_processed, SKIP_ONE, memory_order_relaxed);
            if (lsp_status != 0 || cbm_arena_failed(&result->arena)) {
                cbm_log_error("parallel.resolve.failed", "code",
                              cbm_arena_failed(&result->arena)
                                  ? cbm_arena_failure_code(&result->arena)
                                  : "CBM_LSP_CROSS_DISPATCH_FAILED",
                              "component", "parallel.resolve.lsp_cross", "operation",
                              cbm_arena_failed(&result->arena)
                                  ? cbm_arena_failure_operation(&result->arena)
                                  : "dispatch",
                              "path", rel ? rel : "", "message",
                              "cross-file resolution failed before all associations were derived",
                              "remediation", "inspect the structured cause and retry the complete corpus");
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_registry_reach_cache_end();
                cbm_registry_import_map_cache_end();
                cbm_registry_resolve_cache_end();
                free(module_qn);
                cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
                break;
            }
            if (result->resolved_calls.count < initial_resolved_call_count) {
                cbm_log_error(
                    "parallel.resolve.failed", "code", "CBM_RESOLVE_LSP_PREFIX_SHRANK",
                    "component", "parallel.resolve.progress", "operation",
                    "read_cross_lsp_append", "path", rel ? rel : "", "message",
                    "cross-LSP dispatch removed rows from the immutable resolved-call prefix",
                    "remediation",
                    "preserve the generation and repair cross-LSP to append without mutation");
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_registry_reach_cache_end();
                cbm_registry_import_map_cache_end();
                cbm_registry_resolve_cache_end();
                free(module_qn);
                cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
                break;
            }
            uint64_t dynamic_lsp_items =
                (uint64_t)(result->resolved_calls.count - initial_resolved_call_count);
            if (!resolve_atomic_count_add(&rc->resolve_dynamic_lsp_items,
                                          dynamic_lsp_items)) {
                cbm_log_error(
                    "parallel.resolve.failed", "code", "CBM_RESOLVE_LSP_APPEND_OVERFLOW",
                    "component", "parallel.resolve.progress", "operation",
                    "count_cross_lsp_append", "path", rel ? rel : "", "message",
                    "cross-LSP appended-row accounting exceeded the exact integer range",
                    "remediation", "preserve the generation and inspect resolver cardinalities");
                ws->errors++;
                atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
                cbm_registry_reach_cache_end();
                cbm_registry_import_map_cache_end();
                cbm_registry_resolve_cache_end();
                free(module_qn);
                cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
                break;
            }
            resolve_progress_item_done(rc, ws, rel, "cross_lsp", 0);
        }

        /* Per-sub-phase wall-clock so we can attribute the dominant cost. */
        uint64_t _ph_t0;

        /* ── CALLS resolution ──────────────────────────────────── */
        _ph_t0 = extract_now_ns();
        resolve_file_calls(rc, ws, result, rel, module_qn, imp_keys, imp_vals, imp_count, lang,
                           initial_resolved_call_count);
        uint64_t _ph_elapsed = extract_now_ns() - _ph_t0;
        atomic_fetch_add_explicit(&rc->time_ns_calls, _ph_elapsed, memory_order_relaxed);
        log_resolve_phase_slow(rel, "calls", result->calls.count, _ph_elapsed);

        /* ── USAGE resolution ──────────────────────────────────── */
        _ph_t0 = extract_now_ns();
        resolve_file_usages(rc, ws, result, rel, module_qn, imp_keys, imp_vals, imp_count);
        _ph_elapsed = extract_now_ns() - _ph_t0;
        atomic_fetch_add_explicit(&rc->time_ns_usages, _ph_elapsed, memory_order_relaxed);
        log_resolve_phase_slow(rel, "usages", result->usages.count, _ph_elapsed);

        /* ── THROWS / RAISES ───────────────────────────────────── */
        _ph_t0 = extract_now_ns();
        resolve_file_throws(rc, ws, result, rel, module_qn, imp_keys, imp_vals, imp_count);
        _ph_elapsed = extract_now_ns() - _ph_t0;
        atomic_fetch_add_explicit(&rc->time_ns_throws, _ph_elapsed, memory_order_relaxed);
        log_resolve_phase_slow(rel, "throws", result->throws.count, _ph_elapsed);

        /* ── READS / WRITES ────────────────────────────────────── */
        _ph_t0 = extract_now_ns();
        resolve_file_rw(rc, ws, result, rel, module_qn, imp_keys, imp_vals, imp_count);
        _ph_elapsed = extract_now_ns() - _ph_t0;
        atomic_fetch_add_explicit(&rc->time_ns_rw, _ph_elapsed, memory_order_relaxed);
        log_resolve_phase_slow(rel, "read_write", result->rw.count, _ph_elapsed);

        /* ── INHERITS + DECORATES + IMPLEMENTS ──────────────────── */
        _ph_t0 = extract_now_ns();
        resolve_file_semantic(rc, ws, result, rel, module_qn, imp_keys, imp_vals, imp_count);
        _ph_elapsed = extract_now_ns() - _ph_t0;
        atomic_fetch_add_explicit(&rc->time_ns_semantic, _ph_elapsed, memory_order_relaxed);
        log_resolve_phase_slow(rel, "semantic",
                               result->defs.count + result->impl_traits.count, _ph_elapsed);

        if (cbm_registry_cache_failed()) {
            ws->errors++;
        }
        if (cbm_service_pattern_cache_failed()) {
            ws->errors++;
        }

        cbm_registry_reach_cache_end();
        cbm_registry_import_map_cache_end();
        cbm_registry_resolve_cache_end();

        free(module_qn);
        cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);

        atomic_fetch_add_explicit(&rc->time_ns_total_loop, extract_now_ns() - _loop_t0,
                                  memory_order_relaxed);
        if (cbm_worker_progress_advance_unit(CBM_WORKER_PROGRESS_STAGE_RESOLVE, "resolve",
                                            (uint64_t)rc->file_count) != 0) {
            ws->errors++;
            atomic_store_explicit(rc->cancelled, SKIP_ONE, memory_order_relaxed);
            cbm_pipeline_record_fatal_error(
                rc->pipeline, "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED",
                "publish_parallel_resolve_progress", "resolve", rel ? rel : "",
                (size_t)file_idx,
                "the completed resolution unit could not advance semantic progress",
                "preserve the worker workspace, repair the progress stream, and retry the "
                "unchanged repository");
            break;
        }
    }

    /* Tear down this worker's thread-local parser + slab state, mirroring
     * extract_worker. Without this, resolve-worker pages keep an owner pointer
     * into dead TLS and are never retired, so a later cross-thread free can
     * never bring their refcount to zero (leak). Retiring them here releases
     * each page as its final chunk returns. */
    cbm_destroy_thread_parser();
    cbm_slab_destroy_thread();
    cbm_service_pattern_cache_end();
}

int cbm_parallel_resolve(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                         CBMFileResult **result_cache, _Atomic int64_t *shared_ids,
                         int worker_count, CBMLSPDef *all_defs, int def_count,
                         char *const *def_modules, struct CBMModuleDefIndex *module_def_index,
                         void *cross_registries_v) {
    /* See header: typed as void* across the TU boundary; cast back here. */
    CBMCrossLspRegistries *cross_registries = (CBMCrossLspRegistries *)cross_registries_v;
    if (file_count == 0) {
        return 0;
    }
    if (validate_parallel_source_bindings(ctx, files, file_count,
                                          "validate_parallel_resolve_sources") != 0) {
        return CBM_NOT_FOUND;
    }
    if (worker_count <= 0) {
        return reject_invalid_parallel_worker_count("parallel_resolve", worker_count);
    }

    cbm_log_info("parallel.resolve.start", "files", itoa_log(file_count), "workers",
                 itoa_log(worker_count));

    resolve_worker_state_t *workers = NULL;
    if (cbm_aligned_alloc((void **)&workers, CBM_CACHE_LINE,
                          (size_t)worker_count * sizeof(resolve_worker_state_t)) != 0) {
        return CBM_NOT_FOUND;
    }
    memset(workers, 0, (size_t)worker_count * sizeof(resolve_worker_state_t));

    resolve_ctx_t rc = {
        .files = files,
        .file_count = file_count,
        .source_slab = ctx->source_slab,
        .compile_contexts = ctx->compile_contexts,
        .project_name = ctx->project_name,
        .repo_path = ctx->repo_path,
        .workers = workers,
        .max_workers = worker_count,
        .result_cache = result_cache,
        .main_gbuf = ctx->gbuf,
        .registry = ctx->registry,
        .pipeline = ctx->pipeline,
        .shared_ids = shared_ids,
        .cancelled = ctx->cancelled,
        .all_defs = all_defs,
        .def_count = def_count,
        .def_modules = def_modules,
        .module_def_index = module_def_index,
        .cross_registries = cross_registries,
        .rust_manifest = ctx->rust_manifest,
    };
    atomic_init(&rc.next_file_idx, 0);
    atomic_init(&rc.lsp_cross_processed, 0);
    atomic_init(&rc.resolve_items_completed, 0);
    atomic_init(&rc.resolve_dynamic_lsp_items, 0);
    atomic_init(&rc.resolve_progress_last_attempt_ms, cbm_now_ms());
    atomic_init(&rc.resolve_progress_failed, 0);
    if (resolve_measure_items(&rc, &rc.resolve_items_total) != 0) {
        cbm_log_error("parallel.resolve.failed", "code", "CBM_RESOLVE_ITEM_TOTAL_INVALID",
                      "component", "parallel.resolve.progress", "operation", "measure",
                      "message",
                      "the immutable resolver results could not produce one exact bounded inner "
                      "work denominator",
                      "remediation",
                      "preserve the generation and inspect extraction result cardinalities");
        cbm_aligned_free(workers);
        return CBM_NOT_FOUND;
    }
    char resolve_items_total[32];
    snprintf(resolve_items_total, sizeof(resolve_items_total), "%llu",
             (unsigned long long)rc.resolve_items_total);
    cbm_log_info("parallel.resolve.progress_scope", "files", itoa_log(file_count),
                 "resolver_items", resolve_items_total, "record_interval_ms",
                 itoa_log(CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS));
    /* Sub-phase: Dispatch resolve workers (per-file call/usage resolution, PARALLEL) */
    CBM_PROF_START(t_resolve_dispatch);
    cbm_parallel_for_opts_t opts = {
        .max_workers = worker_count,
        .force_pthreads = false,
        .operation = "parallel_resolve",
    };
    cbm_parallel_for_result_t dispatch_result = {0};
    int dispatch_rc =
        cbm_parallel_for(worker_count, resolve_worker, &rc, opts, &dispatch_result);
    record_worker_pool_dispatch(ctx ? ctx->pipeline : NULL, &dispatch_result);
    CBM_PROF_END_N("parallel_resolve", "1_dispatch_workers_parallel", t_resolve_dispatch,
                   file_count);
    if (dispatch_rc != 0) {
        for (int i = 0; i < worker_count; i++) {
            if (workers[i].local_edge_buf) {
                cbm_gbuf_free(workers[i].local_edge_buf);
            }
        }
        cbm_aligned_free(workers);
        return CBM_NOT_FOUND;
    }
    uint64_t dynamic_lsp_items =
        atomic_load_explicit(&rc.resolve_dynamic_lsp_items, memory_order_relaxed);
    uint64_t cross_lsp_units =
        (uint64_t)atomic_load_explicit(&rc.lsp_cross_processed, memory_order_relaxed);
    uint64_t recounted_items = 0;
    if (resolve_recount_items(&rc, dynamic_lsp_items, cross_lsp_units, &recounted_items) != 0 ||
        recounted_items != rc.resolve_items_total) {
        char recounted[32];
        char dynamic[32];
        char cross_units[32];
        snprintf(recounted, sizeof(recounted), "%llu", (unsigned long long)recounted_items);
        snprintf(dynamic, sizeof(dynamic), "%llu", (unsigned long long)dynamic_lsp_items);
        snprintf(cross_units, sizeof(cross_units), "%llu", (unsigned long long)cross_lsp_units);
        cbm_log_error(
            "parallel.resolve.failed", "code", "CBM_RESOLVE_ITEM_RECOUNT_MISMATCH", "component",
            "parallel.resolve.progress", "operation", "recount", "recounted", recounted,
            "expected", resolve_items_total, "dynamic_lsp_items", dynamic, "cross_lsp_units",
            cross_units, "message",
            "the post-join independent recount did not reconstruct the immutable denominator",
            "remediation",
            "preserve the generation and inspect extraction cardinality or cross-LSP mutation");
        for (int i = 0; i < worker_count; i++) {
            if (workers[i].local_edge_buf) {
                cbm_gbuf_free(workers[i].local_edge_buf);
            }
        }
        cbm_aligned_free(workers);
        return CBM_NOT_FOUND;
    }
    uint64_t resolved_items =
        atomic_load_explicit(&rc.resolve_items_completed, memory_order_relaxed);
    if (resolved_items != rc.resolve_items_total) {
        char completed[32];
        snprintf(completed, sizeof(completed), "%llu", (unsigned long long)resolved_items);
        cbm_log_error("parallel.resolve.failed", "code", "CBM_RESOLVE_ITEM_TOTAL_MISMATCH",
                      "component", "parallel.resolve.progress", "operation", "readback",
                      "completed", completed, "expected", resolve_items_total, "message",
                      "parallel resolution joined without completing the exact measured inner "
                      "work denominator",
                      "remediation",
                      "preserve the generation and inspect the first cancelled or failed item");
        for (int i = 0; i < worker_count; i++) {
            if (workers[i].local_edge_buf) {
                cbm_gbuf_free(workers[i].local_edge_buf);
            }
        }
        cbm_aligned_free(workers);
        return CBM_NOT_FOUND;
    }
    if (cbm_pipeline_record_parallel_resolver_accounting(
            ctx ? ctx->pipeline : NULL, resolved_items, rc.resolve_items_total,
            recounted_items, dynamic_lsp_items, cross_lsp_units) != 0) {
        for (int i = 0; i < worker_count; i++) {
            if (workers[i].local_edge_buf) {
                cbm_gbuf_free(workers[i].local_edge_buf);
            }
        }
        cbm_aligned_free(workers);
        return CBM_NOT_FOUND;
    }
    char completed_items[32];
    char recounted_items_buf[32];
    char dynamic_lsp_items_buf[32];
    char cross_lsp_units_buf[32];
    snprintf(completed_items, sizeof(completed_items), "%llu",
             (unsigned long long)resolved_items);
    snprintf(recounted_items_buf, sizeof(recounted_items_buf), "%llu",
             (unsigned long long)recounted_items);
    snprintf(dynamic_lsp_items_buf, sizeof(dynamic_lsp_items_buf), "%llu",
             (unsigned long long)dynamic_lsp_items);
    snprintf(cross_lsp_units_buf, sizeof(cross_lsp_units_buf), "%llu",
             (unsigned long long)cross_lsp_units);
    cbm_log_info("parallel.resolve.progress_done", "completed", completed_items, "denominator",
                 resolve_items_total, "recounted", recounted_items_buf, "dynamic_lsp_items",
                 dynamic_lsp_items_buf, "cross_lsp_units", cross_lsp_units_buf);

    /* Sub-phase: Merge all local edge bufs into main gbuf (SEQUENTIAL) */
    CBM_PROF_START(t_resolve_merge);
    int total_calls = 0;
    int total_usages = 0;
    int total_semantic = 0;
    int total_lsp_overrides = 0;
    int total_errors = 0;
    int total_reference_local_only = 0;
    int total_reference_member_without_type = 0;
    int total_reference_target_missing = 0;
    int total_reference_ambiguous = 0;
    int total_reference_incompatible = 0;
    for (int i = 0; i < worker_count; i++) {
        total_reference_local_only += workers[i].reference_local_only;
        total_reference_member_without_type += workers[i].reference_member_without_type;
        total_reference_target_missing += workers[i].reference_target_missing;
        total_reference_ambiguous += workers[i].reference_ambiguous;
        total_reference_incompatible += workers[i].reference_incompatible;
        total_errors += workers[i].errors;
        if (workers[i].local_edge_buf) {
            cbm_gbuf_merge(ctx->gbuf, workers[i].local_edge_buf);
            total_calls += workers[i].calls_resolved;
            total_usages += workers[i].usages_resolved;
            total_semantic += workers[i].semantic_resolved;
            total_lsp_overrides += workers[i].lsp_overrides;
            cbm_gbuf_free(workers[i].local_edge_buf);
        }
    }
    CBM_PROF_END_N("parallel_resolve", "2_merge_edge_bufs_seq", t_resolve_merge,
                   total_calls + total_usages);

    cbm_aligned_free(workers);

    /* Go-style implicit interface satisfaction (needs full graph, serial) */
    int go_impl = cbm_pipeline_implements_go(ctx);

    /* The sequential merge preserves worker node IDs but reallocates edges from
     * the main graph, and the Go pass can add more main-only edges afterward.
     * Publish the greater post-join ceiling before cancellation or handoff. */
    cbm_parallel_rebase_shared_ids(ctx->gbuf, shared_ids, "parallel_resolve.post_merge");

    if (atomic_load(ctx->cancelled) || total_errors > 0) {
        return CBM_NOT_FOUND;
    }

    /* Cross-LSP coverage over the complete immutable source slab. */
    cbm_log_info(
        "parallel.resolve.lsp_cross_done", "files_processed",
        itoa_log(atomic_load_explicit(&rc.lsp_cross_processed, memory_order_relaxed)),
        "defs_total", itoa_log(def_count));

    cbm_log_info("parallel.resolve.done", "calls", itoa_log(total_calls), "usages",
                 itoa_log(total_usages), "semantic", itoa_log(total_semantic + go_impl),
                 "lsp_overrides", itoa_log(total_lsp_overrides));
    cbm_log_info("reference.resolution.refused", "code", "CBM_REFERENCE_TARGET_REFUSED", "pass",
                 "parallel", "local_only", itoa_log(total_reference_local_only),
                 "member_without_type", itoa_log(total_reference_member_without_type), "message",
                 "references without persisted scope or receiver/type evidence were not emitted");
    cbm_log_info("reference.resolution.unresolved", "code", "CBM_REFERENCE_TARGET_UNRESOLVED",
                 "pass", "parallel", "target_missing", itoa_log(total_reference_target_missing),
                 "ambiguous", itoa_log(total_reference_ambiguous), "incompatible",
                 itoa_log(total_reference_incompatible), "remediation",
                 "add exact import, module, qualified-path, or LSP type evidence");

    /* Per-sub-phase breakdown so we stop guessing about hot paths.
     * Numbers are summed across workers (total CPU-ms, not wall-time).
     * Split into multiple log lines because itoa_log uses a 4-slot TLS
     * ring buffer — more than 4 values per log_info call would alias
     * each other (we hit that bug in the first profiling run). */
    char loop_buf[32], visits_buf[32];
    snprintf(
        loop_buf, sizeof(loop_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_total_loop, memory_order_relaxed) /
                             1000000ULL));
    snprintf(visits_buf, sizeof(visits_buf), "%d",
             atomic_load_explicit(&rc.total_files_visited, memory_order_relaxed));
    cbm_log_info("parallel.resolve.phase_summary", "total_loop_cpu_ms", loop_buf, "files_visited",
                 visits_buf);

    char imp_buf[32], xls_buf[32], cal_buf[32];
    snprintf(
        imp_buf, sizeof(imp_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_import_map, memory_order_relaxed) /
                             1000000ULL));
    snprintf(
        xls_buf, sizeof(xls_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_cross_lsp, memory_order_relaxed) /
                             1000000ULL));
    snprintf(cal_buf, sizeof(cal_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_calls, memory_order_relaxed) /
                                  1000000ULL));
    cbm_log_info("parallel.resolve.phase_ms_a", "import_map", imp_buf, "cross_lsp", xls_buf,
                 "resolve_calls", cal_buf);

    char use_buf[32], thr_buf[32], rw_buf[32], sem_buf[32];
    snprintf(use_buf, sizeof(use_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_usages, memory_order_relaxed) /
                                  1000000ULL));
    snprintf(thr_buf, sizeof(thr_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_throws, memory_order_relaxed) /
                                  1000000ULL));
    snprintf(rw_buf, sizeof(rw_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_rw, memory_order_relaxed) /
                                  1000000ULL));
    snprintf(sem_buf, sizeof(sem_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_semantic, memory_order_relaxed) /
                                  1000000ULL));
    cbm_log_info("parallel.resolve.phase_ms_b", "resolve_usages", use_buf, "resolve_throws",
                 thr_buf, "resolve_rw", rw_buf, "resolve_semantic", sem_buf);

    char src_buf[32], lsp_buf[32], rsv_buf[32], tgt_buf[32], emt_buf[32];
    snprintf(
        src_buf, sizeof(src_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_rc_source, memory_order_relaxed) /
                             1000000ULL));
    snprintf(
        lsp_buf, sizeof(lsp_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_rc_lsp_lookup, memory_order_relaxed) /
                             1000000ULL));
    snprintf(
        rsv_buf, sizeof(rsv_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_rc_resolve, memory_order_relaxed) /
                             1000000ULL));
    snprintf(
        tgt_buf, sizeof(tgt_buf), "%llu",
        (unsigned long long)(atomic_load_explicit(&rc.time_ns_rc_target, memory_order_relaxed) /
                             1000000ULL));
    snprintf(emt_buf, sizeof(emt_buf), "%llu",
             (unsigned long long)(atomic_load_explicit(&rc.time_ns_rc_emit, memory_order_relaxed) /
                                  1000000ULL));
    cbm_log_info("parallel.resolve.calls_breakdown", "find_source", src_buf, "lsp_lookup", lsp_buf,
                 "resolve", rsv_buf);
    cbm_log_info("parallel.resolve.calls_breakdown2", "find_target", tgt_buf, "emit_edge", emt_buf);
    return 0;
}
