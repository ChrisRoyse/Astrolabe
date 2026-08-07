/*
 * pass_usages.c — Resolve usages, throws, and read/write edges.
 *
 * For each file, re-extracts and resolves:
 *   - USAGE edges: identifier references (not calls) to registered symbols
 *   - THROWS/RAISES edges: exception types
 *   - READS/WRITES edges: variable read/write access patterns
 *
 * All three share the same exact-evidence admission rule. Lexical locals and
 * untyped members become explicit non-edge outcomes; repository-global bare
 * names are never guessed. Combined into one pass to avoid triple re-extraction.
 *
 * Depends on: pass_definitions having populated the registry and graph buffer
 */
#include "foundation/constants.h"
#include "foundation/str_util.h" // cbm_json_escape
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "cbm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* True for languages whose module QN derives from the CONTAINING DIRECTORY
 * (Java/Go package). MUST match cbm_lang_module_is_dir() (internal/cbm/helpers.c)
 * so same-module resolution keys against the directory-based def-node QNs. */
static bool pu_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

/* Read file into heap buffer. Caller must free(). */
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

static const char *itoa_log(int val) {
    enum { RING_BUF_COUNT = 4, RING_BUF_MASK = 3 };
    static CBM_TLS char bufs[RING_BUF_COUNT][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & RING_BUF_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

typedef struct {
    int local_only;
    int member_without_type;
    int target_missing;
    int ambiguous;
    int incompatible;
} reference_resolution_stats_t;

static bool reference_requires_refusal(const CBMReferenceIdentity *identity,
                                       reference_resolution_stats_t *stats) {
    if (identity->evidence == CBM_REF_EVIDENCE_LOCAL) {
        stats->local_only++;
        return true;
    }
    if (identity->evidence == CBM_REF_EVIDENCE_MEMBER && !identity->resolved_target_qn) {
        stats->member_without_type++;
        return true;
    }
    return false;
}

static void record_unresolved(const cbm_resolution_t *resolution,
                              reference_resolution_stats_t *stats) {
    if (resolution->strategy && strstr(resolution->strategy, "ambiguous")) {
        stats->ambiguous++;
    } else if (resolution->strategy && (strstr(resolution->strategy, "overflow") ||
                                        strstr(resolution->strategy, "invalid"))) {
        stats->incompatible++;
    } else {
        stats->target_missing++;
    }
}

/* Check if an exception name is a "checked" exception (Java-style).
 * Checked: Exception, IOException, etc. (extends Exception, not RuntimeException).
 * Simple heuristic: if name contains "Error" or "Panic", it's a runtime exception. */
static bool is_checked_exception(const char *name) {
    if (!name) {
        return false;
    }
    if (strstr(name, "Error") || strstr(name, "Panic") || strstr(name, "error") ||
        strstr(name, "panic")) {
        return false;
    }
    return true; /* Default: treat as checked */
}

/* Find the graph buffer node for an enclosing function QN, falling back to file node. */
static const cbm_gbuf_node_t *find_enclosing_node(cbm_pipeline_ctx_t *ctx, const char *func_qn,
                                                  const char *rel_path, const char *module_qn,
                                                  int source_line, const char *operation) {
    return cbm_pipeline_find_reference_source(ctx->gbuf, ctx->project_name, rel_path, module_qn,
                                              func_qn, source_line, operation);
}

/* Resolve USAGE edges for one file's extracted usages. */
static int resolve_usage_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                               const char *rel, const char *module_qn, const char **imp_keys,
                               const char **imp_vals, int imp_count,
                               reference_resolution_stats_t *stats) {
    int resolved = 0;
    for (int u = 0; u < result->usages.count; u++) {
        CBMUsage *usage = &result->usages.items[u];
        if (!usage->ref_name) {
            continue;
        }
        if (reference_requires_refusal(&usage->reference, stats)) {
            continue;
        }

        const cbm_gbuf_node_t *src =
            find_enclosing_node(ctx, usage->enclosing_func_qn, rel, module_qn, usage->start_line,
                                "usages.reference_source");
        if (!src) {
            continue;
        }

        cbm_resolution_t res =
            usage->reference.resolved_target_qn
                ? (cbm_resolution_t){usage->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(ctx->registry, usage->ref_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            record_unresolved(&res, stats);
            continue;
        }

        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn_domain(
            ctx->gbuf, res.qualified_name, usage->target_domain, "usages.reference_target");
        if (!tgt || src->id == tgt->id) {
            if (!tgt) {
                stats->incompatible++;
            }
            continue;
        }

        /* ref_name is sliced source text and can contain quotes/newlines —
         * escape it or the edge properties JSON is malformed. */
        char esc_ref[CBM_SZ_256];
        cbm_json_escape(esc_ref, sizeof(esc_ref), usage->ref_name);
        char uprops[CBM_SZ_512];
        snprintf(uprops, sizeof(uprops), "{\"callee\":\"%s\"}", esc_ref);
        cbm_gbuf_insert_edge(ctx->gbuf, src->id, tgt->id, "USAGE", uprops);
        resolved++;
    }
    return resolved;
}

/* Resolve THROWS/RAISES edges for one file's extracted throws. */
static int resolve_throw_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result,
                               const char *rel, const char *module_qn, const char **imp_keys,
                               const char **imp_vals, int imp_count,
                               reference_resolution_stats_t *stats) {
    int resolved = 0;
    for (int t = 0; t < result->throws.count; t++) {
        CBMThrow *thr = &result->throws.items[t];
        if (!thr->exception_name || !thr->enclosing_func_qn) {
            continue;
        }
        if (reference_requires_refusal(&thr->reference, stats)) {
            continue;
        }

        const cbm_gbuf_node_t *src =
            find_enclosing_node(ctx, thr->enclosing_func_qn, rel, module_qn, thr->start_line,
                                "throws.reference_source");
        if (!src) {
            continue;
        }

        const char *edge_type = is_checked_exception(thr->exception_name) ? "THROWS" : "RAISES";
        cbm_resolution_t res =
            thr->reference.resolved_target_qn
                ? (cbm_resolution_t){thr->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(ctx->registry, thr->exception_name, module_qn,
                                             imp_keys, imp_vals, imp_count);

        const cbm_gbuf_node_t *tgt = NULL;
        if (res.qualified_name && res.qualified_name[0]) {
            tgt = cbm_gbuf_find_by_qn_domain(ctx->gbuf, res.qualified_name, CBM_REF_DOMAIN_TYPE,
                                             "usages.exception_type");
        }
        if (!res.qualified_name || !res.qualified_name[0]) {
            record_unresolved(&res, stats);
        }
        if (!tgt || src->id == tgt->id) {
            if (res.qualified_name && res.qualified_name[0] && !tgt) {
                stats->incompatible++;
            }
            continue;
        }

        cbm_gbuf_insert_edge(ctx->gbuf, src->id, tgt->id, edge_type, "{}");
        resolved++;
    }
    return resolved;
}

/* Resolve READS/WRITES edges for one file's extracted read/write accesses. */
static int resolve_rw_edges(cbm_pipeline_ctx_t *ctx, const CBMFileResult *result, const char *rel,
                            const char *module_qn, const char **imp_keys, const char **imp_vals,
                            int imp_count, reference_resolution_stats_t *stats) {
    int resolved = 0;
    for (int r = 0; r < result->rw.count; r++) {
        CBMReadWrite *rw = &result->rw.items[r];
        if (!rw->var_name) {
            continue;
        }
        if (reference_requires_refusal(&rw->reference, stats)) {
            continue;
        }

        const cbm_gbuf_node_t *src =
            find_enclosing_node(ctx, rw->enclosing_func_qn, rel, module_qn, rw->start_line,
                                "read_write.reference_source");
        if (!src) {
            continue;
        }

        cbm_resolution_t res =
            rw->reference.resolved_target_qn
                ? (cbm_resolution_t){rw->reference.resolved_target_qn, "self_member", 1.0, 1}
                : cbm_registry_resolve_exact(ctx->registry, rw->var_name, module_qn, imp_keys,
                                             imp_vals, imp_count);
        if (!res.qualified_name || res.qualified_name[0] == '\0') {
            record_unresolved(&res, stats);
            continue;
        }

        const cbm_gbuf_node_t *tgt = cbm_gbuf_find_by_qn_domain(
            ctx->gbuf, res.qualified_name, CBM_REF_DOMAIN_VALUE, "usages.read_write_target");
        if (!tgt || src->id == tgt->id) {
            if (!tgt) {
                stats->incompatible++;
            }
            continue;
        }

        const char *edge_type = rw->is_write ? "WRITES" : "READS";
        cbm_gbuf_insert_edge(ctx->gbuf, src->id, tgt->id, edge_type, "{}");
        resolved++;
    }
    return resolved;
}

int cbm_pipeline_pass_usages(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                             int file_count) {
    cbm_log_info("pass.start", "pass", "usages", "files", itoa_log(file_count));

    int usage_resolved = 0;
    int throw_resolved = 0;
    int rw_resolved = 0;
    int errors = 0;
    reference_resolution_stats_t stats = {0};

    for (int i = 0; i < file_count; i++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            return CBM_NOT_FOUND;
        }

        const char *path = files[i].path;
        const char *rel = files[i].rel_path;

        CBMFileResult *result = NULL;
        bool result_owned = false;
        if (ctx->result_cache) {
            result = ctx->result_cache[i];
        }
        if (!result) {
            int source_len = 0;
            char *source = read_file(path, &source_len);
            if (!source) {
                errors++;
                continue;
            }
            result = cbm_extract_file_at_path_with_rust_edition(
                source, source_len, files[i].language, ctx->project_name, rel, files[i].path,
                cbm_pxc_rust_edition_for_file(ctx, rel),
                cbm_pxc_rust_is_crate_root(ctx, rel),
                cbm_parse_budget_micros((size_t)source_len), NULL, NULL);
            free(source);
            if (!result) {
                errors++;
                continue;
            }
            result_owned = true;
        }

        if (result->usages.count == 0 && result->throws.count == 0 && result->rw.count == 0) {
            if (result_owned) {
                cbm_free_result(result);
            }
            continue;
        }

        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        if (cbm_pipeline_import_map_build(ctx->pipeline, ctx->gbuf, ctx->project_name, rel, &imp_keys, &imp_vals,
                                          &imp_count) != 0) {
            if (result_owned) {
                cbm_free_result(result);
            }
            return CBM_NOT_FOUND;
        }

        char *module_qn = cbm_pipeline_fqn_module_dir(ctx->project_name, rel,
                                                      pu_module_is_dir(files[i].language));

        usage_resolved +=
            resolve_usage_edges(ctx, result, rel, module_qn, imp_keys, imp_vals, imp_count, &stats);
        throw_resolved +=
            resolve_throw_edges(ctx, result, rel, module_qn, imp_keys, imp_vals, imp_count, &stats);
        rw_resolved +=
            resolve_rw_edges(ctx, result, rel, module_qn, imp_keys, imp_vals, imp_count, &stats);

        free(module_qn);
        cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
        if (result_owned) {
            cbm_free_result(result);
        }
    }

    cbm_log_info("pass.done", "pass", "usages", "usage", itoa_log(usage_resolved), "throws",
                 itoa_log(throw_resolved), "rw", itoa_log(rw_resolved), "errors", itoa_log(errors));
    cbm_log_info("reference.resolution.refused", "code", "CBM_REFERENCE_TARGET_REFUSED", "pass",
                 "usages", "local_only", itoa_log(stats.local_only), "member_without_type",
                 itoa_log(stats.member_without_type), "message",
                 "references without persisted scope or receiver/type evidence were not emitted");
    cbm_log_info("reference.resolution.unresolved", "code", "CBM_REFERENCE_TARGET_UNRESOLVED",
                 "pass", "usages", "target_missing", itoa_log(stats.target_missing), "ambiguous",
                 itoa_log(stats.ambiguous), "incompatible", itoa_log(stats.incompatible),
                 "remediation", "add exact import, module, qualified-path, or type evidence");
    return 0;
}
