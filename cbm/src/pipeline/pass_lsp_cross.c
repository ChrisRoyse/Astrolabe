/*
 * pass_lsp_cross.c — Cross-file LSP type-aware call resolution pass.
 *
 * See pass_lsp_cross.h for the high-level contract. This file is the
 * pipeline glue that converts the existing per-file extraction state
 * (CBMDefinition / CBMImport / IMPORTS-edge gbuf state) into the input
 * shape each language LSP's cbm_run_X_lsp_cross expects, then merges
 * the resulting CBMResolvedCall entries back into per-file results.
 *
 * The pass is a no-op for any file whose CBMFileResult is missing or
 * whose language has no cross-file LSP entry registered (e.g. Rust /
 * Java today). Per-LSP emit functions dedup against entries already in
 * resolved_calls, so this pass is also idempotent — safe to invoke
 * multiple times if the pipeline gains a re-run path later.
 */
#include "pipeline/pass_lsp_cross.h"
#include "pipeline/pipeline_internal.h"
#include "lsp/go_lsp.h"
#include "lsp/c_lsp.h"
#include "lsp/py_lsp.h"
#include "lsp/ts_lsp.h"
#include "lsp/php_lsp.h"
#include "lsp/java_lsp.h"
#include "lsp/kotlin_lsp.h"
#include "lsp/rust_lsp.h"
#include "lsp/rust_cargo.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/constants.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/compat_fs.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Constants ─────────────────────────────────────────────────── */

enum {
    PXC_MAX_FILE_BYTES_FACTOR = 100, /* same cap pass_calls.c uses for source size */
    PXC_ITOA_BUF = 16,
};

/* Format an int into a thread-local rotating buffer for log key=value emission.
 * Mirrors the itoa_log helper in pass_calls.c — kept local so passes don't
 * grow a foundation-wide formatting API just for log output. */
static const char *itoa_buf(int val) {
    static _Thread_local char bufs[PXC_ITOA_BUF][PXC_ITOA_BUF];
    static _Thread_local int slot = 0;
    char *out = bufs[slot];
    slot = (slot + 1) & (PXC_ITOA_BUF - 1);
    snprintf(out, PXC_ITOA_BUF, "%d", val);
    return out;
}

/* ── Local helpers ─────────────────────────────────────────────── */

/* True for languages whose module QN is derived from the CONTAINING DIRECTORY
 * (Java package, Go package) rather than the filename stem. MUST match the
 * extraction-side cbm_lang_module_is_dir() in internal/cbm/helpers.c so the
 * cross-file LSP caller_qn agrees with the def-node QN (the lsp_resolve join
 * keys on exact equality). */
static bool pxc_module_is_dir(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_GO;
}

/* Slurp a file into a malloc'd, NUL-terminated buffer. Mirrors the
 * read_file helper in pass_calls.c / pass_parallel.c (kept local so the
 * pipeline doesn't grow a public read-file API just for this pass). */
static char *pxc_read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f)
        return NULL;
    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (long)PXC_MAX_FILE_BYTES_FACTOR * (long)CBM_SZ_1K * (long)CBM_SZ_1K) {
        (void)fclose(f);
        return NULL;
    }
    /* +pad: tree-sitter lexer lookahead reads past EOF; keep it in-bounds */
    enum { CBM_TS_LOOKAHEAD_PAD = 16 };
    char *buf = (char *)malloc((size_t)size + CBM_TS_LOOKAHEAD_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t nread = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    if (nread > (size_t)size)
        nread = (size_t)size;
    memset(buf + nread, 0, CBM_TS_LOOKAHEAD_PAD);
    *out_len = (int)nread;
    return buf;
}

/* Map a CBMDefinition.label to a CBMLSPDef.label. Per-language LSP registrars
 * only care about type-like containers (Class/Struct/Interface/Trait/Enum/Type)
 * plus Protocol/Function/Method — variables, modules, decorators, etc. are
 * skipped. Struct passes through so Rust/Go struct type-registration via the
 * cross-file LSP path is not dropped. */
static const char *pxc_map_label(const char *label) {
    if (!label)
        return NULL;
    if (cbm_label_is_type_like(label) || strcmp(label, "Protocol") == 0 ||
        strcmp(label, "Function") == 0 || strcmp(label, "Method") == 0) {
        return label;
    }
    return NULL;
}

/* Build the embedded_types "|"-separated string from base_classes[].
 * Returns NULL when there are no bases. Allocated in the supplied arena. */
static const char *pxc_join_pipe(CBMArena *arena, const char *const *items) {
    if (!items || !items[0])
        return NULL;
    int count = 0;
    size_t total = 0;
    for (int i = 0; items[i]; i++) {
        count++;
        total += strlen(items[i]);
    }
    if (count == 0)
        return NULL;
    /* count - 1 separators + NUL. */
    size_t bufsz = total + (size_t)(count - 1) + 1;
    char *buf = (char *)cbm_arena_alloc(arena, bufsz);
    if (!buf)
        return NULL;
    char *p = buf;
    for (int i = 0; i < count; i++) {
        size_t n = strlen(items[i]);
        memcpy(p, items[i], n);
        p += n;
        if (i + 1 < count)
            *p++ = '|';
    }
    *p = '\0';
    return buf;
}

static bool pxc_is_jvm_lang(CBMLanguage lang);

static const char *pxc_last_component(const char *qn) {
    if (!qn) {
        return NULL;
    }
    const char *dot = strrchr(qn, '.');
    return dot ? dot + 1 : qn;
}

static const char *pxc_jvm_type_qn(CBMArena *arena, const char *namespace_name,
                                   const char *type_qn_or_name) {
    if (!arena || !namespace_name || !namespace_name[0] || !type_qn_or_name) {
        return type_qn_or_name;
    }
    const char *short_name = pxc_last_component(type_qn_or_name);
    if (!short_name || !short_name[0]) {
        return type_qn_or_name;
    }
    return cbm_arena_sprintf(arena, "%s.%s", namespace_name, short_name);
}

static const char *pxc_jvm_def_qn(CBMArena *arena, const CBMDefinition *src,
                                  const char *namespace_name, const char *label) {
    if (!arena || !src || !namespace_name || !namespace_name[0]) {
        return src ? src->qualified_name : NULL;
    }
    if (strcmp(label, "Method") == 0 || strcmp(label, "Function") == 0 ||
        strcmp(label, "Constructor") == 0) {
        if (src->parent_class && src->parent_class[0]) {
            return cbm_arena_sprintf(arena, "%s.%s.%s", namespace_name,
                                     pxc_last_component(src->parent_class), src->name);
        }
        return cbm_arena_sprintf(arena, "%s.%s", namespace_name, src->name);
    }
    return cbm_arena_sprintf(arena, "%s.%s", namespace_name, src->name);
}

static const char *pxc_infer_jvm_namespace(CBMArena *arena, const char *rel_path,
                                           CBMLanguage lang) {
    if (!arena || !rel_path || !pxc_is_jvm_lang(lang)) {
        return NULL;
    }
    const char *root = NULL;
    const char *lang_root = lang == CBM_LANG_KOTLIN ? "kotlin/" : "java/";
    if (strncmp(rel_path, "src/main/", 9) == 0 &&
        strncmp(rel_path + 9, lang_root, strlen(lang_root)) == 0) {
        root = rel_path + 9 + strlen(lang_root);
    } else if (strncmp(rel_path, "src/test/", 9) == 0 &&
               strncmp(rel_path + 9, lang_root, strlen(lang_root)) == 0) {
        root = rel_path + 9 + strlen(lang_root);
    } else {
        const char *needle = lang == CBM_LANG_KOTLIN ? "/kotlin/" : "/java/";
        root = strstr(rel_path, needle);
        if (root) {
            root += strlen(needle);
        } else if (strncmp(rel_path, "src/", 4) == 0) {
            root = rel_path + 4;
        } else {
            root = strstr(rel_path, "/src/");
            if (root) {
                root += strlen("/src/");
            }
        }
    }
    if (!root || !root[0]) {
        return NULL;
    }
    if (strncmp(root, "main/", 5) == 0 || strncmp(root, "test/", 5) == 0) {
        root += 5;
    }
    if (strncmp(root, "java/", 5) == 0) {
        root += 5;
    } else if (strncmp(root, "kotlin/", 7) == 0) {
        root += 7;
    }
    const char *slash = strrchr(root, '/');
    if (!slash || slash <= root) {
        return NULL;
    }
    size_t len = (size_t)(slash - root);
    char *ns = (char *)cbm_arena_alloc(arena, len + 1);
    if (!ns) {
        return NULL;
    }
    memcpy(ns, root, len);
    ns[len] = '\0';
    for (size_t i = 0; i < len; i++) {
        if (ns[i] == '/') {
            ns[i] = '.';
        }
    }
    return ns;
}

/* Convert one CBMDefinition into a CBMLSPDef. Returns 0 on success, -1
 * to skip (unsupported label or missing required field). dst gets borrowed
 * pointers into src and into `arena` for synthesised composites. */
static int pxc_build_lsp_def(CBMArena *arena, const CBMDefinition *src, const char *module_qn,
                             const char *namespace_name, CBMLanguage lang, CBMLSPDef *dst) {
    const char *label = pxc_map_label(src->label);
    if (!label || !src->qualified_name || !src->name)
        return -1;
    memset(dst, 0, sizeof(*dst));
    if (pxc_is_jvm_lang(lang) && namespace_name && namespace_name[0]) {
        dst->qualified_name = pxc_jvm_def_qn(arena, src, namespace_name, label);
        dst->receiver_type = pxc_jvm_type_qn(arena, namespace_name, src->parent_class);
    } else {
        dst->qualified_name = src->qualified_name;
        dst->receiver_type = src->parent_class;
    }
    dst->short_name = src->name;
    dst->label = label;
    dst->def_module_qn = module_qn;
    dst->namespace_name = namespace_name;
    dst->is_interface = (strcmp(label, "Interface") == 0 || strcmp(label, "Protocol") == 0);
    /* Single return-type string. The per-language registrars split on '|'
     * for multi-return languages (Go); single-return languages just see one
     * piece, which is what's already stored. */
    dst->return_types = src->return_type;
    dst->embedded_types = pxc_join_pipe(arena, src->base_classes);
    dst->lang = lang;
    return 0;
}

/* Collect a project-wide CBMLSPDef[] from all cached results. Returns a
 * malloc'd array (caller frees) of length *out_count. String fields are
 * borrowed from cache[i]->arena and from def_modules[i] (also borrowed). */
CBMLSPDef *cbm_pxc_collect_all_defs(CBMFileResult **cache, const cbm_file_info_t *files,
                                    int file_count, const char *project_name, char **def_modules,
                                    int *out_count) {
    int total = 0;
    for (int i = 0; i < file_count; i++) {
        if (cache[i]) {
            if (cache[i]->defs.count < 0 || total > INT_MAX - cache[i]->defs.count) {
                cbm_log_error("lsp_cross.defs_failed", "code", "CBM_LSP_DEF_COUNT_OVERFLOW",
                              "component", "lsp_cross.definitions", "operation", "count", "message",
                              "definition count exceeds the supported integer range", "remediation",
                              "split the repository into smaller indexing scopes");
                *out_count = -1;
                return NULL;
            }
            total += cache[i]->defs.count;
        }
    }
    if (total == 0) {
        *out_count = 0;
        return NULL;
    }
    CBMLSPDef *defs = (CBMLSPDef *)calloc((size_t)total, sizeof(CBMLSPDef));
    if (!defs) {
        cbm_log_error("lsp_cross.defs_failed", "code", "CBM_LSP_DEFS_ALLOC_FAILED", "component",
                      "lsp_cross.definitions", "operation", "allocate_entries", "message",
                      "cross-LSP could not allocate every definition", "remediation",
                      "free memory or reduce repository size, then retry");
        *out_count = -1;
        return NULL;
    }
    int idx = 0;
    for (int fi = 0; fi < file_count; fi++) {
        if (!cache[fi])
            continue;
        if (!def_modules[fi]) {
            def_modules[fi] = cbm_pipeline_fqn_module_dir(project_name, files[fi].rel_path,
                                                          pxc_module_is_dir(files[fi].language));
            if (!def_modules[fi]) {
                cbm_log_error("lsp_cross.defs_failed", "code", "CBM_LSP_MODULE_FQN_ALLOC_FAILED",
                              "component", "lsp_cross.definitions", "operation", "module_fqn",
                              "file", files[fi].rel_path ? files[fi].rel_path : "<unknown>",
                              "message", "cross-LSP could not retain a module identity",
                              "remediation", "free memory or reduce repository size, then retry");
                free(defs);
                *out_count = -1;
                return NULL;
            }
        }
        const char *namespace_name = cache[fi]->namespace_name;
        if ((!namespace_name || !namespace_name[0]) && files[fi].rel_path) {
            namespace_name =
                pxc_infer_jvm_namespace(&cache[fi]->arena, files[fi].rel_path, files[fi].language);
            if (namespace_name && namespace_name[0]) {
                cache[fi]->namespace_name = namespace_name;
            }
        }
        for (int di = 0; di < cache[fi]->defs.count; di++) {
            if (pxc_build_lsp_def(&cache[fi]->arena, &cache[fi]->defs.items[di], def_modules[fi],
                                  namespace_name, files[fi].language, &defs[idx]) == 0) {
                idx++;
            }
            if (cbm_arena_failed(&cache[fi]->arena)) {
                char requested[32];
                snprintf(requested, sizeof(requested), "%zu",
                         cbm_arena_failure_bytes(&cache[fi]->arena));
                cbm_log_error(
                    "lsp_cross.defs_failed", "code", cbm_arena_failure_code(&cache[fi]->arena),
                    "component", "lsp_cross.definitions", "operation",
                    cbm_arena_failure_operation(&cache[fi]->arena), "file",
                    files[fi].rel_path ? files[fi].rel_path : "<unknown>", "requested_bytes",
                    requested, "message", "cross-LSP definition conversion allocation failed",
                    "remediation", "free memory or reduce repository size, then retry");
                free(defs);
                *out_count = -1;
                return NULL;
            }
        }
    }
    *out_count = idx;
    return defs;
}

/* Detect TS dialect flags from a relative path. */
void cbm_pxc_ts_modes(CBMLanguage lang, const char *rel_path, bool *out_js, bool *out_jsx,
                      bool *out_dts) {
    *out_js = (lang == CBM_LANG_JAVASCRIPT);
    *out_jsx = (lang == CBM_LANG_TSX);
    *out_dts = false;
    if (!rel_path)
        return;
    size_t rl = strlen(rel_path);
    if (lang == CBM_LANG_JAVASCRIPT && rl >= 4 && strcmp(rel_path + rl - 4, ".jsx") == 0) {
        *out_jsx = true;
    }
    if (lang == CBM_LANG_TYPESCRIPT && rl >= 5 && strcmp(rel_path + rl - 5, ".d.ts") == 0) {
        *out_dts = true;
    }
}

/* Returns true when this language has a cross-file LSP wired up. */
bool cbm_pxc_has_cross_lsp(CBMLanguage lang) {
    switch (lang) {
    case CBM_LANG_GO:
    case CBM_LANG_PYTHON:
    case CBM_LANG_JAVASCRIPT:
    case CBM_LANG_TYPESCRIPT:
    case CBM_LANG_TSX:
    case CBM_LANG_PHP:
    case CBM_LANG_CSHARP: /* tier-2 prebuilt registry path (pass_parallel.c) */
    case CBM_LANG_JAVA:   /* fallback cbm_pxc_run_one path */
    case CBM_LANG_KOTLIN: /* fallback cbm_pxc_run_one path */
    case CBM_LANG_RUST:   /* fallback cbm_pxc_run_one path (manifest-aware) */
        return true;
    default:
        return false;
    }
}

/* Append cross-file results from `src_out` (allocated in a scratch arena
 * about to be destroyed) into `dst_calls` (lives in cache_entry->arena),
 * copying every string field into dst_arena. Skips entries whose
 * (caller_qn, callee_qn) is already present — avoids inflating the array with
 * cross-file duplicates of per-file LSP output.
 *
 * Dedup uses a hash set keyed on "caller\x1fcallee", giving O(1) membership.
 * The previous linear strcmp scan made each append O(n), so a file that
 * resolved very many cross-calls turned the whole append into O(n^2) and could
 * peg a core for minutes (observed: an index hung in pxc_append_results/strcmp).
 * The key strings live in a scratch arena that is destroyed after the table. */
static bool pxc_append_results(CBMArena *dst_arena, CBMResolvedCallArray *dst_calls,
                               const CBMResolvedCallArray *src_out) {
    if (!dst_calls || !src_out)
        return false;

    CBMArena keys;
    cbm_arena_init(&keys);
    CBMHashTable *seen = cbm_ht_create((uint32_t)(dst_calls->count + src_out->count + 1));
    if (!seen) {
        cbm_log_error("lsp_cross.append_failed", "code", "CBM_LSP_DEDUP_ALLOC_FAILED", "component",
                      "lsp_cross.resolved_call_dedup", "operation", "create", "key", "", "message",
                      "resolved-call dedup index could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        cbm_arena_destroy(&keys);
        return false;
    }

    for (int i = 0; i < dst_calls->count; i++) {
        const CBMResolvedCall *rc = &dst_calls->items[i];
        if (rc->caller_qn && rc->callee_qn) {
            char *k = cbm_arena_sprintf(&keys, "%s\x1f%s", rc->caller_qn, rc->callee_qn);
            if (!k || !cbm_ht_set_checked(seen, k, (void *)1, NULL)) {
                cbm_log_error("lsp_cross.append_failed", "code", "CBM_LSP_DEDUP_INSERT_FAILED",
                              "component", "lsp_cross.resolved_call_dedup", "operation", "seed",
                              "key", k ? k : "", "message",
                              "resolved-call dedup index could not retain an entry", "remediation",
                              "free memory or reduce repository size, then retry");
                cbm_ht_free(seen);
                cbm_arena_destroy(&keys);
                return false;
            }
        }
    }

    for (int j = 0; j < src_out->count; j++) {
        const CBMResolvedCall *src = &src_out->items[j];
        if (!src->caller_qn || !src->callee_qn)
            continue;
        char *k = cbm_arena_sprintf(&keys, "%s\x1f%s\x1f%s",
                                    src->preprocess_context_id ? src->preprocess_context_id : "",
                                    src->caller_qn, src->callee_qn);
        if (!k) {
            cbm_log_error("lsp_cross.append_failed", "code", "CBM_LSP_DEDUP_KEY_ALLOC_FAILED",
                          "component", "lsp_cross.resolved_call_dedup", "operation", "key", "key",
                          src->caller_qn, "message", "resolved-call key could not be allocated",
                          "remediation", "free memory or reduce repository size, then retry");
            cbm_ht_free(seen);
            cbm_arena_destroy(&keys);
            return false;
        }
        if (cbm_ht_has(seen, k))
            continue;
        if (!cbm_ht_set_checked(seen, k, (void *)1, NULL)) {
            cbm_log_error("lsp_cross.append_failed", "code", "CBM_LSP_DEDUP_INSERT_FAILED",
                          "component", "lsp_cross.resolved_call_dedup", "operation", "insert",
                          "key", k, "message",
                          "resolved-call dedup index could not retain an entry", "remediation",
                          "free memory or reduce repository size, then retry");
            cbm_ht_free(seen);
            cbm_arena_destroy(&keys);
            return false;
        }
        CBMResolvedCall dst = {0};
        dst.caller_qn = cbm_arena_strdup(dst_arena, src->caller_qn);
        dst.callee_qn = cbm_arena_strdup(dst_arena, src->callee_qn);
        dst.strategy = src->strategy ? cbm_arena_strdup(dst_arena, src->strategy) : NULL;
        dst.confidence = src->confidence;
        dst.reason = src->reason ? cbm_arena_strdup(dst_arena, src->reason) : NULL;
        dst.preprocess_context_id =
            src->preprocess_context_id
                ? cbm_arena_strdup(dst_arena, src->preprocess_context_id)
                : NULL;
        if (!dst.caller_qn || !dst.callee_qn || (src->strategy && !dst.strategy) ||
            (src->reason && !dst.reason) ||
            (src->preprocess_context_id && !dst.preprocess_context_id) ||
            !cbm_resolvedcall_push(dst_calls, dst_arena, dst)) {
            cbm_log_error("lsp_cross.append_failed", "code", cbm_arena_failure_code(dst_arena),
                          "component", "lsp_cross.resolved_calls", "operation",
                          cbm_arena_failure_operation(dst_arena), "key", src->caller_qn, "message",
                          "resolved-call clone allocation failed", "remediation",
                          "free memory or reduce repository size, then retry");
            cbm_ht_free(seen);
            cbm_arena_destroy(&keys);
            return false;
        }
    }

    cbm_ht_free(seen);
    cbm_arena_destroy(&keys);
    return true;
}

/* Convert a CBMLSPDef array (the pipeline's lingua franca, go_lsp.h:73)
 * into a CBMRustLSPDef array (rust_lsp.h) inside `arena`. The two structs
 * share their first 9 string fields; CBMRustLSPDef adds `trait_qn` before
 * `is_interface` whereas CBMLSPDef has `is_interface` followed by `lang`,
 * so a memcpy is unsafe — copy field-by-field. trait_qn is left NULL
 * because the pipeline's collect-all-defs step does not carry the
 * impl-Trait-for-Type linkage; the resolver still recovers trait dispatch
 * from the in-file walk (the cross-file path only needs receiver_type). */
static CBMRustLSPDef *pxc_lspdefs_to_rust(CBMArena *arena, const CBMLSPDef *defs, int def_count) {
    if (!defs || def_count <= 0)
        return NULL;
    CBMRustLSPDef *out =
        (CBMRustLSPDef *)cbm_arena_alloc(arena, (size_t)def_count * sizeof(CBMRustLSPDef));
    if (!out)
        return NULL;
    for (int i = 0; i < def_count; i++) {
        out[i].qualified_name = defs[i].qualified_name;
        out[i].short_name = defs[i].short_name;
        out[i].label = defs[i].label;
        out[i].receiver_type = defs[i].receiver_type;
        out[i].def_module_qn = defs[i].def_module_qn;
        out[i].return_types = defs[i].return_types;
        out[i].embedded_types = defs[i].embedded_types;
        out[i].field_defs = defs[i].field_defs;
        out[i].method_names_str = defs[i].method_names_str;
        out[i].trait_qn = NULL;
        out[i].is_interface = defs[i].is_interface;
    }
    return out;
}

/* Run cross-file LSP for a single file inside a scratch arena that gets
 * freed when the call returns. The LSP would otherwise allocate a fresh
 * type registry + stdlib + all project defs into the supplied arena, and
 * that adds up to O(N×project_size) memory if we used cache[i]->arena
 * directly across N files (test_incremental.c saw 3.5 GB peak on a
 * 1100-file repo before this fix). Output gets copied into the file's own
 * arena and merged into result->resolved_calls. */
void cbm_pxc_run_one(CBMLanguage lang, CBMFileResult *r, const char *source, int source_len,
                     const char *module_qn, CBMLSPDef *defs, int def_count, const char **imp_names,
                     const char **imp_qns, int imp_count, const CBMCargoManifest *rust_manifest) {
    TSTree *tree = r->cached_tree; /* may be NULL — LSP re-parses then */

    CBMArena scratch;
    cbm_arena_init(&scratch);
    CBMResolvedCallArray out;
    memset(&out, 0, sizeof(out));

    switch (lang) {
    case CBM_LANG_GO:
        cbm_run_go_lsp_cross(&scratch, source, source_len, module_qn, defs, def_count, imp_names,
                             imp_qns, imp_count, tree, &out);
        break;
    case CBM_LANG_C:
    case CBM_LANG_CPP:
    case CBM_LANG_CUDA: {
        bool cpp_mode = (lang != CBM_LANG_C);
        /* C/C++ cross LSP takes include_paths/include_ns_qns instead of
         * imports — the existing pipeline doesn't carry C-style include
         * resolution as a separate map, so pass NULL/0 and let the LSP
         * fall back to its own #include scan. */
        cbm_run_c_lsp_cross(&scratch, source, source_len, module_qn, cpp_mode, defs, def_count,
                            NULL, NULL, 0, tree, &out);
        break;
    }
    case CBM_LANG_PYTHON:
        cbm_run_py_lsp_cross(&scratch, source, source_len, module_qn, defs, def_count, imp_names,
                             imp_qns, imp_count, tree, &out);
        break;
    case CBM_LANG_PHP:
        cbm_run_php_lsp_cross(&scratch, source, source_len, module_qn, defs, def_count, imp_names,
                              imp_qns, imp_count, tree, &out);
        break;
    case CBM_LANG_JAVA:
        cbm_run_java_lsp_cross(&scratch, source, source_len, module_qn, defs, def_count, imp_names,
                               imp_qns, imp_count, tree, &out);
        break;
    case CBM_LANG_KOTLIN:
        cbm_run_kotlin_lsp_cross(&scratch, source, source_len, module_qn, defs, def_count,
                                 imp_names, imp_qns, imp_count, tree, &out);
        break;
    case CBM_LANG_RUST: {
        /* The Rust resolver wants CBMRustLSPDef (rust_lsp.h), not the
         * pipeline's CBMLSPDef — the structs share their first 9 fields
         * but diverge after, so convert into the scratch arena. The
         * workspace manifest (set once by the sequential driver) lets
         * `crate_a::foo` route across the crate boundary (#56). */
        CBMRustLSPDef *rdefs = pxc_lspdefs_to_rust(&scratch, defs, def_count);
        cbm_run_rust_lsp_cross_with_manifest(&scratch, source, source_len, module_qn, rdefs,
                                             def_count, imp_names, imp_qns, imp_count, tree,
                                             rust_manifest, &out);
        break;
    }
    default:
        break;
    }

    if (!pxc_append_results(&r->arena, &r->resolved_calls, &out)) {
        cbm_file_result_set_error(
            r, "CBM_LSP_RESULT_APPEND_FAILED", "pxc_append_results", "cross_file_lsp",
            (size_t)out.count, "resolved-call results could not be retained",
            "free memory or reduce repository size, then retry the complete corpus");
    }
    cbm_arena_destroy(&scratch);
}

/* Variant of cbm_pxc_run_one for TS/JS/JSX/TSX with explicit dialect
 * flags. Same scratch-arena lifecycle as cbm_pxc_run_one. */
void cbm_pxc_run_one_ts(CBMFileResult *r, const char *source, int source_len, const char *module_qn,
                        CBMLSPDef *defs, int def_count, const char **imp_names,
                        const char **imp_qns, int imp_count, bool js_mode, bool jsx_mode,
                        bool dts_mode) {
    CBMArena scratch;
    cbm_arena_init(&scratch);
    CBMResolvedCallArray out;
    memset(&out, 0, sizeof(out));

    cbm_run_ts_lsp_cross(&scratch, source, source_len, module_qn, js_mode, jsx_mode, dts_mode, defs,
                         def_count, imp_names, imp_qns, imp_count, r->cached_tree, &out);

    if (!pxc_append_results(&r->arena, &r->resolved_calls, &out)) {
        cbm_file_result_set_error(
            r, "CBM_LSP_RESULT_APPEND_FAILED", "pxc_append_results", "cross_file_lsp",
            (size_t)out.count, "resolved-call results could not be retained",
            "free memory or reduce repository size, then retry the complete corpus");
    }
    cbm_arena_destroy(&scratch);
}

/* Parse the project's root Cargo.toml (if present) into `out_m`, using
 * `marena` for the manifest's owned strings. Returns true when a manifest
 * was parsed (a workspace root or any [package]/[dependencies]); false when
 * there is no readable Cargo.toml, leaving *out_m untouched. The resulting
 * manifest feeds cross-CRATE Rust resolution (#56): its [workspace].members
 * map lets `crate_a::foo` route to the member crate's def. */
/* Per-file cross-LSP dispatch, shared by the PARALLEL resolve worker and the
 * SEQUENTIAL driver. One code path = one semantics: filter the global defs
 * down to the file's own+imported modules via the module-def index, resolve
 * through the shared prebuilt registry when the language has one (per-file
 * OVERLAY pattern — no registry build, no finalize), and only fall back to
 * the per-file registry build (with the FILTERED defs) for languages without
 * a shared-registry variant. Before this helper existed the sequential
 * driver fed the FULL def list into full per-file registry builds —
 * O(files x defs), which ground an 81k-file TS corpus for hours.
 *
 * Every allocation failure is terminal. An optimization may not silently
 * widen to a more expensive execution path under memory pressure. */
int cbm_pxc_dispatch_file(CBMLanguage lang, CBMFileResult *result, const char *source,
                          int source_len, const char *rel, const char *def_module,
                          const CBMCrossLspRegistries *cross_registries,
                          const CBMModuleDefIndex *module_def_index, CBMLSPDef *all_defs,
                          int all_def_count, const char **imp_keys, const char **imp_vals,
                          int imp_count, const CBMCargoManifest *rust_manifest) {
    if (!result) {
        cbm_log_error("lsp_cross.dispatch_failed", "code", "CBM_LSP_RESULT_REQUIRED", "path",
                      rel ? rel : "", "message", "cross-LSP dispatch requires an extracted result",
                      "remediation", "preserve the complete extraction result through resolution");
        return -1;
    }
    CBMCargoManifest rust_manifest_view;
    if (lang == CBM_LANG_RUST && rust_manifest) {
        rust_manifest_view = *rust_manifest;
        rust_manifest_view.active_edition = cbm_cargo_edition_for_path(rust_manifest, rel);
        rust_manifest = &rust_manifest_view;
    }
    bool used_prebuilt = false;
    CBMTypeRegistry *prebuilt =
        cross_registries ? cbm_pxc_registry_for_lang(cross_registries, lang) : NULL;
    if (prebuilt) {
        switch (lang) {
        case CBM_LANG_GO:
            /* Tier 3 (metadata-driven): pure lookup over the Tier-1
             * lsp_unresolved entries — no parse, no AST walk. */
            cbm_go_fast_resolve_qualified_calls(result, prebuilt, imp_keys, imp_vals, imp_count);
            used_prebuilt = true;
            break;
        case CBM_LANG_PYTHON:
            cbm_run_py_lsp_cross_with_registry(&result->arena, source, source_len, def_module,
                                               prebuilt, imp_keys, imp_vals, imp_count,
                                               result->cached_tree, &result->resolved_calls);
            used_prebuilt = true;
            break;
        case CBM_LANG_C:
        case CBM_LANG_CPP:
        case CBM_LANG_CUDA:
            cbm_run_c_lsp_cross_with_registry(
                &result->arena, source, source_len, def_module, (lang != CBM_LANG_C), prebuilt,
                imp_keys, imp_vals, imp_count, result->cached_tree, &result->resolved_calls);
            used_prebuilt = true;
            break;
        case CBM_LANG_CSHARP:
            cbm_run_cs_lsp_cross_with_registry(&result->arena, source, source_len, def_module,
                                               prebuilt, imp_vals, imp_count, result->cached_tree,
                                               &result->resolved_calls);
            used_prebuilt = true;
            break;
        case CBM_LANG_JAVASCRIPT:
        case CBM_LANG_TYPESCRIPT:
        case CBM_LANG_TSX: {
            /* TS: per-file OVERLAY chained to the shared base. Filter to
             * own+imports so the overlay builder can pick out own-module
             * defs without scanning the whole project. */
            bool js;
            bool jsx;
            bool dts;
            cbm_pxc_ts_modes(lang, rel, &js, &jsx, &dts);
            CBMLSPDef *ts_defs = all_defs;
            int ts_def_count = all_def_count;
            CBMLSPDef *ts_filtered = NULL;
            if (module_def_index) {
                int fc = 0;
                ts_filtered = cbm_pxc_filter_defs_for_file(module_def_index, all_defs, lang,
                                                           result->namespace_name, def_module,
                                                           imp_vals, imp_count, &fc);
                if (!ts_filtered && fc < 0) {
                    return -1;
                }
                if (ts_filtered) {
                    ts_defs = ts_filtered;
                    ts_def_count = fc;
                }
            }
            cbm_run_ts_lsp_cross_with_registry(&result->arena, source, source_len, def_module, js,
                                               jsx, dts, prebuilt, ts_defs, ts_def_count, imp_keys,
                                               imp_vals, imp_count, result->cached_tree,
                                               &result->resolved_calls);
            free(ts_filtered);
            used_prebuilt = true;
            break;
        }
        case CBM_LANG_RUST:
            cbm_run_rust_lsp_cross_with_registry(
                &result->arena, source, source_len, def_module, prebuilt, imp_keys, imp_vals,
                imp_count, result->cached_tree, rust_manifest, &result->resolved_calls,
                /*result=*/NULL);
            used_prebuilt = true;
            break;
        /* PHP falls through to the per-file build path below until its
         * overlay variant lands. */
        default:
            break;
        }
    }

    if (used_prebuilt) {
        return cbm_arena_failed(&result->arena) ? -1 : 0;
    }
    /* Fallback: gopls per-file filter + per-file registry build. RUST is
     * exempt from the module filter: its resolution is Cargo-manifest-aware
     * and a `crate_a::foo` reference routes to defs in ANOTHER workspace
     * crate — a module that is in neither own_module nor the import map, so
     * the filter starves cross-crate resolution (#56 repro red). Rust
     * therefore always resolves against the FULL def universe: the lazily
     * built shared registry when available, else a full per-file build. */
    CBMLSPDef *filtered = NULL;
    CBMLSPDef *file_defs = all_defs;
    int file_def_count = all_def_count;
    if (module_def_index && lang != CBM_LANG_RUST) {
        int filtered_count = 0;
        filtered =
            cbm_pxc_filter_defs_for_file(module_def_index, all_defs, lang, result->namespace_name,
                                         def_module, imp_vals, imp_count, &filtered_count);
        if (!filtered && filtered_count < 0) {
            return -1;
        }
        if (filtered) {
            file_defs = filtered;
            file_def_count = filtered_count;
        }
    }
    if (lang == CBM_LANG_RUST) {
        cbm_log_error("lsp_cross.dispatch_failed", "code", "CBM_RUST_SHARED_REGISTRY_REQUIRED",
                      "path", rel ? rel : "", "message",
                      "Rust cross-file resolution has no immutable project registry", "remediation",
                      "rebuild the project-wide Rust registry and retry the complete corpus");
        free(filtered);
        return -1;
    } else if (lang == CBM_LANG_JAVASCRIPT || lang == CBM_LANG_TYPESCRIPT || lang == CBM_LANG_TSX) {
        bool js;
        bool jsx;
        bool dts;
        cbm_pxc_ts_modes(lang, rel, &js, &jsx, &dts);
        cbm_pxc_run_one_ts(result, source, source_len, def_module, file_defs, file_def_count,
                           imp_keys, imp_vals, imp_count, js, jsx, dts);
    } else {
        cbm_pxc_run_one(lang, result, source, source_len, def_module, file_defs, file_def_count,
                        imp_keys, imp_vals, imp_count, rust_manifest);
    }
    free(filtered);
    return cbm_arena_failed(&result->arena) ? -1 : 0;
}

typedef struct {
    const char *package_dir;
    const char *package_name;
    const char *edition;
    bool edition_inherits_workspace;
    const char *workspace_path;
    const char *build_path;
    bool build_declared;
    bool build_enabled;
    bool autolib;
    bool autobins;
    bool autoexamples;
    bool autotests;
    bool autobenches;
    bool autolib_declared;
    bool autobins_declared;
    bool autoexamples_declared;
    bool autotests_declared;
    bool autobenches_declared;
    CBMCargoTarget *targets;
    int target_count;
} PXCCargoPackage;

typedef struct {
    const char *dir;
    const char *edition;
} PXCCargoWorkspace;

static const char *pxc_manifest_dir(CBMArena *arena, const char *rel_path) {
    const char *slash = rel_path ? strrchr(rel_path, '/') : NULL;
    if (!slash)
        return cbm_arena_strdup(arena, "");
    return cbm_arena_strndup(arena, rel_path, (size_t)(slash - rel_path));
}

static bool pxc_path_prefix(const char *path, const char *prefix) {
    if (!path || !prefix)
        return false;
    size_t len = strlen(prefix);
    return (len == 0 || strncmp(path, prefix, len) == 0) &&
           (len == 0 || path[len] == '\0' || path[len] == '/');
}

static const PXCCargoPackage *pxc_owning_package(const PXCCargoPackage *packages, int count,
                                                  const char *rel_path) {
    const PXCCargoPackage *selected = NULL;
    size_t selected_len = 0;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(packages[i].package_dir);
        if ((len > selected_len || (!selected && len == 0)) &&
            pxc_path_prefix(rel_path, packages[i].package_dir)) {
            selected = &packages[i];
            selected_len = len;
        }
    }
    return selected;
}

static const char *pxc_nearest_workspace_edition(const PXCCargoWorkspace *workspaces, int count,
                                                  const char *package_dir,
                                                  const char *explicit_workspace) {
    const PXCCargoWorkspace *selected = NULL;
    size_t selected_len = 0;
    for (int i = 0; i < count; i++) {
        const char *dir = workspaces[i].dir;
        size_t len = strlen(dir);
        if (explicit_workspace) {
            if (strcmp(dir, explicit_workspace) == 0)
                return workspaces[i].edition;
            continue;
        }
        if ((len > selected_len || (!selected && len == 0)) &&
            pxc_path_prefix(package_dir, dir)) {
            selected = &workspaces[i];
            selected_len = len;
        }
    }
    return selected ? selected->edition : NULL;
}

static char *pxc_normalize_repo_path(CBMArena *arena, const char *base, const char *relative,
                                     const char *operation, bool allow_empty) {
    if (!relative || !relative[0] || relative[0] == '/' || relative[0] == '\\' ||
        (relative[0] && relative[1] == ':')) {
        cbm_arena_mark_failed(arena, "CBM_CARGO_TARGET_PATH_INVALID", operation, 0);
        return NULL;
    }
    size_t base_len = base ? strlen(base) : 0;
    size_t relative_len = strlen(relative);
    if (base_len > SIZE_MAX - relative_len - 2) {
        cbm_arena_mark_failed(arena, "CBM_CARGO_TARGET_PATH_OVERFLOW", operation,
                              relative_len);
        return NULL;
    }
    char *joined = cbm_arena_alloc(arena, base_len + relative_len + 2);
    if (!joined)
        return NULL;
    size_t joined_len = 0;
    if (base_len) {
        memcpy(joined, base, base_len);
        joined_len = base_len;
        joined[joined_len++] = '/';
    }
    memcpy(joined + joined_len, relative, relative_len + 1);

    size_t read = 0;
    size_t write = 0;
    while (joined[read]) {
        while (joined[read] == '/' || joined[read] == '\\')
            read++;
        size_t start = read;
        while (joined[read] && joined[read] != '/' && joined[read] != '\\')
            read++;
        size_t len = read - start;
        if (len == 0 || (len == 1 && joined[start] == '.'))
            continue;
        if (len == 2 && joined[start] == '.' && joined[start + 1] == '.') {
            if (write == 0) {
                cbm_arena_mark_failed(arena, "CBM_CARGO_TARGET_PATH_ESCAPE", operation, 0);
                return NULL;
            }
            while (write > 0 && joined[write - 1] != '/')
                write--;
            if (write > 0)
                write--;
            continue;
        }
        if (write > 0)
            joined[write++] = '/';
        memmove(joined + write, joined + start, len);
        write += len;
    }
    joined[write] = '\0';
    if (write == 0) {
        if (allow_empty)
            return joined;
        cbm_arena_mark_failed(arena, "CBM_CARGO_TARGET_PATH_INVALID", operation, 0);
        return NULL;
    }
    return joined;
}

static bool pxc_single_or_multifile_root(const char *path, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0)
        return false;
    const char *rest = path + prefix_len;
    const char *slash = strchr(rest, '/');
    if (!slash) {
        size_t len = strlen(rest);
        return len > 3 && strcmp(rest + len - 3, ".rs") == 0;
    }
    return strchr(slash + 1, '/') == NULL && strcmp(slash + 1, "main.rs") == 0;
}

static bool pxc_named_target_root(const PXCCargoPackage *package, const CBMCargoTarget *target,
                                  const char *source_rel) {
    if (target->path)
        return strcmp(source_rel, target->path) == 0;
    if (target->kind == CBM_CARGO_TARGET_LIB) {
        size_t dir_len = strlen(package->package_dir);
        const char *package_rel = source_rel + (dir_len ? dir_len + 1 : 0);
        return strcmp(package_rel, "src/lib.rs") == 0;
    }
    if (!target->name || !target->name[0])
        return false;
    const char *family = target->kind == CBM_CARGO_TARGET_BIN       ? "src/bin"
                         : target->kind == CBM_CARGO_TARGET_EXAMPLE ? "examples"
                         : target->kind == CBM_CARGO_TARGET_TEST    ? "tests"
                                                                    : "benches";
    char first[1024];
    char second[1024];
    int first_n = snprintf(first, sizeof(first), "%s%s%s/%s.rs", package->package_dir,
                           package->package_dir[0] ? "/" : "", family, target->name);
    int second_n = snprintf(second, sizeof(second), "%s%s%s/%s/main.rs", package->package_dir,
                            package->package_dir[0] ? "/" : "", family, target->name);
    if (first_n > 0 && (size_t)first_n < sizeof(first) && strcmp(source_rel, first) == 0)
        return true;
    if (second_n > 0 && (size_t)second_n < sizeof(second) && strcmp(source_rel, second) == 0)
        return true;
    if (target->kind == CBM_CARGO_TARGET_BIN && package->package_name &&
        strcmp(target->name, package->package_name) == 0) {
        char main_path[1024];
        int main_n = snprintf(main_path, sizeof(main_path), "%s%ssrc/main.rs",
                              package->package_dir, package->package_dir[0] ? "/" : "");
        return main_n > 0 && (size_t)main_n < sizeof(main_path) &&
               strcmp(source_rel, main_path) == 0;
    }
    return false;
}

static bool pxc_package_source_is_crate_root(const PXCCargoPackage *package,
                                              const char *source_rel) {
    size_t dir_len = strlen(package->package_dir);
    const char *package_rel = source_rel + (dir_len ? dir_len + 1 : 0);
    if (package->build_enabled) {
        const char *build = package->build_declared ? package->build_path : NULL;
        if ((!build && strcmp(package_rel, "build.rs") == 0) ||
            (build && strcmp(source_rel, build) == 0))
            return true;
    }
    for (int i = 0; i < package->target_count; i++) {
        if (pxc_named_target_root(package, &package->targets[i], source_rel))
            return true;
    }

    bool manual = package->target_count > 0;
    bool edition_2015 = !package->edition || strcmp(package->edition, "2015") == 0;
    bool autolib = package->autolib_declared ? package->autolib
                                             : package->autolib && !(edition_2015 && manual);
    bool autobins = package->autobins_declared ? package->autobins
                                               : package->autobins && !(edition_2015 && manual);
    bool autoexamples = package->autoexamples_declared
                            ? package->autoexamples
                            : package->autoexamples && !(edition_2015 && manual);
    bool autotests = package->autotests_declared ? package->autotests
                                                 : package->autotests && !(edition_2015 && manual);
    bool autobenches = package->autobenches_declared
                           ? package->autobenches
                           : package->autobenches && !(edition_2015 && manual);
    return (autolib && strcmp(package_rel, "src/lib.rs") == 0) ||
           (autobins && (strcmp(package_rel, "src/main.rs") == 0 ||
                         pxc_single_or_multifile_root(package_rel, "src/bin/"))) ||
           (autoexamples && pxc_single_or_multifile_root(package_rel, "examples/")) ||
           (autotests && pxc_single_or_multifile_root(package_rel, "tests/")) ||
           (autobenches && pxc_single_or_multifile_root(package_rel, "benches/"));
}

static int pxc_string_ptr_compare(const void *left, const void *right) {
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;
    return strcmp(*a, *b);
}

static bool pxc_build_rust_manifest(const cbm_pipeline_ctx_t *ctx, CBMArena *marena,
                                    CBMCargoManifest *out_m) {
    if (!ctx || !ctx->source_root || !marena || !out_m)
        return false;
    int manifest_count = 0;
    int rust_count = 0;
    for (int i = 0; i < ctx->all_file_count; i++) {
        const char *rel = ctx->all_files[i].rel_path;
        const char *base = rel ? strrchr(rel, '/') : NULL;
        base = base ? base + 1 : rel;
        if (base && strcmp(base, "Cargo.toml") == 0)
            manifest_count++;
        if (ctx->all_files[i].language == CBM_LANG_RUST)
            rust_count++;
    }
    if (manifest_count == 0)
        return false;

    PXCCargoPackage *packages = cbm_arena_alloc(marena, (size_t)manifest_count * sizeof(*packages));
    PXCCargoWorkspace *workspaces =
        cbm_arena_alloc(marena, (size_t)manifest_count * sizeof(*workspaces));
    const char **crate_roots =
        rust_count > 0 ? cbm_arena_alloc(marena, (size_t)rust_count * sizeof(*crate_roots)) : NULL;
    CBMCargoPackage *public_packages =
        cbm_arena_alloc(marena, (size_t)manifest_count * sizeof(*public_packages));
    if (!packages || !workspaces || (rust_count > 0 && !crate_roots) || !public_packages)
        return false;
    memset(out_m, 0, sizeof(*out_m));
    int package_count = 0;
    int workspace_count = 0;

    for (int i = 0; i < ctx->all_file_count; i++) {
        const cbm_file_info_t *file = &ctx->all_files[i];
        const char *base = file->rel_path ? strrchr(file->rel_path, '/') : NULL;
        base = base ? base + 1 : file->rel_path;
        if (!base || strcmp(base, "Cargo.toml") != 0)
            continue;
        int toml_len = 0;
        char *toml = pxc_read_file(file->path, &toml_len);
        if (!toml || toml_len <= 0) {
            free(toml);
            cbm_arena_mark_failed(marena, "CBM_CARGO_MANIFEST_READ_FAILED",
                                  "read_discovered_manifest", (size_t)(toml_len > 0 ? toml_len : 0));
            return false;
        }
        CBMCargoManifest parsed;
        cbm_cargo_parse(marena, toml, toml_len, &parsed);
        free(toml);
        if (cbm_arena_failed(marena))
            return false;
        const char *dir = pxc_manifest_dir(marena, file->rel_path);
        if (!dir)
            return false;
        if (strcmp(file->rel_path, "Cargo.toml") == 0) {
            *out_m = parsed;
        }
        if (parsed.is_workspace_root) {
            workspaces[workspace_count++] = (PXCCargoWorkspace){
                .dir = dir,
                .edition = parsed.workspace_package_edition,
            };
        }
        if (!parsed.package_name)
            continue;
        PXCCargoPackage *package = &packages[package_count++];
        *package = (PXCCargoPackage){
            .package_dir = dir,
            .package_name = parsed.package_name,
            .edition = parsed.package_edition,
            .edition_inherits_workspace = parsed.package_edition_inherits_workspace,
            .workspace_path = parsed.package_workspace,
            .build_path = parsed.package_build_path,
            .build_declared = parsed.package_build_declared,
            .build_enabled = parsed.package_build_enabled,
            .autolib = parsed.autolib,
            .autobins = parsed.autobins,
            .autoexamples = parsed.autoexamples,
            .autotests = parsed.autotests,
            .autobenches = parsed.autobenches,
            .autolib_declared = parsed.autolib_declared,
            .autobins_declared = parsed.autobins_declared,
            .autoexamples_declared = parsed.autoexamples_declared,
            .autotests_declared = parsed.autotests_declared,
            .autobenches_declared = parsed.autobenches_declared,
            .target_count = parsed.target_count,
        };
        if (parsed.target_count > 0) {
            package->targets = cbm_arena_alloc(
                marena, (size_t)parsed.target_count * sizeof(package->targets[0]));
            if (!package->targets)
                return false;
            memcpy(package->targets, parsed.targets,
                   (size_t)parsed.target_count * sizeof(package->targets[0]));
        }
        if (package->build_declared && package->build_enabled && package->build_path) {
            package->build_path = pxc_normalize_repo_path(
                marena, package->package_dir, package->build_path, "normalize_cargo_build_path",
                false);
            if (!package->build_path)
                return false;
        }
        for (int target = 0; target < package->target_count; target++) {
            if (package->targets[target].path) {
                package->targets[target].path = pxc_normalize_repo_path(
                    marena, package->package_dir, package->targets[target].path,
                    "normalize_cargo_target_path", false);
                if (!package->targets[target].path)
                    return false;
            }
        }
    }

    for (int i = 0; i < package_count; i++) {
        PXCCargoPackage *package = &packages[i];
        if (package->edition_inherits_workspace) {
            const char *workspace_dir = NULL;
            if (package->workspace_path) {
                workspace_dir = pxc_normalize_repo_path(
                    marena, package->package_dir, package->workspace_path,
                    "normalize_cargo_workspace_path", true);
                if (!workspace_dir)
                    return false;
            }
            package->edition = pxc_nearest_workspace_edition(
                workspaces, workspace_count, package->package_dir, workspace_dir);
            if (!package->edition) {
                cbm_arena_mark_failed(marena, "CBM_CARGO_WORKSPACE_EDITION_MISSING",
                                      "resolve_package_edition", 0);
                return false;
            }
        } else if (!package->edition) {
            package->edition = "2015";
        }
        public_packages[i] = (CBMCargoPackage){
            .package_dir = package->package_dir,
            .edition = package->edition,
        };
    }

    int crate_root_count = 0;
    for (int i = 0; i < ctx->all_file_count; i++) {
        const cbm_file_info_t *file = &ctx->all_files[i];
        if (file->language != CBM_LANG_RUST)
            continue;
        const PXCCargoPackage *package =
            pxc_owning_package(packages, package_count, file->rel_path);
        if (package && pxc_package_source_is_crate_root(package, file->rel_path))
            crate_roots[crate_root_count++] = file->rel_path;
    }
    qsort(crate_roots, (size_t)crate_root_count, sizeof(crate_roots[0]), pxc_string_ptr_compare);
    out_m->packages = public_packages;
    out_m->package_count = package_count;
    out_m->crate_roots = crate_roots;
    out_m->crate_root_count = crate_root_count;
    return true;
}

int cbm_pxc_prepare_rust_manifest(cbm_pipeline_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    if (ctx->rust_manifest_prepared) {
        return 0;
    }
    ctx->rust_manifest_prepared = true;

    bool have_rust = false;
    for (int i = 0; i < ctx->all_file_count; i++) {
        if (ctx->all_files[i].language == CBM_LANG_RUST) {
            have_rust = true;
            break;
        }
    }
    if (!have_rust) {
        return 0;
    }

    int cargo_manifest_count = 0;
    for (int i = 0; i < ctx->all_file_count; i++) {
        const char *rel = ctx->all_files[i].rel_path;
        const char *base = rel ? strrchr(rel, '/') : NULL;
        base = base ? base + 1 : rel;
        if (base && strcmp(base, "Cargo.toml") == 0)
            cargo_manifest_count++;
    }
    if (cargo_manifest_count == 0) {
        cbm_log_info("rust_manifest.absent", "path", ctx->source_root, "rust_files",
                     itoa_buf(ctx->all_file_count));
        return 0;
    }

    cbm_arena_init(&ctx->rust_manifest_arena);
    ctx->rust_manifest_arena_live = true;
    ctx->rust_manifest =
        (CBMCargoManifest *)cbm_arena_alloc(&ctx->rust_manifest_arena, sizeof(CBMCargoManifest));
    if (!ctx->rust_manifest ||
        !pxc_build_rust_manifest(ctx, &ctx->rust_manifest_arena, ctx->rust_manifest) ||
        cbm_arena_failed(&ctx->rust_manifest_arena)) {
        const char *failure_code = cbm_arena_failed(&ctx->rust_manifest_arena)
                                       ? cbm_arena_failure_code(&ctx->rust_manifest_arena)
                                       : "CBM_CARGO_MANIFEST_READ_FAILED";
        const char *failure_operation = cbm_arena_failed(&ctx->rust_manifest_arena)
                                            ? cbm_arena_failure_operation(&ctx->rust_manifest_arena)
                                            : "read_root_manifest";
        cbm_log_error("pass.err", "code", failure_code, "pass", "rust_manifest_prepare",
                      "component", "rust_manifest", "operation", failure_operation, "path",
                      ctx->source_root, "message", "Cargo manifests could not be loaded exactly",
                      "remediation", "inspect the manifest path/read error and retry");
        cbm_pxc_destroy_rust_manifest(ctx);
        return -1;
    }
    cbm_log_info("rust_manifest.ready", "path", ctx->source_root, "manifests",
                 itoa_buf(cargo_manifest_count), "packages",
                 itoa_buf(ctx->rust_manifest->package_count), "crate_roots",
                 itoa_buf(ctx->rust_manifest->crate_root_count));
    return 0;
}

void cbm_pxc_destroy_rust_manifest(cbm_pipeline_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->rust_manifest_arena_live) {
        cbm_arena_destroy(&ctx->rust_manifest_arena);
    }
    memset(&ctx->rust_manifest_arena, 0, sizeof(ctx->rust_manifest_arena));
    ctx->rust_manifest = NULL;
    ctx->rust_manifest_arena_live = false;
    ctx->rust_manifest_prepared = false;
}

const char *cbm_pxc_rust_edition_for_file(const cbm_pipeline_ctx_t *ctx,
                                          const char *relative_path) {
    return ctx ? cbm_cargo_edition_for_path(ctx->rust_manifest, relative_path) : NULL;
}

bool cbm_pxc_rust_is_crate_root(const cbm_pipeline_ctx_t *ctx, const char *relative_path) {
    return ctx && cbm_cargo_is_crate_root(ctx->rust_manifest, relative_path);
}

int cbm_pipeline_pass_lsp_cross(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                int file_count, CBMFileResult **cache) {
    if (!ctx || !files || file_count <= 0 || !cache)
        return 0;

    cbm_log_info("pass.start", "pass", "lsp_cross", "files", itoa_buf(file_count));

    int status = 0;
    char **def_modules = NULL;
    CBMLSPDef *all_defs = NULL;
    CBMModuleDefIndex *module_def_index = NULL;

    /* Per-file module QN cache so we don't recompute it once per def + once
     * per call. cbm_pipeline_fqn_module mallocs; freed at end. */
    def_modules = (char **)calloc((size_t)file_count, sizeof(char *));
    if (!def_modules) {
        cbm_log_error("pass.err", "code", "CBM_LSP_MODULE_CACHE_ALLOC_FAILED", "pass", "lsp_cross",
                      "component", "lsp_cross.module_cache", "operation", "allocate_entries",
                      "message", "cross-LSP module cache allocation failed", "remediation",
                      "free memory or reduce repository size, then retry");
        status = -1;
        goto cleanup;
    }

    int def_count = 0;
    all_defs = cbm_pxc_collect_all_defs(cache, files, file_count, ctx->project_name, def_modules,
                                        &def_count);
    if (def_count < 0) {
        status = -1;
        goto cleanup;
    }

    /* Shared prepare (mirrors run_parallel_pipeline): inverted module-def
     * index + per-language shared registries, built ONCE for the whole pass.
     * The per-file loop below then dispatches through the SAME helper the
     * parallel resolve worker uses — previously this driver handed the FULL
     * def list to full per-file registry builds (O(files x defs); the
     * ms-typescript sequential crawl). The registries live in the
     * CALLER-OWNED ctx->seq_cross_arena: resolved_calls may borrow registry
     * strings that the later calls pass still reads, so the arena must
     * outlive this pass (run_sequential_pipeline destroys it after all
     * passes; freeing here was a pass_calls use-after-free). */
    module_def_index = all_defs ? cbm_pxc_build_module_def_index(all_defs, def_count) : NULL;
    if (all_defs && def_count > 0 && !module_def_index) {
        status = -1;
        goto cleanup;
    }
    CBMCrossLspRegistries cross_registries = {0};
    if (all_defs) {
        CBMArena *xa = &ctx->seq_cross_arena;
        if (!ctx->seq_cross_arena_live) {
            cbm_arena_init(xa);
            ctx->seq_cross_arena_live = true;
        }
        cross_registries.go = cbm_go_build_cross_registry(xa, all_defs, def_count);
        cross_registries.python = cbm_py_build_cross_registry(xa, all_defs, def_count);
        cross_registries.cs = cbm_cs_build_cross_registry(xa, all_defs, def_count);
        cross_registries.ts = cbm_ts_build_cross_registry(xa, all_defs, def_count);
        cross_registries.rust = cbm_rust_build_cross_registry(xa, all_defs, def_count);
        if (cbm_arena_failed(xa)) {
            char requested[32];
            snprintf(requested, sizeof(requested), "%zu", cbm_arena_failure_bytes(xa));
            cbm_log_error("pass.err", "code", cbm_arena_failure_code(xa), "pass", "lsp_cross",
                          "component", "lsp_cross.shared_registries", "operation",
                          cbm_arena_failure_operation(xa), "requested_bytes", requested, "message",
                          "cross-LSP shared registry allocation failed", "remediation",
                          "free memory or reduce repository size, then retry");
            status = -1;
            goto cleanup;
        }
    }

    int processed = 0;
    int skipped_no_lsp = 0;
    int empty_source = 0;
    int per_lang_calls = 0;

    for (int i = 0; i < file_count; i++) {
        if (!cache[i])
            continue;
        CBMLanguage lang = files[i].language;
        if (!cbm_pxc_has_cross_lsp(lang)) {
            skipped_no_lsp++;
            continue;
        }

        size_t source_size = 0;
        const uint8_t *source_bytes = NULL;
        if (cbm_pipeline_borrow_source(ctx->pipeline, ctx->source_slab, &files[i],
                                       "sequential_cross_lsp_source", &source_bytes,
                                       &source_size) != 0) {
            status = CBM_NOT_FOUND;
            goto cleanup;
        }
        if (source_size == 0) {
            empty_source++;
            continue;
        }
        const char *source = (const char *)source_bytes;
        int source_len = (int)source_size;

        if (!def_modules[i]) {
            def_modules[i] = cbm_pipeline_fqn_module_dir(ctx->project_name, files[i].rel_path,
                                                         pxc_module_is_dir(files[i].language));
            if (!def_modules[i]) {
                cbm_log_error("pass.err", "code", "CBM_LSP_MODULE_FQN_ALLOC_FAILED", "pass",
                              "lsp_cross", "component", "lsp_cross.module_cache", "operation",
                              "module_fqn", "file",
                              files[i].rel_path ? files[i].rel_path : "<unknown>", "message",
                              "cross-LSP could not retain a module identity", "remediation",
                              "free memory or reduce repository size, then retry");
                status = -1;
                goto cleanup;
            }
        }

        const char **imp_keys = NULL;
        const char **imp_vals = NULL;
        int imp_count = 0;
        if (cbm_pipeline_import_map_build(ctx->pipeline, ctx->gbuf, ctx->project_name, files[i].rel_path,
                                          &imp_keys, &imp_vals, &imp_count) != 0) {
            status = -1;
            goto cleanup;
        }

        if (cbm_pxc_dispatch_file(lang, cache[i], source, source_len, files[i].rel_path,
                                  def_modules[i], &cross_registries, module_def_index, all_defs,
                                  def_count, imp_keys, imp_vals, imp_count, ctx->rust_manifest) != 0) {
            cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
            status = -1;
            goto cleanup;
        }
        if (cbm_arena_failed(&cache[i]->arena)) {
            char requested[32];
            snprintf(requested, sizeof(requested), "%zu",
                     cbm_arena_failure_bytes(&cache[i]->arena));
            cbm_log_error("pass.err", "code", cbm_arena_failure_code(&cache[i]->arena), "pass",
                          "lsp_cross", "component", "lsp_cross.file_resolution", "operation",
                          cbm_arena_failure_operation(&cache[i]->arena), "file",
                          files[i].rel_path ? files[i].rel_path : "<unknown>", "requested_bytes",
                          requested, "message", "cross-LSP file resolution allocation failed",
                          "remediation", "free memory or reduce repository size, then retry");
            cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
            status = -1;
            goto cleanup;
        }
        per_lang_calls++;
        processed++;

        cbm_pipeline_import_map_free(imp_keys, imp_vals, imp_count);
    }

cleanup:
    cbm_pxc_free_module_def_index(module_def_index);
    free(all_defs);
    if (def_modules) {
        for (int i = 0; i < file_count; i++)
            free(def_modules[i]);
    }
    free(def_modules);

    if (status == 0) {
        cbm_log_info("pass.done", "pass", "lsp_cross", "files_processed", itoa_buf(processed),
                     "files_skipped_no_lsp", itoa_buf(skipped_no_lsp), "files_empty_source",
                     itoa_buf(empty_source), "defs_total", itoa_buf(def_count), "lsp_calls",
                     itoa_buf(per_lang_calls));
    }
    return status;
}

/* ── Per-module def index (gopls "package summary" pattern) ──── */

typedef struct {
    int count;
    int cap;
    int *indices; /* malloc'd; indices into the caller's all_defs[] */
} pxc_module_entry_t;

struct CBMModuleDefIndex {
    CBMHashTable *ht;           /* module_qn → pxc_module_entry_t* */
    CBMHashTable *namespace_ht; /* declared package/namespace → pxc_module_entry_t* */
    int def_count;              /* total entries in the all_defs[] array */
};

/* cbm_ht_foreach callback: free each pxc_module_entry_t. */
static void pxc_module_entry_free_cb(const char *key, void *value, void *userdata) {
    (void)key;
    (void)userdata;
    pxc_module_entry_t *e = (pxc_module_entry_t *)value;
    if (!e)
        return;
    free(e->indices);
    free(e);
}
static pxc_module_entry_t *pxc_module_entry_get_or_create(CBMHashTable *ht, const char *key) {
    if (!ht || !key || !key[0]) {
        return NULL;
    }
    pxc_module_entry_t *e = (pxc_module_entry_t *)cbm_ht_get(ht, key);
    if (e) {
        return e;
    }
    e = (pxc_module_entry_t *)calloc(1, sizeof(*e));
    if (!e) {
        return NULL;
    }
    e->cap = 8;
    e->indices = (int *)calloc((size_t)e->cap, sizeof(*e->indices));
    if (!e->indices) {
        free(e);
        return NULL;
    }
    if (!cbm_ht_set_checked(ht, key, e, NULL)) {
        cbm_log_error("lsp_cross.module_index_failed", "code", "CBM_MODULE_DEF_INDEX_INSERT_FAILED",
                      "component", "lsp_cross.module_def_index", "operation", "insert", "key", key,
                      "message", "module definition index could not retain an entry", "remediation",
                      "free memory or reduce repository size, then retry");
        free(e->indices);
        free(e);
        return NULL;
    }
    return e;
}

static bool pxc_module_entry_add_index(pxc_module_entry_t *e, int index) {
    if (!e || e->count < 0 || e->cap <= 0 || e->count > e->cap) {
        return false;
    }
    if (e->count >= e->cap) {
        if (e->cap > INT_MAX / 2) {
            return false;
        }
        int new_cap = e->cap * 2;
        if ((size_t)new_cap > SIZE_MAX / sizeof(*e->indices)) {
            return false;
        }
        int *new_indices = (int *)realloc(e->indices, (size_t)new_cap * sizeof(*new_indices));
        if (!new_indices) {
            return false;
        }
        e->indices = new_indices;
        e->cap = new_cap;
    }
    e->indices[e->count++] = index;
    return true;
}

static bool pxc_is_jvm_lang(CBMLanguage lang);
static bool pxc_def_lang_matches(CBMLanguage caller_lang, CBMLanguage def_lang);

static int pxc_mark_entry_defs(bool *selected, const pxc_module_entry_t *e,
                               const CBMLSPDef *all_defs, CBMLanguage caller_lang) {
    if (!selected || !e) {
        return 0;
    }
    int added = 0;
    for (int j = 0; j < e->count; j++) {
        int idx = e->indices[j];
        const CBMLSPDef *def = &all_defs[idx];
        if (!pxc_def_lang_matches(caller_lang, def->lang) || selected[idx]) {
            continue;
        }
        selected[idx] = true;
        added++;
    }
    return added;
}

static bool pxc_is_jvm_lang(CBMLanguage lang) {
    return lang == CBM_LANG_JAVA || lang == CBM_LANG_KOTLIN;
}

static bool pxc_def_lang_matches(CBMLanguage caller_lang, CBMLanguage def_lang) {
    if (pxc_is_jvm_lang(caller_lang)) {
        return pxc_is_jvm_lang(def_lang);
    }
    return true;
}

static void pxc_mark_module_defs(const CBMModuleDefIndex *idx, bool *selected,
                                 const CBMLSPDef *all_defs, CBMLanguage caller_lang,
                                 const char *module_qn, int *total) {
    if (!idx || !idx->ht || !module_qn || !module_qn[0]) {
        return;
    }
    pxc_module_entry_t *e = (pxc_module_entry_t *)cbm_ht_get(idx->ht, module_qn);
    int added = pxc_mark_entry_defs(selected, e, all_defs, caller_lang);
    if (total) {
        *total += added;
    }
}

CBMModuleDefIndex *cbm_pxc_build_module_def_index(CBMLSPDef *all_defs, int def_count) {
    if (!all_defs || def_count <= 0) {
        return NULL;
    }

    CBMHashTable *ht = cbm_ht_create(64);
    CBMHashTable *namespace_ht = cbm_ht_create(64);
    if (!ht || !namespace_ht) {
        cbm_log_error("lsp_cross.module_index_failed", "code", "CBM_MODULE_DEF_INDEX_CREATE_FAILED",
                      "component", "lsp_cross.module_def_index", "operation", "create", "key", "",
                      "message", "module definition index allocation failed", "remediation",
                      "free memory or reduce repository size, then retry");
        cbm_ht_free(ht);
        cbm_ht_free(namespace_ht);
        return NULL;
    }

    /* Single pass: index each def by file module and by declared package.
     * JVM mixed roots (`src/main/java` + `src/main/kotlin`) share the
     * declared package, not the path-derived module prefix. */
    for (int i = 0; i < def_count; i++) {
        if (all_defs[i].def_module_qn && all_defs[i].def_module_qn[0] &&
            !pxc_module_entry_add_index(
                pxc_module_entry_get_or_create(ht, all_defs[i].def_module_qn), i)) {
            goto fail;
        }
        if (all_defs[i].namespace_name && all_defs[i].namespace_name[0] &&
            !pxc_module_entry_add_index(
                pxc_module_entry_get_or_create(namespace_ht, all_defs[i].namespace_name), i)) {
            goto fail;
        }
    }

    CBMModuleDefIndex *idx = (CBMModuleDefIndex *)calloc(1, sizeof(*idx));
    if (!idx) {
        cbm_log_error("lsp_cross.module_index_failed", "code", "CBM_MODULE_DEF_INDEX_ALLOC_FAILED",
                      "component", "lsp_cross.module_def_index", "operation", "allocate_result",
                      "key", "", "message", "module definition index result allocation failed",
                      "remediation", "free memory or reduce repository size, then retry");
        cbm_ht_foreach(ht, pxc_module_entry_free_cb, NULL);
        cbm_ht_free(ht);
        cbm_ht_foreach(namespace_ht, pxc_module_entry_free_cb, NULL);
        cbm_ht_free(namespace_ht);
        return NULL;
    }
    idx->ht = ht;
    idx->namespace_ht = namespace_ht;
    idx->def_count = def_count;
    return idx;

fail:
    cbm_log_error("lsp_cross.module_index_failed", "code", "CBM_MODULE_DEF_INDEX_GROW_FAILED",
                  "component", "lsp_cross.module_def_index", "operation", "append", "key", "",
                  "message", "module definition index could not retain every definition",
                  "remediation", "free memory or reduce repository size, then retry");
    cbm_ht_foreach(ht, pxc_module_entry_free_cb, NULL);
    cbm_ht_free(ht);
    cbm_ht_foreach(namespace_ht, pxc_module_entry_free_cb, NULL);
    cbm_ht_free(namespace_ht);
    return NULL;
}

void cbm_pxc_free_module_def_index(CBMModuleDefIndex *idx) {
    if (!idx) {
        return;
    }
    if (idx->ht) {
        cbm_ht_foreach(idx->ht, pxc_module_entry_free_cb, NULL);
        cbm_ht_free(idx->ht);
    }
    if (idx->namespace_ht) {
        cbm_ht_foreach(idx->namespace_ht, pxc_module_entry_free_cb, NULL);
        cbm_ht_free(idx->namespace_ht);
    }
    free(idx);
}

CBMLSPDef *cbm_pxc_filter_defs_for_file(const CBMModuleDefIndex *idx, CBMLSPDef *all_defs,
                                        CBMLanguage caller_lang, const char *caller_namespace,
                                        const char *own_module, const char *const *imp_qns,
                                        int imp_count, int *out_count) {
    if (out_count) {
        *out_count = 0;
    }
    if (!idx || !idx->ht || !all_defs || !out_count || idx->def_count <= 0) {
        return NULL;
    }

    bool *selected = (bool *)calloc((size_t)idx->def_count, sizeof(*selected));
    if (!selected) {
        cbm_log_error("lsp_cross.filter_failed", "code", "CBM_MODULE_DEF_FILTER_ALLOC_FAILED",
                      "component", "lsp_cross.module_def_filter", "operation", "allocate_bitmap",
                      "message", "module definition filter bitmap allocation failed", "remediation",
                      "free memory or reduce repository size, then retry");
        *out_count = -1;
        return NULL;
    }

    int total = 0;
    pxc_mark_module_defs(idx, selected, all_defs, caller_lang, own_module, &total);
    for (int i = 0; i < imp_count; i++) {
        pxc_mark_module_defs(idx, selected, all_defs, caller_lang, imp_qns[i], &total);
    }
    if (pxc_is_jvm_lang(caller_lang) && caller_namespace && caller_namespace[0] &&
        idx->namespace_ht) {
        pxc_module_entry_t *e =
            (pxc_module_entry_t *)cbm_ht_get(idx->namespace_ht, caller_namespace);
        total += pxc_mark_entry_defs(selected, e, all_defs, caller_lang);
    }

    if (total == 0) {
        free(selected);
        return NULL;
    }

    CBMLSPDef *out = (CBMLSPDef *)malloc((size_t)total * sizeof(CBMLSPDef));
    if (!out) {
        free(selected);
        cbm_log_error("lsp_cross.filter_failed", "code", "CBM_MODULE_DEF_FILTER_RESULT_FAILED",
                      "component", "lsp_cross.module_def_filter", "operation", "allocate_result",
                      "message", "module definition filter result allocation failed", "remediation",
                      "free memory or reduce repository size, then retry");
        *out_count = -1;
        return NULL;
    }

    int n = 0;
    for (int i = 0; i < idx->def_count; i++) {
        if (selected[i]) {
            out[n++] = all_defs[i];
        }
    }
    *out_count = n;
    free(selected);
    return out;
}
