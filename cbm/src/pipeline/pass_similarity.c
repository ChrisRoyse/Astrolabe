/*
 * pass_similarity.c — Generate SIMILAR_TO edges from MinHash fingerprints.
 *
 * Reads "fp" hex strings from Function/Method node properties,
 * builds an LSH index, and emits SIMILAR_TO edges for pairs with
 * Jaccard similarity ≥ threshold.
 *
 * Runs as a post-pass after enrichment (both full and incremental).
 */
#include "foundation/constants.h"
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "simhash/minhash.h"
#include "foundation/log.h"
#include "foundation/compat.h"

#include "foundation/profile.h"
#include "foundation/platform.h"

enum {
    SIM_EDGE_INIT_CAP = 256,
    SIM_EDGE_GROW = 2,
};
#include "pipeline/worker_pool.h"

#include <stdatomic.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { FP_KEY_PREFIX_LEN = 6, MIN_FP_ENTRIES = 2 }; /* strlen("\"fp\":\"") */

/* ── Helpers ─────────────────────────────────────────────────────── */

/* Extract file extension from a path (including the dot). */
static const char *file_ext(const char *path) {
    if (!path) {
        return "";
    }
    const char *dot = strrchr(path, '.');
    return dot ? dot : "";
}

/* Parse "fp" hex string from a node's properties_json.
 * Returns true if found and decoded successfully. */
static bool parse_fp_from_props(const char *props_json, cbm_minhash_t *out) {
    if (!props_json) {
        return false;
    }
    const char *fp_key = strstr(props_json, "\"fp\":\"");
    if (!fp_key) {
        return false;
    }
    const char *hex_start = fp_key + FP_KEY_PREFIX_LEN;
    /* Find closing quote */
    const char *hex_end = strchr(hex_start, '"');
    if (!hex_end) {
        return false;
    }
    int hex_len = (int)(hex_end - hex_start);
    if (hex_len != CBM_MINHASH_HEX_LEN) {
        return false;
    }
    char hex_buf[CBM_MINHASH_HEX_BUF];
    memcpy(hex_buf, hex_start, (size_t)hex_len);
    hex_buf[hex_len] = '\0';
    return cbm_minhash_from_hex(hex_buf, out);
}

/* Log helper for integer-to-string in log calls. */
static const char *itoa_log(int val) {
    enum { RING_BUF_COUNT = 4, RING_BUF_MASK = 3 };
    static CBM_TLS char bufs[RING_BUF_COUNT][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & RING_BUF_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* ── Internal types ──────────────────────────────────────────────── */

enum { FP_ENTRY_INIT_CAP = 256, FP_ENTRY_GROW = 2, PROPS_BUF_LEN = 256 };

typedef struct {
    int64_t node_id;
    cbm_minhash_t fp;
    const char *file_path;
    const char *ext;
    const char *qn; /* canonical ordering + pair-ownership (determinism) */
} fp_entry_t;

/* Canonical entry order: by qualified name (unique). The label-index order
 * from collect_fp_entries is gbuf insertion order = parallel-extraction merge
 * order, which varies run to run; LSH bucket chains and the per-node edge-cap
 * truncation both inherit it, flickering WHICH SIMILAR_TO edges are emitted. */
static int cmp_fp_entry_by_qn(const void *pa, const void *pb) {
    const fp_entry_t *a = pa;
    const fp_entry_t *b = pb;
    const char *qa = a->qn ? a->qn : "";
    const char *qb = b->qn ? b->qn : "";
    int r = strcmp(qa, qb);
    if (r != 0) {
        return r;
    }
    if (a->node_id != b->node_id) {
        return a->node_id < b->node_id ? -1 : 1;
    }
    return 0;
}

/* Collect all Function/Method nodes with fingerprints from graph buffer.  A
 * growth failure rejects the complete pass; it is never a short collection. */
static bool collect_fp_entries(cbm_gbuf_t *gbuf, fp_entry_t **out_entries, int *out_count) {
    *out_entries = NULL;
    *out_count = 0;
    fp_entry_t *entries = NULL;
    int count = 0;
    int cap = 0;

    const char *labels[] = {"Function", "Method", NULL};
    for (int li = 0; labels[li]; li++) {
        const cbm_gbuf_node_t **nodes = NULL;
        int node_count = 0;
        if (cbm_gbuf_find_by_label(gbuf, labels[li], &nodes, &node_count) != 0) {
            cbm_log_error("pass.similarity.collect_failed", "code",
                          "CBM_SIM_FINGERPRINT_SCAN_FAILED", "label", labels[li], "message",
                          "similarity could not read the complete fingerprint-bearing node set",
                          "remediation", "inspect the graph-buffer state and retry");
            free(entries);
            return false;
        }
        for (int i = 0; i < node_count; i++) {
            const cbm_gbuf_node_t *n = nodes[i];
            cbm_minhash_t fp;
            if (!parse_fp_from_props(n->properties_json, &fp)) {
                continue;
            }
            if (count >= cap) {
                if (cap >= FP_ENTRY_INIT_CAP && cap > INT_MAX / FP_ENTRY_GROW) {
                    cbm_log_error("pass.similarity.collect_failed", "code",
                                  "CBM_SIM_FINGERPRINT_CAPACITY_OVERFLOW", "message",
                                  "similarity fingerprint capacity cannot be represented safely",
                                  "remediation", "reduce the indexed corpus size, then retry");
                    free(entries);
                    return false;
                }
                int new_cap = cap < FP_ENTRY_INIT_CAP ? FP_ENTRY_INIT_CAP : cap * FP_ENTRY_GROW;
                if ((size_t)new_cap > SIZE_MAX / sizeof(fp_entry_t)) {
                    cbm_log_error("pass.similarity.collect_failed", "code",
                                  "CBM_SIM_FINGERPRINT_CAPACITY_OVERFLOW", "message",
                                  "similarity fingerprint allocation size would overflow",
                                  "remediation", "reduce the indexed corpus size, then retry");
                    free(entries);
                    return false;
                }
                fp_entry_t *grown = realloc(entries, (size_t)new_cap * sizeof(fp_entry_t));
                if (!grown) {
                    cbm_log_error("pass.similarity.collect_failed", "code",
                                  "CBM_SIM_FINGERPRINT_ALLOC_FAILED", "message",
                                  "similarity fingerprint storage could not be grown",
                                  "remediation",
                                  "free memory or reduce the indexed corpus size, then retry");
                    free(entries);
                    return false;
                }
                entries = grown;
                cap = new_cap;
            }
            entries[count++] = (fp_entry_t){
                .node_id = n->id,
                .fp = fp,
                .file_path = n->file_path,
                .ext = file_ext(n->file_path),
                .qn = n->qualified_name,
            };
        }
    }
    /* Canonicalize (determinism) — see cmp_fp_entry_by_qn. */
    if (count > 1) {
        qsort(entries, (size_t)count, sizeof(fp_entry_t), cmp_fp_entry_by_qn);
    }
    *out_entries = entries;
    *out_count = count;
    return true;
}

/* ── Parallel query + emit ────────────────────────────────────────── */

/* Deferred edge record; collected per-worker, merged into gbuf sequentially. */
typedef struct {
    int64_t source_id;
    int64_t target_id;
    double jaccard;
    bool same_file;
    int source_index;
    int candidate_rank;
} sim_deferred_edge_t;

typedef struct {
    sim_deferred_edge_t *edges;
    int count;
    int cap;
} sim_edge_buf_t;

static bool sim_edge_buf_push(sim_edge_buf_t *buf, int64_t src, int64_t tgt, double jaccard,
                              bool same_file, int source_index, int candidate_rank) {
    if (buf->count >= buf->cap) {
        if (buf->cap >= SIM_EDGE_INIT_CAP && buf->cap > INT_MAX / SIM_EDGE_GROW) {
            return false;
        }
        int nc = buf->cap < SIM_EDGE_INIT_CAP ? SIM_EDGE_INIT_CAP : buf->cap * SIM_EDGE_GROW;
        if ((size_t)nc > SIZE_MAX / sizeof(sim_deferred_edge_t)) {
            return false;
        }
        sim_deferred_edge_t *grown = realloc(buf->edges, (size_t)nc * sizeof(sim_deferred_edge_t));
        if (!grown) {
            return false;
        }
        buf->edges = grown;
        buf->cap = nc;
    }
    buf->edges[buf->count++] = (sim_deferred_edge_t){
        .source_id = src,
        .target_id = tgt,
        .jaccard = jaccard,
        .same_file = same_file,
        .source_index = source_index,
        .candidate_rank = candidate_rank,
    };
    return true;
}

typedef struct {
    const fp_entry_t *entries;
    int entry_count;
    const cbm_lsh_index_t *lsh;
    sim_edge_buf_t *worker_bufs;
    int64_t *seen_slots;
    _Atomic int next_idx;
    _Atomic int *edge_counts; /* shared atomic array, one per entry */
    _Atomic bool failed;
} sim_query_ctx_t;

enum { SIM_CAND_CAP = 4096 };

static void sim_query_worker(int worker_id, void *ctx_ptr) {
    sim_query_ctx_t *sc = ctx_ptr;
    sim_edge_buf_t *my_buf = &sc->worker_bufs[worker_id];

    /* Thread-local candidate buffer (stack-allocated) */
    const cbm_lsh_entry_t *cands[SIM_CAND_CAP];

    while (!atomic_load_explicit(&sc->failed, memory_order_acquire)) {
        int i = atomic_fetch_add_explicit(&sc->next_idx, SKIP_ONE, memory_order_relaxed);
        if (i >= sc->entry_count) {
            break;
        }

        int ec = atomic_load_explicit(&sc->edge_counts[i], memory_order_relaxed);
        if (ec >= CBM_MINHASH_MAX_EDGES_PER_NODE) {
            continue;
        }

        const fp_entry_t *src = &sc->entries[i];
        int64_t *seen = &sc->seen_slots[(ptrdiff_t)worker_id * CBM_LSH_QUERY_SEEN_CAP];
        int cand_count = cbm_lsh_query_into_scratch(sc->lsh, &src->fp, cands, SIM_CAND_CAP, seen,
                                                    CBM_LSH_QUERY_SEEN_CAP);
        if (cand_count < 0) {
            if (!atomic_exchange_explicit(&sc->failed, true, memory_order_acq_rel)) {
                cbm_log_error("pass.similarity.query_failed", "code",
                              "CBM_SIM_QUERY_SCRATCH_INVALID", "message",
                              "similarity query scratch was invalid or unavailable", "remediation",
                              "preserve the corpus and report this invariant failure");
            }
            return;
        }

        int emitted = 0;
        for (int c = 0; c < cand_count; c++) {
            const cbm_lsh_entry_t *cand = cands[c];
            if (cand->node_id == src->node_id) {
                continue;
            }
            if (strcmp(src->ext, cand->file_ext) != 0) {
                continue;
            }
            /* Pair ownership by canonical QN order, not node id: ids are
             * assigned in parallel-merge order and vary run to run, which
             * flipped which side owned a pair and (with the per-source edge
             * cap) flickered the emitted set (determinism). */
            if (!src->qn || !cand->qualified_name || strcmp(src->qn, cand->qualified_name) >= 0) {
                continue;
            }

            int cur = atomic_load_explicit(&sc->edge_counts[i], memory_order_relaxed);
            if (cur + emitted >= CBM_MINHASH_MAX_EDGES_PER_NODE) {
                break;
            }

            double jaccard = cbm_minhash_jaccard(&src->fp, cand->fingerprint);
            if (jaccard < CBM_MINHASH_JACCARD_THRESHOLD) {
                continue;
            }

            bool same_file =
                src->file_path && cand->file_path && strcmp(src->file_path, cand->file_path) == 0;
            if (!sim_edge_buf_push(my_buf, src->node_id, cand->node_id, jaccard, same_file, i, c)) {
                if (!atomic_exchange_explicit(&sc->failed, true, memory_order_acq_rel)) {
                    cbm_log_error("pass.similarity.edge_stage_failed", "code",
                                  "CBM_SIM_EDGE_STAGE_ALLOC_FAILED", "message",
                                  "similarity worker could not retain its complete staged edge set",
                                  "remediation",
                                  "free memory or reduce the indexed corpus size, then retry");
                }
                return;
            }
            emitted++;
        }
        if (emitted > 0) {
            atomic_fetch_add_explicit(&sc->edge_counts[i], emitted, memory_order_relaxed);
        }
    }
}

static void free_sim_edge_buffers(sim_edge_buf_t *worker_bufs, int worker_count) {
    if (!worker_bufs) {
        return;
    }
    for (int w = 0; w < worker_count; w++) {
        free(worker_bufs[w].edges);
    }
    free(worker_bufs);
}

static int cmp_sim_edge_canonical(const void *pa, const void *pb) {
    const sim_deferred_edge_t *a = pa;
    const sim_deferred_edge_t *b = pb;
    if (a->source_index != b->source_index) {
        return a->source_index < b->source_index ? -1 : 1;
    }
    if (a->candidate_rank != b->candidate_rank) {
        return a->candidate_rank < b->candidate_rank ? -1 : 1;
    }
    return 0;
}

/* Merge worker-local rows only after every worker succeeds. Canonical replay
 * makes graph-buffer edge identity independent of worker assignment/schedule.
 * Returns total edge count or a negative failure and releases every buffer. */
static int merge_sim_edges(cbm_gbuf_t *gbuf, sim_edge_buf_t *worker_bufs, int worker_count) {
    size_t pair_count = 0;
    for (int w = 0; w < worker_count; w++) {
        size_t add = (size_t)worker_bufs[w].count;
        if (add > SIZE_MAX - pair_count) {
            cbm_log_error("pass.similarity.edge_merge_failed", "code",
                          "CBM_SIM_EDGE_MERGE_SIZE_OVERFLOW", "message",
                          "similarity staged-edge count overflowed", "remediation",
                          "reduce the indexed corpus size, then retry");
            free_sim_edge_buffers(worker_bufs, worker_count);
            return CBM_NOT_FOUND;
        }
        pair_count += add;
    }
    if (pair_count == 0) {
        free_sim_edge_buffers(worker_bufs, worker_count);
        return 0;
    }
    if (pair_count > INT_MAX || pair_count > SIZE_MAX / sizeof(sim_deferred_edge_t)) {
        cbm_log_error("pass.similarity.edge_merge_failed", "code",
                      "CBM_SIM_EDGE_MERGE_SIZE_OVERFLOW", "message",
                      "similarity staged-edge storage exceeded the supported range", "remediation",
                      "reduce the indexed corpus size, then retry");
        free_sim_edge_buffers(worker_bufs, worker_count);
        return CBM_NOT_FOUND;
    }
    sim_deferred_edge_t *pairs = malloc(pair_count * sizeof(*pairs));
    if (!pairs) {
        cbm_log_error("pass.similarity.edge_merge_failed", "code",
                      "CBM_SIM_EDGE_MERGE_ALLOC_FAILED", "message",
                      "the complete similarity edge generation could not be gathered",
                      "remediation", "free memory or reduce the indexed corpus size, then retry");
        free_sim_edge_buffers(worker_bufs, worker_count);
        return CBM_NOT_FOUND;
    }
    size_t pair_index = 0;
    for (int w = 0; w < worker_count; w++) {
        size_t count = (size_t)worker_bufs[w].count;
        memcpy(&pairs[pair_index], worker_bufs[w].edges, count * sizeof(*pairs));
        pair_index += count;
    }
    free_sim_edge_buffers(worker_bufs, worker_count);
    qsort(pairs, pair_count, sizeof(*pairs), cmp_sim_edge_canonical);

    for (size_t e = 0; e < pair_count; e++) {
        sim_deferred_edge_t *de = &pairs[e];
        char props[PROPS_BUF_LEN];
        snprintf(props, sizeof(props), "{\"jaccard\":%.3f,\"same_file\":%s}", de->jaccard,
                 de->same_file ? "true" : "false");
        if (cbm_gbuf_insert_edge(gbuf, de->source_id, de->target_id, "SIMILAR_TO", props) <= 0) {
            cbm_log_error("pass.similarity.edge_merge_failed", "code", "CBM_SIM_EDGE_INSERT_FAILED",
                          "message", "the complete similarity edge set could not be merged",
                          "remediation", "inspect the preceding graph-buffer error and retry");
            free(pairs);
            return CBM_NOT_FOUND;
        }
    }
    free(pairs);
    return (int)pair_count;
}

/* ── Pass entry point ────────────────────────────────────────────── */

int cbm_pipeline_pass_similarity(cbm_pipeline_ctx_t *ctx) {
    cbm_log_info("pass.start", "pass", "similarity");

    cbm_gbuf_t *gbuf = ctx->gbuf;

    /* Phase 1: Collect fingerprints from Function/Method nodes */
    CBM_PROF_START(t_collect);
    fp_entry_t *entries = NULL;
    int entry_count = 0;
    if (!collect_fp_entries(gbuf, &entries, &entry_count)) {
        CBM_PROF_END_N("similarity", "1_collect_fp", t_collect, 0);
        return CBM_NOT_FOUND;
    }
    CBM_PROF_END_N("similarity", "1_collect_fp", t_collect, entry_count);

    cbm_log_info("pass.similarity.collected", "nodes_with_fp", itoa_log(entry_count));

    if (entry_count < MIN_FP_ENTRIES) {
        free(entries);
        cbm_log_info("pass.done", "pass", "similarity", "edges", "0");
        return 0;
    }

    /* Phase 2: Build LSH index (sequential — cbm_lsh_insert mutates shared state) */
    CBM_PROF_START(t_lsh_build);
    cbm_lsh_index_t *lsh = cbm_lsh_new();
    cbm_lsh_entry_t *lsh_entries = malloc((size_t)entry_count * sizeof(cbm_lsh_entry_t));
    if (!lsh || !lsh_entries) {
        /* Fail closed with a structured error so the predump gate's remediation
         * ("inspect the preceding structured pass error") always has a real
         * error to surface — a bare negative return here would be swallowed. */
        cbm_log_error("pass.similarity.lsh_alloc_failed", "code", "CBM_SIM_LSH_ALLOC_FAILED",
                      "message", "similarity LSH entry buffer could not be allocated",
                      "remediation", "free memory or reduce the indexed corpus size, then retry");
        free(entries);
        cbm_lsh_free(lsh);
        return CBM_NOT_FOUND;
    }

    for (int i = 0; i < entry_count; i++) {
        lsh_entries[i] = (cbm_lsh_entry_t){
            .node_id = entries[i].node_id,
            .fingerprint = &entries[i].fp,
            .file_path = entries[i].file_path,
            .file_ext = entries[i].ext,
            .qualified_name = entries[i].qn,
        };
        if (!cbm_lsh_insert(lsh, &lsh_entries[i])) {
            cbm_log_error("pass.similarity.lsh_build_failed", "code", "CBM_SIM_LSH_BUILD_FAILED",
                          "entry_ordinal", itoa_log(i), "message",
                          "the complete similarity LSH index could not be retained", "remediation",
                          "inspect the preceding LSH allocation error, free memory, and retry");
            free(lsh_entries);
            free(entries);
            cbm_lsh_free(lsh);
            return CBM_NOT_FOUND;
        }
    }
    CBM_PROF_END_N("similarity", "2_lsh_build_seq", t_lsh_build, entry_count);

    /* Phase 3: Query LSH + emit edges (PARALLEL via cbm_lsh_query_into).
     * Each worker claims entries, queries, scores candidates, stashes edges
     * in its own deferred buffer. Shared edge_counts is atomic.
     * Final merge into gbuf is sequential (gbuf not thread-safe). */
    CBM_PROF_START(t_query_emit);
    _Atomic int *edge_counts = calloc((size_t)entry_count, sizeof(_Atomic int));
    int worker_count = cbm_default_worker_count(false);
    if (worker_count <= 0) {
        cbm_log_error("pass.similarity.worker_count_invalid", "code", "CBM_WORKER_COUNT_INVALID",
                      "worker_count", itoa_log(worker_count), "message",
                      "worker-count configuration is invalid", "remediation",
                      "set CBM_WORKERS to an integer from 1 through 256 or remove it");
        free(edge_counts);
        free(lsh_entries);
        free(entries);
        cbm_lsh_free(lsh);
        return CBM_NOT_FOUND;
    }
    sim_edge_buf_t *worker_bufs = calloc((size_t)worker_count, sizeof(sim_edge_buf_t));
    size_t seen_count = 0;
    if ((size_t)worker_count <= SIZE_MAX / CBM_LSH_QUERY_SEEN_CAP) {
        seen_count = (size_t)worker_count * CBM_LSH_QUERY_SEEN_CAP;
    }
    int64_t *seen_slots = seen_count > 0 && seen_count <= SIZE_MAX / sizeof(int64_t)
                              ? calloc(seen_count, sizeof(int64_t))
                              : NULL;
    if (!edge_counts || !worker_bufs || !seen_slots) {
        cbm_log_error("pass.similarity.parallel_alloc_failed", "code",
                      "CBM_SIM_PARALLEL_ALLOC_FAILED", "message",
                      "similarity parallel worker buffers could not be allocated", "remediation",
                      "free memory or reduce the indexed corpus size, then retry");
        free(worker_bufs);
        free(seen_slots);
        free(edge_counts);
        free(lsh_entries);
        free(entries);
        cbm_lsh_free(lsh);
        return CBM_NOT_FOUND;
    }

    bool query_failed = false;
    {
        sim_query_ctx_t sc = {
            .entries = entries,
            .entry_count = entry_count,
            .lsh = lsh,
            .worker_bufs = worker_bufs,
            .seen_slots = seen_slots,
            .edge_counts = edge_counts,
        };
        atomic_init(&sc.next_idx, 0);
        atomic_init(&sc.failed, false);
        cbm_parallel_for_opts_t opts = {
            .max_workers = worker_count,
            .force_pthreads = false,
            .operation = "similarity.query",
        };
        cbm_parallel_for_result_t dispatch_result = {0};
        if (cbm_parallel_for(worker_count, sim_query_worker, &sc, opts, &dispatch_result) != 0) {
            free_sim_edge_buffers(worker_bufs, worker_count);
            free(seen_slots);
            free(edge_counts);
            free(lsh_entries);
            free(entries);
            cbm_lsh_free(lsh);
            return CBM_NOT_FOUND;
        }
        query_failed = atomic_load_explicit(&sc.failed, memory_order_acquire);
    }
    CBM_PROF_END_N("similarity", "3_query_parallel", t_query_emit, entry_count);
    free(seen_slots);
    if (query_failed) {
        free_sim_edge_buffers(worker_bufs, worker_count);
        free(edge_counts);
        free(lsh_entries);
        free(entries);
        cbm_lsh_free(lsh);
        return CBM_NOT_FOUND;
    }

    CBM_PROF_START(t_merge);
    int total_edges = merge_sim_edges(gbuf, worker_bufs, worker_count);
    CBM_PROF_END_N("similarity", "4_edge_merge_seq", t_merge, total_edges);
    if (total_edges < 0) {
        free(edge_counts);
        free(lsh_entries);
        free(entries);
        cbm_lsh_free(lsh);
        return CBM_NOT_FOUND;
    }

    cbm_log_info("pass.done", "pass", "similarity", "edges", itoa_log(total_edges));

    free(edge_counts);
    free(lsh_entries);
    free(entries);
    cbm_lsh_free(lsh);
    return 0;
}
