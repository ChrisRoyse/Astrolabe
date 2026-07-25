/*
 * pass_configlink.c — Config ↔ Code linking strategies (pre-dump pass).
 *
 * Three strategies link config files to code symbols:
 *   1. Key→Symbol: normalized config key matches code function/variable name
 *   2. Dep→Import: package manifest dependency matches IMPORTS edge target
 *   3. File→Ref: source code string literal references config file path
 *
 * Operates on the graph buffer before dump to .db file.
 *
 * Sizing and cost (#730). Strategies 1 and 2 used to collect their working set
 * into fixed-capacity arrays declared directly in the pass frame
 * (config_entry_t[4096] + code_entry_t[8192] + dep_entry_t[2048]) — about
 * 4.6 MiB of stack. Two defects followed from that shape:
 *
 *   - A frame that large faults in its own `___chkstk_ms` prologue on any thread
 *     whose stack reserve is smaller, killing the process with a
 *     diagnostic-free STATUS_STACK_OVERFLOW before the pass can log. Every
 *     working set is now heap-allocated at exactly the measured cardinality and
 *     every allocation is checked.
 *   - The capacities silently discarded every config key past 4096, code symbol
 *     past 8192, and manifest dependency past 2048: a repository simply lost
 *     CONFIGURES edges, with nothing counted and nothing logged. The exact
 *     inventory is now linked in full, and a cardinality that cannot be
 *     represented or allocated fails the pass closed with {code, operation,
 *     requested, message, remediation} instead of truncating.
 *
 * Removing the caps also removed the accidental bound on the pairwise match
 * loops, so both strategies now answer "which dictionary keys occur inside this
 * candidate?" through one shared Aho-Corasick automaton (below) rather than by
 * comparing every pair.
 */
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/hash_table.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/str_util.h" /* cbm_json_escape — UTF-8-strict edge-property escaping (#528) */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "foundation/compat_regex.h"

/* ── Config link confidence scores ───────────────────────────────── */
/* Strategy 1: Key→Symbol matching */
#define CONF_KEY_EXACT 0.85
#define CONF_KEY_SUBSTRING 0.75
/* Strategy 2: Dep→Import matching */
#define CONF_DEP_EXACT 0.95
#define CONF_DEP_QN_SUBSTR 0.80
/* Strategy 3: File→Ref matching */
#define CONF_FILE_FULLPATH 0.90
#define CONF_FILE_BASENAME 0.70

/* Escaped-property scratch. A node name is at most CBM_SZ_256 bytes and the
 * JSON escaper expands a control byte to six (\u00xx), so CBM_SZ_2K holds the
 * worst-case escaped key AND the fixed property prefix without truncating —
 * a truncated key would otherwise be persisted as a silently different fact. */
#define CONFIGLINK_PROP_BUF CBM_SZ_2K

/* ── Fail-closed diagnostics ─────────────────────────────────────── */

static int configlink_failure(cbm_pipeline_ctx_t *ctx, const char *code, const char *operation,
                              size_t requested, const char *message, const char *remediation) {
    char requested_buf[CBM_SZ_32];
    snprintf(requested_buf, sizeof(requested_buf), "%zu", requested);
    cbm_log_error("configlinker.failed", "code", code, "operation", operation, "requested",
                  requested_buf, "message", message, "remediation", remediation);
    cbm_pipeline_record_fatal_error(ctx->pipeline, code, operation, "configlink",
                                    ctx->repo_path ? ctx->repo_path : "", requested, message,
                                    remediation);
    return CBM_NOT_FOUND;
}

/* Allocate `count` records of `record_size`, or fail the pass closed. A zero
 * count yields a NULL pointer and success — an empty working set is a fact,
 * not an error. */
static int configlink_alloc(cbm_pipeline_ctx_t *ctx, size_t count, size_t record_size,
                            const char *operation, void **out) {
    *out = NULL;
    if (count == 0) {
        return 0;
    }
    if (record_size == 0 || count > SIZE_MAX / record_size) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_ALLOCATION_OVERFLOW", operation, count,
                                  "config-link record allocation size is not representable",
                                  "fix the graph cardinality or record-layout overflow and retry");
    }
    *out = calloc(count, record_size);
    if (!*out) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_ALLOCATION_FAILED", operation,
                                  count * record_size, "exact config-link record allocation failed",
                                  "free sufficient memory for the reported exact allocation and "
                                  "retry");
    }
    return 0;
}

/* ── Shared multi-pattern substring index ────────────────────────── */
/*
 * Both linking strategies ask one question of every candidate string: which of
 * the N dictionary keys occur inside it? Answering that by testing every
 * (key, candidate) pair costs O(N*M) string comparisons, which the deleted
 * fixed capacities used to bound by discarding data. An Aho-Corasick automaton
 * answers it in one pass over each candidate — O(total candidate bytes + hits)
 * — so the exact inventory can be linked in full without a quadratic scan.
 *
 * The trie stores children as a per-state sibling list rather than a
 * state x 256 goto matrix: the matrix is O(states * alphabet) memory, which a
 * repository with tens of thousands of long config keys would inflate into
 * gigabytes, while the sibling list is O(states) and each state's child list is
 * bounded by the (small) set of bytes the dictionary actually uses.
 */

typedef struct {
    int32_t *first_child;  /* head of this state's child list, or CBM_NOT_FOUND */
    int32_t *next_sibling; /* next child of the same parent, or CBM_NOT_FOUND */
    int32_t *fail;         /* Aho-Corasick failure link (root's is the root) */
    int32_t *out_pattern;  /* pattern ending exactly here, or CBM_NOT_FOUND */
    int32_t *out_link;     /* nearest proper suffix state ending a pattern */
    unsigned char *in_byte;
    int32_t state_count;
} configlink_index_t;

/* Every hit callback returns 0 to continue the scan, or a negative pass code to
 * abort it; the code propagates to the strategy and then to the pipeline. */
typedef int (*configlink_hit_fn)(void *user, int32_t pattern_id);

static void configlink_index_dispose(configlink_index_t *ix) {
    if (!ix) {
        return;
    }
    free(ix->first_child);
    free(ix->next_sibling);
    free(ix->fail);
    free(ix->out_pattern);
    free(ix->out_link);
    free(ix->in_byte);
    memset(ix, 0, sizeof(*ix));
}

static int32_t configlink_index_child(const configlink_index_t *ix, int32_t state,
                                      unsigned char byte) {
    for (int32_t s = ix->first_child[state]; s != CBM_NOT_FOUND; s = ix->next_sibling[s]) {
        if (ix->in_byte[s] == byte) {
            return s;
        }
    }
    return CBM_NOT_FOUND;
}

/* Build the automaton over `pattern_count` distinct, non-empty patterns.
 * Patterns must already be deduplicated: a repeated pattern would make one
 * terminal state stand for two dictionary entries, so it is refused rather
 * than silently collapsed. */
static int configlink_index_build(cbm_pipeline_ctx_t *ctx, const char **patterns,
                                  const size_t *lengths, size_t pattern_count,
                                  const char *operation, configlink_index_t *out) {
    memset(out, 0, sizeof(*out));
    if (pattern_count == 0) {
        return 0;
    }
    if (pattern_count > INT32_MAX) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_INDEX_TOO_LARGE", operation, pattern_count,
                                  "config-link pattern count exceeds the index identity width",
                                  "reduce the distinct key cardinality or widen the index "
                                  "identity, then retry");
    }

    /* One state per pattern byte, plus the root. */
    size_t capacity = 1;
    for (size_t p = 0; p < pattern_count; p++) {
        if (lengths[p] == 0) {
            return configlink_failure(ctx, "CBM_CONFIGLINK_INDEX_EMPTY_PATTERN", operation, p,
                                      "config-link index received an empty dictionary key",
                                      "exclude empty keys before building the index and retry");
        }
        if (lengths[p] > (size_t)INT32_MAX - capacity) {
            return configlink_failure(ctx, "CBM_CONFIGLINK_INDEX_TOO_LARGE", operation, capacity,
                                      "config-link index state count is not representable",
                                      "reduce the distinct key cardinality or widen the index "
                                      "identity, then retry");
        }
        capacity += lengths[p];
    }

    if (configlink_alloc(ctx, capacity, sizeof(*out->first_child), operation,
                         (void **)&out->first_child) != 0 ||
        configlink_alloc(ctx, capacity, sizeof(*out->next_sibling), operation,
                         (void **)&out->next_sibling) != 0 ||
        configlink_alloc(ctx, capacity, sizeof(*out->fail), operation, (void **)&out->fail) != 0 ||
        configlink_alloc(ctx, capacity, sizeof(*out->out_pattern), operation,
                         (void **)&out->out_pattern) != 0 ||
        configlink_alloc(ctx, capacity, sizeof(*out->out_link), operation,
                         (void **)&out->out_link) != 0 ||
        configlink_alloc(ctx, capacity, sizeof(*out->in_byte), operation, (void **)&out->in_byte) !=
            0) {
        configlink_index_dispose(out);
        return CBM_NOT_FOUND;
    }

    for (size_t i = 0; i < capacity; i++) {
        out->first_child[i] = CBM_NOT_FOUND;
        out->next_sibling[i] = CBM_NOT_FOUND;
        out->out_pattern[i] = CBM_NOT_FOUND;
        out->out_link[i] = CBM_NOT_FOUND;
        out->fail[i] = 0;
    }

    int32_t state_count = 1; /* state 0 is the root */
    for (size_t p = 0; p < pattern_count; p++) {
        int32_t state = 0;
        for (size_t j = 0; j < lengths[p]; j++) {
            unsigned char byte = (unsigned char)patterns[p][j];
            int32_t child = configlink_index_child(out, state, byte);
            if (child == CBM_NOT_FOUND) {
                child = state_count++;
                out->in_byte[child] = byte;
                out->next_sibling[child] = out->first_child[state];
                out->first_child[state] = child;
            }
            state = child;
        }
        if (out->out_pattern[state] != CBM_NOT_FOUND) {
            configlink_index_dispose(out);
            return configlink_failure(ctx, "CBM_CONFIGLINK_INDEX_DUPLICATE_PATTERN", operation, p,
                                      "config-link index received a repeated dictionary key",
                                      "deduplicate the dictionary keys before building the index "
                                      "and retry");
        }
        out->out_pattern[state] = (int32_t)p;
    }
    out->state_count = state_count;

    /* Breadth-first failure and dictionary-suffix links. */
    int32_t *queue = NULL;
    if (configlink_alloc(ctx, (size_t)state_count, sizeof(*queue), operation, (void **)&queue) !=
        0) {
        configlink_index_dispose(out);
        return CBM_NOT_FOUND;
    }
    int32_t head = 0;
    int32_t tail = 0;
    for (int32_t c = out->first_child[0]; c != CBM_NOT_FOUND; c = out->next_sibling[c]) {
        out->fail[c] = 0;
        out->out_link[c] = CBM_NOT_FOUND;
        queue[tail++] = c;
    }
    while (head < tail) {
        int32_t u = queue[head++];
        for (int32_t v = out->first_child[u]; v != CBM_NOT_FOUND; v = out->next_sibling[v]) {
            unsigned char byte = out->in_byte[v];
            int32_t f = out->fail[u];
            while (f != 0 && configlink_index_child(out, f, byte) == CBM_NOT_FOUND) {
                f = out->fail[f];
            }
            int32_t target = configlink_index_child(out, f, byte);
            out->fail[v] = (target != CBM_NOT_FOUND && target != v) ? target : 0;
            out->out_link[v] = (out->out_pattern[out->fail[v]] != CBM_NOT_FOUND)
                                   ? out->fail[v]
                                   : out->out_link[out->fail[v]];
            queue[tail++] = v;
        }
    }
    free(queue);
    return 0;
}

/* Report every dictionary key occurring anywhere in `text`. */
static int configlink_index_scan(const configlink_index_t *ix, const char *text, size_t text_len,
                                 configlink_hit_fn on_hit, void *user) {
    if (ix->state_count <= 0) {
        return 0;
    }
    int32_t state = 0;
    for (size_t i = 0; i < text_len; i++) {
        unsigned char byte = (unsigned char)text[i];
        int32_t next = configlink_index_child(ix, state, byte);
        while (next == CBM_NOT_FOUND && state != 0) {
            state = ix->fail[state];
            next = configlink_index_child(ix, state, byte);
        }
        state = (next == CBM_NOT_FOUND) ? 0 : next;
        for (int32_t t = (ix->out_pattern[state] != CBM_NOT_FOUND) ? state : ix->out_link[state];
             t != CBM_NOT_FOUND; t = ix->out_link[t]) {
            int rc = on_hit(user, ix->out_pattern[t]);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}

/* Index of `needle` in a sorted, distinct key array, or CBM_NOT_FOUND. */
static ptrdiff_t configlink_find_key(const char **keys, size_t count, const char *needle) {
    size_t low = 0;
    size_t high = count;
    while (low < high) {
        size_t mid = low + ((high - low) / PAIR_LEN);
        int cmp = strcmp(keys[mid], needle);
        if (cmp == 0) {
            return (ptrdiff_t)mid;
        }
        if (cmp < 0) {
            low = mid + SKIP_ONE;
        } else {
            high = mid;
        }
    }
    return CBM_NOT_FOUND;
}

/* ── Manifest / dep section tables ──────────────────────────────── */

static bool is_manifest_file(const char *basename) {
    static const char *names[] = {"Cargo.toml",       "package.json",  "go.mod",
                                  "requirements.txt", "Gemfile",       "build.gradle",
                                  "pom.xml",          "composer.json", NULL};
    for (int i = 0; names[i]; i++) {
        if (strcmp(basename, names[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_dep_section(const char *s) {
    static const char *secs[] = {"dependencies",     "devdependencies",    "peerdependencies",
                                 "dev-dependencies", "build-dependencies", NULL};
    for (int i = 0; secs[i]; i++) {
        if (cbm_strcasestr(s, secs[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* ── Strategy 1: Config Key → Code Symbol ───────────────────────── */

typedef struct {
    int64_t node_id;
    char normalized[CBM_SZ_256];
    char name[CBM_SZ_256];
} config_entry_t;

/* Validate and normalize one config Variable with ≥2 tokens, each ≥3 chars.
 * `out` may be NULL to test candidacy without materializing the record, so the
 * exact cardinality can be measured before allocating for it. */
static bool config_entry_from_node(const cbm_gbuf_node_t *node, config_entry_t *out) {
    if (!node || !node->file_path || !node->name || !cbm_has_config_extension(node->file_path)) {
        return false;
    }

    char norm[CBM_SZ_256];
    int tokens = cbm_normalize_config_key(node->name, norm, sizeof(norm));
    if (tokens < PAIR_LEN) {
        return false;
    }

    /* Every token ≥3 chars */
    const char *p = norm;
    while (*p) {
        const char *end = strchr(p, '_');
        size_t tlen = end ? (size_t)(end - p) : strlen(p);
        if (tlen < CBM_SZ_3) {
            return false;
        }
        p = end ? end + SKIP_ONE : p + tlen;
    }

    if (out) {
        out->node_id = node->id;
        snprintf(out->normalized, sizeof(out->normalized), "%s", norm);
        snprintf(out->name, sizeof(out->name), "%s", node->name);
    }
    return true;
}

/* Collect code nodes (Function/Variable/Class/Struct) not from config files. */
typedef struct {
    int64_t node_id;
    char normalized[CBM_SZ_256];
} code_entry_t;

static bool code_entry_from_node(const cbm_gbuf_node_t *node, code_entry_t *out) {
    if (!node || !node->file_path || !node->name || cbm_has_config_extension(node->file_path)) {
        return false;
    }

    char norm[CBM_SZ_256];
    int tokens = cbm_normalize_config_key(node->name, norm, sizeof(norm));
    if (tokens == 0 || norm[0] == '\0') {
        return false;
    }
    if (out) {
        out->node_id = node->id;
        snprintf(out->normalized, sizeof(out->normalized), "%s", norm);
    }
    return true;
}

/* "Struct" alongside "Class": a config key may name a Go/Rust/Swift/D struct
 * type, which is now labelled "Struct" — keep it linkable. */
static const char *const CODE_ENTRY_LABELS[] = {"Function", "Variable", "Class", "Struct", NULL};

/* Measure (out == NULL) or materialize the exact code-node working set. */
static int collect_code_entries(cbm_pipeline_ctx_t *ctx, code_entry_t *out, size_t capacity,
                                size_t *out_count) {
    size_t n = 0;
    for (int li = 0; CODE_ENTRY_LABELS[li]; li++) {
        const cbm_gbuf_node_t **nodes = NULL;
        int count = 0;
        if (cbm_gbuf_find_by_label(ctx->gbuf, CODE_ENTRY_LABELS[li], &nodes, &count) != 0) {
            return configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_QUERY_FAILED",
                                      "collect_code_entries", 0,
                                      "graph-buffer code-label query failed",
                                      "inspect graph-buffer diagnostics, fix the failed label "
                                      "index, and retry");
        }

        for (int i = 0; i < count; i++) {
            code_entry_t entry;
            if (!code_entry_from_node(nodes[i], &entry)) {
                continue;
            }
            if (out) {
                if (n >= capacity) {
                    return configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED",
                                              "collect_code_entries", n,
                                              "code-node inventory changed while building its "
                                              "exact record array",
                                              "keep graph mutation serialized through predump and "
                                              "retry");
                }
                out[n] = entry;
            }
            n++;
        }
        /* gbuf data is borrowed — no free */
    }
    *out_count = n;
    return 0;
}

/* Total order over config records: normalized key first so equal keys form one
 * contiguous run, then node identity so the sort — and therefore the emitted
 * edge order — is fully determined by the graph rather than by qsort. */
static int config_entry_cmp(const void *lhs, const void *rhs) {
    const config_entry_t *a = (const config_entry_t *)lhs;
    const config_entry_t *b = (const config_entry_t *)rhs;
    int cmp = strcmp(a->normalized, b->normalized);
    if (cmp != 0) {
        return cmp;
    }
    if (a->node_id < b->node_id) {
        return CBM_NOT_FOUND;
    }
    return (a->node_id > b->node_id) ? SKIP_ONE : 0;
}

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    cbm_gbuf_t *gb;
    const config_entry_t *config_entries;
    const size_t *key_start; /* first config record carrying distinct key k */
    const size_t *key_end;   /* one past the last such record */
    const size_t *key_len;
    int64_t *key_stamp; /* last code record that already fired key k */
    int64_t code_index;
    int64_t code_node_id;
    size_t code_len;
    int edge_count;
} key_symbol_scan_t;

static int key_symbol_on_hit(void *user, int32_t pattern_id) {
    key_symbol_scan_t *scan = (key_symbol_scan_t *)user;
    size_t key = (size_t)pattern_id;

    /* A key occurring more than once inside the same symbol is still one
     * (config, code) relation — emit it exactly once. */
    if (scan->key_stamp[key] == scan->code_index) {
        return 0;
    }
    scan->key_stamp[key] = scan->code_index;

    /* Whole-symbol occurrence == the exact-name match; anything shorter is the
     * substring match. */
    double confidence =
        (scan->key_len[key] == scan->code_len) ? CONF_KEY_EXACT : CONF_KEY_SUBSTRING;

    for (size_t e = scan->key_start[key]; e < scan->key_end[key]; e++) {
        /* config key is a parser-derived scalar: escape UTF-8-strict so a
         * bad byte can't corrupt the CONFIGURES edges.properties cell and
         * make the vault importer refuse the repo (#528). */
        char esc_key[CONFIGLINK_PROP_BUF];
        cbm_json_escape(esc_key, (int)sizeof(esc_key), scan->config_entries[e].name);
        char props[CONFIGLINK_PROP_BUF];
        snprintf(props, sizeof(props),
                 "{\"strategy\":\"key_symbol\",\"confidence\":%.2f,\"config_key\":\"%s\"}",
                 confidence, esc_key);

        if (cbm_gbuf_insert_edge(scan->gb, scan->code_node_id, scan->config_entries[e].node_id,
                                 "CONFIGURES", props) <= 0) {
            return configlink_failure(scan->ctx, "CBM_CONFIGLINK_EDGE_INSERT_FAILED",
                                      "insert_key_symbol_edge", (size_t)scan->code_node_id,
                                      "graph buffer refused a CONFIGURES key-symbol edge",
                                      "inspect the preceding graph-buffer diagnostic, repair the "
                                      "rejected edge identity, and retry");
        }
        if (scan->edge_count == INT_MAX) {
            return configlink_failure(scan->ctx, "CBM_CONFIGLINK_EDGE_COUNT_OVERFLOW",
                                      "count_key_symbol_edges", (size_t)scan->edge_count,
                                      "config-link edge count exceeds the pass return contract",
                                      "widen the config-link pass count contract and retry");
        }
        scan->edge_count++;
    }
    return 0;
}

static int strategy_key_symbols(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    const cbm_gbuf_node_t **vars = NULL;
    int var_count = 0;
    if (cbm_gbuf_find_by_label(gb, "Variable", &vars, &var_count) != 0) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_QUERY_FAILED",
                                  "collect_config_entries", 0, "graph-buffer Variable query failed",
                                  "inspect graph-buffer diagnostics, fix the failed label index, "
                                  "and retry");
    }

    size_t config_count = 0;
    for (int i = 0; i < var_count; i++) {
        if (config_entry_from_node(vars[i], NULL)) {
            config_count++;
        }
    }
    if (config_count == 0) {
        return 0;
    }

    int rc = CBM_NOT_FOUND;
    config_entry_t *config_entries = NULL;
    code_entry_t *code_entries = NULL;
    size_t *key_start = NULL;
    size_t *key_end = NULL;
    size_t *key_len = NULL;
    const char **key_ptr = NULL;
    int64_t *key_stamp = NULL;
    size_t config_written = 0;
    size_t key_count = 0;
    size_t code_count = 0;
    size_t code_written = 0;
    key_symbol_scan_t scan;
    configlink_index_t index;
    memset(&index, 0, sizeof(index));

    if (configlink_alloc(ctx, config_count, sizeof(*config_entries), "allocate_config_entries",
                         (void **)&config_entries) != 0) {
        goto done;
    }
    for (int i = 0; i < var_count; i++) {
        config_entry_t entry;
        if (!config_entry_from_node(vars[i], &entry)) {
            continue;
        }
        if (config_written >= config_count) {
            rc = configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED", "collect_config_entries",
                                    config_written,
                                    "config-node inventory changed while building its exact "
                                    "record array",
                                    "keep graph mutation serialized through predump and retry");
            goto done;
        }
        config_entries[config_written++] = entry;
    }
    if (config_written != config_count) {
        rc = configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED", "collect_config_entries",
                                config_written,
                                "config-node inventory changed while building its exact record "
                                "array",
                                "keep graph mutation serialized through predump and retry");
        goto done;
    }

    qsort(config_entries, config_count, sizeof(*config_entries), config_entry_cmp);

    /* Distinct normalized keys are the automaton's dictionary; every config
     * record sharing a key is still its own CONFIGURES target. */
    if (configlink_alloc(ctx, config_count, sizeof(*key_start), "allocate_config_key_runs",
                         (void **)&key_start) != 0 ||
        configlink_alloc(ctx, config_count, sizeof(*key_end), "allocate_config_key_runs",
                         (void **)&key_end) != 0 ||
        configlink_alloc(ctx, config_count, sizeof(*key_len), "allocate_config_key_runs",
                         (void **)&key_len) != 0 ||
        configlink_alloc(ctx, config_count, sizeof(*key_ptr), "allocate_config_key_runs",
                         (void **)&key_ptr) != 0 ||
        configlink_alloc(ctx, config_count, sizeof(*key_stamp), "allocate_config_key_runs",
                         (void **)&key_stamp) != 0) {
        goto done;
    }

    for (size_t i = 0; i < config_count;) {
        size_t j = i;
        while (j < config_count &&
               strcmp(config_entries[j].normalized, config_entries[i].normalized) == 0) {
            j++;
        }
        key_start[key_count] = i;
        key_end[key_count] = j;
        key_ptr[key_count] = config_entries[i].normalized;
        key_len[key_count] = strlen(config_entries[i].normalized);
        key_stamp[key_count] = CBM_NOT_FOUND;
        key_count++;
        i = j;
    }

    if (configlink_index_build(ctx, key_ptr, key_len, key_count, "build_config_key_index",
                               &index) != 0) {
        goto done;
    }

    rc = collect_code_entries(ctx, NULL, 0, &code_count);
    if (rc != 0) {
        goto done;
    }
    rc = CBM_NOT_FOUND;
    if (configlink_alloc(ctx, code_count, sizeof(*code_entries), "allocate_code_entries",
                         (void **)&code_entries) != 0) {
        goto done;
    }
    rc = collect_code_entries(ctx, code_entries, code_count, &code_written);
    if (rc != 0) {
        goto done;
    }
    if (code_written != code_count) {
        rc = configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED", "collect_code_entries",
                                code_written,
                                "code-node inventory changed while building its exact record "
                                "array",
                                "keep graph mutation serialized through predump and retry");
        goto done;
    }

    memset(&scan, 0, sizeof(scan));
    scan.ctx = ctx;
    scan.gb = gb;
    scan.config_entries = config_entries;
    scan.key_start = key_start;
    scan.key_end = key_end;
    scan.key_len = key_len;
    scan.key_stamp = key_stamp;

    rc = 0;
    for (size_t c = 0; c < code_count; c++) {
        scan.code_index = (int64_t)c;
        scan.code_node_id = code_entries[c].node_id;
        scan.code_len = strlen(code_entries[c].normalized);
        rc = configlink_index_scan(&index, code_entries[c].normalized, scan.code_len,
                                   key_symbol_on_hit, &scan);
        if (rc != 0) {
            goto done;
        }
    }
    rc = scan.edge_count;

done:
    configlink_index_dispose(&index);
    free(key_stamp);
    free(key_ptr);
    free(key_len);
    free(key_end);
    free(key_start);
    free(code_entries);
    free(config_entries);
    return rc;
}

/* ── Strategy 2: Dependency → Import ────────────────────────────── */

typedef struct {
    int64_t node_id;
    char name[CBM_SZ_256];
    char lower[CBM_SZ_256];
} dep_entry_t;

/* Extract basename from a file path. */
static const char *path_basename(const char *path) {
    if (!path) {
        return "";
    }
    const char *slash = strrchr(path, '/');
    return slash ? slash + SKIP_ONE : path;
}

/* Check if a Cargo.toml QN contains a dependency section in any dotted part. */
static bool is_cargo_dep_section(const char *qn) {
    char qn_copy[CBM_SZ_512];
    snprintf(qn_copy, sizeof(qn_copy), "%s", qn);
    char *saveptr = NULL;
    char *part = strtok_r(qn_copy, ".", &saveptr);
    while (part) {
        char lower[CBM_SZ_128];
        size_t plen = strlen(part);
        if (plen >= sizeof(lower)) {
            plen = sizeof(lower) - SKIP_ONE;
        }
        for (size_t j = 0; j < plen; j++) {
            lower[j] = (char)tolower((unsigned char)part[j]);
        }
        lower[plen] = '\0';

        static const char *dep_secs[] = {"dependencies",       "devdependencies",
                                         "peerdependencies",   "dev-dependencies",
                                         "build-dependencies", NULL};
        for (int k = 0; dep_secs[k]; k++) {
            if (strcmp(lower, dep_secs[k]) == 0) {
                return true;
            }
        }
        part = strtok_r(NULL, ".", &saveptr);
    }
    return false;
}

/* Lowercase a string into buf. */
static void lowercase_into(char *buf, size_t bufsize, const char *src) {
    size_t len = src ? strlen(src) : 0;
    for (size_t j = 0; j < len && j < bufsize - SKIP_ONE; j++) {
        buf[j] = (char)tolower((unsigned char)src[j]);
    }
    buf[len < bufsize ? len : bufsize - SKIP_ONE] = '\0';
}

/* Is this Variable a manifest dependency? `out` may be NULL to measure. */
static bool dep_entry_from_node(const cbm_gbuf_node_t *node, dep_entry_t *out) {
    if (!node || !node->name) {
        return false;
    }
    const char *base = path_basename(node->file_path);
    if (!is_manifest_file(base)) {
        return false;
    }

    bool is_dep = node->qualified_name && is_dep_section(node->qualified_name);
    if (!is_dep && strcmp(base, "Cargo.toml") == 0 && node->qualified_name) {
        is_dep = is_cargo_dep_section(node->qualified_name);
    }
    if (!is_dep) {
        return false;
    }

    if (out) {
        out->node_id = node->id;
        snprintf(out->name, sizeof(out->name), "%s", node->name);
        lowercase_into(out->lower, sizeof(out->lower), out->name);
    }
    return true;
}

static int dep_entry_cmp(const void *lhs, const void *rhs) {
    const dep_entry_t *a = (const dep_entry_t *)lhs;
    const dep_entry_t *b = (const dep_entry_t *)rhs;
    int cmp = strcmp(a->lower, b->lower);
    if (cmp != 0) {
        return cmp;
    }
    if (a->node_id < b->node_id) {
        return CBM_NOT_FOUND;
    }
    return (a->node_id > b->node_id) ? SKIP_ONE : 0;
}

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    cbm_gbuf_t *gb;
    const dep_entry_t *deps;
    const size_t *key_start;
    const size_t *key_end;
    int64_t *key_stamp;
    int64_t import_index;
    ptrdiff_t exact_key; /* key already emitted at CONF_DEP_EXACT, or CBM_NOT_FOUND */
    int64_t source_id;
    int edge_count;
} dep_import_scan_t;

static int dep_import_emit(dep_import_scan_t *scan, size_t key, double confidence) {
    for (size_t d = scan->key_start[key]; d < scan->key_end[key]; d++) {
        /* Dependency names are parser-derived manifest scalars, so they get the
         * same UTF-8-strict escaping the key_symbol strategy already applied
         * (#528): an unescaped quote or control byte here produced a malformed
         * edges.properties cell that the vault importer refuses. */
        char esc_dep[CONFIGLINK_PROP_BUF];
        cbm_json_escape(esc_dep, (int)sizeof(esc_dep), scan->deps[d].name);
        char props[CONFIGLINK_PROP_BUF];
        snprintf(props, sizeof(props),
                 "{\"strategy\":\"dependency_import\",\"confidence\":%.2f,\"dep_name\":\"%s\"}",
                 confidence, esc_dep);

        if (cbm_gbuf_insert_edge(scan->gb, scan->source_id, scan->deps[d].node_id, "CONFIGURES",
                                 props) <= 0) {
            return configlink_failure(scan->ctx, "CBM_CONFIGLINK_EDGE_INSERT_FAILED",
                                      "insert_dep_import_edge", (size_t)scan->deps[d].node_id,
                                      "graph buffer refused a CONFIGURES dependency-import edge",
                                      "inspect the preceding graph-buffer diagnostic, repair the "
                                      "rejected edge identity, and retry");
        }
        if (scan->edge_count == INT_MAX) {
            return configlink_failure(scan->ctx, "CBM_CONFIGLINK_EDGE_COUNT_OVERFLOW",
                                      "count_dep_import_edges", (size_t)scan->edge_count,
                                      "config-link edge count exceeds the pass return contract",
                                      "widen the config-link pass count contract and retry");
        }
        scan->edge_count++;
    }
    return 0;
}

static int dep_import_on_hit(void *user, int32_t pattern_id) {
    dep_import_scan_t *scan = (dep_import_scan_t *)user;
    size_t key = (size_t)pattern_id;
    if (scan->key_stamp[key] == scan->import_index) {
        return 0;
    }
    scan->key_stamp[key] = scan->import_index;
    /* The exact name match already produced this dependency's edge for this
     * import; the qualified-name substring rule is the weaker alternative, not
     * an additional relation. */
    if ((ptrdiff_t)key == scan->exact_key) {
        return 0;
    }
    return dep_import_emit(scan, key, CONF_DEP_QN_SUBSTR);
}

static int strategy_dep_imports(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    const cbm_gbuf_node_t **vars = NULL;
    int var_count = 0;
    if (cbm_gbuf_find_by_label(gb, "Variable", &vars, &var_count) != 0) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_QUERY_FAILED", "collect_manifest_deps",
                                  0, "graph-buffer Variable query failed",
                                  "inspect graph-buffer diagnostics, fix the failed label index, "
                                  "and retry");
    }

    size_t dep_count = 0;
    for (int i = 0; i < var_count; i++) {
        if (dep_entry_from_node(vars[i], NULL)) {
            dep_count++;
        }
    }
    if (dep_count == 0) {
        return 0;
    }

    const cbm_gbuf_edge_t **imports = NULL;
    int import_count = 0;
    if (cbm_gbuf_find_edges_by_type(gb, "IMPORTS", &imports, &import_count) != 0) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_QUERY_FAILED", "collect_imports", 0,
                                  "graph-buffer IMPORTS edge query failed",
                                  "inspect graph-buffer diagnostics, fix the failed edge index, "
                                  "and retry");
    }
    if (import_count == 0) {
        return 0;
    }

    int rc = CBM_NOT_FOUND;
    dep_entry_t *deps = NULL;
    size_t *key_start = NULL;
    size_t *key_end = NULL;
    const char **key_ptr = NULL;
    size_t *key_len = NULL;
    int64_t *key_stamp = NULL;
    size_t dep_written = 0;
    size_t key_count = 0;
    dep_import_scan_t scan;
    configlink_index_t index;
    memset(&index, 0, sizeof(index));

    if (configlink_alloc(ctx, dep_count, sizeof(*deps), "allocate_manifest_deps", (void **)&deps) !=
        0) {
        goto done;
    }
    for (int i = 0; i < var_count; i++) {
        dep_entry_t entry;
        if (!dep_entry_from_node(vars[i], &entry)) {
            continue;
        }
        if (dep_written >= dep_count) {
            rc = configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED", "collect_manifest_deps",
                                    dep_written,
                                    "manifest-dependency inventory changed while building its "
                                    "exact record array",
                                    "keep graph mutation serialized through predump and retry");
            goto done;
        }
        deps[dep_written++] = entry;
    }
    if (dep_written != dep_count) {
        rc = configlink_failure(ctx, "CBM_CONFIGLINK_GRAPH_CHANGED", "collect_manifest_deps",
                                dep_written,
                                "manifest-dependency inventory changed while building its exact "
                                "record array",
                                "keep graph mutation serialized through predump and retry");
        goto done;
    }

    qsort(deps, dep_count, sizeof(*deps), dep_entry_cmp);

    if (configlink_alloc(ctx, dep_count, sizeof(*key_start), "allocate_dep_key_runs",
                         (void **)&key_start) != 0 ||
        configlink_alloc(ctx, dep_count, sizeof(*key_end), "allocate_dep_key_runs",
                         (void **)&key_end) != 0 ||
        configlink_alloc(ctx, dep_count, sizeof(*key_ptr), "allocate_dep_key_runs",
                         (void **)&key_ptr) != 0 ||
        configlink_alloc(ctx, dep_count, sizeof(*key_len), "allocate_dep_key_runs",
                         (void **)&key_len) != 0 ||
        configlink_alloc(ctx, dep_count, sizeof(*key_stamp), "allocate_dep_key_runs",
                         (void **)&key_stamp) != 0) {
        goto done;
    }

    for (size_t i = 0; i < dep_count;) {
        size_t j = i;
        while (j < dep_count && strcmp(deps[j].lower, deps[i].lower) == 0) {
            j++;
        }
        key_start[key_count] = i;
        key_end[key_count] = j;
        key_ptr[key_count] = deps[i].lower;
        key_len[key_count] = strlen(deps[i].lower);
        key_stamp[key_count] = CBM_NOT_FOUND;
        /* An empty dependency name matches every qualified name, which is not a
         * relation the manifest asserts. */
        if (key_len[key_count] == 0) {
            i = j;
            continue;
        }
        key_count++;
        i = j;
    }
    if (key_count == 0) {
        rc = 0;
        goto done;
    }

    if (configlink_index_build(ctx, key_ptr, key_len, key_count, "build_dep_name_index", &index) !=
        0) {
        goto done;
    }

    memset(&scan, 0, sizeof(scan));
    scan.ctx = ctx;
    scan.gb = gb;
    scan.deps = deps;
    scan.key_start = key_start;
    scan.key_end = key_end;
    scan.key_stamp = key_stamp;
    scan.exact_key = CBM_NOT_FOUND;

    rc = 0;
    for (int ii = 0; ii < import_count; ii++) {
        const cbm_gbuf_node_t *target = cbm_gbuf_find_by_id(gb, imports[ii]->target_id);
        if (!target) {
            continue;
        }
        const cbm_gbuf_node_t *source = cbm_gbuf_find_by_id(gb, imports[ii]->source_id);
        if (!source) {
            continue;
        }

        char target_lower[CBM_SZ_256];
        lowercase_into(target_lower, sizeof(target_lower), target->name);

        scan.import_index = (int64_t)ii;
        scan.source_id = source->id;
        scan.exact_key = configlink_find_key(key_ptr, key_count, target_lower);

        if (scan.exact_key != CBM_NOT_FOUND) {
            scan.key_stamp[scan.exact_key] = scan.import_index;
            rc = dep_import_emit(&scan, (size_t)scan.exact_key, CONF_DEP_EXACT);
            if (rc != 0) {
                goto done;
            }
        }

        if (target->qualified_name) {
            char qn_lower[CBM_SZ_512];
            lowercase_into(qn_lower, sizeof(qn_lower), target->qualified_name);
            rc =
                configlink_index_scan(&index, qn_lower, strlen(qn_lower), dep_import_on_hit, &scan);
            if (rc != 0) {
                goto done;
            }
        }
    }
    rc = scan.edge_count;

done:
    configlink_index_dispose(&index);
    free(key_stamp);
    free(key_len);
    free(key_ptr);
    free(key_end);
    free(key_start);
    free(deps);
    /* gbuf node/edge arrays are borrowed — no free */
    return rc;
}

/* ── Strategy 3: Config File Path → Code String Reference ───────── */

int cbm_pipeline_pass_configlink(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    /* Early exit: check if any config files exist in the project. */
    bool has_config = false;

    const cbm_gbuf_node_t **vars_check = NULL;
    int var_check_count = 0;
    if (!has_config && cbm_gbuf_find_by_label(gb, "Variable", &vars_check, &var_check_count) == 0) {
        for (int i = 0; i < var_check_count; i++) {
            if (cbm_has_config_extension(vars_check[i]->file_path)) {
                has_config = true;
                break;
            }
        }
    }

    if (!has_config) {
        const cbm_gbuf_node_t **mods_check = NULL;
        int mod_check_count = 0;
        if (cbm_gbuf_find_by_label(gb, "Module", &mods_check, &mod_check_count) == 0) {
            for (int i = 0; i < mod_check_count; i++) {
                if (cbm_has_config_extension(mods_check[i]->file_path)) {
                    has_config = true;
                    break;
                }
            }
        }
    }

    if (!has_config) {
        cbm_log_info("configlinker.skip", "reason", "no_config_files");
        return 0;
    }

    char buf1[CBM_SZ_16];
    char buf2[CBM_SZ_16];
    char buf3[CBM_SZ_16];
    char buf4[CBM_SZ_16];

    int key_edges = strategy_key_symbols(ctx);
    if (key_edges < 0) {
        return key_edges;
    }
    snprintf(buf1, sizeof(buf1), "%d", key_edges);
    cbm_log_info("configlinker.strategy", "name", "key_symbol", "edges", buf1);

    int dep_edges = strategy_dep_imports(ctx);
    if (dep_edges < 0) {
        return dep_edges;
    }
    snprintf(buf2, sizeof(buf2), "%d", dep_edges);
    cbm_log_info("configlinker.strategy", "name", "dep_import", "edges", buf2);

    int ref_edges = 0;
    if (ctx->repo_path) {
        /* File refs: no longer reads from disk — config file path matching
         * is handled by CONFIGURES edges created during resolution. */
        ref_edges = 0;
    }
    snprintf(buf3, sizeof(buf3), "%d", ref_edges);
    cbm_log_info("configlinker.strategy", "name", "file_ref", "edges", buf3);

    if (key_edges > INT_MAX - dep_edges - ref_edges) {
        return configlink_failure(ctx, "CBM_CONFIGLINK_EDGE_COUNT_OVERFLOW", "total_config_edges",
                                  (size_t)key_edges,
                                  "config-link total edge count exceeds the pass return contract",
                                  "widen the config-link pass count contract and retry");
    }
    snprintf(buf4, sizeof(buf4), "%d", key_edges + dep_edges + ref_edges);
    cbm_log_info("configlinker.done", "total", buf4);

    return key_edges + dep_edges + ref_edges;
}
