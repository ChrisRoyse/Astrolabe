/*
 * graph_buffer.c — In-memory graph buffer for pipeline indexing.
 *
 * Uses foundation hash tables for O(1) node lookup by QN and edge dedup.
 * Uses dynamic arrays for ordered iteration and secondary indexes.
 *
 * Memory ownership: each node/edge is individually heap-allocated so that
 * pointers stored in hash tables remain stable when the pointer-array grows.
 * The buffer frees everything in cbm_gbuf_free().
 */
#include "foundation/constants.h"

enum {
    GB_ERR = -1,
    GB_COL_2 = 2,
    GB_COL_3 = 3,
    GB_COL_4 = 4,
    GB_COL_5 = 5,
    GB_COL_6 = 6,
    GB_COL_7 = 7,
    GB_URL_PATH_PREFIX = 12, /* strlen(""url_path":"") */
    GB_MIN_FOR_DEDUP = 2,    /* need at least 2 vectors to sort+dedup */
    GB_DEDUP_LOOKAHEAD = 1,  /* compare current with next element */
};
#include "graph_buffer/graph_buffer.h"
#include "graph_buffer/load_error.h"
#include <yyjson/yyjson.h> // url_path extraction must match json_extract semantics
#include "store/store.h"
#include "sqlite_writer.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h" /* cbm_unlink — #579 fail-closed torn-dump removal */
#include "foundation/log.h"
#include "foundation/dyn_array.h"
#include "foundation/profile.h"
#include "foundation/mem.h"
#include "foundation/sha256.h"
#include <sqlite3.h>

#include <limits.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h> // int64_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strdup
#include <time.h>

static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

#define AMBIGUOUS_QN intptr_to_ptr(1)

static void hash_frame(cbm_sha256_ctx *ctx, const void *data, size_t len) {
    uint8_t n[8];
    uint64_t value = (uint64_t)len;
    for (int i = 0; i < 8; i++) {
        n[i] = (uint8_t)(value >> (i * 8));
    }
    cbm_sha256_update(ctx, n, sizeof(n));
    if (len > 0) {
        cbm_sha256_update(ctx, data, len);
    }
}

static void hash_u64(cbm_sha256_ctx *ctx, uint64_t value) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)(value >> (i * 8));
    }
    cbm_sha256_update(ctx, bytes, sizeof(bytes));
}

static char *sha256_hex_alloc(const uint8_t *bytes, size_t len) {
    cbm_sha256_ctx ctx;
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    char *hex = malloc(CBM_SHA256_HEX_LEN + 1);
    if (!hex) {
        return NULL;
    }
    cbm_sha256_init(&ctx);
    if (len > 0) {
        cbm_sha256_update(&ctx, bytes, len);
    }
    cbm_sha256_final(&ctx, digest);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[CBM_SHA256_HEX_LEN] = '\0';
    return hex;
}

/* Identity-bearing text has one canonical absence representation: an empty
 * UTF-8 byte sequence. JSON properties are a separate domain whose absent
 * value is the empty object document. Keep these conversions named and at
 * domain boundaries so hashing, retained state, persistence, and reload all
 * observe the same bytes. */
static const char *canonical_identity_text(const char *text) {
    return text ? text : "";
}

static const char *canonical_properties_json(const char *properties_json) {
    return properties_json ? properties_json : "{}";
}

static char *make_atom_id(const char *project, const char *label, const char *name,
                          const char *qualified_name, const char *file_path, int start_line,
                          int end_line, bool source_present, const uint8_t *source_bytes,
                          size_t source_len, uint64_t start_byte, uint64_t end_byte) {
    cbm_sha256_ctx ctx;
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    char *hex = malloc(CBM_SHA256_HEX_LEN + 1);
    if (!hex) {
        return NULL;
    }
    cbm_sha256_init(&ctx);
    const char *parts[] = {"astrolabe.cbm.atom.v2",
                           canonical_identity_text(project),
                           canonical_identity_text(label),
                           canonical_identity_text(name),
                           canonical_identity_text(qualified_name),
                           canonical_identity_text(file_path)};
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        hash_frame(&ctx, parts[i], strlen(parts[i]));
    }
    const uint8_t present = source_present ? 1 : 0;
    hash_frame(&ctx, &present, sizeof(present));
    hash_frame(&ctx, source_bytes, source_len);
    hash_u64(&ctx, (uint64_t)(int64_t)start_line);
    hash_u64(&ctx, (uint64_t)(int64_t)end_line);
    hash_u64(&ctx, start_byte);
    hash_u64(&ctx, end_byte);
    cbm_sha256_final(&ctx, digest);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[CBM_SHA256_HEX_LEN] = '\0';
    return hex;
}

static bool valid_properties_object(const char *properties_json) {
    const char *json = canonical_properties_json(properties_json);
    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    if (!doc) {
        return false;
    }
    bool valid = yyjson_is_obj(yyjson_doc_get_root(doc));
    yyjson_doc_free(doc);
    return valid;
}

static bool valid_utf8_text(const char *text) {
    if (!text) {
        return true;
    }
    const unsigned char *p = (const unsigned char *)text;
    size_t remaining = strlen(text);
    while (remaining > 0) {
        if (*p <= 0x7f) {
            p++;
            remaining--;
        } else if (remaining >= 2 && *p >= 0xc2 && *p <= 0xdf && (p[1] & 0xc0) == 0x80) {
            p += 2;
            remaining -= 2;
        } else if (remaining >= 3 && *p == 0xe0 && p[1] >= 0xa0 && p[1] <= 0xbf &&
                   (p[2] & 0xc0) == 0x80) {
            p += 3;
            remaining -= 3;
        } else if (remaining >= 3 && ((*p >= 0xe1 && *p <= 0xec) || (*p >= 0xee && *p <= 0xef)) &&
                   (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80) {
            p += 3;
            remaining -= 3;
        } else if (remaining >= 3 && *p == 0xed && p[1] >= 0x80 && p[1] <= 0x9f &&
                   (p[2] & 0xc0) == 0x80) {
            p += 3;
            remaining -= 3;
        } else if (remaining >= 4 && *p == 0xf0 && p[1] >= 0x90 && p[1] <= 0xbf &&
                   (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) {
            p += 4;
            remaining -= 4;
        } else if (remaining >= 4 && *p >= 0xf1 && *p <= 0xf3 && (p[1] & 0xc0) == 0x80 &&
                   (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) {
            p += 4;
            remaining -= 4;
        } else if (remaining >= 4 && *p == 0xf4 && p[1] >= 0x80 && p[1] <= 0x8f &&
                   (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) {
            p += 4;
            remaining -= 4;
        } else {
            return false;
        }
    }
    return true;
}

/* ── Internal types ──────────────────────────────────────────────── */

/* Edge key for dedup hash table — composite key as string "srcID:tgtID:type",
 * plus ":local_name" for IMPORTS edges (#768). 256 bytes fit two int64s, the
 * type and a ~200-char local_name verbatim; longer local_names are re-keyed
 * with a hash of the full name in make_edge_key (never silently truncated). */
#define EDGE_KEY_BUF CBM_SZ_256

/* Per-type or per-key edge list stored in hash tables as values */
typedef CBM_DYN_ARRAY(const cbm_gbuf_edge_t *) edge_ptr_array_t;

/* Per-label or per-name node list */
typedef CBM_DYN_ARRAY(const cbm_gbuf_node_t *) node_ptr_array_t;

struct cbm_gbuf {
    char *project;
    char *root_path;
    int64_t next_id;
    _Atomic int64_t *shared_ids; /* NULL = use next_id, non-NULL = atomic source */

    /* Node storage: array of pointers to individually heap-allocated nodes.
     * This ensures pointers stored in hash tables remain valid when the
     * pointer array reallocs (only the pointer array moves, not the nodes). */
    CBM_DYN_ARRAY(cbm_gbuf_node_t *) nodes;

    /* Stable atom identity is primary. QN is a non-unique lookup key: its
     * value is either the sole node or the ambiguity sentinel. */
    CBMHashTable *node_by_atom;
    CBMHashTable *node_by_qn;
    _Atomic bool resolution_failed;
    /* Primary index: "id" string → cbm_gbuf_node_t* */
    /* Dense id → node array (ids are sequential from alloc_next_id, shared
     * with edges → holes where edges took ids). Replaces a hash table keyed
     * on STRDUP'D DECIMAL STRINGS of the id — ~0.44 GB of buckets + key
     * strings at kernel scale, plus a snprintf+strdup+hash on every one of
     * the ~18 hot find_by_id call sites. */
    cbm_gbuf_node_t **by_id;
    int64_t by_id_cap;

    /* Secondary node indexes */
    CBMHashTable *nodes_by_label; /* key: label, value: (node_ptr_array_t*) */
    CBMHashTable *nodes_by_name;  /* key: name, value: (node_ptr_array_t*) */

    /* Edge storage: array of pointers to individually heap-allocated edges */
    CBM_DYN_ARRAY(cbm_gbuf_edge_t *) edges;

    /* Edge dedup index: "srcID:tgtID:type" → cbm_gbuf_edge_t* */
    CBMHashTable *edge_by_key;

    /* Edge secondary indexes: composite keys → edge_ptr_array_t */
    CBMHashTable *edges_by_source_type; /* "srcID:type" → edge_ptr_array_t* */
    CBMHashTable *edges_by_target_type; /* "tgtID:type" → edge_ptr_array_t* */
    CBMHashTable *edges_by_type;        /* "type" → edge_ptr_array_t* */

    /* String intern pool for highly-repetitive fields (node label/file_path,
     * edge type). Maps string content → owned canonical copy, collapsing
     * O(nodes+edges) duplicate allocations to O(distinct). The pool owns the
     * copies; interned pointers are stable for the buffer lifetime and are NOT
     * freed by free_node_strings/free_edge_strings — only once in cbm_gbuf_free. */
    CBMHashTable *intern_pool;

    /* Vector storage for semantic embeddings (filled by pass_semantic_edges,
     * consumed by cbm_write_db during dump). */
    CBMDumpVector *dump_vectors;
    int dump_vector_count;
    int dump_vector_cap;

    /* Token vector storage for enriched RI vectors (query-time lookup). */
    CBMDumpTokenVec *dump_token_vecs;
    int dump_token_vec_count;
    int dump_token_vec_cap;

    /* Optional dump-row sink. NULL callbacks preserve normal dump behavior. */
    cbm_gbuf_row_node_sink_fn row_node_sink;
    cbm_gbuf_row_edge_sink_fn row_edge_sink;
    void *row_sink_ctx;
};

/* ── Helpers ─────────────────────────────────────────────────────── */

static void gbuf_index_failure(cbm_gbuf_t *gb, const char *operation, const char *key) {
    if (gb) {
        atomic_store(&gb->resolution_failed, true);
    }
    cbm_log_error("gbuf.index_insert_failed", "code", "CBM_GRAPH_INDEX_INSERT_FAILED", "component",
                  "graph_buffer", "operation", operation ? operation : "", "key", key ? key : "",
                  "message", "authoritative graph index insertion or growth failed", "remediation",
                  "free memory or reduce the indexed repository size, then retry; the store was "
                  "not committed");
}

static bool gbuf_ht_set(cbm_gbuf_t *gb, CBMHashTable *ht, const char *key, void *value,
                        void **previous_out, const char *operation) {
    if (cbm_ht_set_checked(ht, key, value, previous_out)) {
        return true;
    }
    gbuf_index_failure(gb, operation, key);
    return false;
}

static char *heap_strdup(const char *s) {
    return s ? strdup(s) : NULL;
}

/* Intern a repetitive string into the buffer's pool: identical content collapses
 * to a single heap copy owned by the pool. Callers must pass their domain's
 * already-canonical, non-NULL bytes. The returned pointer is stable for the
 * buffer's lifetime and must never be freed or mutated by callers. */
static const char *gb_intern(cbm_gbuf_t *gb, const char *s) {
    if (!gb || !s) {
        gbuf_index_failure(gb, "intern.input", "");
        return NULL;
    }
    const char *key = s;
    const char *found = cbm_ht_get(gb->intern_pool, key);
    if (found) {
        return found;
    }
    char *copy = strdup(key);
    if (!copy) {
        gbuf_index_failure(gb, "intern.copy", key);
        return NULL;
    }
    if (!gbuf_ht_set(gb, gb->intern_pool, copy, copy, NULL, "intern.insert")) {
        free(copy);
        return NULL;
    }
    return copy;
}

static void make_id_key(char *buf, size_t bufsz, int64_t id) {
    snprintf(buf, bufsz, "%lld", (long long)id);
}

/* FNV-1a 64-bit over a byte slice — for re-keying oversized local_names. */
static uint64_t fnv1a64(const char *s, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* IMPORTS edges carry exactly one imported symbol's local_name (#768): two
 * named imports from the same specifier resolve to the same (source,
 * target) pair but are distinct symbols. Key on local_name too so the
 * second import doesn't dedup-collide with and overwrite the first —
 * every pass that walks IMPORTS edges (pass_calls.c, pass_usages.c,
 * pass_semantic.c, pass_lsp_cross.c) expects one local_name per edge, so
 * losing an edge here silently breaks cross-file call resolution for
 * whichever symbol got dropped, not just "who imports X" queries. Other
 * edge types keep the plain (source,target,type) key: collapsing repeat
 * edges of the same type between the same two nodes (e.g. multiple call
 * sites) into one is the existing, intended dedup behavior there.
 *
 * A local_name too long for the key buffer is re-keyed with an FNV-1a hash
 * of the FULL name instead of being truncated — a truncated key would
 * collide two long names sharing a prefix and silently drop an edge again.
 * The hash key is prefixed with byte 0x01, which cannot appear in the raw
 * JSON slice (control characters must be \u-escaped in JSON), so hash keys
 * can never collide with verbatim keys. */
static void make_edge_key(char *buf, size_t bufsz, int64_t src, int64_t tgt, const char *type,
                          const char *properties_json) {
    if (properties_json && strcmp(type, "IMPORTS") == 0) {
        static const char local_name_key[] = "\"local_name\":\"";
        const char *ln = strstr(properties_json, local_name_key);
        if (ln) {
            ln += sizeof(local_name_key) - 1;
            const char *end = strchr(ln, '"');
            size_t ln_len = end ? (size_t)(end - ln) : strlen(ln);
            int n = snprintf(buf, bufsz, "%lld:%lld:%s:%.*s", (long long)src, (long long)tgt, type,
                             (int)ln_len, ln);
            if (n < 0 || (size_t)n >= bufsz) {
                snprintf(buf, bufsz, "%lld:%lld:%s:\x01%016llx", (long long)src, (long long)tgt,
                         type, (unsigned long long)fnv1a64(ln, ln_len));
            }
            return;
        }
    }
    snprintf(buf, bufsz, "%lld:%lld:%s", (long long)src, (long long)tgt, type);
}

static void make_src_type_key(char *buf, size_t bufsz, int64_t src, const char *type) {
    snprintf(buf, bufsz, "%lld:%s", (long long)src, type);
}

/* Get or create a node_ptr_array_t in a hash table */
static node_ptr_array_t *get_or_create_node_array(cbm_gbuf_t *gb, CBMHashTable *ht, const char *key,
                                                  const char *operation) {
    node_ptr_array_t *arr = cbm_ht_get(ht, key);
    if (!arr) {
        arr = calloc(CBM_ALLOC_ONE, sizeof(node_ptr_array_t));
        char *owned_key = strdup(key);
        if (!arr || !owned_key) {
            free(arr);
            free(owned_key);
            gbuf_index_failure(gb, operation, key);
            return NULL;
        }
        if (!gbuf_ht_set(gb, ht, owned_key, arr, NULL, operation)) {
            free(owned_key);
            free(arr);
            return NULL;
        }
    }
    return arr;
}

/* Get or create an edge_ptr_array_t in a hash table */
static edge_ptr_array_t *get_or_create_edge_array(cbm_gbuf_t *gb, CBMHashTable *ht, const char *key,
                                                  const char *operation) {
    edge_ptr_array_t *arr = cbm_ht_get(ht, key);
    if (!arr) {
        arr = calloc(CBM_ALLOC_ONE, sizeof(edge_ptr_array_t));
        char *owned_key = strdup(key);
        if (!arr || !owned_key) {
            free(arr);
            free(owned_key);
            gbuf_index_failure(gb, operation, key);
            return NULL;
        }
        if (!gbuf_ht_set(gb, ht, owned_key, arr, NULL, operation)) {
            free(owned_key);
            free(arr);
            return NULL;
        }
    }
    return arr;
}

/* Free a node_ptr_array_t (callback for hash table iteration) */
static void free_node_array(const char *key, void *value, void *ud) {
    (void)ud;
    node_ptr_array_t *arr = value;
    if (arr) {
        cbm_da_free(arr);
        free(arr);
    }
    free((void *)key);
}

/* Free an edge_ptr_array_t (callback) */
static void free_edge_array(const char *key, void *value, void *ud) {
    (void)ud;
    edge_ptr_array_t *arr = value;
    if (arr) {
        cbm_da_free(arr);
        free(arr);
    }
    free((void *)key);
}

/* Free keys only (for edge_by_key, deleted_set) */
static void free_key_only(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    free((void *)key);
}

/* Free a single node's owned strings. label and file_path are interned
 * (pool-owned) — NOT freed here; the pool frees them once in cbm_gbuf_free. */
static void free_node_strings(cbm_gbuf_node_t *n) {
    free(n->name);
    free(n->atom_id);
    free(n->qualified_name);
    free(n->source_bytes);
    free(n->source_sha256);
    free(n->properties_json);
}

/* Free a single edge's owned strings. type is interned (pool-owned) — NOT
 * freed here; the pool frees it once in cbm_gbuf_free. */
static void free_edge_strings(cbm_gbuf_edge_t *e) {
    free(e->properties_json);
}

/* Allocate the next buffer-local or shared-atomic ID. */
static int64_t alloc_next_id(cbm_gbuf_t *gb) {
    if (gb->shared_ids) {
        return atomic_fetch_add_explicit(gb->shared_ids, SKIP_ONE, memory_order_relaxed);
    }
    return gb->next_id++;
}

/* Swap-remove an edge from a pointer array by ID. */
static void remove_edge_from_ptr_array(edge_ptr_array_t *arr, int64_t edge_id) {
    if (!arr) {
        return;
    }
    for (int j = 0; j < arr->count; j++) {
        if (arr->items[j]->id == edge_id) {
            arr->items[j] = arr->items[--arr->count];
            return;
        }
    }
}

/* Swap-remove a node from a node_ptr_array by ID. */
static void remove_node_from_ptr_array(node_ptr_array_t *arr, int64_t node_id) {
    if (!arr) {
        return;
    }
    for (int j = 0; j < arr->count; j++) {
        if (arr->items[j]->id == node_id) {
            arr->items[j] = arr->items[--arr->count];
            return;
        }
    }
}

/* Remove an edge from all indexes (dedup + source_type + target_type + type). */
static void unindex_edge(cbm_gbuf_t *gb, const cbm_gbuf_edge_t *e) {
    char key[EDGE_KEY_BUF];

    make_edge_key(key, sizeof(key), e->source_id, e->target_id, e->type, e->properties_json);
    const char *ekey = cbm_ht_get_key(gb->edge_by_key, key);
    cbm_ht_delete(gb->edge_by_key, key);
    free((void *)ekey);

    make_src_type_key(key, sizeof(key), e->source_id, e->type);
    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_source_type, key), e->id);

    make_src_type_key(key, sizeof(key), e->target_id, e->type);
    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_target_type, key), e->id);

    remove_edge_from_ptr_array(cbm_ht_get(gb->edges_by_type, e->type), e->id);
}

/* Cascade-delete all edges touching nodes in deleted_set. */
static void cascade_delete_edges(cbm_gbuf_t *gb, CBMHashTable *deleted_set) {
    int write_idx = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        char src_id[CBM_SZ_32];
        char tgt_id[CBM_SZ_32];
        make_id_key(src_id, sizeof(src_id), e->source_id);
        make_id_key(tgt_id, sizeof(tgt_id), e->target_id);

        if (cbm_ht_get(deleted_set, src_id) || cbm_ht_get(deleted_set, tgt_id)) {
            unindex_edge(gb, e);
            free_edge_strings(e);
            free(e);
        } else {
            gb->edges.items[write_idx++] = gb->edges.items[i];
        }
    }
    gb->edges.count = write_idx;
}

/* Register a node in primary (QN, ID) and secondary (label, name) indexes. */
static bool register_node_in_indexes(cbm_gbuf_t *gb, cbm_gbuf_node_t *node) {
    if (!gbuf_ht_set(gb, gb->node_by_atom, node->atom_id, node, NULL, "node_by_atom.insert")) {
        return false;
    }
    void *by_qn = cbm_ht_get(gb->node_by_qn, node->qualified_name);
    if (!by_qn) {
        if (!gbuf_ht_set(gb, gb->node_by_qn, node->qualified_name, node, NULL,
                         "node_by_qn.insert")) {
            return false;
        }
    } else if (by_qn != node) {
        if (!gbuf_ht_set(gb, gb->node_by_qn, node->qualified_name, AMBIGUOUS_QN, NULL,
                         "node_by_qn.mark_ambiguous")) {
            return false;
        }
    }

    if (node->id >= gb->by_id_cap) {
        int64_t nc = gb->by_id_cap > 0 ? gb->by_id_cap : CBM_SZ_1K;
        while (nc <= node->id) {
            nc *= 2;
        }
        cbm_gbuf_node_t **grown = realloc(gb->by_id, (size_t)nc * sizeof(*grown));
        if (!grown) {
            gbuf_index_failure(gb, "node_by_id.grow", node->atom_id);
            return false;
        }
        memset(grown + gb->by_id_cap, 0, (size_t)(nc - gb->by_id_cap) * sizeof(*grown));
        gb->by_id = grown;
        gb->by_id_cap = nc;
    }
    if (node->id >= 0 && node->id < gb->by_id_cap) {
        gb->by_id[node->id] = node;
    }

    node_ptr_array_t *by_label = get_or_create_node_array(
        gb, gb->nodes_by_label, node->label ? node->label : "", "nodes_by_label.insert");
    if (!by_label || !cbm_da_push_checked(by_label, (const cbm_gbuf_node_t *)node)) {
        gbuf_index_failure(gb, "nodes_by_label.append", node->label);
        return false;
    }

    node_ptr_array_t *by_name = get_or_create_node_array(
        gb, gb->nodes_by_name, node->name ? node->name : "", "nodes_by_name.insert");
    if (!by_name || !cbm_da_push_checked(by_name, (const cbm_gbuf_node_t *)node)) {
        gbuf_index_failure(gb, "nodes_by_name.append", node->name);
        return false;
    }
    return true;
}

static bool node_is_live(const cbm_gbuf_t *gb, const cbm_gbuf_node_t *node) {
    return gb && node && node->atom_id && cbm_ht_get(gb->node_by_atom, node->atom_id) == node;
}

static void rebuild_qn_index(cbm_gbuf_t *gb) {
    cbm_ht_free(gb->node_by_qn);
    gb->node_by_qn = cbm_ht_create(CBM_SZ_256);
    if (!gb->node_by_qn) {
        gbuf_index_failure(gb, "node_by_qn.create", "");
        return;
    }
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *node = gb->nodes.items[i];
        if (!node_is_live(gb, node) || !node->qualified_name) {
            continue;
        }
        void *existing = cbm_ht_get(gb->node_by_qn, node->qualified_name);
        if (!gbuf_ht_set(gb, gb->node_by_qn, node->qualified_name,
                         existing && existing != node ? AMBIGUOUS_QN : node, NULL,
                         "node_by_qn.rebuild")) {
            return;
        }
    }
}

/* Push an edge pointer into a dynamic array (wraps macro to reduce CC contribution). */
static bool edge_array_push(edge_ptr_array_t *arr, const cbm_gbuf_edge_t *edge) {
    return cbm_da_push_checked(arr, edge);
}

/* Index an edge by one key into a hash table bucket. */
static bool index_edge_by_key(cbm_gbuf_t *gb, CBMHashTable *ht, const char *key,
                              cbm_gbuf_edge_t *edge, const char *operation) {
    edge_ptr_array_t *arr = get_or_create_edge_array(gb, ht, key, operation);
    if (!arr || !edge_array_push(arr, (const cbm_gbuf_edge_t *)edge)) {
        gbuf_index_failure(gb, operation, key);
        return false;
    }
    return true;
}

/* Register an edge in secondary indexes (source_type, target_type, type). */
static bool register_edge_in_indexes(cbm_gbuf_t *gb, cbm_gbuf_edge_t *edge) {
    char key[EDGE_KEY_BUF];

    make_src_type_key(key, sizeof(key), edge->source_id, edge->type);
    if (!index_edge_by_key(gb, gb->edges_by_source_type, key, edge,
                           "edges_by_source_type.append")) {
        return false;
    }

    make_src_type_key(key, sizeof(key), edge->target_id, edge->type);
    if (!index_edge_by_key(gb, gb->edges_by_target_type, key, edge,
                           "edges_by_target_type.append")) {
        return false;
    }

    return index_edge_by_key(gb, gb->edges_by_type, edge->type, edge, "edges_by_type.append");
}

/* Rebuild edge secondary indexes from scratch (after bulk deletion). */
static void rebuild_edge_secondary_indexes(cbm_gbuf_t *gb) {
    cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_source_type);
    cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_target_type);
    cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_type);

    gb->edges_by_source_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_target_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_type = cbm_ht_create(CBM_SZ_32);
    if (!gb->edges_by_source_type || !gb->edges_by_target_type || !gb->edges_by_type) {
        gbuf_index_failure(gb, "edge_secondary_indexes.create", "");
        return;
    }

    for (int i = 0; i < gb->edges.count; i++) {
        if (!register_edge_in_indexes(gb, gb->edges.items[i])) {
            return;
        }
    }
}

/* Release all lookup hash tables (used by dump after building arrays). */
static void release_gbuf_indexes(cbm_gbuf_t *gb) {
    cbm_ht_free(gb->node_by_atom);
    gb->node_by_atom = NULL;
    cbm_ht_free(gb->node_by_qn);
    gb->node_by_qn = NULL;
    free(gb->by_id);
    gb->by_id = NULL;
    gb->by_id_cap = 0;
    cbm_ht_foreach(gb->nodes_by_label, free_node_array, NULL);
    cbm_ht_free(gb->nodes_by_label);
    gb->nodes_by_label = NULL;
    cbm_ht_foreach(gb->nodes_by_name, free_node_array, NULL);
    cbm_ht_free(gb->nodes_by_name);
    gb->nodes_by_name = NULL;
    cbm_ht_foreach(gb->edge_by_key, free_key_only, NULL);
    cbm_ht_free(gb->edge_by_key);
    gb->edge_by_key = NULL;
    cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_source_type);
    gb->edges_by_source_type = NULL;
    cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_target_type);
    gb->edges_by_target_type = NULL;
    cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
    cbm_ht_free(gb->edges_by_type);
    gb->edges_by_type = NULL;
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

cbm_gbuf_t *cbm_gbuf_new(const char *project, const char *root_path) {
    if (!project || !project[0] || !valid_utf8_text(project) || !valid_utf8_text(root_path)) {
        cbm_log_error("gbuf.create_refused", "code", "CBM_GRAPH_IDENTITY_TEXT_INVALID", "project",
                      project ? project : "", "message",
                      "project or root identity is empty or not valid UTF-8", "remediation",
                      "supply a non-empty UTF-8 project name and UTF-8 root path");
        return NULL;
    }
    cbm_gbuf_t *gb = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_t));
    if (!gb) {
        return NULL;
    }

    gb->project = strdup(project ? project : "");
    gb->root_path = strdup(root_path ? root_path : "");
    gb->next_id = SKIP_ONE;
    gb->shared_ids = NULL;

    gb->node_by_atom = cbm_ht_create(CBM_SZ_256);
    gb->node_by_qn = cbm_ht_create(CBM_SZ_256);
    gb->by_id = NULL;
    gb->by_id_cap = 0;
    gb->nodes_by_label = cbm_ht_create(CBM_SZ_32);
    gb->nodes_by_name = cbm_ht_create(CBM_SZ_256);

    gb->edge_by_key = cbm_ht_create(CBM_SZ_512);
    gb->edges_by_source_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_target_type = cbm_ht_create(CBM_SZ_256);
    gb->edges_by_type = cbm_ht_create(CBM_SZ_32);

    gb->intern_pool = cbm_ht_create(CBM_SZ_1K);

    if (!gb->project || !gb->root_path || !gb->node_by_atom || !gb->node_by_qn ||
        !gb->nodes_by_label || !gb->nodes_by_name || !gb->edge_by_key ||
        !gb->edges_by_source_type || !gb->edges_by_target_type || !gb->edges_by_type ||
        !gb->intern_pool) {
        cbm_log_error("gbuf.create_failed", "code", "CBM_GRAPH_ALLOC_FAILED", "project", project,
                      "message", "graph-buffer state could not be fully allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        cbm_gbuf_free(gb);
        return NULL;
    }

    return gb;
}

cbm_gbuf_t *cbm_gbuf_new_shared_ids(const char *project, const char *root_path,
                                    _Atomic int64_t *id_source) {
    cbm_gbuf_t *gb = cbm_gbuf_new(project, root_path);
    if (gb && id_source) {
        gb->shared_ids = id_source;
    }
    return gb;
}

void cbm_gbuf_free(cbm_gbuf_t *gb) {
    if (!gb) {
        return;
    }

    /* Free each individually-allocated node */
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        free_node_strings(n);
        free(n);
    }
    cbm_da_free(&gb->nodes);

    /* Free each individually-allocated edge */
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        free_edge_strings(e);
        free(e);
    }
    cbm_da_free(&gb->edges);

    /* Free hash tables — may be NULL if already released by dump_to_sqlite */
    if (gb->node_by_atom) {
        cbm_ht_free(gb->node_by_atom);
    }
    if (gb->node_by_qn) {
        cbm_ht_free(gb->node_by_qn);
    }
    free(gb->by_id);
    if (gb->nodes_by_label) {
        cbm_ht_foreach(gb->nodes_by_label, free_node_array, NULL);
        cbm_ht_free(gb->nodes_by_label);
    }
    if (gb->nodes_by_name) {
        cbm_ht_foreach(gb->nodes_by_name, free_node_array, NULL);
        cbm_ht_free(gb->nodes_by_name);
    }
    if (gb->edge_by_key) {
        cbm_ht_foreach(gb->edge_by_key, free_key_only, NULL);
        cbm_ht_free(gb->edge_by_key);
    }
    if (gb->edges_by_source_type) {
        cbm_ht_foreach(gb->edges_by_source_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_source_type);
    }
    if (gb->edges_by_target_type) {
        cbm_ht_foreach(gb->edges_by_target_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_target_type);
    }
    if (gb->edges_by_type) {
        cbm_ht_foreach(gb->edges_by_type, free_edge_array, NULL);
        cbm_ht_free(gb->edges_by_type);
    }

    /* Free vector storage */
    for (int i = 0; i < gb->dump_vector_count; i++) {
        free((void *)gb->dump_vectors[i].vector);
    }
    free(gb->dump_vectors);

    /* Free token vector storage */
    for (int i = 0; i < gb->dump_token_vec_count; i++) {
        free((void *)gb->dump_token_vecs[i].token);
        free((void *)gb->dump_token_vecs[i].vector);
    }
    free(gb->dump_token_vecs);

    /* Free interned strings (node label/file_path, edge type) — pool owns one
     * copy each (key == value), freed exactly once via free_key_only. Done after
     * nodes/edges since they borrowed these pointers. */
    if (gb->intern_pool) {
        cbm_ht_foreach(gb->intern_pool, free_key_only, NULL);
        cbm_ht_free(gb->intern_pool);
    }

    free(gb->project);
    free(gb->root_path);
    free(gb);
}

/* ── Vector storage ──────────────────────────────────────────────── */

int cbm_gbuf_store_vector(cbm_gbuf_t *gb, int64_t node_id, const uint8_t *vector, int vector_len) {
    if (!gb || !vector || vector_len <= 0) {
        return GB_ERR;
    }
    enum { VEC_INIT_CAP = 1024, VEC_GROW = 2 };
    if (gb->dump_vector_count >= gb->dump_vector_cap) {
        int new_cap =
            gb->dump_vector_cap < VEC_INIT_CAP ? VEC_INIT_CAP : gb->dump_vector_cap * VEC_GROW;
        CBMDumpVector *grown = realloc(gb->dump_vectors, (size_t)new_cap * sizeof(CBMDumpVector));
        if (!grown) {
            return GB_ERR;
        }
        gb->dump_vectors = grown;
        gb->dump_vector_cap = new_cap;
    }
    /* Copy vector data */
    uint8_t *vec_copy = malloc((size_t)vector_len);
    if (!vec_copy) {
        return GB_ERR;
    }
    memcpy(vec_copy, vector, (size_t)vector_len);

    gb->dump_vectors[gb->dump_vector_count++] = (CBMDumpVector){
        .node_id = node_id,
        .project = gb->project, /* borrowed — valid until gbuf_free */
        .vector = vec_copy,
        .vector_len = vector_len,
    };
    return 0;
}

int cbm_gbuf_store_token_vector(cbm_gbuf_t *gb, const char *token, const uint8_t *vector,
                                int vector_len, float idf) {
    if (!gb || !token || !valid_utf8_text(token) || !vector || vector_len <= 0) {
        cbm_log_error("gbuf.token_vector_refused", "code", "CBM_TOKEN_VECTOR_INPUT_INVALID",
                      "message",
                      "token vectors require valid UTF-8 text, non-empty vector bytes, and a "
                      "live graph buffer",
                      NULL);
        return GB_ERR;
    }
    enum { TV_INIT_CAP = 256, TV_GROW = 2 };
    if (gb->dump_token_vec_count >= gb->dump_token_vec_cap) {
        int new_cap =
            gb->dump_token_vec_cap < TV_INIT_CAP ? TV_INIT_CAP : gb->dump_token_vec_cap * TV_GROW;
        CBMDumpTokenVec *grown =
            realloc(gb->dump_token_vecs, (size_t)new_cap * sizeof(CBMDumpTokenVec));
        if (!grown) {
            return GB_ERR;
        }
        gb->dump_token_vecs = grown;
        gb->dump_token_vec_cap = new_cap;
    }
    uint8_t *vec_copy = malloc((size_t)vector_len);
    if (!vec_copy) {
        cbm_log_error("gbuf.token_vector_alloc_failed", "code", "CBM_TOKEN_VECTOR_ALLOC_FAILED",
                      "field", "vector", NULL);
        return GB_ERR;
    }
    memcpy(vec_copy, vector, (size_t)vector_len);
    char *token_copy = heap_strdup(token);
    if (!token_copy) {
        free(vec_copy);
        cbm_log_error("gbuf.token_vector_alloc_failed", "code", "CBM_TOKEN_VECTOR_ALLOC_FAILED",
                      "field", "token", NULL);
        return GB_ERR;
    }

    int idx = gb->dump_token_vec_count;
    gb->dump_token_vecs[idx] = (CBMDumpTokenVec){
        .id = idx + SKIP_ONE, /* 1-based sequential ID */
        .project = gb->project,
        .token = token_copy,
        .vector = vec_copy,
        .vector_len = vector_len,
        .idf = idf,
    };
    gb->dump_token_vec_count++;
    return 0;
}

/* ── ID accessors ────────────────────────────────────────────────── */

int64_t cbm_gbuf_next_id(const cbm_gbuf_t *gb) {
    if (!gb) {
        return SKIP_ONE;
    }
    if (gb->shared_ids) {
        return atomic_load(gb->shared_ids);
    }
    return gb->next_id;
}

void cbm_gbuf_set_next_id(cbm_gbuf_t *gb, int64_t next_id) {
    if (!gb) {
        return;
    }
    gb->next_id = next_id;
}

/* ── Node operations ─────────────────────────────────────────────── */

static bool same_atom_payload(const cbm_gbuf_node_t *node, const char *label, const char *name,
                              const char *qualified_name, const char *file_path, int start_line,
                              int end_line, bool source_present, const uint8_t *source_bytes,
                              size_t source_len, uint64_t start_byte, uint64_t end_byte) {
    return node &&
           strcmp(canonical_identity_text(node->label), canonical_identity_text(label)) == 0 &&
           strcmp(canonical_identity_text(node->name), canonical_identity_text(name)) == 0 &&
           strcmp(canonical_identity_text(node->qualified_name),
                  canonical_identity_text(qualified_name)) == 0 &&
           strcmp(canonical_identity_text(node->file_path), canonical_identity_text(file_path)) ==
               0 &&
           node->start_line == start_line && node->end_line == end_line &&
           node->source_present == source_present && node->source_len == source_len &&
           node->start_byte == start_byte && node->end_byte == end_byte &&
           (source_len == 0 || memcmp(node->source_bytes, source_bytes, source_len) == 0);
}

static int64_t upsert_node_internal(cbm_gbuf_t *gb, const char *label, const char *name,
                                    const char *qualified_name, const char *file_path,
                                    int start_line, int end_line, bool source_present,
                                    const uint8_t *source_bytes, size_t source_len,
                                    uint64_t start_byte, uint64_t end_byte,
                                    const char *properties_json) {
    const char *canonical_file_path = canonical_identity_text(file_path);
    const char *json = canonical_properties_json(properties_json);
    if (!gb || !label || !label[0] || !name || !qualified_name || !qualified_name[0] ||
        (source_present && source_len > 0 && !source_bytes) || end_byte < start_byte ||
        (source_present && end_byte - start_byte != source_len) ||
        (!source_present && (source_len != 0 || start_byte != 0 || end_byte != 0)) ||
        !valid_utf8_text(label) || !valid_utf8_text(name) || !valid_utf8_text(qualified_name) ||
        !valid_utf8_text(canonical_file_path) || !valid_properties_object(json)) {
        if (gb) {
            atomic_store(&gb->resolution_failed, true);
        }
        cbm_log_error("gbuf.node_refused", "code", "CBM_NODE_CANONICAL_INPUT_INVALID",
                      "qualified_name", qualified_name ? qualified_name : "", "message",
                      "node identity text, source span, or properties JSON is malformed",
                      "remediation",
                      "supply valid UTF-8 identity text, object JSON, and byte-exact end-exclusive "
                      "source spans");
        return 0;
    }

    char *atom_id =
        make_atom_id(gb->project, label, name, qualified_name, canonical_file_path, start_line,
                     end_line, source_present, source_bytes, source_len, start_byte, end_byte);
    if (!atom_id) {
        atomic_store(&gb->resolution_failed, true);
        cbm_log_error("gbuf.node_alloc_failed", "code", "CBM_NODE_ATOM_ALLOC_FAILED", "message",
                      "stable source atom allocation failed", "remediation",
                      "free memory or reduce the indexed repository size, then retry");
        return 0;
    }

    /* Exact source identity is the only upsert key. A matching atom may receive
     * derived-property enrichment, but immutable identity/source fields never mutate. */
    cbm_gbuf_node_t *existing = cbm_ht_get(gb->node_by_atom, atom_id);
    if (existing) {
        bool equal = same_atom_payload(existing, label, name, qualified_name, canonical_file_path,
                                       start_line, end_line, source_present, source_bytes,
                                       source_len, start_byte, end_byte);
        free(atom_id);
        if (!equal) {
            atomic_store(&gb->resolution_failed, true);
            cbm_log_error("gbuf.atom_collision", "code", "CBM_NODE_ATOM_COLLISION",
                          "qualified_name", qualified_name, "message",
                          "one stable atom resolved to unequal canonical payloads", "remediation",
                          "preserve this store and report the colliding canonical inputs");
            return 0;
        }
        char *new_props = heap_strdup(json);
        if (!new_props) {
            atomic_store(&gb->resolution_failed, true);
            cbm_log_error("gbuf.node_alloc_failed", "code", "CBM_NODE_PROPERTIES_ALLOC_FAILED",
                          "qualified_name", qualified_name, "message",
                          "same-atom property enrichment allocation failed", "remediation",
                          "free memory or reduce the indexed repository size, then retry");
            return 0;
        }
        free(existing->properties_json);
        existing->properties_json = new_props;
        return existing->id;
    }

    cbm_gbuf_node_t *node = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_node_t));
    if (!node) {
        free(atom_id);
        atomic_store(&gb->resolution_failed, true);
        cbm_log_error("gbuf.node_alloc_failed", "code", "CBM_NODE_ALLOC_FAILED", "message",
                      "graph node allocation failed", "remediation",
                      "free memory or reduce the indexed repository size, then retry");
        return 0;
    }

    node->label = (char *)gb_intern(gb, label);
    node->name = heap_strdup(name);
    node->atom_id = atom_id;
    node->qualified_name = heap_strdup(qualified_name);
    node->file_path = (char *)gb_intern(gb, canonical_file_path);
    node->start_line = start_line;
    node->end_line = end_line;
    node->source_present = source_present;
    node->source_len = source_len;
    node->start_byte = start_byte;
    node->end_byte = end_byte;
    node->properties_json = heap_strdup(json);
    if (source_present) {
        node->source_sha256 = sha256_hex_alloc(source_bytes, source_len);
        if (source_len > 0) {
            node->source_bytes = malloc(source_len);
            if (node->source_bytes) {
                memcpy(node->source_bytes, source_bytes, source_len);
            }
        }
    }
    if (!node->label || !node->name || !node->qualified_name || !node->file_path ||
        !node->properties_json || (source_present && !node->source_sha256) ||
        (source_len > 0 && !node->source_bytes)) {
        free_node_strings(node);
        free(node);
        atomic_store(&gb->resolution_failed, true);
        cbm_log_error("gbuf.node_alloc_failed", "code", "CBM_NODE_FIELDS_ALLOC_FAILED",
                      "qualified_name", qualified_name, "message",
                      "one or more graph-node fields could not be retained", "remediation",
                      "free memory or reduce the indexed repository size, then retry");
        return 0;
    }

    node->id = alloc_next_id(gb);
    if (!cbm_da_push_checked(&gb->nodes, node)) {
        free_node_strings(node);
        free(node);
        gbuf_index_failure(gb, "nodes.append", qualified_name);
        return 0;
    }
    if (!register_node_in_indexes(gb, node)) {
        return 0;
    }
    return node->id;
}

int64_t cbm_gbuf_upsert_node(cbm_gbuf_t *gb, const char *label, const char *name,
                             const char *qualified_name, const char *file_path, int start_line,
                             int end_line, const char *properties_json) {
    return upsert_node_internal(gb, label, name, qualified_name, file_path, start_line, end_line,
                                false, NULL, 0, 0, 0, properties_json);
}

int64_t cbm_gbuf_upsert_source_node(cbm_gbuf_t *gb, const char *label, const char *name,
                                    const char *qualified_name, const char *file_path,
                                    int start_line, int end_line, const uint8_t *source_bytes,
                                    size_t source_len, uint64_t start_byte, uint64_t end_byte,
                                    const char *properties_json) {
    return upsert_node_internal(gb, label, name, qualified_name, file_path, start_line, end_line,
                                true, source_bytes, source_len, start_byte, end_byte,
                                properties_json);
}

const cbm_gbuf_node_t *cbm_gbuf_find_source_node(const cbm_gbuf_t *gb, const char *label,
                                                 const char *name, const char *qualified_name,
                                                 const char *file_path, int start_line,
                                                 int end_line, const uint8_t *source_bytes,
                                                 size_t source_len, uint64_t start_byte,
                                                 uint64_t end_byte) {
    if (!gb || !label || !name || !qualified_name || (source_len > 0 && !source_bytes) ||
        end_byte < start_byte || end_byte - start_byte != source_len) {
        return NULL;
    }
    char *atom_id = make_atom_id(gb->project, label, name, qualified_name, file_path, start_line,
                                 end_line, true, source_bytes, source_len, start_byte, end_byte);
    if (!atom_id) {
        atomic_store(&((cbm_gbuf_t *)gb)->resolution_failed, true);
        return NULL;
    }
    const cbm_gbuf_node_t *node = cbm_ht_get(gb->node_by_atom, atom_id);
    free(atom_id);
    return node;
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_atom_id(const cbm_gbuf_t *gb, const char *atom_id) {
    if (!gb || !atom_id || !atom_id[0]) {
        return NULL;
    }
    return cbm_ht_get(gb->node_by_atom, atom_id);
}

bool cbm_gbuf_resolution_failed(const cbm_gbuf_t *gb) {
    return gb && atomic_load(&gb->resolution_failed);
}

static void log_qn_resolution_ambiguity(const cbm_gbuf_t *gb, const char *qn) {
    int candidate_count = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *candidate = gb->nodes.items[i];
        if (node_is_live(gb, candidate) && candidate->qualified_name &&
            strcmp(candidate->qualified_name, qn) == 0) {
            candidate_count++;
        }
    }

    char count_buf[CBM_SZ_32];
    snprintf(count_buf, sizeof(count_buf), "%d", candidate_count);
    cbm_log_error("gbuf.qn_resolution_ambiguous", "code", "CBM_NODE_QN_AMBIGUOUS", "qualified_name",
                  qn, "candidate_count", count_buf, "message",
                  "qualified name resolves to multiple stable source atoms", "remediation",
                  "resolve by atom_id, exact signature, or source location before persistence");

    int ordinal = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *candidate = gb->nodes.items[i];
        if (!node_is_live(gb, candidate) || !candidate->qualified_name ||
            strcmp(candidate->qualified_name, qn) != 0) {
            continue;
        }

        char ordinal_buf[CBM_SZ_32];
        char start_line_buf[CBM_SZ_32];
        char end_line_buf[CBM_SZ_32];
        snprintf(ordinal_buf, sizeof(ordinal_buf), "%d", ++ordinal);
        snprintf(start_line_buf, sizeof(start_line_buf), "%d", candidate->start_line);
        snprintf(end_line_buf, sizeof(end_line_buf), "%d", candidate->end_line);
        cbm_log_error("gbuf.qn_resolution_candidate", "code", "CBM_NODE_QN_CANDIDATE",
                      "qualified_name", qn, "candidate_ordinal", ordinal_buf, "atom_id",
                      candidate->atom_id ? candidate->atom_id : "", "label",
                      candidate->label ? candidate->label : "", "file_path",
                      candidate->file_path ? candidate->file_path : "", "start_line",
                      start_line_buf, "end_line", end_line_buf, "source_sha256",
                      candidate->source_sha256 ? candidate->source_sha256 : "");
    }
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_qn(const cbm_gbuf_t *gb, const char *qn) {
    if (!gb || !qn) {
        return NULL;
    }
    void *node = cbm_ht_get(gb->node_by_qn, qn);
    if (node == AMBIGUOUS_QN) {
        atomic_store(&((cbm_gbuf_t *)gb)->resolution_failed, true);
        log_qn_resolution_ambiguity(gb, qn);
        return NULL;
    }
    return node;
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_qn_location(const cbm_gbuf_t *gb, const char *qn,
                                                    const char *file_path, int line) {
    if (!gb || !qn || !file_path || line <= 0) {
        return NULL;
    }

    const cbm_gbuf_node_t *match = NULL;
    int match_count = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *node = gb->nodes.items[i];
        if (!node_is_live(gb, node) || !node->qualified_name || !node->file_path ||
            strcmp(node->qualified_name, qn) != 0 || strcmp(node->file_path, file_path) != 0 ||
            node->start_line <= 0 || node->end_line < node->start_line || line < node->start_line ||
            line > node->end_line) {
            continue;
        }
        match = node;
        match_count++;
    }

    if (match_count > 1) {
        char line_buf[CBM_SZ_32];
        char count_buf[CBM_SZ_32];
        snprintf(line_buf, sizeof(line_buf), "%d", line);
        snprintf(count_buf, sizeof(count_buf), "%d", match_count);
        atomic_store(&((cbm_gbuf_t *)gb)->resolution_failed, true);
        cbm_log_error("gbuf.location_resolution_ambiguous", "code", "CBM_NODE_LOCATION_AMBIGUOUS",
                      "qualified_name", qn, "file_path", file_path, "line", line_buf,
                      "candidate_count", count_buf, "message",
                      "source location resolves to multiple stable atoms", "remediation",
                      "resolve by atom_id or an exact byte span before persistence");
        return NULL;
    }
    return match;
}

const cbm_gbuf_node_t *cbm_gbuf_find_by_id(const cbm_gbuf_t *gb, int64_t id) {
    if (!gb || !gb->by_id || id < 0 || id >= gb->by_id_cap) {
        return NULL;
    }
    return gb->by_id[id];
}

int cbm_gbuf_find_by_label(const cbm_gbuf_t *gb, const char *label, const cbm_gbuf_node_t ***out,
                           int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_label, label ? label : "");
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_by_name(const cbm_gbuf_t *gb, const char *name, const cbm_gbuf_node_t ***out,
                          int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_name, name ? name : "");
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_node_count(const cbm_gbuf_t *gb) {
    return gb ? (int)cbm_ht_count(gb->node_by_atom) : 0;
}

int cbm_gbuf_delete_by_label(cbm_gbuf_t *gb, const char *label) {
    if (!gb || !label) {
        return CBM_NOT_FOUND;
    }

    node_ptr_array_t *arr = cbm_ht_get(gb->nodes_by_label, label);
    if (!arr || arr->count == 0) {
        return 0;
    }

    /* Build hash set of deleted node IDs for O(1) lookup */
    CBMHashTable *deleted_set = cbm_ht_create(arr->count);
    if (!deleted_set) {
        gbuf_index_failure(gb, "delete_by_label.set_create", label);
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < arr->count; i++) {
        const cbm_gbuf_node_t *n = arr->items[i];

        char id_buf[CBM_SZ_32];
        make_id_key(id_buf, sizeof(id_buf), n->id);
        char *owned_id = strdup(id_buf);
        if (!owned_id || !gbuf_ht_set(gb, deleted_set, owned_id, intptr_to_ptr(SKIP_ONE), NULL,
                                      "delete_by_label.id_set_insert")) {
            free(owned_id);
            cbm_ht_foreach(deleted_set, free_key_only, NULL);
            cbm_ht_free(deleted_set);
            return CBM_NOT_FOUND;
        }

        /* Remove from primary indexes */
        cbm_ht_delete(gb->node_by_atom, n->atom_id);
        if (n->id >= 0 && n->id < gb->by_id_cap) {
            gb->by_id[n->id] = NULL;
        }
    }

    /* Clear the label array */
    cbm_da_clear(arr);
    rebuild_qn_index(gb);

    /* Cascade-delete edges referencing deleted nodes */
    cascade_delete_edges(gb, deleted_set);

    cbm_ht_foreach(deleted_set, free_key_only, NULL);
    cbm_ht_free(deleted_set);
    return 0;
}

int cbm_gbuf_delete_by_file(cbm_gbuf_t *gb, const char *file_path) {
    if (!gb || !file_path) {
        return CBM_NOT_FOUND;
    }

    /* Collect IDs of nodes in this file */
    CBMHashTable *deleted_set = cbm_ht_create(CBM_SZ_64);
    if (!deleted_set) {
        gbuf_index_failure(gb, "delete_by_file.set_create", file_path);
        return CBM_NOT_FOUND;
    }
    int deleted_count = 0;
    int scanned = 0;

    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        scanned++;
        if (!n->file_path || strcmp(n->file_path, file_path) != 0) {
            continue;
        }
        if (!node_is_live(gb, n)) {
            continue;
        }

        char id_buf[CBM_SZ_32];
        make_id_key(id_buf, sizeof(id_buf), n->id);
        char *owned_id = strdup(id_buf);
        if (!owned_id || !gbuf_ht_set(gb, deleted_set, owned_id, intptr_to_ptr(SKIP_ONE), NULL,
                                      "delete_by_file.id_set_insert")) {
            free(owned_id);
            cbm_ht_foreach(deleted_set, free_key_only, NULL);
            cbm_ht_free(deleted_set);
            return CBM_NOT_FOUND;
        }

        /* Remove from secondary indexes */
        remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_label, n->label), n->id);
        remove_node_from_ptr_array(cbm_ht_get(gb->nodes_by_name, n->name), n->id);

        /* Remove from primary indexes */
        cbm_ht_delete(gb->node_by_atom, n->atom_id);
        if (n->id >= 0 && n->id < gb->by_id_cap) {
            gb->by_id[n->id] = NULL;
        }

        /* NULL out QN so dump's liveness check (cbm_ht_get by QN) fails
         * even if a new node with the same QN is inserted later via merge. */
        free(n->qualified_name);
        n->qualified_name = NULL;
        deleted_count++;
    }

    if (deleted_count == 0) {
        cbm_ht_free(deleted_set);
        return 0;
    }
    rebuild_qn_index(gb);

    /* Cascade-delete edges referencing deleted nodes */
    cascade_delete_edges(gb, deleted_set);

    cbm_ht_foreach(deleted_set, free_key_only, NULL);
    cbm_ht_free(deleted_set);
    {
        char s_buf[CBM_SZ_16];
        char d_buf[CBM_SZ_16];
        snprintf(s_buf, sizeof(s_buf), "%d", scanned);
        snprintf(d_buf, sizeof(d_buf), "%d", deleted_count);
        cbm_log_info("gbuf.delete_by_file", "file", file_path, "scanned", s_buf, "deleted", d_buf);
    }
    return deleted_count;
}

static void log_load_store_verification_failure(const char *db_path, const char *project,
                                                cbm_store_verify_status_t status,
                                                const cbm_store_verify_result_t *verification) {
    const char *code = "CBM_GRAPH_STORE_VERIFICATION_FAILED";
    if (status == CBM_STORE_VERIFY_SOURCE_MISSING) {
        code = "CBM_GRAPH_STORE_SOURCE_MISSING";
    } else if (status == CBM_STORE_VERIFY_INTEGRITY_FAILED) {
        code = "CBM_GRAPH_STORE_INTEGRITY_FAILED";
    }
    char status_buf[CBM_SZ_16];
    char native_error_buf[CBM_SZ_32];
    char sqlite_error_buf[CBM_SZ_32];
    snprintf(status_buf, sizeof(status_buf), "%d", (int)status);
    snprintf(native_error_buf, sizeof(native_error_buf), "%lu",
             (unsigned long)verification->native_error);
    snprintf(sqlite_error_buf, sizeof(sqlite_error_buf), "%d", verification->sqlite_error);
    cbm_log_error(
        "gbuf.load_store_refused", "code", code, "project", project ? project : "", "db_path",
        db_path ? db_path : "", "verification_status", status_buf, "operation",
        verification->operation, "native_error", native_error_buf, "sqlite_error", sqlite_error_buf,
        "detail", verification->detail, "message",
        "the source graph store could not be verified for an immutable read", "remediation",
        "preserve the database, WAL, and SHM together; repair the exact reported source-family "
        "failure, then retry");
}

static void set_load_error(cbm_gbuf_load_error_t *error, const char *code, const char *operation,
                           const char *path, size_t requested, const char *message,
                           const char *remediation) {
    if (!error || error->code[0] != '\0') {
        return;
    }
    (void)snprintf(error->code, sizeof(error->code), "%s",
                   code ? code : "CBM_GRAPH_STORE_LOAD_FAILED");
    (void)snprintf(error->operation, sizeof(error->operation), "%s",
                   operation ? operation : "graph_store_load");
    (void)snprintf(error->phase, sizeof(error->phase), "%s", "incremental_load");
    (void)snprintf(error->path, sizeof(error->path), "%s", path ? path : "");
    (void)snprintf(error->message, sizeof(error->message), "%s",
                   message ? message : "the existing graph could not be loaded");
    (void)snprintf(error->remediation, sizeof(error->remediation), "%s",
                   remediation ? remediation : "repair the exact graph-store failure, then retry");
    error->requested = requested;
}

static const char *graph_verify_code(cbm_store_verify_status_t status) {
    if (status == CBM_STORE_VERIFY_SOURCE_MISSING) {
        return "CBM_GRAPH_STORE_SOURCE_MISSING";
    }
    if (status == CBM_STORE_VERIFY_INTEGRITY_FAILED) {
        return "CBM_GRAPH_STORE_INTEGRITY_FAILED";
    }
    return "CBM_GRAPH_STORE_VERIFICATION_FAILED";
}

static void set_verification_load_error(cbm_gbuf_load_error_t *error, const char *db_path,
                                        cbm_store_verify_status_t status,
                                        const cbm_store_verify_result_t *verification) {
    char message[CBM_SZ_512];
    (void)snprintf(message, sizeof(message),
                   "graph store verification failed: status=%d native_error=%lu "
                   "sqlite_error=%d detail=%s",
                   (int)status, (unsigned long)verification->native_error,
                   verification->sqlite_error,
                   verification->detail[0] ? verification->detail : "unspecified");
    size_t requested =
        verification->native_error != 0
            ? (size_t)verification->native_error
            : (size_t)(verification->sqlite_error < 0 ? 0 : verification->sqlite_error);
    set_load_error(
        error, graph_verify_code(status),
        verification->operation[0] ? verification->operation : "graph_store_verify", db_path,
        requested, message,
        "preserve the database, WAL, and SHM together; repair the exact reported source-family "
        "failure, then retry");
}

static void set_sqlite_load_error(cbm_gbuf_load_error_t *error, sqlite3 *db, const char *db_path,
                                  const char *code, const char *operation, const char *message) {
    int sqlite_error = db ? sqlite3_extended_errcode(db) : SQLITE_MISUSE;
    char detail[CBM_SZ_512];
    (void)snprintf(detail, sizeof(detail), "%s: sqlite_error=%d sqlite_message=%s", message,
                   sqlite_error, db ? sqlite3_errmsg(db) : "database handle unavailable");
    set_load_error(error, code, operation, db_path, (size_t)(sqlite_error < 0 ? 0 : sqlite_error),
                   detail,
                   "preserve the graph store, repair the exact SQLite failure, then retry the "
                   "complete corpus");
}

int cbm_gbuf_load_from_db_checked(cbm_gbuf_t *gb, const char *db_path, const char *project,
                                  cbm_gbuf_load_error_t *error) {
    if (error) {
        memset(error, 0, sizeof(*error));
    }
    if (!gb || !db_path || !project) {
        set_load_error(error, "CBM_GRAPH_STORE_LOAD_ARGUMENT_INVALID", "validate_graph_store_load",
                       db_path, 0,
                       "graph reload requires a graph buffer, database path, and project",
                       "repair the incremental graph-load call contract before retrying");
        return CBM_NOT_FOUND;
    }

    cbm_store_t *store = NULL;
    cbm_store_verify_result_t verification = {0};
    cbm_store_verify_status_t verify_status =
        cbm_store_open_path_graph_verified(db_path, project, &store, &verification);
    if (verify_status != CBM_STORE_VERIFY_OK || !store) {
        if (store) {
            cbm_store_close(store);
        }
        log_load_store_verification_failure(db_path, project, verify_status, &verification);
        set_verification_load_error(error, db_path, verify_status, &verification);
        return CBM_NOT_FOUND;
    }

    sqlite3 *db = cbm_store_get_db(store);
    if (!db) {
        set_load_error(error, "CBM_GRAPH_STORE_HANDLE_UNAVAILABLE", "graph_store_verified_handle",
                       db_path, 0, "verified graph-store open returned no SQLite handle",
                       "repair the verified store-open contract before retrying");
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    /* First pass: find max node ID for mapping array */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MAX(id) FROM nodes WHERE project = ?", CBM_NOT_FOUND, &stmt,
                           NULL) != SQLITE_OK) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_NODE_MAX_PREPARE_FAILED",
                              "graph_load_prepare_max_node_id",
                              "the maximum persisted node ID query could not be prepared");
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_bind_text(stmt, SKIP_ONE, project, CBM_NOT_FOUND, SQLITE_STATIC);
    int64_t max_old_id = 0;
    int step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        max_old_id = sqlite3_column_int64(stmt, 0);
    } else if (step_rc != SQLITE_DONE) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_NODE_MAX_READ_FAILED",
                              "graph_load_read_max_node_id",
                              "the maximum persisted node ID could not be read");
        sqlite3_finalize(stmt);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_finalize(stmt);

    if (max_old_id < 0 ||
        (uint64_t)max_old_id > ((uint64_t)SIZE_MAX / sizeof(int64_t)) - SKIP_ONE) {
        set_load_error(
            error, "CBM_GRAPH_NODE_ID_CAPACITY_OVERFLOW", "graph_load_allocate_node_id_map",
            db_path, max_old_id < 0 ? 0 : (size_t)max_old_id,
            "persisted node IDs exceed the exact in-memory mapping capacity",
            "preserve and inspect the graph store; rebuild it only from the exact source "
            "after correcting its node-ID domain");
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    int64_t *old_to_new = calloc((size_t)(max_old_id + SKIP_ONE), sizeof(int64_t));
    if (!old_to_new) {
        set_load_error(error, "CBM_GRAPH_NODE_ID_MAP_ALLOC_FAILED",
                       "graph_load_allocate_node_id_map", db_path,
                       (size_t)(max_old_id + SKIP_ONE) * sizeof(int64_t),
                       "the exact persisted-to-memory node ID map could not be allocated",
                       "free memory or reduce concurrent repository workload, then retry the "
                       "complete corpus");
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }

    /* Load all nodes */
    if (sqlite3_prepare_v2(
            db,
            "SELECT id, label, name, qualified_name, file_path, start_line, end_line, properties, "
            "atom_id, source_present, source_bytes, source_sha256, start_byte, end_byte "
            "FROM nodes WHERE project = ? ORDER BY id",
            CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_NODE_ROWS_PREPARE_FAILED",
                              "graph_load_prepare_nodes",
                              "the complete persisted node query could not be prepared");
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_bind_text(stmt, SKIP_ONE, project, CBM_NOT_FOUND, SQLITE_STATIC);

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t old_id = sqlite3_column_int64(stmt, 0);
        const char *label = (const char *)sqlite3_column_text(stmt, SKIP_ONE);
        const char *name = (const char *)sqlite3_column_text(stmt, GB_COL_2);
        const char *qn = (const char *)sqlite3_column_text(stmt, GB_COL_3);
        const char *fp = (const char *)sqlite3_column_text(stmt, GB_COL_4);
        int sl = sqlite3_column_int(stmt, GB_COL_5);
        int el = sqlite3_column_int(stmt, GB_COL_6);
        const char *props = (const char *)sqlite3_column_text(stmt, GB_COL_7);
        const char *expected_atom = (const char *)sqlite3_column_text(stmt, 8);
        bool source_present = sqlite3_column_int(stmt, 9) != 0;
        const uint8_t *source_bytes = sqlite3_column_blob(stmt, 10);
        int source_len = sqlite3_column_bytes(stmt, 10);
        const char *expected_source_sha = (const char *)sqlite3_column_text(stmt, 11);
        uint64_t start_byte = (uint64_t)sqlite3_column_int64(stmt, 12);
        uint64_t end_byte = (uint64_t)sqlite3_column_int64(stmt, 13);
        static const uint8_t empty_source = 0;

        if (old_id <= 0 || old_id > max_old_id) {
            set_load_error(
                error, "CBM_GRAPH_NODE_ID_INVALID", "graph_load_validate_node_id", db_path,
                old_id < 0 ? 0 : (size_t)old_id,
                "a persisted graph node ID is outside the positive mapping domain",
                "preserve and inspect the graph store; rebuild it only from the exact source "
                "after correcting its node-ID domain");
            sqlite3_finalize(stmt);
            free(old_to_new);
            cbm_store_close(store);
            return CBM_NOT_FOUND;
        }
        int64_t new_id =
            source_present
                ? cbm_gbuf_upsert_source_node(gb, label, name, qn, fp, sl, el,
                                              source_bytes ? source_bytes : &empty_source,
                                              (size_t)source_len, start_byte, end_byte, props)
                : cbm_gbuf_upsert_node(gb, label, name, qn, fp, sl, el, props);
        const cbm_gbuf_node_t *loaded = cbm_gbuf_find_by_id(gb, new_id);
        if (new_id <= 0 || !loaded || !loaded->atom_id) {
            set_load_error(error, "CBM_GRAPH_NODE_RECONSTRUCTION_FAILED",
                           "graph_load_reconstruct_node", qn ? qn : db_path,
                           (size_t)(old_id < 0 ? 0 : old_id),
                           "a persisted graph node could not be reconstructed exactly in memory",
                           "inspect the preceding graph-buffer diagnostic, repair the exact "
                           "identity or allocation failure, then retry");
            sqlite3_finalize(stmt);
            free(old_to_new);
            cbm_store_close(store);
            return CBM_NOT_FOUND;
        }
        if (!expected_atom || strcmp(loaded->atom_id, expected_atom) != 0 ||
            strcmp(loaded->source_sha256 ? loaded->source_sha256 : "",
                   expected_source_sha ? expected_source_sha : "") != 0) {
            cbm_log_error("gbuf.load_atom_mismatch", "code", "CBM_NODE_ATOM_ID_MISMATCH",
                          "qualified_name", qn ? qn : "", "message",
                          "persisted atom_id does not match immutable source facts", "remediation",
                          "rebuild the SQLite store from the exact source bytes");
            set_load_error(error, "CBM_NODE_ATOM_ID_MISMATCH", "graph_load_verify_immutable_atom",
                           qn ? qn : db_path, 0,
                           "persisted atom_id does not match immutable source facts",
                           "rebuild the SQLite store from the exact source bytes");
            sqlite3_finalize(stmt);
            free(old_to_new);
            cbm_store_close(store);
            return CBM_NOT_FOUND;
        }
        old_to_new[old_id] = new_id;
    }
    if (step_rc != SQLITE_DONE) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_NODE_ROWS_READ_FAILED",
                              "graph_load_read_nodes",
                              "the complete persisted node set could not be read");
        sqlite3_finalize(stmt);
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_finalize(stmt);

    /* Load all edges, remap IDs */
    if (sqlite3_prepare_v2(db,
                           "SELECT source_id, target_id, type, properties "
                           "FROM edges WHERE project = ?",
                           CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_EDGE_ROWS_PREPARE_FAILED",
                              "graph_load_prepare_edges",
                              "the complete persisted edge query could not be prepared");
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_bind_text(stmt, SKIP_ONE, project, CBM_NOT_FOUND, SQLITE_STATIC);

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t old_src = sqlite3_column_int64(stmt, 0);
        int64_t old_tgt = sqlite3_column_int64(stmt, SKIP_ONE);
        const char *type = (const char *)sqlite3_column_text(stmt, GB_COL_2);
        const char *props = (const char *)sqlite3_column_text(stmt, GB_COL_3);

        int64_t new_src = (old_src > 0 && old_src <= max_old_id) ? old_to_new[old_src] : 0;
        int64_t new_tgt = (old_tgt > 0 && old_tgt <= max_old_id) ? old_to_new[old_tgt] : 0;
        if (new_src > 0 && new_tgt > 0) {
            if (cbm_gbuf_insert_edge(gb, new_src, new_tgt, type, props) <= 0) {
                set_load_error(error, "CBM_GRAPH_EDGE_RECONSTRUCTION_FAILED",
                               "graph_load_reconstruct_edge", type ? type : db_path,
                               (size_t)(old_src < 0 ? 0 : old_src),
                               "a persisted graph edge could not be reconstructed exactly in "
                               "memory",
                               "inspect the preceding graph-buffer diagnostic, repair the exact "
                               "edge identity or allocation failure, then retry");
                sqlite3_finalize(stmt);
                free(old_to_new);
                cbm_store_close(store);
                return CBM_NOT_FOUND;
            }
        } else {
            set_load_error(error, "CBM_GRAPH_EDGE_ENDPOINT_MISSING",
                           "graph_load_resolve_edge_endpoints", type ? type : db_path,
                           (size_t)(old_src < 0 ? 0 : old_src),
                           "a persisted edge does not resolve to two reconstructed nodes",
                           "preserve and inspect the graph store; repair its exact referential "
                           "integrity before retrying");
            sqlite3_finalize(stmt);
            free(old_to_new);
            cbm_store_close(store);
            return CBM_NOT_FOUND;
        }
    }
    if (step_rc != SQLITE_DONE) {
        set_sqlite_load_error(error, db, db_path, "CBM_GRAPH_EDGE_ROWS_READ_FAILED",
                              "graph_load_read_edges",
                              "the complete persisted edge set could not be read");
        sqlite3_finalize(stmt);
        free(old_to_new);
        cbm_store_close(store);
        return CBM_NOT_FOUND;
    }
    sqlite3_finalize(stmt);

    free(old_to_new);
    cbm_store_close(store);
    return 0;
}

int cbm_gbuf_load_from_db(cbm_gbuf_t *gb, const char *db_path, const char *project) {
    return cbm_gbuf_load_from_db_checked(gb, db_path, project, NULL);
}

void cbm_gbuf_foreach_node(const cbm_gbuf_t *gb, cbm_gbuf_node_visitor_fn fn, void *userdata) {
    if (!gb || !fn) {
        return;
    }
    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (node_is_live(gb, n)) {
            fn(n, userdata);
        }
    }
}

void cbm_gbuf_foreach_edge(const cbm_gbuf_t *gb, cbm_gbuf_edge_visitor_fn fn, void *userdata) {
    if (!gb || !fn) {
        return;
    }
    for (int i = 0; i < gb->edges.count; i++) {
        fn(gb->edges.items[i], userdata);
    }
}

void cbm_gbuf_set_row_sink(cbm_gbuf_t *gb, cbm_gbuf_row_node_sink_fn node_cb,
                           cbm_gbuf_row_edge_sink_fn edge_cb, void *ctx) {
    if (!gb) {
        return;
    }
    gb->row_node_sink = node_cb;
    gb->row_edge_sink = edge_cb;
    gb->row_sink_ctx = ctx;
}

/* ── Edge operations ─────────────────────────────────────────────── */

int64_t cbm_gbuf_insert_edge(cbm_gbuf_t *gb, int64_t source_id, int64_t target_id, const char *type,
                             const char *properties_json) {
    const char *json = canonical_properties_json(properties_json);
    if (!gb || !type || !type[0] || !valid_utf8_text(type) || !valid_properties_object(json)) {
        if (gb) {
            atomic_store(&gb->resolution_failed, true);
        }
        cbm_log_error("gbuf.edge_refused", "code", "CBM_EDGE_CANONICAL_INPUT_INVALID", "type",
                      type ? type : "", "message",
                      "edges require a non-empty UTF-8 type and a JSON object properties value",
                      "remediation", "repair the exact edge type/properties input, then re-index");
        return 0;
    }

    /* Check for dedup */
    char key[EDGE_KEY_BUF];
    make_edge_key(key, sizeof(key), source_id, target_id, type, json);

    cbm_gbuf_edge_t *existing = cbm_ht_get(gb->edge_by_key, key);
    if (existing) {
        /* Merge properties (just replace for now) */
        if (strcmp(json, "{}") != 0) {
            char *replacement = heap_strdup(json);
            if (!replacement) {
                gbuf_index_failure(gb, "edge.properties.copy", key);
                return 0;
            }
            free(existing->properties_json);
            existing->properties_json = replacement;
        }
        return existing->id;
    }

    /* Heap-allocate a new edge (pointer stays stable) */
    cbm_gbuf_edge_t *edge = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_edge_t));
    if (!edge) {
        return 0;
    }

    int64_t id = alloc_next_id(gb);
    edge->id = id;
    edge->source_id = source_id;
    edge->target_id = target_id;
    edge->type = (char *)gb_intern(gb, type);
    edge->properties_json = heap_strdup(json);
    if (!edge->type || !edge->properties_json) {
        free_edge_strings(edge);
        free(edge);
        gbuf_index_failure(gb, "edge.fields.copy", key);
        return 0;
    }

    /* Store pointer in array */
    if (!cbm_da_push_checked(&gb->edges, edge)) {
        free_edge_strings(edge);
        free(edge);
        gbuf_index_failure(gb, "edges.append", key);
        return 0;
    }

    /* Dedup index */
    char *owned_key = strdup(key);
    if (!owned_key ||
        !gbuf_ht_set(gb, gb->edge_by_key, owned_key, edge, NULL, "edge_by_key.insert")) {
        free(owned_key);
        return 0;
    }

    /* Secondary indexes */
    if (!register_edge_in_indexes(gb, edge)) {
        return 0;
    }

    return id;
}

int cbm_gbuf_find_edges_by_source_type(const cbm_gbuf_t *gb, int64_t source_id, const char *type,
                                       const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    char key[EDGE_KEY_BUF];
    make_src_type_key(key, sizeof(key), source_id, type);
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_source_type, key);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_edges_by_target_type(const cbm_gbuf_t *gb, int64_t target_id, const char *type,
                                       const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    char key[EDGE_KEY_BUF];
    make_src_type_key(key, sizeof(key), target_id, type);
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_target_type, key);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_find_edges_by_type(const cbm_gbuf_t *gb, const char *type,
                                const cbm_gbuf_edge_t ***out, int *count) {
    if (!gb || !out || !count) {
        return CBM_NOT_FOUND;
    }
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_type, type);
    if (arr && arr->count > 0) {
        *out = arr->items;
        *count = arr->count;
    } else {
        *out = NULL;
        *count = 0;
    }
    return 0;
}

int cbm_gbuf_edge_count(const cbm_gbuf_t *gb) {
    return gb ? gb->edges.count : 0;
}

int cbm_gbuf_edge_count_by_type(const cbm_gbuf_t *gb, const char *type) {
    if (!gb || !type) {
        return 0;
    }
    edge_ptr_array_t *arr = cbm_ht_get(gb->edges_by_type, type);
    return arr ? arr->count : 0;
}

int cbm_gbuf_delete_edges_by_type(cbm_gbuf_t *gb, const char *type) {
    if (!gb || !type) {
        return CBM_NOT_FOUND;
    }

    /* Remove edges of the given type from array and dedup index */
    int write_idx = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        if (strcmp(e->type, type) == 0) {
            char key[EDGE_KEY_BUF];
            make_edge_key(key, sizeof(key), e->source_id, e->target_id, e->type,
                          e->properties_json);
            const char *ekey = cbm_ht_get_key(gb->edge_by_key, key);
            cbm_ht_delete(gb->edge_by_key, key);
            free((void *)ekey);
            free_edge_strings(e);
            free(e);
        } else {
            gb->edges.items[write_idx++] = gb->edges.items[i];
        }
    }
    gb->edges.count = write_idx;

    /* Rebuild edge secondary indexes */
    rebuild_edge_secondary_indexes(gb);

    return 0;
}

/* ── Merge ───────────────────────────────────────────────────────── */

/* Free remap hash table entries (key = heap string, value = heap int64_t*) */
static void free_remap_entry(const char *key, void *val, void *ud) {
    (void)ud;
    free((void *)key);
    free(val);
}

/* Handle an exact-atom duplicate. Identity-bearing fields are immutable; only
 * derived properties may be refreshed, and unequal payloads poison persistence. */
static void merge_update_existing(cbm_gbuf_t *dst, cbm_gbuf_node_t *existing,
                                  const cbm_gbuf_node_t *sn, CBMHashTable **remap) {
    if (!same_atom_payload(existing, sn->label, sn->name, sn->qualified_name, sn->file_path,
                           sn->start_line, sn->end_line, sn->source_present, sn->source_bytes,
                           sn->source_len, sn->start_byte, sn->end_byte)) {
        atomic_store(&dst->resolution_failed, true);
        cbm_log_error("gbuf.atom_collision", "code", "CBM_NODE_ATOM_COLLISION", "qualified_name",
                      sn->qualified_name ? sn->qualified_name : "", "message",
                      "worker atom resolved to unequal canonical payloads", "remediation",
                      "preserve the inputs and report the colliding canonical frames");
        return;
    }
    char *new_props = heap_strdup(canonical_properties_json(sn->properties_json));
    if (!new_props) {
        atomic_store(&dst->resolution_failed, true);
        cbm_log_error("gbuf.node_alloc_failed", "code", "CBM_NODE_PROPERTIES_ALLOC_FAILED",
                      "qualified_name", sn->qualified_name ? sn->qualified_name : "", "message",
                      "worker property merge allocation failed", "remediation",
                      "free memory or reduce the indexed repository size, then retry");
        return;
    }
    free(existing->properties_json);
    existing->properties_json = new_props;

    if (sn->id != existing->id) {
        if (!*remap) {
            *remap = cbm_ht_create(CBM_SZ_32);
        }
        char key[CBM_SZ_32];
        make_id_key(key, sizeof(key), sn->id);
        int64_t *val = malloc(sizeof(int64_t));
        char *owned_key = strdup(key);
        if (!*remap || !val || !owned_key) {
            free(val);
            free(owned_key);
            atomic_store(&dst->resolution_failed, true);
            cbm_log_error("gbuf.merge_alloc_failed", "code", "CBM_NODE_REMAP_ALLOC_FAILED",
                          "message", "worker node-id remap allocation failed", "remediation",
                          "free memory or reduce the indexed repository size, then retry");
            return;
        }
        *val = existing->id;
        if (!gbuf_ht_set(dst, *remap, owned_key, val, NULL, "node_id_remap.insert")) {
            free(owned_key);
            free(val);
        }
    }
}

/* Copy a non-colliding src node into dst with its original ID. */
static void merge_copy_new_node(cbm_gbuf_t *dst, const cbm_gbuf_node_t *sn) {
    cbm_gbuf_node_t *node = calloc(CBM_ALLOC_ONE, sizeof(cbm_gbuf_node_t));
    if (!node) {
        return;
    }

    node->id = sn->id;
    node->label = (char *)gb_intern(dst, sn->label);
    node->name = heap_strdup(sn->name);
    node->atom_id = heap_strdup(sn->atom_id);
    node->qualified_name = heap_strdup(sn->qualified_name);
    node->file_path = (char *)gb_intern(dst, canonical_identity_text(sn->file_path));
    node->start_line = sn->start_line;
    node->end_line = sn->end_line;
    node->source_present = sn->source_present;
    node->source_len = sn->source_len;
    node->start_byte = sn->start_byte;
    node->end_byte = sn->end_byte;
    node->source_sha256 = sn->source_present ? heap_strdup(sn->source_sha256) : NULL;
    if (sn->source_len > 0) {
        node->source_bytes = malloc(sn->source_len);
        if (node->source_bytes) {
            memcpy(node->source_bytes, sn->source_bytes, sn->source_len);
        }
    }
    node->properties_json = heap_strdup(canonical_properties_json(sn->properties_json));

    if (!node->label || !node->name || !node->atom_id || !node->qualified_name ||
        !node->file_path || !node->properties_json ||
        (node->source_present && !node->source_sha256) ||
        (node->source_len > 0 && !node->source_bytes)) {
        free_node_strings(node);
        free(node);
        atomic_store(&dst->resolution_failed, true);
        cbm_log_error("gbuf.merge_alloc_failed", "code", "CBM_NODE_COPY_ALLOC_FAILED", "message",
                      "worker node copy allocation failed", "remediation",
                      "free memory or reduce the indexed repository size, then retry");
        return;
    }

    if (!cbm_da_push_checked(&dst->nodes, node)) {
        free_node_strings(node);
        free(node);
        gbuf_index_failure(dst, "merge.nodes.append", sn->qualified_name);
        return;
    }
    if (!register_node_in_indexes(dst, node)) {
        return;
    }

    if (node->id >= dst->next_id) {
        dst->next_id = node->id + SKIP_ONE;
    }
}

/* Remap edge IDs using the collision remap table and insert into dst. */
static void merge_remap_edges(cbm_gbuf_t *dst, cbm_gbuf_t *src, CBMHashTable *remap) {
    for (int i = 0; i < src->edges.count; i++) {
        cbm_gbuf_edge_t *se = src->edges.items[i];

        int64_t new_src = se->source_id;
        int64_t new_tgt = se->target_id;

        if (remap) {
            char key[CBM_SZ_32];
            make_id_key(key, sizeof(key), se->source_id);
            int64_t *remapped = cbm_ht_get(remap, key);
            if (remapped) {
                new_src = *remapped;
            }

            make_id_key(key, sizeof(key), se->target_id);
            remapped = cbm_ht_get(remap, key);
            if (remapped) {
                new_tgt = *remapped;
            }
        }

        cbm_gbuf_insert_edge(dst, new_src, new_tgt, se->type, se->properties_json);
    }
}

int cbm_gbuf_merge(cbm_gbuf_t *dst, cbm_gbuf_t *src) {
    if (!dst || !src) {
        return CBM_NOT_FOUND;
    }
    if (atomic_load(&src->resolution_failed)) {
        atomic_store(&dst->resolution_failed, true);
        cbm_log_error(
            "gbuf.merge_refused", "code", "CBM_SOURCE_WORKER_FAILED", "message",
            "a worker graph contains a canonical identity or source retention failure",
            "remediation",
            "inspect the earlier structured worker error and retry only after fixing its cause");
        return CBM_NOT_FOUND;
    }
    if (src->nodes.count == 0 && src->edges.count == 0) {
        return 0;
    }

    /* ID remap for QN-colliding nodes: "src_id" → (int64_t*) dst_id.
     * Only populated when a src node's QN already exists in dst. */
    CBMHashTable *remap = NULL;

    for (int i = 0; i < src->nodes.count; i++) {
        cbm_gbuf_node_t *sn = src->nodes.items[i];
        if (!sn->qualified_name) {
            continue;
        }

        /* Skip nodes deleted from QN index */
        if (!node_is_live(src, sn)) {
            continue;
        }

        cbm_gbuf_node_t *existing = cbm_ht_get(dst->node_by_atom, sn->atom_id);
        if (existing) {
            merge_update_existing(dst, existing, sn, &remap);
        } else {
            merge_copy_new_node(dst, sn);
        }
    }

    /* Merge edges with optional ID remapping */
    merge_remap_edges(dst, src, remap);

    if (remap) {
        cbm_ht_foreach(remap, free_remap_entry, NULL);
        cbm_ht_free(remap);
    }

    return atomic_load(&dst->resolution_failed) ? CBM_NOT_FOUND : 0;
}

/* ── Dump / Flush ────────────────────────────────────────────────── */

/* Extract a string property from a properties JSON string.
 * Returns heap-allocated string or NULL. Caller must free.
 * Parses real JSON: the dump writer feeds these values into indexes whose
 * backing columns are GENERATED AS json_extract(properties,'$.<key>').
 * Naive byte slicing returned the ESCAPED text (and cut at embedded \\")
 * while json_extract yields the unescaped value — the mismatch left rows
 * "missing from index idx_edges_url_path" under PRAGMA integrity_check.
 * key_quoted ("\"key\"") is a fast pre-filter to skip the JSON parse. */
static char *extract_prop_string(const char *props, const char *key_quoted, const char *key) {
    if (!props || !strstr(props, key_quoted)) {
        return NULL;
    }
    yyjson_doc *doc = yyjson_read(props, strlen(props), 0);
    if (!doc) {
        return NULL;
    }
    char *out = NULL;
    yyjson_val *v = yyjson_obj_get(yyjson_doc_get_root(doc), key);
    if (v && yyjson_is_str(v)) {
        const char *sv = yyjson_get_str(v);
        out = cbm_strndup(sv, strlen(sv));
    }
    yyjson_doc_free(doc);
    return out;
}

const cbm_gbuf_node_t *cbm_gbuf_find_successor_node(const cbm_gbuf_t *gb,
                                                    const char *qualified_name,
                                                    const char *file_path, const char *label,
                                                    const char *name,
                                                    const char *previous_properties_json) {
    if (!gb || !qualified_name || !file_path || !label || !name || !previous_properties_json) {
        return NULL;
    }

    char *previous_signature =
        extract_prop_string(previous_properties_json, "\"signature\"", "signature");
    const cbm_gbuf_node_t *only_basic = NULL;
    const cbm_gbuf_node_t *only_signature = NULL;
    int basic_count = 0;
    int signature_count = 0;

    for (int i = 0; i < gb->nodes.count; i++) {
        const cbm_gbuf_node_t *node = gb->nodes.items[i];
        if (!node_is_live(gb, node) || strcmp(node->qualified_name, qualified_name) != 0 ||
            strcmp(node->file_path, file_path) != 0 || strcmp(node->label, label) != 0 ||
            strcmp(node->name, name) != 0) {
            continue;
        }
        only_basic = node;
        basic_count++;
        if (previous_signature) {
            char *candidate_signature =
                extract_prop_string(node->properties_json, "\"signature\"", "signature");
            bool matches =
                candidate_signature && strcmp(candidate_signature, previous_signature) == 0;
            free(candidate_signature);
            if (matches) {
                only_signature = node;
                signature_count++;
            }
        }
    }

    if (basic_count == 0) {
        free(previous_signature);
        return NULL; /* The old entity was deleted or renamed. */
    }
    if (previous_signature && signature_count == 1) {
        free(previous_signature);
        return only_signature;
    }
    if (!previous_signature && basic_count == 1) {
        return only_basic;
    }

    bool ambiguous = signature_count > 1 || (!previous_signature && basic_count > 1);
    char basic_buf[CBM_SZ_32];
    char signature_buf[CBM_SZ_32];
    snprintf(basic_buf, sizeof(basic_buf), "%d", basic_count);
    snprintf(signature_buf, sizeof(signature_buf), "%d", signature_count);
    atomic_store(&((cbm_gbuf_t *)gb)->resolution_failed, true);
    cbm_log_error(
        "gbuf.successor_resolution_failed", "code",
        ambiguous ? "CBM_NODE_SUCCESSOR_AMBIGUOUS" : "CBM_NODE_SUCCESSOR_SIGNATURE_CHANGED",
        "qualified_name", qualified_name, "file_path", file_path, "label", label, "name", name,
        "candidate_count", basic_buf, "signature_matches", signature_buf, "message",
        ambiguous ? "incremental successor locator resolves to multiple stable atoms"
                  : "existing incremental successor candidates do not preserve the prior signature",
        "remediation", "run a clean re-index so every dependent source reference is re-resolved");
    free(previous_signature);
    return NULL;
}

static char *extract_url_path(const char *props) {
    return extract_prop_string(props, "\"url_path\"", "url_path");
}

/* local_name feeds the hand-built sqlite_autoindex_edges_1 — its backing
 * column local_name_gen is GENERATED only for IMPORTS edges (#768). */
static char *extract_local_name(const char *props) {
    return extract_prop_string(props, "\"local_name\"", "local_name");
}

/* Remap a temp edge ID to its final sequential ID, or 0 if out of range. */
static int64_t remap_id(const int64_t *temp_to_final, int64_t max_temp_id, int64_t temp_id) {
    return (temp_id < max_temp_id) ? temp_to_final[temp_id] : 0;
}

/* Build dump-ready node array with sequential IDs. Populates temp_to_final mapping. */
static int cmp_dump_vectors_by_id(const void *a, const void *b) {
    int64_t da = ((const CBMDumpVector *)a)->node_id;
    int64_t db = ((const CBMDumpVector *)b)->node_id;
    return (da > db) - (da < db);
}

static int cmp_nodes_by_atom_id(const void *a, const void *b) {
    const cbm_gbuf_node_t *left = *(const cbm_gbuf_node_t *const *)a;
    const cbm_gbuf_node_t *right = *(const cbm_gbuf_node_t *const *)b;
    return strcmp(left->atom_id, right->atom_id);
}

static CBMDumpNode *build_dump_nodes(cbm_gbuf_t *gb, int live_count, int64_t *temp_to_final,
                                     int64_t max_temp_id, int *out_count,
                                     cbm_gbuf_node_t ***src_out) {
    size_t cap = (size_t)(live_count > 0 ? live_count : SKIP_ONE);
    CBMDumpNode *dump_nodes = malloc(cap * sizeof(CBMDumpNode));
    if (!dump_nodes) {
        /* #579: the node dump array is sized to the live node count, so it is one
         * of the first large allocations to fail under real memory pressure. It is
         * indexed unconditionally in the loop below, so a NULL here would be a hard
         * access violation. Fail closed with a structured error and let the caller
         * abort the dump before any writer opens — no torn store is produced. */
        cbm_log_error("gbuf.dump.node_alloc_failed", "code", "CBM_DUMP_NODE_ALLOC_FAILED",
                      "operation", "build_dump_nodes", "detail",
                      "dump node array allocation failed", "message",
                      "graph dump could not allocate its node row array", "remediation",
                      "free memory or reduce the indexed repository size, then retry the index");
        *out_count = 0;
        *src_out = NULL;
        return NULL;
    }
    /* The exact atom order is the persistent ID order. It must not inherit
     * parallel extraction/merge scheduling. This array also lets streamed
     * partitions release their source properties after persistence. */
    cbm_gbuf_node_t **src = malloc(cap * sizeof(cbm_gbuf_node_t *));
    if (!src) {
        free(dump_nodes);
        cbm_log_error("gbuf.dump.node_order_alloc_failed", "code",
                      "CBM_DUMP_NODE_ORDER_ALLOC_FAILED", "operation", "build_dump_nodes",
                      "message", "graph dump could not allocate its deterministic atom order",
                      "remediation", "free memory or reduce repository size, then retry");
        *out_count = 0;
        *src_out = NULL;
        return NULL;
    }

    int idx = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (node_is_live(gb, n)) {
            src[idx++] = n;
        }
    }
    qsort(src, (size_t)idx, sizeof(cbm_gbuf_node_t *), cmp_nodes_by_atom_id);

    for (int row = 0; row < idx; row++) {
        if (src[row]->source_len > INT_MAX) {
            cbm_log_error("gbuf.dump.source_too_large", "code", "CBM_SOURCE_BLOB_TOO_LARGE",
                          "qualified_name", src[row]->qualified_name, "message",
                          "one exact source payload exceeds the SQLite writer ABI", "remediation",
                          "reject files above INT_MAX bytes before extraction");
            free(src);
            free(dump_nodes);
            atomic_store(&gb->resolution_failed, true);
            *out_count = 0;
            *src_out = NULL;
            return NULL;
        }
    }

    for (int row = 0; row < idx; row++) {
        cbm_gbuf_node_t *n = src[row];
        int64_t final_id = row + SKIP_ONE; /* 1-based sequential */
        if (n->id < max_temp_id) {
            temp_to_final[n->id] = final_id;
        }

        const char *fp = canonical_identity_text(n->file_path);
        const char *props = canonical_properties_json(n->properties_json);
        /* Identity text was validated before atom hashing. Dump exact copies:
         * changing even one byte here would sever atom_id from its canonical input. */
        dump_nodes[row] = (CBMDumpNode){
            .id = final_id,
            .project = gb->project,
            .label = n->label,
            .name = heap_strdup(canonical_identity_text(n->name)),
            .atom_id = n->atom_id,
            .qualified_name = heap_strdup(canonical_identity_text(n->qualified_name)),
            .file_path = heap_strdup(fp),
            .start_line = n->start_line,
            .end_line = n->end_line,
            .source_present = n->source_present ? 1 : 0,
            .source_bytes = n->source_bytes,
            .source_len = n->source_len,
            .source_sha256 = n->source_sha256 ? n->source_sha256 : "",
            .start_byte = n->start_byte,
            .end_byte = n->end_byte,
            .properties = props,
        };
        if (!dump_nodes[row].name || !dump_nodes[row].qualified_name ||
            !dump_nodes[row].file_path) {
            cbm_log_error("gbuf.dump.identity_copy_failed", "code",
                          "CBM_DUMP_IDENTITY_COPY_ALLOC_FAILED", "qualified_name",
                          n->qualified_name ? n->qualified_name : "", "message",
                          "exact identity text could not be copied into the dump row",
                          "remediation", "free memory or reduce repository size, then retry");
            for (int completed = 0; completed <= row; completed++) {
                free((void *)dump_nodes[completed].name);
                free((void *)dump_nodes[completed].qualified_name);
                free((void *)dump_nodes[completed].file_path);
            }
            free(src);
            free(dump_nodes);
            atomic_store(&gb->resolution_failed, true);
            *out_count = 0;
            *src_out = NULL;
            return NULL;
        }
    }

    *out_count = idx;
    *src_out = src;
    return dump_nodes;
}

/* Build dump-ready edge array with remapped IDs. Returns url_paths and
 * local_names (heap string arrays owned by the caller) via out params. */
static CBMDumpEdge *build_dump_edges(cbm_gbuf_t *gb, const int64_t *temp_to_final,
                                     int64_t max_temp_id, int *out_count, char ***out_url_paths,
                                     char ***out_local_names) {
    /* Count valid edges (both endpoints resolved) */
    int valid_edges = 0;
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        if (remap_id(temp_to_final, max_temp_id, e->source_id) > 0 &&
            remap_id(temp_to_final, max_temp_id, e->target_id) > 0) {
            valid_edges++;
        }
    }

    size_t edge_cap = (size_t)(valid_edges > 0 ? valid_edges : SKIP_ONE);
    CBMDumpEdge *dump_edges = malloc(edge_cap * sizeof(CBMDumpEdge));
    char **url_paths = calloc(edge_cap, sizeof(char *));
    char **local_names = calloc(edge_cap, sizeof(char *));
    if (!dump_edges || !url_paths || !local_names) {
        /* #579: these three arrays are sized to the valid-edge count and indexed
         * unconditionally in the loop below; any NULL would be a hard access
         * violation. Fail closed with a structured error and signal the caller
         * (NULL return, *out_count = 0) so the dump aborts instead of crashing. */
        free(dump_edges);
        free(url_paths);
        free(local_names);
        cbm_log_error("gbuf.dump.edge_alloc_failed", "code", "CBM_DUMP_EDGE_ALLOC_FAILED",
                      "operation", "build_dump_edges", "detail",
                      "paired dump edge arrays allocation failed", "message",
                      "graph dump could not allocate its edge row arrays", "remediation",
                      "free memory or reduce the indexed repository size, then retry the index");
        *out_count = 0;
        *out_url_paths = NULL;
        *out_local_names = NULL;
        return NULL;
    }
    int idx = 0;

    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        int64_t src = remap_id(temp_to_final, max_temp_id, e->source_id);
        int64_t tgt = remap_id(temp_to_final, max_temp_id, e->target_id);
        if (src == 0 || tgt == 0) {
            continue;
        }

        char *url_path = extract_url_path(e->properties_json);
        url_paths[idx] = url_path;

        /* IMPORTS only — mirrors the local_name_gen CASE in the edges DDL. */
        char *local_name = (e->type && strcmp(e->type, "IMPORTS") == 0)
                               ? extract_local_name(e->properties_json)
                               : NULL;
        local_names[idx] = local_name;

        const char *props = canonical_properties_json(e->properties_json);
        dump_edges[idx] = (CBMDumpEdge){
            .id = idx + SKIP_ONE,
            .project = gb->project,
            .source_id = src,
            .target_id = tgt,
            .type = e->type,
            .properties = props,
            .url_path = url_path ? url_path : "",
            .local_name = local_name ? local_name : "",
        };
        idx++;
    }

    *out_count = idx;
    *out_url_paths = url_paths;
    *out_local_names = local_names;
    return dump_edges;
}

/* Remap vector node IDs through temp_to_final, sort by ID, deduplicate. */
static void remap_sort_dedup_vectors(cbm_gbuf_t *gb, const int64_t *temp_to_final,
                                     int64_t max_temp_id) {
    int remapped = 0;
    int dropped = 0;
    for (int i = 0; i < gb->dump_vector_count; i++) {
        int64_t old_id = gb->dump_vectors[i].node_id;
        int64_t new_id = (old_id > 0 && old_id < max_temp_id) ? temp_to_final[old_id] : 0;
        if (new_id > 0) {
            gb->dump_vectors[remapped] = gb->dump_vectors[i];
            gb->dump_vectors[remapped].node_id = new_id;
            remapped++;
        } else {
            dropped++;
        }
    }
    if (dropped > 0) {
        char r_buf[CBM_SZ_16];
        char d_buf[CBM_SZ_16];
        snprintf(r_buf, sizeof(r_buf), "%d", remapped);
        snprintf(d_buf, sizeof(d_buf), "%d", dropped);
        cbm_log_info("dump.vectors.remap", "remapped", r_buf, "dropped", d_buf);
    }
    gb->dump_vector_count = remapped;

    if (gb->dump_vector_count >= GB_MIN_FOR_DEDUP) {
        qsort(gb->dump_vectors, (size_t)gb->dump_vector_count, sizeof(CBMDumpVector),
              cmp_dump_vectors_by_id);
        int deduped = 0;
        for (int i = 0; i < gb->dump_vector_count; i++) {
            if (i + GB_DEDUP_LOOKAHEAD < gb->dump_vector_count &&
                gb->dump_vectors[i].node_id == gb->dump_vectors[i + GB_DEDUP_LOOKAHEAD].node_id) {
                continue;
            }
            gb->dump_vectors[deduped++] = gb->dump_vectors[i];
        }
        gb->dump_vector_count = deduped;
    }
}

static void log_dump_summary(int node_count, int edge_count) {
    char b1[CBM_SZ_16];
    char b2[CBM_SZ_16];
    snprintf(b1, sizeof(b1), "%d", node_count);
    snprintf(b2, sizeof(b2), "%d", edge_count);
    cbm_log_info("gbuf.dump", "nodes", b1, "edges", b2);
}

static void free_dump_resources(char **url_paths, char **local_names, int edge_count,
                                CBMDumpEdge *dump_edges, CBMDumpNode *dump_nodes, int node_count,
                                int64_t *temp_to_final) {
    for (int i = 0; i < edge_count; i++) {
        free(url_paths[i]);
        free(local_names[i]);
    }
    /* #503: name/qualified_name/file_path are the sanitized owned copies built in
     * build_dump_nodes (properties/label/project stay borrowed from the gbuf). */
    if (dump_nodes) {
        for (int i = 0; i < node_count; i++) {
            free((void *)dump_nodes[i].name);
            free((void *)dump_nodes[i].qualified_name);
            free((void *)dump_nodes[i].file_path);
        }
    }
    free(url_paths);
    free(local_names);
    free(dump_edges);
    free(dump_nodes);
    free(temp_to_final);
}

static bool gbuf_has_row_sink(const cbm_gbuf_t *gb) {
    return gb && (gb->row_node_sink || gb->row_edge_sink);
}

static int emit_row_sink_nodes(cbm_gbuf_t *gb, const CBMDumpNode *nodes, int node_count) {
    if (!gb || !gb->row_node_sink) {
        return 0;
    }
    for (int i = 0; i < node_count; i++) {
        const CBMDumpNode *n = &nodes[i];
        cbm_gbuf_row_node_t row = {
            .id = n->id,
            .project = n->project,
            .label = n->label,
            .name = n->name,
            .atom_id = n->atom_id,
            .qualified_name = n->qualified_name,
            .file_path = n->file_path ? n->file_path : "",
            .start_line = n->start_line,
            .end_line = n->end_line,
            .source_present = n->source_present,
            .source_bytes = n->source_bytes,
            .source_len = n->source_len,
            .source_sha256 = n->source_sha256 ? n->source_sha256 : "",
            .start_byte = n->start_byte,
            .end_byte = n->end_byte,
            .properties_json = n->properties ? n->properties : "{}",
        };
        if (gb->row_node_sink(&row, gb->row_sink_ctx) != 0) {
            cbm_log_error("gbuf.row_sink.err", "kind", "node");
            return GB_ERR;
        }
    }
    return 0;
}

static int emit_row_sink_edges(cbm_gbuf_t *gb, const CBMDumpEdge *edges, int edge_count) {
    if (!gb || !gb->row_edge_sink) {
        return 0;
    }
    for (int i = 0; i < edge_count; i++) {
        const CBMDumpEdge *e = &edges[i];
        cbm_gbuf_row_edge_t row = {
            .id = e->id,
            .project = e->project,
            .source_id = e->source_id,
            .target_id = e->target_id,
            .type = e->type,
            .properties_json = e->properties ? e->properties : "{}",
            .url_path_gen = e->url_path ? e->url_path : "",
            .local_name_gen = e->local_name ? e->local_name : "",
        };
        if (gb->row_edge_sink(&row, gb->row_sink_ctx) != 0) {
            cbm_log_error("gbuf.row_sink.err", "kind", "edge");
            return GB_ERR;
        }
    }
    return 0;
}

static int count_live_nodes(cbm_gbuf_t *gb) {
    int count = 0;
    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];
        if (node_is_live(gb, n)) {
            count++;
        }
    }
    return count;
}

static void generate_iso_timestamp(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_val = cbm_gmtime_r(&now, &tm_buf);
    if (strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", tm_val) == 0) {
        snprintf(buf, buf_size, "1970-01-01T00:00:00Z");
    }
}

/* Release lookup indexes then remap+sort+dedup vectors for the B-tree writer. */
static void release_and_remap_vectors(cbm_gbuf_t *gb, const int64_t *temp_to_final,
                                      int64_t max_temp_id) {
    CBM_PROF_START(t_vec_remap);
    remap_sort_dedup_vectors(gb, temp_to_final, max_temp_id);
    CBM_PROF_END_N("dump", "5_vector_remap_sort", t_vec_remap, gb->dump_vector_count);
}

int cbm_gbuf_dump_to_sqlite(cbm_gbuf_t *gb, const char *path) {
    if (!gb || !path) {
        return CBM_NOT_FOUND;
    }
    if (atomic_load(&gb->resolution_failed)) {
        cbm_log_error("gbuf.dump_refused", "code", "CBM_GRAPH_RESOLUTION_FAILED", "message",
                      "an earlier canonical identity or reference-resolution operation failed; no "
                      "store or row-sink mutation was attempted",
                      "remediation", "inspect the preceding structured graph-buffer error");
        return CBM_NOT_FOUND;
    }

    CBM_PROF_START(t_count);
    int live_count = count_live_nodes(gb);
    CBM_PROF_END_N("dump", "1_count_live_nodes", t_count, live_count);

    CBM_PROF_START(t_build_nodes);
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_final = calloc((size_t)max_temp_id, sizeof(int64_t));
    if (!temp_to_final) {
        return CBM_NOT_FOUND;
    }

    int node_idx = 0;
    cbm_gbuf_node_t **src_nodes = NULL;
    CBMDumpNode *dump_nodes =
        build_dump_nodes(gb, live_count, temp_to_final, max_temp_id, &node_idx, &src_nodes);
    CBM_PROF_END_N("dump", "2_build_dump_nodes", t_build_nodes, node_idx);
    if (!dump_nodes) {
        /* #579: node dump array allocation failed (structured error already logged
         * in build_dump_nodes). No writer has opened yet, so the store file is
         * never created; release the transients and fail closed. */
        free(src_nodes); /* NULL on this path — build_dump_nodes cleared *src_out */
        free(temp_to_final);
        return CBM_NOT_FOUND;
    }

    /* Release ALL lookup indexes NOW: nothing between here and finalize reads
     * them (stream-append uses dump_nodes/src_nodes, build_dump_edges uses
     * temp_to_final + gb->edges, the vector remap uses temp_to_final). At
     * kernel scale they are ~3.8 GB (hash buckets + key strings + pointer
     * arrays); releasing them only AFTER edge building made them coexist with
     * every dump-side transient array — the dump-phase RSS peak. */
    CBM_PROF_START(t_release_idx);
    release_gbuf_indexes(gb);
    CBM_PROF_END("dump", "4_release_gbuf_indexes", t_release_idx);

    char indexed_at[CBM_SZ_64];
    generate_iso_timestamp(indexed_at, sizeof(indexed_at));

    int edge_idx = 0;
    char **url_paths = NULL;
    char **local_names = NULL;
    CBMDumpEdge *dump_edges = NULL;
    bool has_row_sink = gbuf_has_row_sink(gb);
    if (has_row_sink) {
        CBM_PROF_START(t_build_edges_sink);
        dump_edges =
            build_dump_edges(gb, temp_to_final, max_temp_id, &edge_idx, &url_paths, &local_names);
        CBM_PROF_END_N("dump", "3_build_dump_edges", t_build_edges_sink, edge_idx);
        if (!dump_edges) {
            /* #579: edge dump arrays allocation failed (structured error already
             * logged). No file writer has opened on this row-sink path, so nothing
             * is persisted; release the transients and fail closed. */
            free_dump_resources(url_paths, local_names, edge_idx, dump_edges, dump_nodes, node_idx,
                                temp_to_final);
            free(src_nodes);
            return CBM_NOT_FOUND;
        }
        release_and_remap_vectors(gb, temp_to_final, max_temp_id);

        int sink_rc = emit_row_sink_nodes(gb, dump_nodes, node_idx);
        if (sink_rc == 0) {
            sink_rc = emit_row_sink_edges(gb, dump_edges, edge_idx);
        }
        if (sink_rc != 0) {
            free_dump_resources(url_paths, local_names, edge_idx, dump_edges, dump_nodes, node_idx,
                                temp_to_final);
            free(src_nodes);
            return sink_rc;
        }
    }

    /* Stream node rows to the DB in partitions. Under memory pressure, free each
     * partition's heavy properties_json once persisted — the heavy column is
     * write-once and never read again, so this bounds the dump/finalize peak.
     * The DB output is identical whether or not freeing engages, so non-pressure
     * runs (and tests) leave the gbuf intact (the budget>0 guard keeps an
     * uninitialized budget from ever triggering the free). */
    cbm_db_writer_t *w = cbm_writer_open(path);
    if (!w) {
        free_dump_resources(url_paths, local_names, edge_idx, dump_edges, dump_nodes, node_idx,
                            temp_to_final);
        free(src_nodes);
        return CBM_NOT_FOUND;
    }

    CBM_PROF_START(t_append);
    enum { DUMP_PARTITION_NODES = 1 << 16 };
    bool free_heavy = false;
    int rc = 0;
    for (int off = 0; off < node_idx; off += DUMP_PARTITION_NODES) {
        int chunk = node_idx - off;
        if (chunk > DUMP_PARTITION_NODES) {
            chunk = DUMP_PARTITION_NODES;
        }
        rc = cbm_writer_append_nodes(w, &dump_nodes[off], chunk);
        if (rc != 0) {
            break;
        }
        free_heavy = free_heavy || (cbm_mem_budget() > 0 && cbm_mem_over_budget());
        if (free_heavy && src_nodes) {
            for (int j = off; j < off + chunk; j++) {
                free(src_nodes[j]->properties_json);
                src_nodes[j]->properties_json = NULL;
                dump_nodes[j].properties = NULL;
            }
            cbm_mem_collect();
        }
    }
    CBM_PROF_END_N("dump", "2b_stream_append_nodes", t_append, node_idx);

    if (rc == 0 && !has_row_sink) {
        CBM_PROF_START(t_build_edges);
        dump_edges =
            build_dump_edges(gb, temp_to_final, max_temp_id, &edge_idx, &url_paths, &local_names);
        CBM_PROF_END_N("dump", "3_build_dump_edges", t_build_edges, edge_idx);
        if (!dump_edges) {
            /* #579: edge dump arrays allocation failed (structured error already
             * logged) AFTER node rows were streamed into the open writer. Persisting
             * a node-only graph would be a silent incomplete dump, so mark the dump
             * failed and remove the store file below — the store must be absent or
             * complete, never torn. release_and_remap_vectors is skipped since the
             * dump is aborting. */
            rc = CBM_NOT_FOUND;
        } else {
            release_and_remap_vectors(gb, temp_to_final, max_temp_id);
        }
    }

    /* Finalize: nodes-table interior + edges/vectors/metadata/indexes/sqlite_master.
     * Frees w and closes the file; handles a prior append error cleanly. Always
     * called so the writer handle is released and the file descriptor closed even
     * on the edge-build-failed path (the resulting file is unlinked below). */
    CBM_PROF_START(t_finalize);
    int frc = cbm_writer_finalize(w, gb->project, gb->root_path, indexed_at, dump_nodes, node_idx,
                                  dump_edges, edge_idx, gb->dump_vectors, gb->dump_vector_count,
                                  gb->dump_token_vecs, gb->dump_token_vec_count);
    CBM_PROF_END_N("dump", "6_write_db_finalize", t_finalize, node_idx + edge_idx);
    if (rc == 0) {
        rc = frc;
    }
    if (rc != 0) {
        /* #579/#676: every writer failure leaves the requested staging path
         * absent. A partially written direct-page file is never a readable or
         * publishable database, regardless of which phase failed. */
        errno = 0;
        if (cbm_unlink(path) != 0 && errno != ENOENT) {
            char native_error[32];
            (void)snprintf(native_error, sizeof(native_error), "%d", errno ? errno : EIO);
            cbm_log_error("gbuf.dump_cleanup_failed", "code", "CBM_DUMP_PARTIAL_REMOVE_FAILED",
                          "path", path, "native_error_kind", "errno", "native_error", native_error,
                          "message", "the failed direct-writer staging file could not be removed",
                          "remediation",
                          "preserve the path, resolve the reported filesystem failure, and retry");
        }
    }

    log_dump_summary(node_idx, edge_idx);
    free_dump_resources(url_paths, local_names, edge_idx, dump_edges, dump_nodes, node_idx,
                        temp_to_final);
    free(src_nodes);
    return rc;
}

int cbm_gbuf_flush_to_store(cbm_gbuf_t *gb, cbm_store_t *store) {
    if (!gb || !store) {
        return CBM_NOT_FOUND;
    }
    if (atomic_load(&gb->resolution_failed)) {
        cbm_log_error("gbuf.flush_refused", "code", "CBM_GRAPH_RESOLUTION_FAILED", "message",
                      "an earlier canonical identity or reference-resolution operation failed; no "
                      "store mutation was attempted",
                      "remediation", "inspect the preceding structured graph-buffer error");
        return CBM_NOT_FOUND;
    }

    /* Upsert project */
    cbm_store_upsert_project(store, gb->project, gb->root_path);

    /* Begin bulk mode */
    cbm_store_begin_bulk(store);
    cbm_store_drop_indexes(store);
    cbm_store_begin(store);

    /* Delete existing project data */
    cbm_store_delete_edges_by_project(store, gb->project);
    cbm_store_delete_nodes_by_project(store, gb->project);

    /* Build temp_id → real_id map.
     * Temp IDs start at 1 and are sequential, but can have gaps from edge inserts.
     * Use max_id as size. */
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_real = calloc(max_temp_id, sizeof(int64_t));

    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];

        /* Skip if deleted from QN index */
        if (!node_is_live(gb, n)) {
            continue;
        }

        cbm_node_t sn = {
            .project = gb->project,
            .label = n->label,
            .name = n->name,
            .atom_id = n->atom_id,
            .qualified_name = n->qualified_name,
            .file_path = n->file_path,
            .start_line = n->start_line,
            .end_line = n->end_line,
            .source_present = n->source_present,
            .source_bytes = n->source_bytes,
            .source_len = n->source_len,
            .source_sha256 = n->source_sha256,
            .start_byte = n->start_byte,
            .end_byte = n->end_byte,
            .properties_json = n->properties_json,
        };
        int64_t real_id = cbm_store_upsert_node(store, &sn);
        if (real_id > 0 && n->id < max_temp_id) {
            temp_to_real[n->id] = real_id;
        }
    }

    /* Insert all edges with remapped IDs */
    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        int64_t real_src = (e->source_id < max_temp_id) ? temp_to_real[e->source_id] : 0;
        int64_t real_tgt = (e->target_id < max_temp_id) ? temp_to_real[e->target_id] : 0;
        if (real_src == 0 || real_tgt == 0) {
            continue;
        }

        cbm_edge_t se = {
            .project = gb->project,
            .source_id = real_src,
            .target_id = real_tgt,
            .type = e->type,
            .properties_json = e->properties_json,
        };
        cbm_store_insert_edge(store, &se);
    }

    cbm_store_commit(store);
    cbm_store_create_indexes(store);
    cbm_store_end_bulk(store);

    free(temp_to_real);
    return 0;
}

int cbm_gbuf_merge_into_store(cbm_gbuf_t *gb, cbm_store_t *store) {
    if (!gb || !store) {
        return CBM_NOT_FOUND;
    }
    if (atomic_load(&gb->resolution_failed)) {
        cbm_log_error("gbuf.merge_refused", "code", "CBM_GRAPH_RESOLUTION_FAILED", "message",
                      "an earlier canonical identity or reference-resolution operation failed; no "
                      "store mutation was attempted",
                      "remediation", "inspect the preceding structured graph-buffer error");
        return CBM_NOT_FOUND;
    }

    /* Begin bulk mode — no project wipe */
    cbm_store_begin(store);

    /* Build temp_id → real_id map */
    int64_t max_temp_id = gb->next_id;
    int64_t *temp_to_real = calloc(max_temp_id, sizeof(int64_t));

    for (int i = 0; i < gb->nodes.count; i++) {
        cbm_gbuf_node_t *n = gb->nodes.items[i];

        if (!node_is_live(gb, n)) {
            continue;
        }

        cbm_node_t sn = {
            .project = gb->project,
            .label = n->label,
            .name = n->name,
            .atom_id = n->atom_id,
            .qualified_name = n->qualified_name,
            .file_path = n->file_path,
            .start_line = n->start_line,
            .end_line = n->end_line,
            .properties_json = n->properties_json,
        };
        int64_t real_id = cbm_store_upsert_node(store, &sn);
        if (real_id > 0 && n->id < max_temp_id) {
            temp_to_real[n->id] = real_id;
        }
    }

    for (int i = 0; i < gb->edges.count; i++) {
        cbm_gbuf_edge_t *e = gb->edges.items[i];
        int64_t real_src = (e->source_id < max_temp_id) ? temp_to_real[e->source_id] : 0;
        int64_t real_tgt = (e->target_id < max_temp_id) ? temp_to_real[e->target_id] : 0;
        if (real_src == 0 || real_tgt == 0) {
            continue;
        }

        cbm_edge_t se = {
            .project = gb->project,
            .source_id = real_src,
            .target_id = real_tgt,
            .type = e->type,
            .properties_json = e->properties_json,
        };
        cbm_store_insert_edge(store, &se);
    }

    cbm_store_commit(store);

    free(temp_to_real);
    return 0;
}
