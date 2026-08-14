/*
 * minhash.c — MinHash fingerprinting + LSH for near-clone detection.
 *
 * Computes K=64 MinHash signatures from normalised AST node-type
 * trigrams.  Uses xxHash with distinct seeds for each permutation.
 * Pure functions — thread-safe, no shared state.
 *
 * LSH index uses b=32 bands × r=2 rows for candidate generation.
 */
#include "simhash/minhash.h"
#include "foundation/constants.h"
#include "foundation/log.h"
/* Inline all xxHash functions — avoids separate compilation unit. */
#define XXH_INLINE_ALL
#include "xxhash/xxhash.h"
#include "tree_sitter/api.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>

/* ── AST node type normalisation ─────────────────────────────────── */

/* Maximum trigram string length: 3 node types × max 40 chars each + separators */
enum { TRIGRAM_BUF_LEN = 160 };

/* Maximum AST body nodes to walk (stack depth). */
enum { AST_WALK_CAP = 2048 };

/* Hex encoding constants */
enum { HEX_CHARS_PER_U32 = 8, HEX_BASE = 16 };

/* Trigram constants */
enum { TRIGRAM_WINDOW = 2 };

/* Minimum unique structural trigrams for a meaningful fingerprint.
 * K/2 = 32 ensures most MinHash slots get populated from distinct features. */
enum { MIN_UNIQUE_TRIGRAMS = 32 };

/* Maximum structural weight per trigram (3 tokens × 1 each). */
enum { MAX_STRUCTURAL_WEIGHT = 3 };

/* Hash truncation mask (uint64 → uint32) */
enum { U32_MASK = 0xFFFFFFFF };

/* Dynamic array growth constants */
enum { BUCKET_INIT_CAP = 8, GROW_FACTOR = 2, ENTRY_INIT_CAP = 64, RESULT_INIT_CAP = 64 };

/* Maximum bucket size — skip oversized buckets (noise from trivially similar functions). */
enum { MAX_BUCKET_SIZE = 200 };

/* Seen-set for O(1) dedup during query (simple open-addressing hash table). */
enum {
    SEEN_SET_BITS = 14,
    SEEN_SET_SIZE = CBM_LSH_QUERY_SEEN_CAP,
    SEEN_SET_MASK = CBM_LSH_QUERY_SEEN_CAP - 1,
};

/* Knuth multiplicative hash constant for node_id → seen-set slot. */
enum { KNUTH_MULT = 2654435761ULL };

/* Maximum normalised tokens per function body. */
enum { MAX_TOKENS = 4096 };

/* Check if a node type is an identifier-like leaf. */
static bool is_identifier_type(const char *kind) {
    return strcmp(kind, "identifier") == 0 || strcmp(kind, "field_identifier") == 0 ||
           strcmp(kind, "property_identifier") == 0 || strcmp(kind, "type_identifier") == 0 ||
           strcmp(kind, "shorthand_property_identifier") == 0 ||
           strcmp(kind, "shorthand_field_identifier") == 0 || strcmp(kind, "variable_name") == 0 ||
           strcmp(kind, "name") == 0;
}

/* Check if a node type is a string literal. */
static bool is_string_type(const char *kind) {
    return strcmp(kind, "string") == 0 || strcmp(kind, "string_literal") == 0 ||
           strcmp(kind, "interpreted_string_literal") == 0 ||
           strcmp(kind, "raw_string_literal") == 0 || strcmp(kind, "template_string") == 0 ||
           strcmp(kind, "string_content") == 0 || strcmp(kind, "escape_sequence") == 0;
}

/* Check if a node type is a number literal. */
static bool is_number_type(const char *kind) {
    return strcmp(kind, "number") == 0 || strcmp(kind, "integer") == 0 ||
           strcmp(kind, "float") == 0 || strcmp(kind, "integer_literal") == 0 ||
           strcmp(kind, "float_literal") == 0 || strcmp(kind, "int_literal") == 0 ||
           strcmp(kind, "number_literal") == 0;
}

/* Check if a node type is a type annotation. */
static bool is_type_annotation(const char *kind) {
    return strcmp(kind, "type_identifier") == 0 || strcmp(kind, "predefined_type") == 0 ||
           strcmp(kind, "primitive_type") == 0 || strcmp(kind, "builtin_type") == 0 ||
           strcmp(kind, "type_annotation") == 0 || strcmp(kind, "simple_type") == 0;
}

/* Normalise a node type string.  Returns a short canonical string
 * or the original kind if no normalisation applies. */
static const char *normalise_node_type(const char *kind) {
    if (is_identifier_type(kind)) {
        return "I";
    }
    if (is_string_type(kind)) {
        return "S";
    }
    if (is_number_type(kind)) {
        return "N";
    }
    if (is_type_annotation(kind)) {
        return "T";
    }
    return kind;
}

/* ── MinHash computation ─────────────────────────────────────────── */

/* Check if a normalised token is one of the generic types (I/S/N/T).
 * These carry no structural info — used to compute trigram weight. */
static bool is_normalised_token(const char *tok) {
    return tok[0] != '\0' && tok[SKIP_ONE] == '\0' &&
           (tok[0] == 'I' || tok[0] == 'S' || tok[0] == 'N' || tok[0] == 'T');
}

/* Compute structural weight of a trigram: count of non-normalised tokens (0-3).
 * Weight 0 = pure data manipulation (noise), weight 3 = rich control flow (signal). */
static int trigram_structural_weight(const char *a, const char *b, const char *c) {
    int w = 0;
    if (!is_normalised_token(a)) {
        w++;
    }
    if (!is_normalised_token(b)) {
        w++;
    }
    if (!is_normalised_token(c)) {
        w++;
    }
    return w;
}

/* Phase 1: Walk AST iteratively and collect normalised LEAF token types.
 * Leaf-only counting is language-agnostic: leaf nodes correspond to actual
 * source tokens, not grammar-internal structure that varies across parsers. */
static int collect_ast_tokens(TSNode root, const char **tokens, int max_tokens) {
    int token_count = 0;
    TSNode stack[AST_WALK_CAP];
    int top = 0;
    stack[top++] = root;

    while (top > 0 && token_count < max_tokens) {
        TSNode node = stack[--top];
        uint32_t child_count = ts_node_child_count(node);

        if (child_count == 0) {
            /* Leaf node — actual source token.  Normalise and record. */
            const char *kind = ts_node_type(node);
            if (kind[0] != '\0') {
                tokens[token_count++] = normalise_node_type(kind);
            }
        } else {
            /* Internal node — push children only (skip the node itself).
             * Structural info comes from leaf token patterns, not grammar nodes. */
            for (int i = (int)child_count - SKIP_ONE; i >= 0 && top < AST_WALK_CAP; i--) {
                stack[top++] = ts_node_child(node, (uint32_t)i);
            }
        }
    }
    return token_count;
}

/* Phase 2: Hash trigrams into MinHash signature with structural weighting.
 *
 * - Skip weight-0 trigrams (all tokens are I/S/N/T — pure noise)
 * - Use repetition-based weighted MinHash: hash w times per seed for weight w
 * - Track unique trigrams via hash set; reject if < MIN_UNIQUE_TRIGRAMS
 *
 * Returns the number of unique structural trigrams processed. */
/* Unique-trigram set: open addressing on 64-bit hashes. */
enum { UNIQ_SET_SIZE = 4096, UNIQ_SET_MASK = 4095 };

typedef struct {
    uint64_t slots[UNIQ_SET_SIZE];
    int count;
} uniq_trig_set_t;

static void uniq_trig_init(uniq_trig_set_t *s) {
    memset(s->slots, 0, sizeof(s->slots));
    s->count = 0;
}

/* Insert a trigram hash.  Returns true if newly inserted. */
static bool uniq_trig_insert(uniq_trig_set_t *s, uint64_t trig_hash) {
    uint64_t val = trig_hash | SKIP_ONE; /* ensure non-zero */
    uint32_t slot = (uint32_t)(trig_hash & UNIQ_SET_MASK);
    for (int probe = 0; probe < UNIQ_SET_SIZE; probe++) {
        uint32_t idx = (slot + (uint32_t)probe) & UNIQ_SET_MASK;
        if (s->slots[idx] == 0) {
            s->slots[idx] = val;
            s->count++;
            return true;
        }
        if (s->slots[idx] == val) {
            return false;
        }
    }
    return false;
}

/* Apply weighted MinHash for one trigram: hash w times per seed. */
static void weighted_minhash_update(cbm_minhash_t *out, const char *trigram, int len, int w) {
    for (int k = 0; k < CBM_MINHASH_K; k++) {
        for (int rep = 0; rep < w; rep++) {
            uint64_t seed = ((uint64_t)k * MAX_STRUCTURAL_WEIGHT) + (uint64_t)rep;
            uint64_t h = XXH3_64bits_withSeed(trigram, (size_t)len, seed);
            uint32_t h32 = (uint32_t)(h & U32_MASK);
            if (h32 < out->values[k]) {
                out->values[k] = h32;
            }
        }
    }
}

static int hash_trigrams(const char **tokens, int token_count, cbm_minhash_t *out) {
    for (int k = 0; k < CBM_MINHASH_K; k++) {
        out->values[k] = UINT32_MAX;
    }

    uniq_trig_set_t uniq;
    uniq_trig_init(&uniq);
    char trigram_buf[TRIGRAM_BUF_LEN];

    for (int i = 0; i + TRIGRAM_WINDOW < token_count; i++) {
        int w =
            trigram_structural_weight(tokens[i], tokens[i + SKIP_ONE], tokens[i + TRIGRAM_WINDOW]);
        if (w == 0) {
            continue;
        }

        int len = snprintf(trigram_buf, sizeof(trigram_buf), "%s|%s|%s", tokens[i],
                           tokens[i + SKIP_ONE], tokens[i + TRIGRAM_WINDOW]);
        if (len <= 0 || (size_t)len >= sizeof(trigram_buf)) {
            continue;
        }

        uniq_trig_insert(&uniq, XXH3_64bits(trigram_buf, (size_t)len));
        weighted_minhash_update(out, trigram_buf, len, w);
    }
    return uniq.count;
}

bool cbm_minhash_compute(TSNode func_body, const char *source, int language, cbm_minhash_t *out) {
    (void)source;
    (void)language;

    if (ts_node_is_null(func_body)) {
        return false;
    }

    const char *tokens[MAX_TOKENS];
    int token_count = collect_ast_tokens(func_body, tokens, MAX_TOKENS);
    if (token_count < CBM_MINHASH_MIN_NODES) {
        return false;
    }

    int unique_structural = hash_trigrams(tokens, token_count, out);
    return unique_structural >= MIN_UNIQUE_TRIGRAMS;
}

/* ── Struct-trigram serialization (panel S1 encoder source) ──────────
 *
 * Surfaces the identical normalised AST node-type trigrams that drive the
 * MinHash fingerprint as a text list the Rust panel S1 lens can hash into a
 * sparse structural vector. This is the shared instrument between per-symbol
 * indexing (compute_fingerprint stores the result on the definition) and the
 * per-snippet guard reparse (which reads it back through the same extraction),
 * so identical body bytes yield a byte-identical trigram list either way. */
int cbm_struct_trigrams_serialize(TSNode func_body, char *buf, int bufsize) {
    if (!buf || bufsize < SKIP_ONE) {
        return 0;
    }
    buf[0] = '\0';
    if (ts_node_is_null(func_body)) {
        return 0;
    }

    const char *tokens[MAX_TOKENS];
    int token_count = collect_ast_tokens(func_body, tokens, MAX_TOKENS);

    int pos = 0;
    for (int i = 0; i + TRIGRAM_WINDOW < token_count; i++) {
        const char *a = tokens[i];
        const char *b = tokens[i + SKIP_ONE];
        const char *c = tokens[i + TRIGRAM_WINDOW];
        int w = trigram_structural_weight(a, b, c);
        if (w == 0) {
            continue; /* pure I/S/N/T noise — skipped exactly as MinHash does */
        }
        char rec[TRIGRAM_BUF_LEN + 16];
        int len = snprintf(rec, sizeof(rec), "%s\t%s\t%s\t%d\n", a, b, c, w);
        if (len <= 0 || (size_t)len >= sizeof(rec)) {
            continue; /* pathologically long kind string — skip this record */
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

/* ── Jaccard similarity ──────────────────────────────────────────── */

double cbm_minhash_jaccard(const cbm_minhash_t *a, const cbm_minhash_t *b) {
    if (!a || !b) {
        return 0.0;
    }
    int matching = 0;
    for (int i = 0; i < CBM_MINHASH_K; i++) {
        if (a->values[i] == b->values[i]) {
            matching++;
        }
    }
    return (double)matching / (double)CBM_MINHASH_K;
}

/* ── Hex encoding/decoding ───────────────────────────────────────── */

void cbm_minhash_to_hex(const cbm_minhash_t *fp, char *buf, int bufsize) {
    if (!fp || !buf || bufsize < CBM_MINHASH_HEX_BUF) {
        if (buf && bufsize > 0) {
            buf[0] = '\0';
        }
        return;
    }
    int pos = 0;
    for (int i = 0; i < CBM_MINHASH_K; i++) {
        pos += snprintf(buf + pos, (size_t)(bufsize - pos), "%08x", fp->values[i]);
    }
}

bool cbm_minhash_from_hex(const char *hex, cbm_minhash_t *out) {
    if (!hex || !out) {
        return false;
    }
    size_t len = strlen(hex);
    if ((int)len != CBM_MINHASH_HEX_LEN) {
        return false;
    }
    for (int i = 0; i < CBM_MINHASH_K; i++) {
        char chunk[HEX_CHARS_PER_U32 + SKIP_ONE];
        ptrdiff_t offset = (ptrdiff_t)i * HEX_CHARS_PER_U32;
        memcpy(chunk, hex + offset, HEX_CHARS_PER_U32);
        chunk[HEX_CHARS_PER_U32] = '\0';
        unsigned long val = strtoul(chunk, NULL, HEX_BASE);
        out->values[i] = (uint32_t)val;
    }
    return true;
}

/* ── LSH index ───────────────────────────────────────────────────── */

/* Each band bucket is a dynamic array of entry indices (not pointers —
 * the entries array may be reallocated during insert, invalidating ptrs). */
typedef struct {
    int *items; /* indices into idx->entries */
    int count;
    int cap;
} lsh_bucket_t;

/* Band hash table: 65536 buckets per band (16-bit hash of r=2 values). */
enum { LSH_BUCKET_COUNT = 65536, LSH_BUCKET_MASK = 65535 };

struct cbm_lsh_index {
    /* b=32 bands, each with LSH_BUCKET_COUNT buckets */
    lsh_bucket_t bands[CBM_LSH_BANDS][LSH_BUCKET_COUNT];
    /* All entries stored for lifetime management */
    cbm_lsh_entry_t *entries;
    int entry_count;
    int entry_cap;
    /* Candidate result buffer (reused across queries) */
    const cbm_lsh_entry_t **result_buf;
    int result_count;
    int result_cap;
};

/* Compute band hash for band `b` from a MinHash signature.
 * Uses r=2 consecutive values starting at position b*r. */
static uint32_t band_hash(const cbm_minhash_t *fp, int band) {
    int base = band * CBM_LSH_ROWS;
    /* Combine r=2 values into a single hash */
    uint32_t combined[CBM_LSH_ROWS];
    for (int r = 0; r < CBM_LSH_ROWS; r++) {
        combined[r] = fp->values[base + r];
    }
    uint64_t h = XXH3_64bits(combined, sizeof(combined));
    return (uint32_t)(h & LSH_BUCKET_MASK);
}

static bool checked_grow_cap(int current, int initial, size_t item_size, int *out) {
    if (!out || current < 0 || initial <= 0 || item_size == 0) {
        return false;
    }
    int next = initial;
    if (current >= initial) {
        if (current > INT_MAX / GROW_FACTOR) {
            return false;
        }
        next = current * GROW_FACTOR;
    }
    if ((size_t)next > SIZE_MAX / item_size) {
        return false;
    }
    *out = next;
    return true;
}

static bool bucket_reserve_one(lsh_bucket_t *bucket) {
    if (bucket->count >= bucket->cap) {
        int new_cap = 0;
        if (!checked_grow_cap(bucket->cap, BUCKET_INIT_CAP, sizeof(int), &new_cap)) {
            cbm_log_error("minhash.lsh_bucket_capacity_failed", "code",
                          "CBM_LSH_BUCKET_CAPACITY_OVERFLOW", "message",
                          "LSH bucket capacity cannot be represented safely", "remediation",
                          "reduce the indexed corpus size, then retry");
            return false;
        }
        int *new_items = realloc(bucket->items, (size_t)new_cap * sizeof(int));
        if (!new_items) {
            cbm_log_error("minhash.lsh_bucket_alloc_failed", "code", "CBM_LSH_BUCKET_ALLOC_FAILED",
                          "message", "LSH bucket storage could not be grown", "remediation",
                          "free memory or reduce the indexed corpus size, then retry");
            return false;
        }
        bucket->items = new_items;
        bucket->cap = new_cap;
    }
    return true;
}

cbm_lsh_index_t *cbm_lsh_new(void) {
    cbm_lsh_index_t *idx = calloc(SKIP_ONE, sizeof(cbm_lsh_index_t));
    if (!idx) {
        cbm_log_error("minhash.lsh_alloc_failed", "code", "CBM_LSH_INDEX_ALLOC_FAILED", "message",
                      "LSH index storage could not be allocated", "remediation",
                      "free memory or reduce the indexed corpus size, then retry");
    }
    return idx;
}

bool cbm_lsh_insert(cbm_lsh_index_t *idx, const cbm_lsh_entry_t *entry) {
    if (!idx || !entry || !entry->fingerprint) {
        return false;
    }

    /* Admit every allocation before changing entry_count or any bucket count.
     * Capacity growth may move an owned buffer, but a failure leaves the
     * complete logical index unchanged and therefore safely retryable. */
    if (idx->entry_count >= idx->entry_cap) {
        int new_cap = 0;
        if (!checked_grow_cap(idx->entry_cap, ENTRY_INIT_CAP, sizeof(cbm_lsh_entry_t), &new_cap)) {
            cbm_log_error("minhash.lsh_entry_capacity_failed", "code",
                          "CBM_LSH_ENTRY_CAPACITY_OVERFLOW", "message",
                          "LSH entry capacity cannot be represented safely", "remediation",
                          "reduce the indexed corpus size, then retry");
            return false;
        }
        cbm_lsh_entry_t *new_entries =
            realloc(idx->entries, (size_t)new_cap * sizeof(cbm_lsh_entry_t));
        if (!new_entries) {
            cbm_log_error("minhash.lsh_entry_alloc_failed", "code", "CBM_LSH_ENTRY_ALLOC_FAILED",
                          "message", "LSH entry storage could not be grown", "remediation",
                          "free memory or reduce the indexed corpus size, then retry");
            return false;
        }
        idx->entries = new_entries;
        idx->entry_cap = new_cap;
    }
    int entry_idx = idx->entry_count;
    for (int b = 0; b < CBM_LSH_BANDS; b++) {
        uint32_t h = band_hash(entry->fingerprint, b);
        if (!bucket_reserve_one(&idx->bands[b][h])) {
            return false;
        }
    }

    idx->entries[entry_idx] = *entry;
    idx->entry_count++;
    for (int b = 0; b < CBM_LSH_BANDS; b++) {
        uint32_t h = band_hash(entry->fingerprint, b);
        lsh_bucket_t *bucket = &idx->bands[b][h];
        bucket->items[bucket->count++] = entry_idx;
    }
    return true;
}

/* O(1) seen-set: open-addressing hash table on node_id for dedup. */
typedef struct {
    int64_t *slots;
    int cap;
} seen_set_t;

static bool seen_set_init(seen_set_t *s) {
    s->slots = calloc(SEEN_SET_SIZE, sizeof(int64_t));
    s->cap = SEEN_SET_SIZE;
    /* 0 means empty — node_ids are always > 0 */
    return s->slots != NULL;
}

static bool seen_set_insert(seen_set_t *s, int64_t node_id) {
    if (!s->slots) {
        return false;
    }
    uint32_t idx = (uint32_t)(node_id * KNUTH_MULT) & SEEN_SET_MASK;
    for (int probe = 0; probe < SEEN_SET_SIZE; probe++) {
        uint32_t slot = (idx + (uint32_t)probe) & SEEN_SET_MASK;
        if (s->slots[slot] == 0) {
            s->slots[slot] = node_id;
            return true; /* inserted (was not present) */
        }
        if (s->slots[slot] == node_id) {
            return false; /* already present */
        }
    }
    return false; /* table full */
}

static void seen_set_free(seen_set_t *s) {
    free(s->slots);
    s->slots = NULL;
}

/* Append a candidate to the result buffer, growing if needed. */
static bool result_push(cbm_lsh_index_t *idx, const cbm_lsh_entry_t *candidate) {
    if (idx->result_count >= idx->result_cap) {
        int new_cap = 0;
        if (!checked_grow_cap(idx->result_cap, RESULT_INIT_CAP, sizeof(const cbm_lsh_entry_t *),
                              &new_cap)) {
            cbm_log_error("minhash.lsh_query_capacity_failed", "code",
                          "CBM_LSH_QUERY_RESULT_CAPACITY_OVERFLOW", "message",
                          "LSH query result capacity cannot be represented safely", "remediation",
                          "reduce the indexed corpus size, then retry");
            return false;
        }
        const cbm_lsh_entry_t **new_buf =
            realloc(idx->result_buf, (size_t)new_cap * sizeof(const cbm_lsh_entry_t *));
        if (!new_buf) {
            return false;
        }
        idx->result_buf = new_buf;
        idx->result_cap = new_cap;
    }
    idx->result_buf[idx->result_count++] = candidate;
    return true;
}

bool cbm_lsh_query(const cbm_lsh_index_t *idx, const cbm_minhash_t *fp,
                   const cbm_lsh_entry_t ***out, int *count) {
    if (!out || !count) {
        return false;
    }
    *out = NULL;
    *count = 0;

    if (!idx || !fp) {
        return false;
    }

    cbm_lsh_index_t *mut_idx = (cbm_lsh_index_t *)idx;
    mut_idx->result_count = 0;

    /* O(1) dedup via open-addressing hash set */
    seen_set_t seen;
    if (!seen_set_init(&seen)) {
        cbm_log_error("minhash.lsh_query_alloc_failed", "code",
                      "CBM_LSH_QUERY_SCRATCH_ALLOC_FAILED", "message",
                      "LSH query deduplication scratch could not be allocated", "remediation",
                      "free memory or reduce concurrent query pressure, then retry");
        return false;
    }

    for (int b = 0; b < CBM_LSH_BANDS; b++) {
        uint32_t h = band_hash(fp, b);
        const lsh_bucket_t *bucket = &idx->bands[b][h];
        /* Skip oversized buckets — noise from trivially similar utility functions */
        if (bucket->count > MAX_BUCKET_SIZE) {
            continue;
        }
        for (int i = 0; i < bucket->count; i++) {
            const cbm_lsh_entry_t *candidate = &idx->entries[bucket->items[i]];
            if (!seen_set_insert(&seen, candidate->node_id)) {
                continue; /* already seen */
            }
            if (!result_push(mut_idx, candidate)) {
                seen_set_free(&seen);
                cbm_log_error("minhash.lsh_query_alloc_failed", "code",
                              "CBM_LSH_QUERY_RESULT_ALLOC_FAILED", "message",
                              "LSH query result storage could not be grown", "remediation",
                              "free memory or reduce concurrent query pressure, then retry");
                return false;
            }
        }
    }

    seen_set_free(&seen);
    *out = mut_idx->result_buf;
    *count = mut_idx->result_count;
    return true;
}

int cbm_lsh_query_into_scratch(const cbm_lsh_index_t *idx, const cbm_minhash_t *fp,
                               const cbm_lsh_entry_t **out_buf, int out_cap, int64_t *seen_slots,
                               int seen_cap) {
    if (!idx || !fp || !out_buf || out_cap <= 0 || !seen_slots || seen_cap != SEEN_SET_SIZE) {
        return -1;
    }

    memset(seen_slots, 0, (size_t)seen_cap * sizeof(*seen_slots));
    seen_set_t seen = {.slots = seen_slots, .cap = seen_cap};

    int count = 0;
    for (int b = 0; b < CBM_LSH_BANDS; b++) {
        uint32_t h = band_hash(fp, b);
        const lsh_bucket_t *bucket = &idx->bands[b][h];
        if (bucket->count > MAX_BUCKET_SIZE) {
            continue;
        }
        for (int i = 0; i < bucket->count && count < out_cap; i++) {
            const cbm_lsh_entry_t *candidate = &idx->entries[bucket->items[i]];
            if (!seen_set_insert(&seen, candidate->node_id)) {
                continue;
            }
            out_buf[count++] = candidate;
        }
        if (count >= out_cap) {
            break;
        }
    }

    return count;
}

int cbm_lsh_query_into(const cbm_lsh_index_t *idx, const cbm_minhash_t *fp,
                       const cbm_lsh_entry_t **out_buf, int out_cap) {
    int64_t *seen_slots = calloc(SEEN_SET_SIZE, sizeof(*seen_slots));
    if (!seen_slots) {
        cbm_log_error("minhash.lsh_query_alloc_failed", "code",
                      "CBM_LSH_QUERY_SCRATCH_ALLOC_FAILED", "message",
                      "LSH query deduplication scratch could not be allocated", "remediation",
                      "free memory or reduce concurrent query pressure, then retry");
        return -1;
    }
    int count = cbm_lsh_query_into_scratch(idx, fp, out_buf, out_cap, seen_slots, SEEN_SET_SIZE);
    free(seen_slots);
    return count;
}

void cbm_lsh_free(cbm_lsh_index_t *idx) {
    if (!idx) {
        return;
    }
    /* Free bucket arrays */
    for (int b = 0; b < CBM_LSH_BANDS; b++) {
        for (int h = 0; h < LSH_BUCKET_COUNT; h++) {
            free(idx->bands[b][h].items);
        }
    }
    free(idx->entries);
    free(idx->result_buf);
    free(idx);
}
