/*
 * pass_enrichment.c — Decorator tokenization, camelCase splitting,
 * and decorator_tags pass (post-flush enrichment).
 *
 * Pure helper functions + a store-level pass that classifies decorators
 * into semantic tags via auto-discovery (words on 2+ nodes become tags).
 */
#include "foundation/constants.h"

enum { ENRICH_ATTR_SKIP = 2, ENRICH_MAX_CAMEL = 16 };
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "foundation/log.h"
#include "foundation/hash_table.h"
#include "foundation/dyn_array.h"
#include "foundation/platform.h"
#include "foundation/compat.h"
#include "yyjson/yyjson.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Convert intptr_t to void* without triggering performance-no-int-to-ptr. */
static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

static bool is_decorator_stopword(const char *w) {
    static const char *stopwords[] = {"get",   "set",  "new",   "class",  "method", "function",
                                      "value", "type", "param", "return", "public", "private",
                                      "for",   "if",   "the",   "and",    "or",     "not",
                                      "with",  "from", "app",   "router", NULL};
    for (int i = 0; stopwords[i]; i++) {
        if (strcmp(w, stopwords[i]) == 0) {
            return true;
        }
    }
    return false;
}

int cbm_split_camel_case(const char *s, char **out, int max_out) {
    if (!s || !out || max_out <= 0) {
        return 0;
    }
    size_t len = strlen(s);
    if (len == 0) {
        return 0;
    }

    int count = 0;
    size_t start = 0;

    for (size_t i = SKIP_ONE; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z' && s[i - SKIP_ONE] >= 'a' && s[i - SKIP_ONE] <= 'z') {
            if (count < max_out) {
                out[count] = cbm_strndup(s + start, i - start);
                count++;
            }
            start = i;
        }
    }
    /* Emit remaining */
    if (count < max_out) {
        out[count] = cbm_strndup(s + start, len - start);
        count++;
    }
    return count;
}

/* Strip decorator syntax: leading @, #[...], and arguments (...).
 * Operates in-place on buf. Returns pointer to the cleaned token start. */
static char *strip_decorator_syntax(char *buf) {
    char *p = buf;
    if (*p == '@') {
        p++;
    }
    if (p[0] == '#' && p[SKIP_ONE] == '[') {
        p += ENRICH_ATTR_SKIP;
        size_t plen = strlen(p);
        if (plen > 0 && p[plen - SKIP_ONE] == ']') {
            p[plen - SKIP_ONE] = '\0';
        }
    }
    char *paren = strchr(p, '(');
    if (paren) {
        *paren = '\0';
    }
    for (char *c = p; *c; c++) {
        if (*c == '.' || *c == '_' || *c == '-' || *c == ':' || *c == '/') {
            *c = ' ';
        }
    }
    return p;
}

int cbm_tokenize_decorator(const char *dec, char **out, int max_out) {
    if (!dec || !out || max_out <= 0) {
        return 0;
    }

    char buf[CBM_SZ_256];
    size_t len = strlen(dec);
    if (len >= sizeof(buf)) {
        len = sizeof(buf) - SKIP_ONE;
    }
    memcpy(buf, dec, len);
    buf[len] = '\0';

    char *p = strip_decorator_syntax(buf);

    int count = 0;
    char *saveptr = NULL;
    char *part = strtok_r(p, " ", &saveptr);

    while (part && count < max_out) {
        char *camel_parts[ENRICH_MAX_CAMEL];
        int camel_count = cbm_split_camel_case(part, camel_parts, ENRICH_MAX_CAMEL);

        for (int i = 0; i < camel_count && count < max_out; i++) {
            for (char *c = camel_parts[i]; *c; c++) {
                *c = (char)tolower((unsigned char)*c);
            }
            if (strlen(camel_parts[i]) >= PAIR_LEN && !is_decorator_stopword(camel_parts[i])) {
                out[count++] = camel_parts[i];
            } else {
                free(camel_parts[i]);
            }
        }
        part = strtok_r(NULL, " ", &saveptr);
    }

    return count;
}

/* ══════════════════════════════════════════════════════════════════
 *  Decorator Tags Pass (post-flush, operates on store)
 *
 *  Algorithm:
 *  1. Load all Function/Method/Class nodes from the store
 *  2. For each node with "decorators" property, tokenize decorators
 *  3. Count word frequency across all nodes
 *  4. Words on 2+ distinct nodes become candidates
 *  5. Update each node's properties_json with "decorator_tags" array
 * ══════════════════════════════════════════════════════════════════ */

/* Per-node tokenization state */
typedef struct {
    int64_t node_id;
    char **words;
    int word_count;
} tagged_node_t;

/* Extract the "decorators" array from a properties_json string.
 * Returns a NULL-terminated array of strings. Caller must free array and strings. */
static char **extract_decorators_from_json(const char *json) {
    if (!json) {
        return NULL;
    }

    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    if (!doc) {
        return NULL;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *decs = yyjson_obj_get(root, "decorators");
    if (!decs || !yyjson_is_arr(decs)) {
        yyjson_doc_free(doc);
        return NULL;
    }

    size_t cnt = yyjson_arr_size(decs);
    if (cnt == 0) {
        yyjson_doc_free(doc);
        return NULL;
    }

    char **out = calloc(cnt + SKIP_ONE, sizeof(char *));
    size_t idx = 0;
    yyjson_val *item;
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(decs, &iter);
    while ((item = yyjson_arr_iter_next(&iter))) {
        if (yyjson_is_str(item)) {
            out[idx++] = strdup(yyjson_get_str(item));
        }
    }
    out[idx] = NULL;

    yyjson_doc_free(doc);
    if (idx > 0) {
        return out;
    }
    free(out);
    return NULL;
}

/* Tokenize all decorators on a node into unique words.
 * Returns heap-allocated array, caller frees each word and the array. */
static int extract_decorator_words(const char *json, char ***out_words) {
    char **decorators = extract_decorators_from_json(json);
    if (!decorators) {
        *out_words = NULL;
        return 0;
    }

    /* Collect unique words from all decorators */
    char *all_words[CBM_SZ_256];
    int total = 0;
    CBMHashTable *seen = cbm_ht_create(CBM_SZ_32);
    if (!seen) {
        for (int i = 0; decorators[i]; i++) {
            free(decorators[i]);
        }
        free(decorators);
        cbm_log_error("decorator_tags.index_failed", "code", "CBM_DECORATOR_SEEN_ALLOC_FAILED",
                      "component", "decorator_tags.seen", "operation", "create", "key", "",
                      "message", "decorator token set could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        *out_words = NULL;
        return CBM_NOT_FOUND;
    }

    for (int i = 0; decorators[i]; i++) {
        char *tokens[CBM_SZ_32];
        int tc = cbm_tokenize_decorator(decorators[i], tokens, CBM_SZ_32);
        for (int j = 0; j < tc; j++) {
            if (!cbm_ht_get(seen, tokens[j]) && total < CBM_SZ_256) {
                if (!cbm_ht_set_checked(seen, tokens[j], intptr_to_ptr(SKIP_ONE), NULL)) {
                    cbm_log_error(
                        "decorator_tags.index_failed", "code", "CBM_DECORATOR_SEEN_INSERT_FAILED",
                        "component", "decorator_tags.seen", "operation", "insert", "key", tokens[j],
                        "message", "decorator token set could not retain an entry", "remediation",
                        "free memory or reduce repository size, then retry");
                    for (int k = j; k < tc; k++) {
                        free(tokens[k]);
                    }
                    for (int k = 0; k < total; k++) {
                        free(all_words[k]);
                    }
                    free(decorators[i]);
                    for (int k = i + 1; decorators[k]; k++) {
                        free(decorators[k]);
                    }
                    free(decorators);
                    cbm_ht_free(seen);
                    *out_words = NULL;
                    return CBM_NOT_FOUND;
                }
                all_words[total++] = tokens[j];
            } else {
                free(tokens[j]);
            }
        }
        free(decorators[i]);
    }
    free(decorators);
    cbm_ht_free(seen);

    if (total == 0) {
        *out_words = NULL;
        return 0;
    }

    *out_words = malloc(sizeof(char *) * total);
    if (!*out_words) {
        for (int i = 0; i < total; i++) {
            free(all_words[i]);
        }
        cbm_log_error("decorator_tags.index_failed", "code", "CBM_DECORATOR_WORDS_ALLOC_FAILED",
                      "component", "decorator_tags.words", "operation", "output_alloc", "key", "",
                      "message", "decorator word output could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    memcpy(*out_words, all_words, sizeof(char *) * total);
    return total;
}

/* Insert "decorator_tags" into a properties_json string.
 * Returns a newly allocated JSON string. Caller must free(). */
static char *inject_decorator_tags(const char *json, char **tags, int tag_count) {
    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;

    yyjson_mut_doc *mdoc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *mroot;

    if (root && yyjson_is_obj(root)) {
        mroot = yyjson_val_mut_copy(mdoc, root);
    } else {
        mroot = yyjson_mut_obj(mdoc);
    }
    yyjson_mut_doc_set_root(mdoc, mroot);

    /* Remove existing decorator_tags if any */
    yyjson_mut_obj_remove_key(mroot, "decorator_tags");

    /* Add sorted tag array */
    yyjson_mut_val *arr = yyjson_mut_arr(mdoc);
    for (int i = 0; i < tag_count; i++) {
        yyjson_mut_arr_add_str(mdoc, arr, tags[i]);
    }
    yyjson_mut_obj_add_val(mdoc, mroot, "decorator_tags", arr);

    char *result = yyjson_mut_write(mdoc, 0, NULL);
    yyjson_mut_doc_free(mdoc);
    yyjson_doc_free(doc);
    return result;
}

/* Simple string comparison for qsort */
static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* Free tagged_node_t array. */
static void free_tagged_nodes(tagged_node_t *nodes, int count) {
    for (int n = 0; n < count; n++) {
        for (int w = 0; w < nodes[n].word_count; w++) {
            free(nodes[n].words[w]);
        }
        free(nodes[n].words);
    }
    free(nodes);
}

/* Phase 1: Collect decorated nodes and count word frequency. */
static int collect_decorated_nodes(cbm_gbuf_t *gbuf, tagged_node_t **out_nodes,
                                   CBMHashTable *word_counts) {
    /* "Struct" alongside "Class" so Go/Rust/Swift/D struct names keep
     * contributing to / receiving auto-tags as they did when structs were
     * labelled "Class". */
    static const char *labels[] = {"Function", "Method", "Class", "Struct"};
    static const int nlabels = 4;
    tagged_node_t *nodes = NULL;
    int node_count = 0;
    int node_cap = 0;

    for (int l = 0; l < nlabels; l++) {
        const cbm_gbuf_node_t **found = NULL;
        int fc = 0;
        cbm_gbuf_find_by_label(gbuf, labels[l], &found, &fc);
        if (!found || fc <= 0) {
            continue;
        }

        for (int i = 0; i < fc; i++) {
            char **words = NULL;
            int wc = extract_decorator_words(found[i]->properties_json, &words);
            if (wc < 0) {
                free_tagged_nodes(nodes, node_count);
                *out_nodes = NULL;
                return CBM_NOT_FOUND;
            }
            if (wc <= 0) {
                continue;
            }
            if (!cbm_da_ensure_capacity((void **)&nodes, &node_cap, node_count + 1,
                                        sizeof(*nodes))) {
                cbm_log_error("decorator_tags.collect", "code",
                              "CBM_DECORATOR_NODE_ALLOCATION_FAILED", "message",
                              "decorated-node result allocation failed", "remediation",
                              "free memory or reduce repository size, then retry; no partial tags "
                              "were applied");
                for (int w = 0; w < wc; w++) {
                    free(words[w]);
                }
                free(words);
                free_tagged_nodes(nodes, node_count);
                *out_nodes = NULL;
                return CBM_NOT_FOUND;
            }
            tagged_node_t *tn = &nodes[node_count++];
            tn->node_id = found[i]->id;
            tn->words = words;
            tn->word_count = wc;
            for (int w = 0; w < wc; w++) {
                intptr_t cnt = (intptr_t)cbm_ht_get(word_counts, words[w]);
                if (!cbm_ht_set_checked(word_counts, words[w], intptr_to_ptr(cnt + SKIP_ONE),
                                        NULL)) {
                    cbm_log_error(
                        "decorator_tags.index_failed", "code", "CBM_DECORATOR_COUNT_INSERT_FAILED",
                        "component", "decorator_tags.word_counts", "operation", "insert", "key",
                        words[w], "message", "decorator count map could not retain an entry",
                        "remediation", "free memory or reduce repository size, then retry");
                    free_tagged_nodes(nodes, node_count);
                    *out_nodes = NULL;
                    return CBM_NOT_FOUND;
                }
            }
        }
    }

    *out_nodes = nodes;
    return node_count;
}

/* Phase 3: Apply candidate tags to nodes in the gbuf. */
static int apply_decorator_tags(cbm_gbuf_t *gbuf, tagged_node_t *nodes, int node_count,
                                CBMHashTable *candidates) {
    int tagged = 0;
    for (int n = 0; n < node_count; n++) {
        char *tag_words[CBM_SZ_256];
        int tag_count = 0;
        for (int w = 0; w < nodes[n].word_count; w++) {
            if (cbm_ht_get(candidates, nodes[n].words[w]) && tag_count < CBM_SZ_256) {
                tag_words[tag_count++] = nodes[n].words[w];
            }
        }
        if (tag_count == 0) {
            continue;
        }
        qsort(tag_words, tag_count, sizeof(char *), cmp_str);

        const cbm_gbuf_node_t *gn = cbm_gbuf_find_by_id(gbuf, nodes[n].node_id);
        if (!gn) {
            continue;
        }

        const char *props = gn->properties_json ? gn->properties_json : "{}";
        char *new_props = inject_decorator_tags(props, tag_words, tag_count);
        if (new_props) {
            int64_t updated =
                gn->source_present
                    ? cbm_gbuf_upsert_source_node(gbuf, gn->label, gn->name, gn->qualified_name,
                                                  gn->file_path, gn->start_line, gn->end_line,
                                                  gn->source_bytes, gn->source_len, gn->start_byte,
                                                  gn->end_byte, new_props)
                    : cbm_gbuf_upsert_node(gbuf, gn->label, gn->name, gn->qualified_name,
                                           gn->file_path, gn->start_line, gn->end_line, new_props);
            free(new_props);
            if (updated > 0) {
                tagged++;
            }
        }
    }
    return tagged;
}

int cbm_pipeline_pass_decorator_tags(cbm_gbuf_t *gbuf, const char *project) {
    if (!gbuf || !project) {
        return 0;
    }

    CBMHashTable *word_counts = cbm_ht_create(CBM_SZ_128);
    if (!word_counts) {
        cbm_log_error("decorator_tags.index_failed", "code", "CBM_DECORATOR_COUNT_ALLOC_FAILED",
                      "component", "decorator_tags.word_counts", "operation", "create", "key", "",
                      "message", "decorator count map could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        return CBM_NOT_FOUND;
    }
    tagged_node_t *nodes = NULL;
    int node_count = collect_decorated_nodes(gbuf, &nodes, word_counts);
    if (node_count < 0) {
        cbm_ht_free(word_counts);
        return CBM_NOT_FOUND;
    }
    if (node_count == 0) {
        cbm_ht_free(word_counts);
        free(nodes);
        return 0;
    }

    /* Phase 2: Determine candidates (words on 2+ nodes) */
    CBMHashTable *candidates = cbm_ht_create(CBM_SZ_64);
    if (!candidates) {
        cbm_log_error("decorator_tags.index_failed", "code", "CBM_DECORATOR_CANDIDATE_ALLOC_FAILED",
                      "component", "decorator_tags.candidates", "operation", "create", "key", "",
                      "message", "decorator candidate map could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry");
        free_tagged_nodes(nodes, node_count);
        cbm_ht_free(word_counts);
        return CBM_NOT_FOUND;
    }
    int candidate_count = 0;
    for (int n = 0; n < node_count; n++) {
        for (int w = 0; w < nodes[n].word_count; w++) {
            const char *word = nodes[n].words[w];
            intptr_t cnt = (intptr_t)cbm_ht_get(word_counts, word);
            if (cnt >= PAIR_LEN && !cbm_ht_get(candidates, word)) {
                if (!cbm_ht_set_checked(candidates, word, intptr_to_ptr(SKIP_ONE), NULL)) {
                    cbm_log_error("decorator_tags.index_failed", "code",
                                  "CBM_DECORATOR_CANDIDATE_INSERT_FAILED", "component",
                                  "decorator_tags.candidates", "operation", "insert", "key", word,
                                  "message", "decorator candidate map could not retain an entry",
                                  "remediation",
                                  "free memory or reduce repository size, then retry");
                    free_tagged_nodes(nodes, node_count);
                    cbm_ht_free(word_counts);
                    cbm_ht_free(candidates);
                    return CBM_NOT_FOUND;
                }
                candidate_count++;
            }
        }
    }

    int tagged = 0;
    if (candidate_count > 0) {
        tagged = apply_decorator_tags(gbuf, nodes, node_count, candidates);
    }

    free_tagged_nodes(nodes, node_count);
    cbm_ht_free(word_counts);
    cbm_ht_free(candidates);

    cbm_log_info("pass.decorator_tags", "candidates", candidate_count > 0 ? "yes" : "0", "tagged",
                 tagged > 0 ? "yes" : "0");
    return tagged;
}
