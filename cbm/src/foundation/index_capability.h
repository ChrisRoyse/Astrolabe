#ifndef CBM_INDEX_CAPABILITY_H
#define CBM_INDEX_CAPABILITY_H

#include <stdbool.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

/* Persisted index-generation capability contract. These values are part of the
 * graph database file format: change them only with CBM_GRAPH_SCHEMA_VERSION. */
typedef enum {
    CBM_MODE_FULL = 0,
    CBM_MODE_MODERATE = 1,
    CBM_MODE_FAST = 2,
} cbm_index_mode_t;

typedef enum {
    CBM_SEMANTIC_AVAILABLE = 0,
    CBM_SEMANTIC_UNAVAILABLE_MODE = 1,
    CBM_SEMANTIC_UNAVAILABLE_CORPUS = 2,
} cbm_semantic_state_t;

enum {
    CBM_SEMANTIC_VECTOR_DIMENSION = 768,
    CBM_SEMANTIC_MIN_ELIGIBLE_NODES = 2,
    CBM_SEMANTIC_ELIGIBLE_NOT_EVALUATED = -1,
    CBM_SEMANTIC_IDF_FIXED_POINT_SCALE = 1000,
};

#define CBM_SEMANTIC_VECTOR_DIMENSION_SQL "768"
#define CBM_SEMANTIC_MIN_ELIGIBLE_NODES_SQL "2"

typedef struct {
    cbm_index_mode_t index_mode;
    cbm_semantic_state_t semantic_state;
    int vector_dimension;
    int eligible_node_count;
    int node_vector_count;
    int token_vector_count;
} cbm_index_capability_t;

/* The direct page writer cannot rely on SQLite expression evaluation while it
 * constructs records. Keep the float-to-schema conversion shared and refuse
 * NaN, infinity, underflow-to-zero, or signed-integer overflow before any page
 * is written. */
static inline bool cbm_semantic_idf_to_fixed(float idf, int64_t *out) {
    double scaled = (double)idf * (double)CBM_SEMANTIC_IDF_FIXED_POINT_SCALE;
    if (!out || !isfinite(scaled) || scaled < 1.0 || scaled > (double)INT64_MAX) {
        return false;
    }
    *out = (int64_t)scaled;
    return true;
}

/* A dimension-correct all-zero vector has no semantic direction and must never
 * be published or scored as an ordinary zero-similarity result. */
static inline bool cbm_semantic_i8_vector_nonzero(const uint8_t *vector, int vector_len) {
    if (!vector || vector_len != CBM_SEMANTIC_VECTOR_DIMENSION) {
        return false;
    }
    for (int i = 0; i < vector_len; i++) {
        if (vector[i] != 0) {
            return true;
        }
    }
    return false;
}

static inline const char *cbm_index_mode_name(cbm_index_mode_t mode) {
    switch (mode) {
    case CBM_MODE_FULL:
        return "full";
    case CBM_MODE_MODERATE:
        return "moderate";
    case CBM_MODE_FAST:
        return "fast";
    default:
        return NULL;
    }
}

static inline bool cbm_index_mode_parse(const char *text, cbm_index_mode_t *out) {
    if (!text || !out) {
        return false;
    }
    if (strcmp(text, "full") == 0) {
        *out = CBM_MODE_FULL;
        return true;
    }
    if (strcmp(text, "moderate") == 0) {
        *out = CBM_MODE_MODERATE;
        return true;
    }
    if (strcmp(text, "fast") == 0) {
        *out = CBM_MODE_FAST;
        return true;
    }
    return false;
}

static inline const char *cbm_semantic_state_name(cbm_semantic_state_t state) {
    switch (state) {
    case CBM_SEMANTIC_AVAILABLE:
        return "available";
    case CBM_SEMANTIC_UNAVAILABLE_MODE:
        return "unavailable_mode";
    case CBM_SEMANTIC_UNAVAILABLE_CORPUS:
        return "unavailable_corpus";
    default:
        return NULL;
    }
}

static inline bool cbm_semantic_state_parse(const char *text, cbm_semantic_state_t *out) {
    if (!text || !out) {
        return false;
    }
    if (strcmp(text, "available") == 0) {
        *out = CBM_SEMANTIC_AVAILABLE;
        return true;
    }
    if (strcmp(text, "unavailable_mode") == 0) {
        *out = CBM_SEMANTIC_UNAVAILABLE_MODE;
        return true;
    }
    if (strcmp(text, "unavailable_corpus") == 0) {
        *out = CBM_SEMANTIC_UNAVAILABLE_CORPUS;
        return true;
    }
    return false;
}

/* Validate the complete relational contract, not fields in isolation. This is
 * shared by producer, direct writer, and reader so no boundary can reinterpret
 * an incomplete generation as searchable. */
static inline bool cbm_index_capability_valid(const cbm_index_capability_t *capability) {
    if (!capability || !cbm_index_mode_name(capability->index_mode) ||
        !cbm_semantic_state_name(capability->semantic_state) ||
        capability->vector_dimension != CBM_SEMANTIC_VECTOR_DIMENSION ||
        capability->node_vector_count < 0 || capability->token_vector_count < 0) {
        return false;
    }

    switch (capability->semantic_state) {
    case CBM_SEMANTIC_AVAILABLE:
        return capability->index_mode != CBM_MODE_FAST &&
               capability->eligible_node_count >= CBM_SEMANTIC_MIN_ELIGIBLE_NODES &&
               capability->node_vector_count == capability->eligible_node_count &&
               capability->token_vector_count > 0;
    case CBM_SEMANTIC_UNAVAILABLE_MODE:
        return capability->index_mode == CBM_MODE_FAST &&
               capability->eligible_node_count == CBM_SEMANTIC_ELIGIBLE_NOT_EVALUATED &&
               capability->node_vector_count == 0 && capability->token_vector_count == 0;
    case CBM_SEMANTIC_UNAVAILABLE_CORPUS:
        return capability->index_mode != CBM_MODE_FAST && capability->eligible_node_count >= 0 &&
               capability->eligible_node_count < CBM_SEMANTIC_MIN_ELIGIBLE_NODES &&
               capability->node_vector_count == 0 && capability->token_vector_count == 0;
    default:
        return false;
    }
}

#endif /* CBM_INDEX_CAPABILITY_H */
