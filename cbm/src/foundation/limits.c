/*
 * limits.c — Env-configurable safety limits (Stage 2 / Track B4).
 */
#include "foundation/limits.h"
#include "parse_budget.h"

#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>

long cbm_max_file_bytes(void) {
    /* 512 MiB — generous: real source files never approach it, but a
     * pathological / vendored blob degrades to a reported "oversized" skip
     * instead of a silent drop or an unbounded read. */
    const long default_cap = 512L * 1024 * 1024;

    const char *raw = getenv("CBM_MAX_FILE_BYTES");
    if (raw && raw[0]) {
        errno = 0;
        char *end = NULL;
        long v = strtol(raw, &end, 10);
        if (errno == 0 && end != raw && *end == '\0' && v > 0) {
            return v;
        }
        /* Unparseable / non-positive → fall through to the safe default. */
    }
    return default_cap;
}

/* Shared env-int parser: a positive integer in [1, INT_MAX], else the fallback.
 * Read fresh each call (see cbm_max_file_bytes rationale — cheap, test-friendly,
 * no stale memoized copy across runs). */
static int env_positive_int(const char *name, int fallback) {
    const char *raw = getenv(name);
    if (raw && raw[0]) {
        errno = 0;
        char *end = NULL;
        long v = strtol(raw, &end, 10);
        if (errno == 0 && end != raw && *end == '\0' && v > 0 && v <= INT_MAX) {
            return (int)v;
        }
        /* Unparseable / non-positive / out-of-range → safe default. */
    }
    return fallback;
}

int cbm_cypher_max_depth(void) {
    /* 10 — generous for a code call/def graph; an explicit `*1..N` above this is
     * WARN-capped, never an unbounded (cyclic-graph DoS) traversal. */
    return env_positive_int("CBM_CYPHER_MAX_DEPTH", 10);
}

int cbm_mcp_max_depth(void) {
    /* 15 — ceiling for client-driven MCP graph traversals (trace_call_path,
     * detect_changes); the caller's `depth` is WARN-clamped to this. */
    return env_positive_int("CBM_MCP_MAX_DEPTH", 15);
}

const cbm_parse_budget_policy_t *cbm_parse_budget_policy(void) {
    /* #978 source of truth: the failed canonical 4,349-file self-index at
     * 84524cc7 recorded a 20,123,481-byte generated CUDA parser completing in
     * 14.863 s while 32 extraction workers contended (~1.29 MiB/s), whereas a
     * fixed five-second callback cancelled 26 larger generated parsers.  The
     * declared 256 KiB/s floor is five times more conservative than that real
     * completed observation. */
    static const cbm_parse_budget_policy_t policy = {
        .registry_version = "cbm.parse-budget.v1",
        .measurement_source = "Astrolabe#978 canonical Windows/GNU self-index 84524cc7",
        .base_micros = 5000000ULL,
        .minimum_forward_bytes_per_second = 256ULL * 1024ULL,
        .forward_stall_micros = 15000000ULL,
        .final_balance_micros = 30000000ULL,
        .maximum_total_micros = 3600000000ULL,
    };
    return &policy;
}

int64_t cbm_parse_budget_micros(size_t source_bytes) {
    const cbm_parse_budget_policy_t *policy = cbm_parse_budget_policy();
    if (!policy || policy->minimum_forward_bytes_per_second == 0 ||
        policy->base_micros == 0 || policy->maximum_total_micros == 0 ||
        policy->maximum_total_micros > (uint64_t)INT64_MAX) {
        return 0;
    }

    uint64_t bytes = (uint64_t)source_bytes;
    uint64_t seconds = bytes / policy->minimum_forward_bytes_per_second;
    if (bytes % policy->minimum_forward_bytes_per_second != 0) {
        seconds++;
    }
    if (seconds > (UINT64_MAX - policy->base_micros) / 1000000ULL) {
        return (int64_t)policy->maximum_total_micros;
    }
    uint64_t total = policy->base_micros + seconds * 1000000ULL;
    if (total > policy->maximum_total_micros) {
        total = policy->maximum_total_micros;
    }
    return total <= (uint64_t)INT64_MAX ? (int64_t)total : 0;
}
