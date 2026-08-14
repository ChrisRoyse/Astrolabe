#ifndef CBM_LSP_SCOPE_H
#define CBM_LSP_SCOPE_H

#include "type_rep.h"
#include "../arena.h"
#include "foundation/platform.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

typedef struct {
    const char *name;
    const CBMType *type;
} CBMVarBinding;

#define CBM_SCOPE_CHUNK_BINDINGS 16

typedef struct CBMScopeChunk {
    CBMVarBinding bindings[CBM_SCOPE_CHUNK_BINDINGS];
    int used;
    struct CBMScopeChunk *next;
} CBMScopeChunk;

typedef struct CBMScope {
    struct CBMScope *parent;
    CBMScopeChunk *chunks;
    CBMArena *arena; // owning arena, propagated to children at push time
} CBMScope;

// Default per-file type-lookup depth. Every authoritative resolver snapshots a
// strictly parsed CBM_LSP_MAX_LOOKUP_DEPTH value and fails the file when the
// bound is reached; this is a safety budget, never permission to publish a
// shortened alias/MRO/embedded-type walk as complete.
#define CBM_LSP_DEFAULT_LOOKUP_DEPTH 16

// Default recursion cap for per-language AST call-resolution walkers. Each file
// snapshots a strictly parsed positive value during context initialization. A
// reached cap is an extraction failure because publishing the shortened graph
// would misrepresent incomplete analysis as authoritative.
#define CBM_LSP_DEFAULT_WALK_DEPTH 512

/* Read a positive analysis bound without changing policy on malformed input.
 * Absence selects the named default. A present empty, truncated, non-numeric,
 * non-positive, or overflowing value makes the file extraction fail closed via
 * the arena's sticky error channel. */
static inline bool cbm_lsp_read_positive_limit(CBMArena *arena, const char *name, int default_value,
                                               const char *operation, int *out_value) {
    char raw[64];
    int env_status = cbm_read_env(name, raw, sizeof(raw));
    if (env_status == 0) {
        *out_value = default_value;
        return true;
    }
    if (env_status < 0 || raw[0] == '\0') {
        cbm_arena_mark_failed(arena, "CBM_LSP_LIMIT_CONFIG_INVALID", operation, 0);
        return false;
    }
    errno = 0;
    char *end = NULL;
    long parsed = strtol(raw, &end, 10);
    if (errno == ERANGE || end == raw || !end || *end != '\0' || parsed <= 0
#if LONG_MAX > INT_MAX
        || parsed > INT_MAX
#endif
    ) {
        cbm_arena_mark_failed(arena, "CBM_LSP_LIMIT_CONFIG_INVALID", operation, 0);
        return false;
    }
    *out_value = (int)parsed;
    return true;
}

CBMScope *cbm_scope_push(CBMArena *a, CBMScope *current);
CBMScope *cbm_scope_pop(CBMScope *scope);
void cbm_scope_bind(CBMScope *scope, const char *name, const CBMType *type);
const CBMType *cbm_scope_lookup(const CBMScope *scope, const char *name);

#endif // CBM_LSP_SCOPE_H
