#ifndef CBM_EXTRACT_UNIFIED_H
#define CBM_EXTRACT_UNIFIED_H

#include "cbm.h"
#include "lang_specs.h"

// Scope kinds for the walk state stack.
#define SCOPE_FUNC 1
#define SCOPE_CLASS 2
#define SCOPE_CALL 3
#define SCOPE_IMPORT 4
#define SCOPE_LOOP 5
#define SCOPE_BRANCH 6

#define MAX_SCOPES 64

// WalkState tracks scope context during the unified cursor walk.
// Replaces parent-chain walks for enclosing_func_qn, inside_call, etc.
typedef struct {
    const char *enclosing_func_qn;  // current function QN (module_qn at top level)
    const char *enclosing_class_qn; // current class QN (NULL outside class)
    bool inside_call;               // within a call_node_types subtree
    bool inside_import;             // within an import_node_types subtree
    int loop_depth;                 // count of enclosing loop scopes (for bottleneck metrics)
    int branch_depth;               // count of enclosing branch scopes

    struct {
        const char *qn;
        uint32_t depth;
        uint8_t kind;
    } scopes[MAX_SCOPES];
    int scope_top;
} WalkState;

// Per-node handler prototypes. Each is called once per node during the
// unified cursor walk, replacing the old recursive walk_* functions.
void handle_calls(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state);
/* Conservative ownership discriminator for the compiler-expansion projection.
 * True includes every node kind from which handle_calls may emit a C-family
 * call; it may also include nodes whose syntax does not ultimately emit one. */
bool cbm_preprocessed_call_candidate(CBMLanguage language, TSNode node);
void handle_usages(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state);
void handle_throws(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state);
void handle_readwrites(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state);
void handle_type_refs(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state);
void handle_env_accesses(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                         WalkState *state);
void handle_type_assigns(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec,
                         WalkState *state);

/* Capture source-span-bound lexical bindings before the unified reference walk,
 * then classify a concrete reference without consulting repository-global
 * names. The current complete implementation covers Rust's binding constructs;
 * other languages retain syntax evidence and are resolved only by exact
 * import/module/path rules downstream. */
void cbm_extract_reference_bindings(CBMExtractCtx *ctx);
CBMReferenceIdentity cbm_reference_identity(CBMExtractCtx *ctx, TSNode node, const char *name,
                                            CBMReferenceDomain domain, bool is_member);
bool cbm_reference_is_local_definition(const CBMExtractCtx *ctx, TSNode node);

// Single-pass extraction using TSTreeCursor. Visits every node once,
// dispatching to all handlers per node. Replaces the 7 separate walk_*
// functions for calls/usages/throws/readwrites/type_refs/env_accesses/type_assigns.
// Definitions and imports stay as separate passes (different recursion patterns).
void cbm_extract_unified(CBMExtractCtx *ctx);

// C/C++ preprocessor second pass. It intentionally emits only calls (plus the
// internal scope/string-constant state needed to construct those calls). The
// caller must translate every appended expanded-buffer line through the
// preprocessor expansion map before the file result can leave extraction.
void cbm_extract_preprocessed_calls(CBMExtractCtx *ctx);

#endif // CBM_EXTRACT_UNIFIED_H
