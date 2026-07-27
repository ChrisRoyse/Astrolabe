#include "cbm.h"
#include "helpers.h"
#include "lang_specs.h"
#include "extract_unified.h"
#include "tree_sitter/api.h" // TSNode, ts_node_*
#include "foundation/constants.h"
#include "extract_node_stack.h"

enum { MAX_PARENT_DEPTH = 10, LAST_IDX = 1, MAX_BINDING_PATTERN_DEPTH = 256 };
#include <stdint.h> // uint32_t
#include <string.h>
#include <ctype.h>

// Forward declaration
static void walk_usages(CBMExtractCtx *ctx, TSNode root, const CBMLangSpec *spec);

// Check if a node is inside a call expression (to avoid double-counting as usage)
static bool is_inside_call(TSNode node, const CBMLangSpec *spec) {
    TSNode cur = ts_node_parent(node);
    int depth = 0;
    while (!ts_node_is_null(cur) && depth < MAX_PARENT_DEPTH) {
        if (cbm_kind_in_set(cur, spec->call_node_types)) {
            return true;
        }
        cur = ts_node_parent(cur);
        depth++;
    }
    return false;
}

// Check if a node is inside an import statement
static bool is_inside_import(TSNode node, const CBMLangSpec *spec) {
    if (!spec->import_node_types || !spec->import_node_types[0]) {
        return false;
    }
    TSNode cur = ts_node_parent(node);
    int depth = 0;
    while (!ts_node_is_null(cur) && depth < MAX_PARENT_DEPTH) {
        if (cbm_kind_in_set(cur, spec->import_node_types)) {
            return true;
        }
        cur = ts_node_parent(cur);
        depth++;
    }
    return false;
}

// Is this an identifier-like node that represents a reference?
static bool is_reference_node(TSNode node, CBMLanguage lang) {
    const char *kind = ts_node_type(node);

    // Common identifier types across languages
    if (strcmp(kind, "identifier") == 0 || strcmp(kind, "simple_identifier") == 0 ||
        strcmp(kind, "type_identifier") == 0) {
        return true;
    }

    // Language-specific reference types
    switch (lang) {
    case CBM_LANG_GO:
        return strcmp(kind, "field_identifier") == 0 || strcmp(kind, "package_identifier") == 0;
    case CBM_LANG_PYTHON:
        return strcmp(kind, "attribute") == 0;
    case CBM_LANG_RUST:
        return strcmp(kind, "field_identifier") == 0 || strcmp(kind, "scoped_identifier") == 0 ||
               strcmp(kind, "scoped_type_identifier") == 0;
    case CBM_LANG_HASKELL:
        return strcmp(kind, "variable") == 0 || strcmp(kind, "constructor") == 0;
    case CBM_LANG_OCAML:
        return strcmp(kind, "value_path") == 0 || strcmp(kind, "constructor_path") == 0;
    case CBM_LANG_ERLANG:
        return strcmp(kind, "atom") == 0 || strcmp(kind, "var") == 0;
    default:
        return false;
    }
}

/* Preserve the semantic namespace expressed by the concrete syntax. Rust (and
 * several other grammars) deliberately distinguishes `x.field` from
 * `x.method()`: field_identifier outside a call is a value reference, while a
 * type_identifier is a type reference. Other identifier shapes can denote a
 * first-class function, value, or type and therefore retain the wider SYMBOL
 * domain; the graph resolver will still require exactly one stable atom. */
static CBMReferenceDomain reference_target_domain(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "type_identifier") == 0 || strcmp(kind, "scoped_type_identifier") == 0 ||
        strcmp(kind, "constructor") == 0 || strcmp(kind, "constructor_path") == 0) {
        return CBM_REF_DOMAIN_TYPE;
    }
    if (strcmp(kind, "field_identifier") == 0) {
        return CBM_REF_DOMAIN_VALUE;
    }
    return CBM_REF_DOMAIN_SYMBOL;
}

static bool reference_domain_accepts_binding(CBMReferenceDomain reference_domain,
                                             CBMReferenceDomain binding_domain) {
    if (reference_domain == CBM_REF_DOMAIN_TYPE) {
        return binding_domain == CBM_REF_DOMAIN_TYPE;
    }
    return binding_domain != CBM_REF_DOMAIN_TYPE;
}

static bool same_qn(const char *left, const char *right) {
    if (!left || !right) {
        return left == right;
    }
    return strcmp(left, right) == 0;
}

static bool rust_add_binding(CBMExtractCtx *ctx, TSNode definition, const char *name,
                             const char *func_qn, uint32_t scope_start, uint32_t scope_end,
                             CBMReferenceDomain domain) {
    if (!name || !name[0] || strcmp(name, "_") == 0 || scope_end <= scope_start) {
        return true;
    }
    CBMLocalBinding binding = {
        .name = name,
        .enclosing_func_qn = func_qn,
        .definition_start_byte = ts_node_start_byte(definition),
        .definition_end_byte = ts_node_end_byte(definition),
        .scope_start_byte = scope_start,
        .scope_end_byte = scope_end,
        .target_domain = domain,
    };
    return cbm_local_bindings_push(&ctx->result->local_bindings, ctx->arena, binding);
}

static bool rust_add_binding_node(CBMExtractCtx *ctx, TSNode definition, const char *func_qn,
                                  uint32_t scope_start, uint32_t scope_end,
                                  CBMReferenceDomain domain) {
    char *name = cbm_node_text(ctx->arena, definition, ctx->source);
    return rust_add_binding(ctx, definition, name, func_qn, scope_start, scope_end, domain);
}

/* Record exactly the identifier nodes which Rust treats as pattern bindings.
 * Constructor/type paths are deliberately skipped; tuple-struct patterns skip
 * their first named child, and an or-pattern uses its first branch because Rust
 * requires every branch to bind the same names. */
static bool rust_record_pattern(CBMExtractCtx *ctx, TSNode pattern, const char *func_qn,
                                uint32_t scope_start, uint32_t scope_end, int depth) {
    if (ts_node_is_null(pattern)) {
        return true;
    }
    if (depth >= MAX_BINDING_PATTERN_DEPTH) {
        cbm_arena_mark_failed(ctx->arena, "CBM_REFERENCE_BINDING_DEPTH_EXCEEDED",
                              "rust_reference_binding_pattern", MAX_BINDING_PATTERN_DEPTH);
        return false;
    }
    const char *kind = ts_node_type(pattern);
    if (strcmp(kind, "identifier") == 0 || strcmp(kind, "shorthand_field_identifier") == 0) {
        return rust_add_binding_node(ctx, pattern, func_qn, scope_start, scope_end,
                                     CBM_REF_DOMAIN_VALUE);
    }
    if (strcmp(kind, "captured_pattern") == 0) {
        TSNode name = ts_node_child_by_field_name(pattern, TS_FIELD("name"));
        if (!ts_node_is_null(name) && !rust_add_binding_node(ctx, name, func_qn, scope_start,
                                                             scope_end, CBM_REF_DOMAIN_VALUE)) {
            return false;
        }
        return rust_record_pattern(ctx, ts_node_child_by_field_name(pattern, TS_FIELD("pattern")),
                                   func_qn, scope_start, scope_end, depth + LAST_IDX);
    }
    if (strcmp(kind, "ref_pattern") == 0 || strcmp(kind, "mut_pattern") == 0 ||
        strcmp(kind, "reference_pattern") == 0) {
        return ts_node_named_child_count(pattern) == 0 ||
               rust_record_pattern(ctx, ts_node_named_child(pattern, 0), func_qn, scope_start,
                                   scope_end, depth + LAST_IDX);
    }
    if (strcmp(kind, "or_pattern") == 0) {
        return ts_node_named_child_count(pattern) == 0 ||
               rust_record_pattern(ctx, ts_node_named_child(pattern, 0), func_qn, scope_start,
                                   scope_end, depth + LAST_IDX);
    }
    if (strcmp(kind, "tuple_struct_pattern") == 0) {
        uint32_t count = ts_node_named_child_count(pattern);
        for (uint32_t i = 1; i < count; i++) {
            if (!rust_record_pattern(ctx, ts_node_named_child(pattern, i), func_qn, scope_start,
                                     scope_end, depth + LAST_IDX)) {
                return false;
            }
        }
        return true;
    }
    if (strcmp(kind, "struct_pattern") == 0) {
        TSNode body = ts_node_child_by_field_name(pattern, TS_FIELD("body"));
        TSNode fields = ts_node_is_null(body) ? pattern : body;
        uint32_t count = ts_node_named_child_count(fields);
        for (uint32_t i = 0; i < count; i++) {
            TSNode field = ts_node_named_child(fields, i);
            const char *field_kind = ts_node_type(field);
            if (strcmp(field_kind, "field_pattern") == 0) {
                TSNode nested = ts_node_child_by_field_name(field, TS_FIELD("pattern"));
                TSNode name = ts_node_child_by_field_name(field, TS_FIELD("name"));
                if (!ts_node_is_null(nested)) {
                    if (!rust_record_pattern(ctx, nested, func_qn, scope_start, scope_end,
                                             depth + LAST_IDX)) {
                        return false;
                    }
                } else if (!ts_node_is_null(name) &&
                           !rust_add_binding_node(ctx, name, func_qn, scope_start, scope_end,
                                                  CBM_REF_DOMAIN_VALUE)) {
                    return false;
                }
            } else if ((strcmp(field_kind, "shorthand_field_identifier") == 0 ||
                        strcmp(field_kind, "identifier") == 0) &&
                       !rust_add_binding_node(ctx, field, func_qn, scope_start, scope_end,
                                              CBM_REF_DOMAIN_VALUE)) {
                return false;
            }
        }
        return true;
    }
    if (strcmp(kind, "tuple_pattern") == 0 || strcmp(kind, "slice_pattern") == 0) {
        uint32_t count = ts_node_named_child_count(pattern);
        for (uint32_t i = 0; i < count; i++) {
            if (!rust_record_pattern(ctx, ts_node_named_child(pattern, i), func_qn, scope_start,
                                     scope_end, depth + LAST_IDX)) {
                return false;
            }
        }
    }
    return true;
}

static TSNode rust_nearest_parent_kind(TSNode node, const char *first, const char *second) {
    TSNode parent = ts_node_parent(node);
    while (!ts_node_is_null(parent)) {
        const char *kind = ts_node_type(parent);
        if (strcmp(kind, first) == 0 || (second && strcmp(kind, second) == 0)) {
            return parent;
        }
        parent = ts_node_parent(parent);
    }
    return (TSNode){0};
}

static TSNode rust_body_or_last_named(TSNode node, const char *primary_field) {
    TSNode body = ts_node_child_by_field_name(node, primary_field, (uint32_t)strlen(primary_field));
    if (ts_node_is_null(body) && ts_node_named_child_count(node) > 0) {
        body = ts_node_named_child(node, ts_node_named_child_count(node) - LAST_IDX);
    }
    return body;
}

static bool rust_record_parameters(CBMExtractCtx *ctx, TSNode parameters, const char *func_qn,
                                   uint32_t scope_start, uint32_t scope_end) {
    uint32_t count = ts_node_named_child_count(parameters);
    for (uint32_t i = 0; i < count; i++) {
        TSNode parameter = ts_node_named_child(parameters, i);
        const char *kind = ts_node_type(parameter);
        if (strcmp(kind, "self_parameter") == 0) {
            if (!rust_add_binding(ctx, parameter, "self", func_qn, scope_start, scope_end,
                                  CBM_REF_DOMAIN_VALUE)) {
                return false;
            }
            continue;
        }
        TSNode pattern = ts_node_child_by_field_name(parameter, TS_FIELD("pattern"));
        if (ts_node_is_null(pattern)) {
            pattern = parameter;
        }
        if (!rust_record_pattern(ctx, pattern, func_qn, scope_start, scope_end, 0)) {
            return false;
        }
    }
    return true;
}

static bool rust_record_construct_bindings(CBMExtractCtx *ctx, TSNode node) {
    const char *kind = ts_node_type(node);
    const char *func_qn = cbm_enclosing_func_qn_cached(ctx, node);

    if (strcmp(kind, "function_item") == 0) {
        TSNode body = rust_body_or_last_named(node, "body");
        TSNode parameters = ts_node_child_by_field_name(node, TS_FIELD("parameters"));
        if (!ts_node_is_null(body) && !ts_node_is_null(parameters)) {
            return rust_record_parameters(ctx, parameters, cbm_enclosing_func_qn_cached(ctx, body),
                                          ts_node_start_byte(body), ts_node_end_byte(body));
        }
        return true;
    }
    if (strcmp(kind, "let_declaration") == 0) {
        TSNode block = rust_nearest_parent_kind(node, "block", NULL);
        TSNode pattern = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
        if (!ts_node_is_null(block) && !ts_node_is_null(pattern)) {
            return rust_record_pattern(ctx, pattern, func_qn, ts_node_end_byte(node),
                                       ts_node_end_byte(block), 0);
        }
        return true;
    }
    if (strcmp(kind, "for_expression") == 0) {
        TSNode body = rust_body_or_last_named(node, "body");
        TSNode pattern = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
        return ts_node_is_null(body) || ts_node_is_null(pattern) ||
               rust_record_pattern(ctx, pattern, func_qn, ts_node_start_byte(body),
                                   ts_node_end_byte(body), 0);
    }
    if (strcmp(kind, "closure_expression") == 0) {
        TSNode body = rust_body_or_last_named(node, "body");
        TSNode parameters = ts_node_child_by_field_name(node, TS_FIELD("parameters"));
        return ts_node_is_null(body) || ts_node_is_null(parameters) ||
               rust_record_parameters(ctx, parameters, func_qn, ts_node_start_byte(body),
                                      ts_node_end_byte(body));
    }
    if (strcmp(kind, "match_arm") == 0) {
        TSNode pattern = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
        return ts_node_is_null(pattern) ||
               rust_record_pattern(ctx, pattern, func_qn, ts_node_end_byte(pattern),
                                   ts_node_end_byte(node), 0);
    }
    if (strcmp(kind, "let_condition") == 0) {
        TSNode owner = rust_nearest_parent_kind(node, "if_expression", "while_expression");
        const char *field =
            !ts_node_is_null(owner) && strcmp(ts_node_type(owner), "if_expression") == 0
                ? "consequence"
                : "body";
        TSNode body = ts_node_is_null(owner) ? (TSNode){0} : rust_body_or_last_named(owner, field);
        TSNode pattern = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
        if (ts_node_is_null(body) || ts_node_is_null(pattern)) {
            return true;
        }
        TSNode condition = ts_node_child_by_field_name(owner, TS_FIELD("condition"));
        if (!ts_node_is_null(condition) && ts_node_end_byte(node) < ts_node_end_byte(condition) &&
            !rust_record_pattern(ctx, pattern, func_qn, ts_node_end_byte(node),
                                 ts_node_end_byte(condition), 0)) {
            return false;
        }
        return rust_record_pattern(ctx, pattern, func_qn, ts_node_start_byte(body),
                                   ts_node_end_byte(body), 0);
    }
    if (strcmp(kind, "if_let_expression") == 0 || strcmp(kind, "while_let_expression") == 0) {
        const char *field = strcmp(kind, "if_let_expression") == 0 ? "consequence" : "body";
        TSNode body = rust_body_or_last_named(node, field);
        TSNode pattern = ts_node_child_by_field_name(node, TS_FIELD("pattern"));
        return ts_node_is_null(body) || ts_node_is_null(pattern) ||
               rust_record_pattern(ctx, pattern, func_qn, ts_node_start_byte(body),
                                   ts_node_end_byte(body), 0);
    }
    return true;
}

void cbm_extract_reference_bindings(CBMExtractCtx *ctx) {
    if (!ctx || ctx->language != CBM_LANG_RUST) {
        return;
    }
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, CBM_SZ_256);
    ts_nstack_push(&stack, ctx->arena, ctx->root);
    while (stack.count > 0 && !cbm_arena_failed(ctx->arena)) {
        TSNode node = ts_nstack_pop(&stack);
        if (!rust_record_construct_bindings(ctx, node)) {
            return;
        }
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - LAST_IDX; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

CBMReferenceIdentity cbm_reference_identity(CBMExtractCtx *ctx, TSNode node, const char *name,
                                            CBMReferenceDomain domain, bool is_member) {
    CBMReferenceIdentity identity = {
        .evidence = CBM_REF_EVIDENCE_UNQUALIFIED,
        .reference_start_byte = ts_node_start_byte(node),
        .reference_end_byte = ts_node_end_byte(node),
    };
    if (is_member || strcmp(ts_node_type(node), "field_identifier") == 0) {
        identity.evidence = CBM_REF_EVIDENCE_MEMBER;
        if (ctx && name && ctx->language == CBM_LANG_RUST) {
            TSNode field_expression = {0};
            TSNode field = {0};
            const char *node_kind = ts_node_type(node);
            if (strcmp(node_kind, "field_identifier") == 0) {
                field_expression = ts_node_parent(node);
                field = node;
            } else if (strcmp(node_kind, "field_expression") == 0) {
                field_expression = node;
                field = ts_node_child_by_field_name(field_expression, TS_FIELD("field"));
                if (ts_node_is_null(field)) {
                    field = ts_node_child_by_field_name(field_expression, TS_FIELD("name"));
                }
            }
            if (ts_node_is_null(field_expression) ||
                strcmp(ts_node_type(field_expression), "field_expression") != 0 ||
                ts_node_is_null(field)) {
                return identity;
            }
            TSNode receiver = ts_node_child_by_field_name(field_expression, TS_FIELD("value"));
            char *receiver_name =
                ts_node_is_null(receiver) ? NULL : cbm_node_text(ctx->arena, receiver, ctx->source);
            char *field_name = cbm_node_text(ctx->arena, field, ctx->source);
            if (receiver_name && field_name && field_name[0] &&
                strcmp(receiver_name, "self") == 0) {
                const char *func_qn = cbm_enclosing_func_qn_cached(ctx, node);
                const char *last_dot = func_qn ? strrchr(func_qn, '.') : NULL;
                if (last_dot) {
                    identity.resolved_target_qn = cbm_arena_sprintf(
                        ctx->arena, "%.*s.%s", (int)(last_dot - func_qn), func_qn, field_name);
                }
            }
        }
        return identity;
    }
    if (!ctx || !name) {
        return identity;
    }
    const char *func_qn = cbm_enclosing_func_qn_cached(ctx, node);
    const CBMLocalBinding *best = NULL;
    for (int i = 0; i < ctx->result->local_bindings.count; i++) {
        const CBMLocalBinding *binding = &ctx->result->local_bindings.items[i];
        if (strcmp(binding->name, name) != 0 || !same_qn(binding->enclosing_func_qn, func_qn) ||
            !reference_domain_accepts_binding(domain, binding->target_domain) ||
            identity.reference_start_byte < binding->scope_start_byte ||
            identity.reference_start_byte >= binding->scope_end_byte) {
            continue;
        }
        if (!best || binding->scope_start_byte > best->scope_start_byte ||
            (binding->scope_start_byte == best->scope_start_byte &&
             binding->definition_start_byte > best->definition_start_byte)) {
            best = binding;
        }
    }
    if (best) {
        identity.evidence = CBM_REF_EVIDENCE_LOCAL;
        identity.binding_start_byte = best->definition_start_byte;
        identity.binding_end_byte = best->definition_end_byte;
        identity.scope_start_byte = best->scope_start_byte;
        identity.scope_end_byte = best->scope_end_byte;
        return identity;
    }
    const char *kind = ts_node_type(node);
    if (strstr(name, "::") || strcmp(kind, "scoped_identifier") == 0 ||
        strcmp(kind, "scoped_type_identifier") == 0) {
        identity.evidence = CBM_REF_EVIDENCE_QUALIFIED_PATH;
    }
    return identity;
}

bool cbm_reference_is_local_definition(const CBMExtractCtx *ctx, TSNode node) {
    if (!ctx) {
        return false;
    }
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    for (int i = 0; i < ctx->result->local_bindings.count; i++) {
        const CBMLocalBinding *binding = &ctx->result->local_bindings.items[i];
        if (binding->definition_start_byte == start && binding->definition_end_byte == end) {
            return true;
        }
    }
    return false;
}

/* A Rust scoped path is one reference identity. Its nested path/name children
 * carry no independent binding evidence and must not be emitted as additional
 * unqualified references (for example `a::b::Thing` must not also persist a
 * guessed bare `Thing` edge). */
static bool is_nested_rust_qualified_component(const CBMExtractCtx *ctx, TSNode node) {
    if (!ctx || ctx->language != CBM_LANG_RUST) {
        return false;
    }
    TSNode parent = ts_node_parent(node);
    if (ts_node_is_null(parent)) {
        return false;
    }
    const char *parent_kind = ts_node_type(parent);
    return strcmp(parent_kind, "scoped_identifier") == 0 ||
           strcmp(parent_kind, "scoped_type_identifier") == 0;
}

static bool same_source_span(TSNode left, TSNode right) {
    return !ts_node_is_null(left) && ts_node_start_byte(left) == ts_node_start_byte(right) &&
           ts_node_end_byte(left) == ts_node_end_byte(right);
}

// Check whether a reference node is the binding owned by its direct parent.
//
// Tree-sitter grammars do not use one universal field for bindings. Languages
// such as JavaScript expose a declaration through `name`, while the C and C++
// grammars put function, parameter, pointer, and variable bindings in a
// `declarator` chain. Only compare the direct field's exact source span: walking
// upward through a whole function declarator would incorrectly classify
// references in default arguments as declarations.
static bool is_definition_binding(TSNode node) {
    TSNode parent = ts_node_parent(node);
    if (ts_node_is_null(parent)) {
        return false;
    }

    TSNode name_field = ts_node_child_by_field_name(parent, TS_FIELD("name"));
    if (same_source_span(name_field, node)) {
        return true;
    }

    TSNode declarator_field = ts_node_child_by_field_name(parent, TS_FIELD("declarator"));
    return same_source_span(declarator_field, node);
}

// Try to emit a usage for a reference node. Returns early if the node should be skipped.
static void try_emit_usage(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec) {
    if (!is_reference_node(node, ctx->language)) {
        return;
    }
    if (is_nested_rust_qualified_component(ctx, node)) {
        return;
    }
    if (is_inside_call(node, spec) || is_inside_import(node, spec)) {
        return;
    }
    if (is_definition_binding(node) || cbm_reference_is_local_definition(ctx, node)) {
        return;
    }
    char *name = cbm_node_text(ctx->arena, node, ctx->source);
    if (name && name[0] && !cbm_is_keyword(name, ctx->language)) {
        CBMUsage usage = {0};
        usage.ref_name = name;
        usage.enclosing_func_qn = cbm_enclosing_func_qn_cached(ctx, node);
        usage.start_line = (int)ts_node_start_point(node).row + 1;
        usage.target_domain = reference_target_domain(node);
        usage.reference =
            cbm_reference_identity(ctx, node, name, usage.target_domain,
                                   strcmp(ts_node_type(node), "field_identifier") == 0);
        if (!cbm_usages_push(&ctx->result->usages, ctx->arena, usage)) {
            return;
        }
    }
}

// Iterative usage walker — explicit stack
static void walk_usages(CBMExtractCtx *ctx, TSNode root, const CBMLangSpec *spec) {
    TSNodeStack stack;
    ts_nstack_init(&stack, ctx->arena, 4096);
    ts_nstack_push(&stack, ctx->arena, root);

    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        try_emit_usage(ctx, node, spec);
        uint32_t count = ts_node_child_count(node);
        for (int i = (int)count - LAST_IDX; i >= 0; i--) {
            ts_nstack_push(&stack, ctx->arena, ts_node_child(node, (uint32_t)i));
        }
    }
}

void cbm_extract_usages(CBMExtractCtx *ctx) {
    const CBMLangSpec *spec = cbm_lang_spec(ctx->language);
    if (!spec) {
        return;
    }

    walk_usages(ctx, ctx->root, spec);
}

// --- Unified handler: called once per node by the cursor walk ---
// Uses WalkState flags instead of parent-chain walks for O(1) context checks.

void handle_usages(CBMExtractCtx *ctx, TSNode node, const CBMLangSpec *spec, WalkState *state) {
    (void)spec;
    if (!is_reference_node(node, ctx->language)) {
        return;
    }
    if (is_nested_rust_qualified_component(ctx, node)) {
        return;
    }

    // Skip if inside a call (already counted as CALLS edge) — O(1) via state
    if (state->inside_call) {
        return;
    }
    // Skip if inside an import
    if (state->inside_import) {
        return;
    }

    if (is_definition_binding(node) || cbm_reference_is_local_definition(ctx, node)) {
        return;
    }

    char *name = cbm_node_text(ctx->arena, node, ctx->source);
    if (name && name[0] && !cbm_is_keyword(name, ctx->language)) {
        CBMUsage usage = {0};
        usage.ref_name = name;
        usage.enclosing_func_qn = state->enclosing_func_qn;
        usage.start_line = (int)ts_node_start_point(node).row + 1;
        usage.target_domain = reference_target_domain(node);
        usage.reference =
            cbm_reference_identity(ctx, node, name, usage.target_domain,
                                   strcmp(ts_node_type(node), "field_identifier") == 0);
        if (!cbm_usages_push(&ctx->result->usages, ctx->arena, usage)) {
            return;
        }
    }
}
