#include "cbm.h"

#include "arena.h"
#include "extract_node_stack.h"
#include "helpers.h"
#include "lang_specs.h"
#include "tree_sitter/api.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool ps_ci_equal(const char *left, const char *right) {
    if (!left || !right) {
        return false;
    }
    while (*left && *right) {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return false;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

bool cbm_powershell_add_diagnostic(CBMExtractCtx *ctx, TSNode node, const char *code,
                                   const char *operation, const char *message,
                                   const char *remediation, bool is_missing) {
    if (!ctx || !ctx->result || !ctx->arena || ts_node_is_null(node)) {
        return false;
    }
    uint32_t start = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    CBMParseDiagnostic diag = {
        .code = code,
        .operation = operation,
        .message = message,
        .remediation = remediation,
        .node_type = ts_node_type(node),
        .start_line = ts_node_start_point(node).row + 1,
        .end_line = ts_node_end_point(node).row + 1,
        .start_byte = start,
        .end_byte = end,
        .is_missing = is_missing,
    };
    if (end > start && end <= (uint32_t)ctx->source_len) {
        diag.source = cbm_arena_strndup(ctx->arena, ctx->source + start, (size_t)(end - start));
        diag.source_len = end - start;
    }
    return cbm_diagnostics_push(&ctx->result->diagnostics, ctx->arena, diag);
}

static void ps_record_tree_diagnostics(CBMExtractCtx *ctx, TSNode root, bool embedded_csharp) {
    CBMArena scratch;
    cbm_arena_init(&scratch);
    TSNodeStack stack;
    ts_nstack_init(&stack, &scratch, 128);
    ts_nstack_push(&stack, &scratch, root);
    while (stack.count > 0 && !cbm_arena_failed(ctx->arena)) {
        TSNode node = ts_nstack_pop(&stack);
        bool missing = ts_node_is_missing(node);
        if (ts_node_is_error(node) || missing) {
            cbm_powershell_add_diagnostic(
                ctx, node,
                embedded_csharp
                    ? (missing ? "CBM_POWERSHELL_EMBEDDED_CSHARP_MISSING_TOKEN"
                               : "CBM_POWERSHELL_EMBEDDED_CSHARP_PARSE_RECOVERY")
                    : (missing ? "CBM_POWERSHELL_MISSING_TOKEN" : "CBM_POWERSHELL_PARSE_RECOVERY"),
                embedded_csharp ? "parse_add_type_csharp" : "parse_powershell",
                embedded_csharp
                    ? "the Add-Type C# payload required tree-sitter error recovery"
                    : "the PowerShell grammar required error recovery at this exact source span",
                embedded_csharp
                    ? "repair the literal Add-Type C# payload before relying on nested symbols"
                    : "inspect the exact span; unaffected syntax remains indexed with this "
                      "degradation labeled",
                missing);
        }
        ts_nstack_push_children(&stack, &scratch, node);
    }
    cbm_arena_destroy(&scratch);
}

void cbm_powershell_record_parse_diagnostics(CBMExtractCtx *ctx) {
    if (!ctx || ctx->language != CBM_LANG_POWERSHELL) {
        return;
    }
    ps_record_tree_diagnostics(ctx, ctx->root, false);
}

static bool ps_value_kind(const char *kind) {
    return strcmp(kind, "variable") == 0 || strcmp(kind, "generic_token") == 0 ||
           strcmp(kind, "string_literal") == 0 || strcmp(kind, "expandable_string_literal") == 0 ||
           strcmp(kind, "verbatim_here_string_characters") == 0 ||
           strcmp(kind, "expandable_here_string_literal") == 0;
}

static TSNode ps_command_elements(TSNode command) {
    return ts_node_child_by_field_name(command, "command_elements", 16);
}

static TSNode ps_find_command_parameter(CBMExtractCtx *ctx, TSNode command, const char *parameter,
                                        int *matches) {
    TSNode found = {0};
    *matches = 0;
    TSNode elements = ps_command_elements(command);
    uint32_t count = ts_node_is_null(elements) ? 0 : ts_node_named_child_count(elements);
    for (uint32_t i = 0; i < count; i++) {
        TSNode child = ts_node_named_child(elements, i);
        if (strcmp(ts_node_type(child), "command_parameter") != 0) {
            continue;
        }
        char *text = cbm_node_text(ctx->arena, child, ctx->source);
        if (ps_ci_equal(text, parameter)) {
            found = child;
            (*matches)++;
        }
    }
    return found;
}

static TSNode ps_single_value(TSNode element) {
    if (ps_value_kind(ts_node_type(element))) {
        return element;
    }
    TSNode found = {0};
    CBMArena scratch;
    cbm_arena_init(&scratch);
    TSNodeStack stack;
    ts_nstack_init(&stack, &scratch, 32);
    ts_nstack_push_children(&stack, &scratch, element);
    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "command") == 0 || strcmp(kind, "command_parameter") == 0) {
            found = (TSNode){0};
            break;
        }
        if (ps_value_kind(kind)) {
            if (!ts_node_is_null(found)) {
                found = (TSNode){0};
                break;
            }
            found = node;
            continue;
        }
        ts_nstack_push_children(&stack, &scratch, node);
    }
    cbm_arena_destroy(&scratch);
    return found;
}

static TSNode ps_value_after_parameter(CBMExtractCtx *ctx, TSNode command, TSNode parameter) {
    (void)ctx;
    TSNode elements = ps_command_elements(command);
    uint32_t count = ts_node_is_null(elements) ? 0 : ts_node_named_child_count(elements);
    for (uint32_t i = 0; i < count; i++) {
        TSNode child = ts_node_named_child(elements, i);
        if (ts_node_start_byte(child) != ts_node_start_byte(parameter)) {
            continue;
        }
        if (i + 1 >= count ||
            strcmp(ts_node_type(ts_node_named_child(elements, i + 1)), "command_parameter") == 0) {
            return (TSNode){0};
        }
        return ps_single_value(ts_node_named_child(elements, i + 1));
    }
    return (TSNode){0};
}

static TSNode ps_first_descendant(TSNode root, const char *kind, CBMArena *scratch) {
    TSNodeStack stack;
    ts_nstack_init(&stack, scratch, 64);
    ts_nstack_push(&stack, scratch, root);
    TSNode best = {0};
    uint32_t best_start = UINT32_MAX;
    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        uint32_t start = ts_node_start_byte(node);
        if (strcmp(ts_node_type(node), kind) == 0 && start < best_start) {
            best = node;
            best_start = start;
        }
        ts_nstack_push_children(&stack, scratch, node);
    }
    return best;
}

static bool ps_scope_kind(const char *kind) {
    return strcmp(kind, "function_statement") == 0 ||
           strcmp(kind, "class_method_definition") == 0 ||
           strcmp(kind, "script_block_expression") == 0;
}

static TSNode ps_enclosing_scope(CBMExtractCtx *ctx, TSNode target) {
    TSNode best = {0};
    uint32_t target_start = ts_node_start_byte(target);
    uint32_t target_end = ts_node_end_byte(target);
    uint32_t best_width = UINT32_MAX;
    CBMArena scratch;
    cbm_arena_init(&scratch);
    TSNodeStack stack;
    ts_nstack_init(&stack, &scratch, 128);
    ts_nstack_push(&stack, &scratch, ctx->root);
    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        uint32_t start = ts_node_start_byte(node);
        uint32_t end = ts_node_end_byte(node);
        if (start <= target_start && end >= target_end) {
            if (ps_scope_kind(ts_node_type(node)) && start < end && end - start < best_width) {
                best = node;
                best_width = end - start;
            }
            ts_nstack_push_children(&stack, &scratch, node);
        }
    }
    cbm_arena_destroy(&scratch);
    return best;
}

static bool ps_same_scope(TSNode left, TSNode right) {
    if (ts_node_is_null(left) || ts_node_is_null(right)) {
        return ts_node_is_null(left) && ts_node_is_null(right);
    }
    return ts_node_start_byte(left) == ts_node_start_byte(right) &&
           ts_node_end_byte(left) == ts_node_end_byte(right) &&
           strcmp(ts_node_type(left), ts_node_type(right)) == 0;
}

static TSNode ps_bound_literal(CBMExtractCtx *ctx, TSNode command, const char *variable,
                               int *assignment_count) {
    TSNode literal = {0};
    *assignment_count = 0;
    uint32_t command_start = ts_node_start_byte(command);
    TSNode command_scope = ps_enclosing_scope(ctx, command);
    CBMArena scratch;
    cbm_arena_init(&scratch);
    TSNodeStack stack;
    ts_nstack_init(&stack, &scratch, 128);
    ts_nstack_push(&stack, &scratch, ctx->root);
    while (stack.count > 0) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "assignment_expression") == 0 &&
            ts_node_start_byte(node) < command_start) {
            TSNode assignment_scope = ps_enclosing_scope(ctx, node);
            bool visible_scope =
                ts_node_is_null(assignment_scope) || ps_same_scope(assignment_scope, command_scope);
            if (!visible_scope) {
                ts_nstack_push_children(&stack, &scratch, node);
                continue;
            }
            TSNode lhs = ps_first_descendant(node, "variable", &scratch);
            char *lhs_text =
                ts_node_is_null(lhs) ? NULL : cbm_node_text(&scratch, lhs, ctx->source);
            if (ps_ci_equal(lhs_text, variable)) {
                (*assignment_count)++;
                literal = ps_first_descendant(node, "verbatim_here_string_characters", &scratch);
            }
        }
        ts_nstack_push_children(&stack, &scratch, node);
    }
    cbm_arena_destroy(&scratch);
    return literal;
}

static bool ps_here_string_range(CBMExtractCtx *ctx, TSNode literal, TSRange *range) {
    uint32_t start = ts_node_start_byte(literal);
    uint32_t end = ts_node_end_byte(literal);
    if (end <= start || end > (uint32_t)ctx->source_len || end - start < 6 ||
        ctx->source[start] != '@' || ctx->source[start + 1] != '\'' ||
        ctx->source[end - 2] != '\'' || ctx->source[end - 1] != '@' ||
        ctx->source[end - 3] != '\n') {
        return false;
    }
    uint32_t content_start;
    if (ctx->source[start + 2] == '\n') {
        content_start = start + 3;
    } else if (ctx->source[start + 2] == '\r' && ctx->source[start + 3] == '\n') {
        content_start = start + 4;
    } else {
        return false;
    }
    /* Include the newline immediately before the closing delimiter. That makes
     * end_byte and end_point both identify column zero of the delimiter line,
     * which is the exact Tree-sitter included-range contract. */
    uint32_t content_end = end - 2;
    if (content_end <= content_start) {
        return false;
    }
    TSPoint start_point = ts_node_start_point(literal);
    TSPoint end_point = ts_node_end_point(literal);
    start_point.row++;
    start_point.column = 0;
    end_point.column = 0;
    *range = (TSRange){
        .start_point = start_point,
        .end_point = end_point,
        .start_byte = content_start,
        .end_byte = content_end,
    };
    return true;
}

static bool ps_range_seen(const uint32_t *ranges, int count, uint32_t start, uint32_t end) {
    for (int i = 0; i < count; i++) {
        if (ranges[i * 2] == start && ranges[i * 2 + 1] == end) {
            return true;
        }
    }
    return false;
}

static bool ps_remember_range(CBMExtractCtx *ctx, uint32_t **ranges, int *count, int *cap,
                              uint32_t start, uint32_t end) {
    if (*count == *cap) {
        int next = *cap == 0 ? 4 : *cap * 2;
        uint32_t *grown = realloc(*ranges, (size_t)next * 2 * sizeof(uint32_t));
        if (!grown) {
            cbm_file_result_set_error(
                ctx->result, "CBM_POWERSHELL_EMBEDDED_RANGE_ALLOC_FAILED", "realloc", "extraction",
                (size_t)next * 2 * sizeof(uint32_t),
                "the embedded C# range inventory could not be allocated",
                "free memory or reduce the number of Add-Type payloads, then retry");
            return false;
        }
        *ranges = grown;
        *cap = next;
    }
    (*ranges)[*count * 2] = start;
    (*ranges)[*count * 2 + 1] = end;
    (*count)++;
    return true;
}

static void ps_extract_csharp_range(CBMExtractCtx *ctx, TSNode command, TSNode literal,
                                    uint32_t **ranges, int *range_count, int *range_cap) {
    TSRange range;
    if (!ps_here_string_range(ctx, literal, &range)) {
        cbm_powershell_add_diagnostic(
            ctx, literal, "CBM_POWERSHELL_ADD_TYPE_LITERAL_INVALID", "parse_add_type_csharp",
            "the Add-Type payload is not a well-formed single-quoted here-string",
            "use a literal @' here-string whose opening and closing delimiters occupy valid lines",
            false);
        return;
    }
    if (ps_range_seen(*ranges, *range_count, range.start_byte, range.end_byte)) {
        return;
    }
    if (!ps_remember_range(ctx, ranges, range_count, range_cap, range.start_byte, range.end_byte)) {
        return;
    }

    const TSLanguage *csharp = cbm_ts_language(CBM_LANG_CSHARP);
    TSParser *parser = ts_parser_new();
    if (!parser || !csharp || !ts_parser_set_language(parser, csharp) ||
        !ts_parser_set_included_ranges(parser, &range, 1)) {
        if (parser) {
            ts_parser_delete(parser);
        }
        cbm_file_result_set_error(
            ctx->result, "CBM_POWERSHELL_EMBEDDED_PARSER_INIT_FAILED", "tree_sitter_parser",
            "extraction", 0, "the authoritative C# included-range parser could not be initialized",
            "verify the C# core grammar and available memory, then retry");
        return;
    }
    TSTree *tree = ts_parser_parse_string(parser, NULL, ctx->source, (uint32_t)ctx->source_len);
    ts_parser_delete(parser);
    if (!tree) {
        cbm_file_result_set_error(
            ctx->result, "CBM_POWERSHELL_EMBEDDED_PARSE_FAILED", "ts_parser_parse_string",
            "extraction", range.end_byte - range.start_byte,
            "the authoritative C# included-range parse failed",
            "inspect the exact Add-Type literal and retry after repairing the parser failure");
        return;
    }

    TSNode root = ts_tree_root_node(tree);
    CBMExtractCtx nested = {
        .arena = ctx->arena,
        .result = ctx->result,
        .source = ctx->source,
        .source_len = ctx->source_len,
        .language = CBM_LANG_CSHARP,
        .project = ctx->project,
        .rel_path = ctx->rel_path,
        .module_qn = ctx->module_qn,
        .root = root,
        .embedded = true,
    };
    if (ts_node_has_error(root)) {
        ps_record_tree_diagnostics(&nested, root, true);
        ts_tree_delete(tree);
        return;
    }

    const char *host_namespace = ctx->result->namespace_name;
    cbm_extract_definitions(&nested);
    cbm_extract_imports(&nested);
    ctx->result->namespace_name = host_namespace;
    cbm_extract_unified(&nested);
    ts_tree_delete(tree);
    (void)command;
}

static void ps_process_add_type(CBMExtractCtx *ctx, TSNode command, uint32_t **ranges,
                                int *range_count, int *range_cap) {
    int type_param_count = 0;
    TSNode type_param =
        ps_find_command_parameter(ctx, command, "-TypeDefinition", &type_param_count);
    if (ts_node_is_null(type_param)) {
        return; // another documented Add-Type parameter set, not embedded source
    }
    if (type_param_count != 1) {
        cbm_powershell_add_diagnostic(
            ctx, command, "CBM_POWERSHELL_ADD_TYPE_PARAMETER_AMBIGUOUS", "parse_add_type_csharp",
            "Add-Type contains more than one -TypeDefinition parameter",
            "supply exactly one -TypeDefinition parameter and one static source value", false);
        return;
    }
    int language_param_count = 0;
    TSNode language_param =
        ps_find_command_parameter(ctx, command, "-Language", &language_param_count);
    if (language_param_count > 1) {
        cbm_powershell_add_diagnostic(ctx, command, "CBM_POWERSHELL_ADD_TYPE_PARAMETER_AMBIGUOUS",
                                      "parse_add_type_csharp",
                                      "Add-Type contains more than one -Language parameter",
                                      "supply at most one -Language CSharp parameter", false);
        return;
    }
    if (!ts_node_is_null(language_param)) {
        TSNode language_value = ps_value_after_parameter(ctx, command, language_param);
        char *language = ts_node_is_null(language_value)
                             ? NULL
                             : cbm_node_text(ctx->arena, language_value, ctx->source);
        if (!ps_ci_equal(language, "CSharp")) {
            cbm_powershell_add_diagnostic(
                ctx, command, "CBM_POWERSHELL_ADD_TYPE_LANGUAGE_UNSUPPORTED",
                "parse_add_type_csharp",
                "Add-Type -TypeDefinition names a language other than CSharp or omits its value",
                "use -Language CSharp for an authoritative nested parse", false);
            return;
        }
    }

    TSNode value = ps_value_after_parameter(ctx, command, type_param);
    if (ts_node_is_null(value)) {
        cbm_powershell_add_diagnostic(
            ctx, command, "CBM_POWERSHELL_ADD_TYPE_VALUE_MISSING", "parse_add_type_csharp",
            "Add-Type -TypeDefinition has no source value",
            "supply one literal single-quoted here-string or one unambiguous variable bound to it",
            false);
        return;
    }
    const char *kind = ts_node_type(value);
    TSNode literal = {0};
    if (strcmp(kind, "verbatim_here_string_characters") == 0) {
        literal = value;
    } else if (strcmp(kind, "variable") == 0) {
        char *variable = cbm_node_text(ctx->arena, value, ctx->source);
        int assignments = 0;
        literal = ps_bound_literal(ctx, command, variable, &assignments);
        if (assignments != 1 || ts_node_is_null(literal)) {
            cbm_powershell_add_diagnostic(
                ctx, value, "CBM_POWERSHELL_ADD_TYPE_BINDING_AMBIGUOUS",
                "resolve_add_type_definition",
                "the Add-Type source variable is not bound by exactly one prior literal "
                "here-string assignment",
                "bind the variable exactly once to a single-quoted here-string before Add-Type",
                false);
            return;
        }
    } else {
        cbm_powershell_add_diagnostic(
            ctx, value, "CBM_POWERSHELL_ADD_TYPE_VALUE_UNSUPPORTED", "parse_add_type_csharp",
            "the Add-Type source value is dynamic or is not a single-quoted here-string",
            "use a literal single-quoted here-string or one unambiguous variable bound to it",
            false);
        return;
    }
    ps_extract_csharp_range(ctx, command, literal, ranges, range_count, range_cap);
}

void cbm_powershell_extract_embedded_csharp(CBMExtractCtx *ctx) {
    if (!ctx || ctx->language != CBM_LANG_POWERSHELL) {
        return;
    }
    uint32_t *ranges = NULL;
    int range_count = 0;
    int range_cap = 0;
    CBMArena scratch;
    cbm_arena_init(&scratch);
    TSNodeStack stack;
    ts_nstack_init(&stack, &scratch, 128);
    ts_nstack_push(&stack, &scratch, ctx->root);
    while (stack.count > 0 && !ctx->result->has_error) {
        TSNode node = ts_nstack_pop(&stack);
        if (strcmp(ts_node_type(node), "command") == 0 && !ts_node_has_error(node)) {
            TSNode name = ts_node_child_by_field_name(node, "command_name", 12);
            char *text = ts_node_is_null(name) ? NULL : cbm_node_text(&scratch, name, ctx->source);
            if (ps_ci_equal(text, "Add-Type")) {
                ps_process_add_type(ctx, node, &ranges, &range_count, &range_cap);
                continue;
            }
        }
        ts_nstack_push_children(&stack, &scratch, node);
    }
    cbm_arena_destroy(&scratch);
    free(ranges);
}
