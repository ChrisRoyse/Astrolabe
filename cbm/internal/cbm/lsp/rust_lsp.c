/* rust_lsp.c — Type-aware call resolution for Rust source files.
 *
 * Mirrors the structure of `go_lsp.c` and reverse-engineers the relevant
 * pieces of `rust-analyzer` (`hir-def/resolver.rs`,
 * `hir-ty/method_resolution.rs`, `hir-ty/infer.rs`) into a per-file walk
 * driven by tree-sitter-rust.
 *
 * The compilation unit is split into clearly-labelled sections:
 *
 *   1.  Init + helpers            (~150 lines)
 *   2.  Builtin / prelude tables  (~100 lines)
 *   3.  Path & use resolution     (~250 lines)
 *   4.  Type-AST → CBMType        (~250 lines)
 *   5.  Generic substitution      (~150 lines)
 *   6.  Expression evaluator      (~700 lines)
 *   7.  Method dispatch           (~400 lines)
 *   8.  Macro handling            (~200 lines)
 *   9.  Statement / pattern bind  (~400 lines)
 *   10. Function & file walk      (~250 lines)
 *   11. Per-file entry            (~250 lines)
 *   12. Cross-file + batch        (~250 lines)
 *
 * Total ~3300 lines, matching the depth of go_lsp.c (2750) and py_lsp.c
 * (3188). The code is structured so each section has a single coherent
 * responsibility — there are no surprise back-edges between sections.
 */

#include "rust_lsp.h"
#include "rust_cargo.h"
#include "semantic_array.h"
#include "../helpers.h"
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ════════════════════════════════════════════════════════════════════
 * 1. Initialisation + arena helpers
 * ════════════════════════════════════════════════════════════════════ */

/* Forward declarations for early callers in the file. */
static void rust_resolve_calls_in_node(RustLSPContext *ctx, TSNode node);
static void rust_resolve_calls_in_node_inner(RustLSPContext *ctx, TSNode node);
static void rust_process_function(RustLSPContext *ctx, TSNode func_node, const char *receiver_qn);
static void rust_emit_resolved_call(RustLSPContext *ctx, const char *callee_qn,
                                    const char *strategy, float confidence);
static void rust_inject_syn_call(RustLSPContext *ctx, const char *callee_qn, int start_line);
static void rust_emit_unresolved_call(RustLSPContext *ctx, const char *expr_text,
                                      const char *reason);
static const CBMType *rust_lookup_field(RustLSPContext *ctx, const char *type_qn,
                                        const char *field_name, int depth);
static const CBMRegisteredFunc *rust_lookup_method_depth(RustLSPContext *ctx, const char *type_qn,
                                                         const char *member_name, int depth);
static const CBMRegisteredFunc *rust_lookup_method_in_trait(RustLSPContext *ctx,
                                                            const char *trait_qn,
                                                            const char *method_name);
static char *rust_node_text(RustLSPContext *ctx, TSNode node);
static const char *convert_path_to_qn(CBMArena *arena, const char *path);
static bool rust_type_derefs_to_first_arg(const char *type_qn);
static const char *rust_lookup_type_param_bound(RustLSPContext *ctx, const char *name);
static void rust_collect_bounds_from_text(RustLSPContext *ctx, const char *text);
static void rust_record_type_param_bound(RustLSPContext *ctx, const char *param_name,
                                         const char *trait_qn);

enum {
    RUST_LSP_DEFAULT_MACRO_DEPTH_LIMIT = 8,
    RUST_LSP_DEFAULT_MACRO_WORK_FLOOR = 200000,
    RUST_LSP_DEFAULT_MACRO_WORK_PER_SOURCE_BYTE = 64,
    RUST_LSP_DEFAULT_MACRO_MATCH_DEPTH_LIMIT = 512,
    RUST_LSP_DEFAULT_EVAL_STEP_LIMIT = 200000,
};

static bool rust_lsp_read_macro_work_limit(CBMArena *arena, int source_len, int *out_value) {
    int work_per_source_byte = 0;
    if (!cbm_lsp_read_positive_limit(arena, "CBM_RUST_MACRO_WORK_PER_SOURCE_BYTE",
                                     RUST_LSP_DEFAULT_MACRO_WORK_PER_SOURCE_BYTE,
                                     "rust_lsp_macro_work_per_source_byte_config",
                                     &work_per_source_byte)) {
        return false;
    }
    size_t measured_source_bytes = source_len > 0 ? (size_t)source_len : 0;
    size_t scaled_limit = measured_source_bytes > (size_t)INT_MAX / (size_t)work_per_source_byte
                              ? (size_t)INT_MAX
                              : measured_source_bytes * (size_t)work_per_source_byte;
    int derived_default = scaled_limit > (size_t)RUST_LSP_DEFAULT_MACRO_WORK_FLOOR
                              ? (int)scaled_limit
                              : RUST_LSP_DEFAULT_MACRO_WORK_FLOOR;
    return cbm_lsp_read_positive_limit(arena, "CBM_RUST_MAX_MACRO_WORK", derived_default,
                                       "rust_lsp_macro_work_config", out_value);
}

void rust_lsp_init(RustLSPContext *ctx, CBMArena *arena, const char *source, int source_len,
                   const CBMTypeRegistry *registry, const char *module_qn,
                   CBMResolvedCallArray *out) {
    memset(ctx, 0, sizeof(RustLSPContext));
    ctx->arena = arena;
    ctx->source = source;
    ctx->source_len = source_len;
    ctx->registry = registry;
    ctx->module_qn = module_qn;
    ctx->resolved_calls = out;
    ctx->current_scope = cbm_scope_push(arena, NULL);
    if (!cbm_lsp_read_positive_limit(arena, "CBM_LSP_MAX_LOOKUP_DEPTH",
                                     CBM_LSP_DEFAULT_LOOKUP_DEPTH, "rust_lsp_lookup_depth_config",
                                     &ctx->lookup_depth_limit) ||
        !cbm_lsp_read_positive_limit(
            arena, "CBM_RUST_MAX_MACRO_DEPTH", RUST_LSP_DEFAULT_MACRO_DEPTH_LIMIT,
            "rust_lsp_macro_depth_config", &ctx->macro_expand_depth_limit) ||
        !rust_lsp_read_macro_work_limit(arena, source_len, &ctx->macro_work_limit) ||
        !cbm_lsp_read_positive_limit(
            arena, "CBM_RUST_MAX_MACRO_MATCH_DEPTH", RUST_LSP_DEFAULT_MACRO_MATCH_DEPTH_LIMIT,
            "rust_lsp_macro_match_depth_config", &ctx->macro_match_depth_limit) ||
        !cbm_lsp_read_positive_limit(arena, "CBM_LSP_MAX_EVAL_STEPS",
                                     RUST_LSP_DEFAULT_EVAL_STEP_LIMIT, "rust_lsp_eval_steps_config",
                                     &ctx->eval_step_limit) ||
        !cbm_lsp_read_positive_limit(arena, "CBM_LSP_MAX_WALK_DEPTH", CBM_LSP_DEFAULT_WALK_DEPTH,
                                     "rust_lsp_walk_depth_config", &ctx->walk_depth_limit)) {
        return;
    }

    const char *dbg = getenv("CBM_LSP_DEBUG");
    ctx->debug = (dbg && dbg[0]);
}

/* Doubling-array push of a `(local, full-path)` use entry. */
void rust_lsp_add_use(RustLSPContext *ctx, const char *local_name, const char *module_path) {
    if (!ctx || !local_name || !module_path) {
        return;
    }
    if (ctx->use_count % 32 == 0) {
        int new_cap = ctx->use_count + 32;
        const char **nl =
            (const char **)cbm_arena_alloc(ctx->arena, (new_cap + 1) * sizeof(char *));
        const char **np =
            (const char **)cbm_arena_alloc(ctx->arena, (new_cap + 1) * sizeof(char *));
        if (!nl || !np) {
            return;
        }
        if (ctx->use_local_names && ctx->use_count > 0) {
            memcpy(nl, ctx->use_local_names, ctx->use_count * sizeof(char *));
            memcpy(np, ctx->use_module_paths, ctx->use_count * sizeof(char *));
        }
        ctx->use_local_names = nl;
        ctx->use_module_paths = np;
    }
    ctx->use_local_names[ctx->use_count] = cbm_arena_strdup(ctx->arena, local_name);
    ctx->use_module_paths[ctx->use_count] = cbm_arena_strdup(ctx->arena, module_path);
    ctx->use_count++;
}

void rust_lsp_add_glob(RustLSPContext *ctx, const char *module_qn) {
    if (!ctx || !module_qn) {
        return;
    }
    if (ctx->glob_count % 16 == 0) {
        int new_cap = ctx->glob_count + 16;
        const char **ng =
            (const char **)cbm_arena_alloc(ctx->arena, (new_cap + 1) * sizeof(char *));
        if (!ng) {
            return;
        }
        if (ctx->glob_module_qns && ctx->glob_count > 0) {
            memcpy(ng, ctx->glob_module_qns, ctx->glob_count * sizeof(char *));
        }
        ctx->glob_module_qns = ng;
    }
    ctx->glob_module_qns[ctx->glob_count++] = cbm_arena_strdup(ctx->arena, module_qn);
}

static char *rust_node_text(RustLSPContext *ctx, TSNode node) {
    return cbm_node_text(ctx->arena, node, ctx->source);
}

/* ════════════════════════════════════════════════════════════════════
 * 2. Builtin / prelude tables
 * ════════════════════════════════════════════════════════════════════ */

/* Rust primitive types that the grammar reports as `primitive_type`. */
static const char *RUST_PRIMITIVES[] = {"i8",   "i16",  "i32", "i64",  "i128",  "isize", "u8",
                                        "u16",  "u32",  "u64", "u128", "usize", "f32",   "f64",
                                        "bool", "char", "str", "()",   "!",     NULL};

static bool is_rust_primitive(const char *name) {
    if (!name) {
        return false;
    }
    for (const char **p = RUST_PRIMITIVES; *p; p++) {
        if (strcmp(*p, name) == 0) {
            return true;
        }
    }
    return false;
}

/* Names of macros that behave like println-family: side effects only,
 * return type `()`. */
static bool is_void_macro(const char *name) {
    if (!name) {
        return false;
    }
    static const char *m[] = {"println",
                              "print",
                              "eprintln",
                              "eprint",
                              "panic",
                              "unimplemented",
                              "todo",
                              "unreachable",
                              "assert",
                              "assert_eq",
                              "assert_ne",
                              "debug_assert",
                              "debug_assert_eq",
                              "debug_assert_ne",
                              "writeln",
                              "write",
                              NULL};
    for (const char **p = m; *p; p++) {
        if (strcmp(*p, name) == 0) {
            return true;
        }
    }
    return false;
}

/* Names of macros that produce a `String` value. */
static bool is_string_macro(const char *name) {
    if (!name) {
        return false;
    }
    return strcmp(name, "format") == 0 || strcmp(name, "concat") == 0 ||
           strcmp(name, "stringify") == 0 || strcmp(name, "env") == 0 ||
           strcmp(name, "include_str") == 0;
}

/* Prelude trait names whose method short-names we treat as universally
 * available (for emit-on-best-effort when we cannot pin down the trait
 * impl). Borrowed from `core::prelude::v1`. */
static bool is_prelude_trait_method(const char *method_name) {
    if (!method_name) {
        return false;
    }
    static const char *m[] = {/* Clone / Copy / Default */
                              "clone", "default",
                              /* PartialEq / Eq / PartialOrd / Ord */
                              "eq", "ne", "cmp", "partial_cmp", "lt", "le", "gt", "ge",
                              /* Hash */
                              "hash",
                              /* Display / Debug */
                              "fmt", "to_string",
                              /* From / Into / TryFrom / TryInto */
                              "from", "into", "try_from", "try_into",
                              /* AsRef / AsMut / Borrow / BorrowMut */
                              "as_ref", "as_mut", "borrow", "borrow_mut",
                              /* Deref */
                              "deref", "deref_mut",
                              /* Drop */
                              "drop",
                              /* Iterator (most-used subset) */
                              "next", "iter", "iter_mut", "into_iter", "map", "filter", "fold",
                              "for_each", "collect", "count", "sum", "max", "min", "any", "all",
                              "find", "position", "enumerate", "zip", "chain", "take", "skip",
                              "rev", "cloned", "copied", "by_ref", "step_by", "flat_map", "flatten",
                              "filter_map", "peekable",
                              /* Future */
                              "poll", NULL};
    for (const char **p = m; *p; p++) {
        if (strcmp(*p, method_name) == 0) {
            return true;
        }
    }
    return false;
}

/* ════════════════════════════════════════════════════════════════════
 * 3. Path & use resolution
 * ════════════════════════════════════════════════════════════════════ */

/* Return the last `::`-separated segment of a Rust path (`std::io::Read` →
 * `Read`). Pointer aliases into `path` — caller does not own. */
static const char *path_last_segment(const char *path) {
    if (!path || !path[0]) {
        return path;
    }
    const char *p = path;
    const char *last = path;
    while (*p) {
        if (p[0] == ':' && p[1] == ':') {
            last = p + 2;
            p += 2;
            continue;
        }
        p++;
    }
    return last;
}

/* Convert a Rust path with `::` separators into our internal QN form using
 * `.` separators. Always allocates a fresh string. */
static const char *convert_path_to_qn(CBMArena *arena, const char *path) {
    if (!path || !path[0]) {
        return path;
    }
    size_t len = strlen(path);
    char *out = (char *)cbm_arena_alloc(arena, len + 1);
    if (!out) {
        return path;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (path[i] == ':' && i + 1 < len && path[i + 1] == ':') {
            out[j++] = '.';
            i++;
        } else {
            out[j++] = path[i];
        }
    }
    out[j] = '\0';
    return out;
}

/* In-place strip turbofish segments (`::<...>`) from a Rust path. The
 * grammar exposes paths like `Vec::<i32>::new` or `parse::<u32>(s)` —
 * the LSP cares about the underlying name, not the explicit type
 * arguments, so we collapse `head::<args>::tail` to `head::tail`.
 *
 * Modifies `path` in place. Safe on NULL. */
static void rust_strip_turbofish(char *path) {
    if (!path)
        return;
    char *read = path;
    char *write = path;
    while (*read) {
        if (read[0] == ':' && read[1] == ':' && read[2] == '<') {
            /* Skip ::< … > balanced. */
            int depth = 1;
            const char *p = read + 3;
            while (*p && depth > 0) {
                if (*p == '<')
                    depth++;
                else if (*p == '>')
                    depth--;
                p++;
            }
            read = (char *)p;
            continue;
        }
        *write++ = *read++;
    }
    *write = '\0';
}

/* Look up a `use` alias and return its fully-qualified module path,
 * or NULL if absent. The returned pointer aliases into the use map. */
static const char *rust_resolve_use(RustLSPContext *ctx, const char *local_name) {
    if (!ctx || !local_name) {
        return NULL;
    }
    for (int i = 0; i < ctx->use_count; i++) {
        if (strcmp(ctx->use_local_names[i], local_name) == 0) {
            return ctx->use_module_paths[i];
        }
    }
    return NULL;
}

/* The Rust prelude is auto-imported into every module. We map each name
 * to its canonical QN so bare references (`String`, `Vec::new`, …)
 * resolve without an explicit `use`. The list mirrors `core::prelude::v1`
 * + `alloc::prelude` + `std::prelude::v1`. The mapping is consulted before
 * the project-local fallback so prelude names always win. */
typedef struct {
    const char *name;
    const char *qn;
} RustPreludeEntry;

static const RustPreludeEntry RUST_PRELUDE[] = {{"String", "alloc.string.String"},
                                                {"ToString", "alloc.string.ToString"},
                                                {"Vec", "alloc.vec.Vec"},
                                                {"VecDeque", "alloc.collections.VecDeque"},
                                                {"HashMap", "alloc.collections.HashMap"},
                                                {"BTreeMap", "alloc.collections.BTreeMap"},
                                                {"HashSet", "alloc.collections.HashSet"},
                                                {"BTreeSet", "alloc.collections.BTreeSet"},
                                                {"Box", "alloc.boxed.Box"},
                                                {"Rc", "alloc.rc.Rc"},
                                                {"Arc", "alloc.sync.Arc"},
                                                {"Option", "core.option.Option"},
                                                {"Some", "core.option.Option.Some"},
                                                {"None", "core.option.Option.None"},
                                                {"Result", "core.result.Result"},
                                                {"Ok", "core.result.Result.Ok"},
                                                {"Err", "core.result.Result.Err"},
                                                {"Iterator", "core.iter.Iterator"},
                                                {"IntoIterator", "core.iter.IntoIterator"},
                                                {"Future", "core.future.Future"},
                                                {"Clone", "core.clone.Clone"},
                                                {"Copy", "core.marker.Copy"},
                                                {"Send", "core.marker.Send"},
                                                {"Sync", "core.marker.Sync"},
                                                {"Default", "core.default.Default"},
                                                {"PartialEq", "core.cmp.PartialEq"},
                                                {"Eq", "core.cmp.Eq"},
                                                {"PartialOrd", "core.cmp.PartialOrd"},
                                                {"Ord", "core.cmp.Ord"},
                                                {"Hash", "core.hash.Hash"},
                                                {"Display", "core.fmt.Display"},
                                                {"Debug", "core.fmt.Debug"},
                                                {"From", "core.convert.From"},
                                                {"Into", "core.convert.Into"},
                                                {"TryFrom", "core.convert.TryFrom"},
                                                {"TryInto", "core.convert.TryInto"},
                                                {"AsRef", "core.convert.AsRef"},
                                                {"AsMut", "core.convert.AsMut"},
                                                {"Borrow", "core.borrow.Borrow"},
                                                {"BorrowMut", "core.borrow.BorrowMut"},
                                                {"Deref", "core.ops.Deref"},
                                                {"DerefMut", "core.ops.DerefMut"},
                                                {"Drop", "core.ops.Drop"},
                                                {"RefCell", "core.cell.RefCell"},
                                                {"Cell", "core.cell.Cell"},
                                                {"Mutex", "std.sync.Mutex"},
                                                {"RwLock", "std.sync.RwLock"},
                                                {NULL, NULL}};

static const char *rust_lookup_prelude(const char *name) {
    if (!name)
        return NULL;
    for (const RustPreludeEntry *e = RUST_PRELUDE; e->name; e++) {
        if (strcmp(e->name, name) == 0)
            return e->qn;
    }
    return NULL;
}

/* Strip a leading `&` / `&mut` reference prefix from a textual type so we
 * can compare the inner head segment against builtins. */
static const char *skip_ref_prefix(const char *text) {
    if (!text) {
        return text;
    }
    while (*text == '&' || isspace((unsigned char)*text)) {
        text++;
    }
    if (strncmp(text, "mut ", 4) == 0) {
        text += 4;
        while (isspace((unsigned char)*text)) {
            text++;
        }
    }
    /* Also strip a single explicit lifetime: `'a ` */
    if (*text == '\'') {
        text++;
        while (*text && (isalnum((unsigned char)*text) || *text == '_')) {
            text++;
        }
        while (isspace((unsigned char)*text)) {
            text++;
        }
    }
    return text;
}

/* Resolve a Rust *path expression* (e.g. `Foo::bar` or `crate::x::y`)
 * into a canonical QN. The resolver cascades through these rules,
 * matching what `rust-analyzer`'s name resolver does at the path level:
 *
 *   1.  `Self::X` → `<self_type_qn>.X`
 *   2.  `crate::a::b` → `<root_module_qn>.a.b`
 *   3.  `super::a` → strip last segment of `module_qn` and prepend
 *   4.  Single-segment + matches a `use` local-name → `<full path>.X`
 *   5.  Multi-segment whose first segment is a `use` local → splice
 *   6.  Falls through unchanged (caller decides what to do).
 *
 * The returned string is arena-owned; in case (6) we return the input
 * with `::` already converted to `.`. */
static const char *rust_resolve_path_expr(RustLSPContext *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return path;
    }

    /* Self:: handling — we treat the receiver type's QN as the head. */
    if (strncmp(path, "Self::", 6) == 0 && ctx->self_type_qn) {
        return cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->self_type_qn,
                                 convert_path_to_qn(ctx->arena, path + 6));
    }
    if (strcmp(path, "Self") == 0 && ctx->self_type_qn) {
        return ctx->self_type_qn;
    }

    /* crate:: → <root>. We approximate the crate root as the first dotted
     * segment of `module_qn` after the project prefix. The pipeline
     * forms `module_qn` as `<project>.<crate>.<rel-path-segments>`, so
     * the first two segments are project + crate root. */
    if (strncmp(path, "crate::", 7) == 0 && ctx->module_qn) {
        const char *p = ctx->module_qn;
        int dots = 0;
        const char *second_dot = NULL;
        for (; *p; p++) {
            if (*p == '.') {
                if (++dots == 2) {
                    second_dot = p;
                    break;
                }
            }
        }
        size_t crate_len =
            second_dot ? (size_t)(second_dot - ctx->module_qn) : strlen(ctx->module_qn);
        char *crate_buf = cbm_arena_strndup(ctx->arena, ctx->module_qn, crate_len);
        return cbm_arena_sprintf(ctx->arena, "%s.%s", crate_buf,
                                 convert_path_to_qn(ctx->arena, path + 7));
    }

    /* super:: → drop last segment of module_qn. */
    if (strncmp(path, "super::", 7) == 0 && ctx->module_qn) {
        const char *dot = strrchr(ctx->module_qn, '.');
        if (dot) {
            char *parent =
                cbm_arena_strndup(ctx->arena, ctx->module_qn, (size_t)(dot - ctx->module_qn));
            return cbm_arena_sprintf(ctx->arena, "%s.%s", parent,
                                     convert_path_to_qn(ctx->arena, path + 7));
        }
    }

    /* Find first "::" — split into head + tail. */
    const char *sep = strstr(path, "::");
    if (!sep) {
        const char *full = rust_resolve_use(ctx, path);
        if (full) {
            return convert_path_to_qn(ctx->arena, full);
        }
        /* Prelude name (e.g. `String`, `Vec`)? */
        const char *prelude = rust_lookup_prelude(path);
        if (prelude) {
            return prelude;
        }
        /* Bare identifier — assume same module. */
        if (ctx->module_qn) {
            return cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, path);
        }
        return path;
    }

    char *head = cbm_arena_strndup(ctx->arena, path, (size_t)(sep - path));
    const char *tail = sep + 2;

    const char *full = rust_resolve_use(ctx, head);
    if (full) {
        /* The use-map's full path already includes `head` as the last
         * segment; concat its parent with the rest. */
        const char *full_dotted = convert_path_to_qn(ctx->arena, full);
        const char *tail_dotted = convert_path_to_qn(ctx->arena, tail);
        return cbm_arena_sprintf(ctx->arena, "%s.%s", full_dotted, tail_dotted);
    }

    /* Prelude head: `String::from` → `alloc.string.String.from`. */
    const char *prelude = rust_lookup_prelude(head);
    if (prelude) {
        return cbm_arena_sprintf(ctx->arena, "%s.%s", prelude,
                                 convert_path_to_qn(ctx->arena, tail));
    }

    /* Cargo-manifest aware routing — when a Cargo.toml has been parsed
     * and the path head matches either a declared dependency or a
     * workspace member, return the canonical form `<head>.<tail>` so
     * the resolver doesn't pollute the module-prefix space. */
    if (ctx->cargo_manifest) {
        const CBMCargoManifest *m = (const CBMCargoManifest *)ctx->cargo_manifest;
        const CBMCargoMember *mem = cbm_cargo_find_member(m, head);
        if (mem) {
            /* Workspace member: route to `<member_name>.<tail>` so the
             * pipeline's cross-crate resolution can match it. */
            return cbm_arena_sprintf(ctx->arena, "%s.%s", head,
                                     convert_path_to_qn(ctx->arena, tail));
        }
        if (cbm_cargo_is_known_dep(m, head)) {
            /* Declared dependency: same canonical form. The actual
             * methods may have been pre-seeded by rust_crates_seed.c;
             * otherwise the call is correctly attributed to an
             * external crate rather than fabricated locally. */
            return cbm_arena_sprintf(ctx->arena, "%s.%s", head,
                                     convert_path_to_qn(ctx->arena, tail));
        }
    }

    /* Treat unknown-head paths as absolute: `std::io::Read` → `std.io.Read`. */
    return convert_path_to_qn(ctx->arena, path);
}

/* ════════════════════════════════════════════════════════════════════
 * 4. Type-AST → CBMType
 * ════════════════════════════════════════════════════════════════════ */

/* Reconstruct the textual Rust path under a `scoped_type_identifier` /
 * `scoped_identifier` node. We deliberately walk the named children
 * rather than using the literal source text so we do not preserve
 * whitespace or trailing turbofish noise. */
static char *gather_scoped_path(RustLSPContext *ctx, TSNode node) {
    /* Fall back to the raw source text — the grammar already produces a
     * tight `path::to::name` literal under the node. */
    return rust_node_text(ctx, node);
}

/* Resolve a textual Rust path (with `::`) into a registered type's QN, or
 * NULL if no match. */
static const char *resolve_path_to_type_qn(RustLSPContext *ctx, const char *path) {
    if (!ctx || !path || !path[0]) {
        return NULL;
    }
    if (is_rust_primitive(path)) {
        return NULL;
    }
    const char *qn = rust_resolve_path_expr(ctx, path);
    if (!qn) {
        return NULL;
    }
    if (cbm_registry_lookup_type(ctx->registry, qn)) {
        return qn;
    }
    return qn; /* may not be registered yet but caller can still wrap as NAMED */
}

const CBMType *rust_parse_type_node(RustLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node)) {
        return cbm_type_unknown();
    }
    const char *kind = ts_node_type(node);

    /* primitive_type: i32, bool, char, str, … */
    if (strcmp(kind, "primitive_type") == 0) {
        char *name = rust_node_text(ctx, node);
        if (!name) {
            return cbm_type_unknown();
        }
        return cbm_type_builtin(ctx->arena, name);
    }

    /* type_identifier: simple named type */
    if (strcmp(kind, "type_identifier") == 0) {
        char *name = rust_node_text(ctx, node);
        if (!name) {
            return cbm_type_unknown();
        }
        if (is_rust_primitive(name)) {
            return cbm_type_builtin(ctx->arena, name);
        }
        if (strcmp(name, "Self") == 0 && ctx->self_type_qn) {
            return cbm_type_named(ctx->arena, ctx->self_type_qn);
        }
        const char *qn = rust_resolve_path_expr(ctx, name);
        return cbm_type_named(ctx->arena, qn);
    }

    /* scoped_type_identifier: A::B::C */
    if (strcmp(kind, "scoped_type_identifier") == 0) {
        char *path = gather_scoped_path(ctx, node);
        if (!path) {
            return cbm_type_unknown();
        }
        const char *qn = rust_resolve_path_expr(ctx, path);
        return cbm_type_named(ctx->arena, qn);
    }

    /* reference_type: &T or &mut T */
    if (strcmp(kind, "reference_type") == 0) {
        TSNode inner = ts_node_child_by_field_name(node, "type", 4);
        if (ts_node_is_null(inner)) {
            uint32_t nc = ts_node_named_child_count(node);
            if (nc > 0) {
                inner = ts_node_named_child(node, nc - 1);
            }
        }
        const CBMType *elem = rust_parse_type_node(ctx, inner);
        return cbm_type_reference(ctx->arena, elem);
    }

    /* pointer_type: *const T / *mut T */
    if (strcmp(kind, "pointer_type") == 0) {
        TSNode inner = ts_node_child_by_field_name(node, "type", 4);
        if (ts_node_is_null(inner)) {
            uint32_t nc = ts_node_named_child_count(node);
            if (nc > 0) {
                inner = ts_node_named_child(node, nc - 1);
            }
        }
        return cbm_type_pointer(ctx->arena, rust_parse_type_node(ctx, inner));
    }

    /* array_type: [T; N] — treated as slice T */
    if (strcmp(kind, "array_type") == 0) {
        TSNode elem = ts_node_child_by_field_name(node, "element", 7);
        if (ts_node_is_null(elem)) {
            elem = ts_node_child_by_field_name(node, "type", 4);
        }
        if (ts_node_is_null(elem) && ts_node_named_child_count(node) > 0) {
            elem = ts_node_named_child(node, 0);
        }
        return cbm_type_slice(ctx->arena, rust_parse_type_node(ctx, elem));
    }

    /* slice_type: [T] */
    if (strcmp(kind, "slice_type") == 0) {
        TSNode elem = ts_node_child_by_field_name(node, "element", 7);
        if (ts_node_is_null(elem) && ts_node_named_child_count(node) > 0) {
            elem = ts_node_named_child(node, 0);
        }
        return cbm_type_slice(ctx->arena, rust_parse_type_node(ctx, elem));
    }

    /* tuple_type: (T1, T2, …) */
    if (strcmp(kind, "tuple_type") == 0) {
        const CBMType **elems = NULL;
        size_t count = 0;
        size_t capacity = 0;
        uint32_t nc = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < nc; i++) {
            if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&elems, count, &capacity,
                                                sizeof(*elems), count + 1,
                                                "rust tuple type elements")) {
                return cbm_type_unknown();
            }
            elems[count++] = rust_parse_type_node(ctx, ts_node_named_child(node, i));
        }
        if (count == 0) {
            return cbm_type_builtin(ctx->arena, "()");
        }
        if (count == 1) {
            return elems[0];
        }
        return cbm_type_tuple(ctx->arena, elems, (int)count);
    }

    /* unit_type: () */
    if (strcmp(kind, "unit_type") == 0) {
        return cbm_type_builtin(ctx->arena, "()");
    }

    /* never_type: ! */
    if (strcmp(kind, "never_type") == 0) {
        return cbm_type_builtin(ctx->arena, "!");
    }

    /* generic_type: Foo<T1, T2, …> */
    if (strcmp(kind, "generic_type") == 0) {
        TSNode tn = ts_node_child_by_field_name(node, "type", 4);
        if (ts_node_is_null(tn) && ts_node_named_child_count(node) > 0) {
            tn = ts_node_named_child(node, 0);
        }
        char *head = rust_node_text(ctx, tn);
        if (!head) {
            return cbm_type_unknown();
        }
        const char *head_qn = rust_resolve_path_expr(ctx, head);

        /* Gather type_arguments. */
        TSNode args = ts_node_child_by_field_name(node, "type_arguments", 14);
        const CBMType **targs = NULL;
        size_t targ_count = 0;
        size_t targ_capacity = 0;
        if (!ts_node_is_null(args)) {
            uint32_t anc = ts_node_named_child_count(args);
            for (uint32_t i = 0; i < anc; i++) {
                TSNode tc = ts_node_named_child(args, i);
                const char *tk = ts_node_type(tc);
                /* Skip lifetime arguments — we ignore lifetimes entirely. */
                if (strcmp(tk, "lifetime") == 0) {
                    continue;
                }
                if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&targs, targ_count,
                                                    &targ_capacity, sizeof(*targs), targ_count + 1,
                                                    "rust generic type arguments")) {
                    return cbm_type_unknown();
                }
                targs[targ_count++] = rust_parse_type_node(ctx, tc);
            }
        }
        if (targ_count > 0) {
            return cbm_type_template(ctx->arena, head_qn, targs, (int)targ_count);
        }
        return cbm_type_named(ctx->arena, head_qn);
    }

    /* function_type: fn(T1, T2) -> R */
    if (strcmp(kind, "function_type") == 0) {
        return cbm_type_func(ctx->arena, NULL, NULL, NULL);
    }

    /* dynamic_type: dyn Trait — record as named on the trait QN */
    if (strcmp(kind, "dynamic_type") == 0) {
        TSNode inner = ts_node_child_by_field_name(node, "trait", 5);
        if (ts_node_is_null(inner) && ts_node_named_child_count(node) > 0) {
            inner = ts_node_named_child(node, 0);
        }
        return rust_parse_type_node(ctx, inner);
    }

    /* abstract_type: impl Trait — best-effort same as dyn Trait */
    if (strcmp(kind, "abstract_type") == 0) {
        TSNode inner = ts_node_child_by_field_name(node, "trait", 5);
        if (ts_node_is_null(inner) && ts_node_named_child_count(node) > 0) {
            inner = ts_node_named_child(node, 0);
        }
        return rust_parse_type_node(ctx, inner);
    }

    /* bounded_type: T + Trait + 'a — take the first child */
    if (strcmp(kind, "bounded_type") == 0 && ts_node_named_child_count(node) > 0) {
        return rust_parse_type_node(ctx, ts_node_named_child(node, 0));
    }

    /* parenthesized_type or wrapped types */
    if (strcmp(kind, "parenthesized_type") == 0 && ts_node_named_child_count(node) > 0) {
        return rust_parse_type_node(ctx, ts_node_named_child(node, 0));
    }

    /* qualified_type: <T as Trait>::Item */
    if (strcmp(kind, "qualified_type") == 0) {
        return cbm_type_unknown();
    }

    return cbm_type_unknown();
}

/* Parse a textual Rust type (`Vec<String>`, `&mut Foo`, `Result<T, E>`)
 * into a CBMType. Used when we receive types as strings (return types of
 * extracted `CBMDefinition`s, cross-file `CBMRustLSPDef::return_types`,
 * stdlib seed entries).
 *
 * The parser is intentionally simple: it recognises the small surface
 * area that tree-sitter would produce in `rust_parse_type_node` but
 * without a parser. This is the same trade-off `cbm_rust_parse_return_type_text`
 * makes for Go. */
static const CBMType *parse_type_text_with_params(CBMArena *arena, const char *text,
                                                  const char *module_qn, const char **type_params) {
    if (!text || !text[0]) {
        return cbm_type_unknown();
    }
    /* Skip leading whitespace + lifetime + mut markers. */
    while (*text == ' ' || *text == '\t') {
        text++;
    }

    /* HRTB: `for<'a, 'b> Fn(&'a T) -> R` — strip the higher-rank
     * binder. We don't reason about explicit lifetimes anywhere, so
     * dropping it leaves the rest of the type untouched. */
    if (strncmp(text, "for<", 4) == 0) {
        const char *p = text + 4;
        int depth = 1;
        while (*p && depth > 0) {
            if (*p == '<')
                depth++;
            else if (*p == '>')
                depth--;
            p++;
        }
        while (*p == ' ')
            p++;
        text = p;
        if (!*text)
            return cbm_type_unknown();
    }

    /* Bare leading lifetime (e.g. `'a`) — accept and skip, treating
     * the rest of the text as the actual type. Rare outside of HRTBs
     * but cheap to handle. */
    if (text[0] == '\'' && (isalpha((unsigned char)text[1]) || text[1] == '_')) {
        const char *p = text + 1;
        while (*p && (isalnum((unsigned char)*p) || *p == '_'))
            p++;
        while (*p == ' ')
            p++;
        text = p;
        if (!*text)
            return cbm_type_unknown();
    }

    /* Reference: &T or &'a T or &mut T or &'a mut T */
    if (text[0] == '&') {
        const char *p = text + 1;
        if (*p == '\'') {
            p++;
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) {
                p++;
            }
        }
        while (*p == ' ') {
            p++;
        }
        if (strncmp(p, "mut ", 4) == 0) {
            p += 4;
        }
        const CBMType *elem = parse_type_text_with_params(arena, p, module_qn, type_params);
        return cbm_type_reference(arena, elem);
    }

    /* Pointer: *const T / *mut T */
    if (text[0] == '*') {
        const char *p = text + 1;
        if (strncmp(p, "const ", 6) == 0) {
            p += 6;
        } else if (strncmp(p, "mut ", 4) == 0) {
            p += 4;
        }
        return cbm_type_pointer(arena,
                                parse_type_text_with_params(arena, p, module_qn, type_params));
    }

    /* Slice: [T] */
    if (text[0] == '[' && text[strlen(text) - 1] == ']') {
        const char *p = text + 1;
        const char *end = text + strlen(text) - 1;
        size_t inner_len = (size_t)(end - p);
        char *inner = cbm_arena_strndup(arena, p, inner_len);
        /* Array form `[T; N]` — strip the count. */
        char *semi = strchr(inner, ';');
        if (semi) {
            *semi = '\0';
            /* Trim trailing whitespace. */
            char *q = semi - 1;
            while (q > inner && isspace((unsigned char)*q)) {
                *q-- = '\0';
            }
        }
        return cbm_type_slice(arena,
                              parse_type_text_with_params(arena, inner, module_qn, type_params));
    }

    /* Unit / never */
    if (strcmp(text, "()") == 0) {
        return cbm_type_builtin(arena, "()");
    }
    if (strcmp(text, "!") == 0) {
        return cbm_type_builtin(arena, "!");
    }

    /* Tuple: (T1, T2, …) — only when not a single parenthesised type. */
    if (text[0] == '(' && text[strlen(text) - 1] == ')') {
        const char *p = text + 1;
        size_t inner_len = strlen(text) - 2;
        char *inner = cbm_arena_strndup(arena, p, inner_len);
        /* Detect comma at top level. */
        int depth = 0;
        bool has_comma = false;
        for (char *q = inner; *q; q++) {
            if (*q == '<' || *q == '(' || *q == '[')
                depth++;
            else if (*q == '>' || *q == ')' || *q == ']')
                depth--;
            else if (*q == ',' && depth == 0) {
                has_comma = true;
                break;
            }
        }
        if (!has_comma) {
            return parse_type_text_with_params(arena, inner, module_qn, type_params);
        }
        /* Split by top-level commas. */
        const CBMType **elems = NULL;
        size_t count = 0;
        size_t capacity = 0;
        char *start = inner;
        depth = 0;
        for (char *q = inner;; q++) {
            if (*q == '<' || *q == '(' || *q == '[')
                depth++;
            else if (*q == '>' || *q == ')' || *q == ']')
                depth--;
            if ((*q == ',' && depth == 0) || *q == '\0') {
                char save = *q;
                *q = '\0';
                /* Trim. */
                while (*start == ' ')
                    start++;
                if (*start) {
                    if (!cbm_lsp_semantic_array_reserve(arena, (void **)&elems, count, &capacity,
                                                        sizeof(*elems), count + 1,
                                                        "rust textual tuple type elements")) {
                        return cbm_type_unknown();
                    }
                    elems[count++] =
                        parse_type_text_with_params(arena, start, module_qn, type_params);
                }
                if (save == '\0')
                    break;
                start = q + 1;
            }
        }
        if (count == 0)
            return cbm_type_builtin(arena, "()");
        if (count == 1)
            return elems[0];
        return cbm_type_tuple(arena, elems, (int)count);
    }

    /* Generic head: head<args> */
    const char *lt = strchr(text, '<');
    if (lt) {
        const char *gt = text + strlen(text) - 1;
        if (*gt == '>') {
            size_t head_len = (size_t)(lt - text);
            char *head = cbm_arena_strndup(arena, text, head_len);
            /* Recursive split of args by top-level commas. */
            const char *args = lt + 1;
            size_t args_len = (size_t)(gt - args);
            char *abuf = cbm_arena_strndup(arena, args, args_len);
            const CBMType **targs = NULL;
            size_t targ_count = 0;
            size_t targ_capacity = 0;
            int depth = 0;
            char *start = abuf;
            for (char *q = abuf;; q++) {
                if (*q == '<' || *q == '(' || *q == '[')
                    depth++;
                else if (*q == '>' || *q == ')' || *q == ']')
                    depth--;
                if ((*q == ',' && depth == 0) || *q == '\0') {
                    char save = *q;
                    *q = '\0';
                    while (*start == ' ')
                        start++;
                    /* Skip lifetime args. */
                    if (*start != '\'' && *start) {
                        if (!cbm_lsp_semantic_array_reserve(
                                arena, (void **)&targs, targ_count, &targ_capacity, sizeof(*targs),
                                targ_count + 1, "rust textual generic type arguments")) {
                            return cbm_type_unknown();
                        }
                        targs[targ_count++] =
                            parse_type_text_with_params(arena, start, module_qn, type_params);
                    }
                    if (save == '\0')
                        break;
                    start = q + 1;
                }
            }
            const char *head_qn = head;
            if (is_rust_primitive(head)) {
                /* Primitives don't take generics in practice except for str ref — pass through. */
                return cbm_type_builtin(arena, head);
            }
            /* Map a few well-known std type sugars. */
            return cbm_type_template(arena, head_qn, targs, (int)targ_count);
        }
    }

    /* Bare identifier or path. */
    if (is_rust_primitive(text)) {
        return cbm_type_builtin(arena, text);
    }
    if (type_params) {
        for (int i = 0; type_params[i]; i++) {
            if (strcmp(text, type_params[i]) == 0) {
                return cbm_type_type_param(arena, text);
            }
        }
    }
    /* Self -> module-qualified placeholder caller will substitute. */
    if (strcmp(text, "Self") == 0) {
        return cbm_type_named(arena, "Self");
    }
    /* Has `::` → absolute path; treat dotted paths as already-qualified
     * QNs (cross-file callers pass module-qualified text directly). */
    if (strstr(text, "::")) {
        return cbm_type_named(arena, convert_path_to_qn(arena, text));
    }
    if (strchr(text, '.')) {
        return cbm_type_named(arena, text);
    }
    return cbm_type_named(arena, cbm_arena_sprintf(arena, "%s.%s", module_qn, text));
}

/* Public-ish helper used by the cross-file path. */
static const CBMType *rust_parse_return_type_text(CBMArena *arena, const char *text,
                                                  const char *module_qn) {
    return parse_type_text_with_params(arena, text, module_qn, NULL);
}

/* ════════════════════════════════════════════════════════════════════
 * 5. Generic substitution
 * ════════════════════════════════════════════════════════════════════ */

/* Recursively substitute every `TYPE_PARAM` reference in `t` whose name
 * matches `params[i]` with `args[i]`. Preserves structure for composite
 * types. */
static const CBMType *rust_substitute_type(CBMArena *arena, const CBMType *t, const char **params,
                                           const CBMType **args) {
    if (!t || !params || !args) {
        return t;
    }
    switch (t->kind) {
    case CBM_TYPE_TYPE_PARAM:
        for (int i = 0; params[i]; i++) {
            if (strcmp(t->data.type_param.name, params[i]) == 0) {
                return args[i];
            }
        }
        return t;
    case CBM_TYPE_REFERENCE:
        return cbm_type_reference(
            arena, rust_substitute_type(arena, t->data.reference.elem, params, args));
    case CBM_TYPE_POINTER:
        return cbm_type_pointer(arena,
                                rust_substitute_type(arena, t->data.pointer.elem, params, args));
    case CBM_TYPE_SLICE:
        return cbm_type_slice(arena, rust_substitute_type(arena, t->data.slice.elem, params, args));
    case CBM_TYPE_TEMPLATE: {
        int n = t->data.template_type.arg_count;
        const CBMType **new_args = NULL;
        size_t capacity = 0;
        if (n > 0 && !cbm_lsp_semantic_array_reserve(arena, (void **)&new_args, 0, &capacity,
                                                     sizeof(*new_args), (size_t)n,
                                                     "rust substituted generic type arguments")) {
            return cbm_type_unknown();
        }
        for (int i = 0; i < n; i++) {
            new_args[i] =
                rust_substitute_type(arena, t->data.template_type.template_args[i], params, args);
        }
        return cbm_type_template(arena, t->data.template_type.template_name, new_args, n);
    }
    case CBM_TYPE_TUPLE: {
        int n = t->data.tuple.count;
        const CBMType **new_elems = NULL;
        size_t capacity = 0;
        if (n > 0 && !cbm_lsp_semantic_array_reserve(arena, (void **)&new_elems, 0, &capacity,
                                                     sizeof(*new_elems), (size_t)n,
                                                     "rust substituted tuple elements")) {
            return cbm_type_unknown();
        }
        for (int i = 0; i < n; i++) {
            new_elems[i] = rust_substitute_type(arena, t->data.tuple.elems[i], params, args);
        }
        return cbm_type_tuple(arena, new_elems, n);
    }
    default:
        return t;
    }
}

/* Naive Hindley-Milner-style type unification. Walks `param_type`
 * structurally against `arg_type`; whenever a `TYPE_PARAM` is bound for
 * the first time, store the corresponding `arg_type`. Subsequent
 * conflicting bindings are ignored (best-effort). */
static void rust_unify_type(const CBMType *param_type, const CBMType *arg_type,
                            const char **type_param_names, const CBMType **inferred,
                            int param_count) {
    if (!param_type || !arg_type || cbm_type_is_unknown(arg_type)) {
        return;
    }
    if (param_type->kind == CBM_TYPE_TYPE_PARAM) {
        for (int i = 0; i < param_count; i++) {
            if (strcmp(param_type->data.type_param.name, type_param_names[i]) == 0) {
                if (!inferred[i]) {
                    inferred[i] = arg_type;
                }
                return;
            }
        }
        return;
    }
    if (param_type->kind == CBM_TYPE_REFERENCE && arg_type->kind == CBM_TYPE_REFERENCE) {
        rust_unify_type(param_type->data.reference.elem, arg_type->data.reference.elem,
                        type_param_names, inferred, param_count);
        return;
    }
    if (param_type->kind == CBM_TYPE_REFERENCE) {
        rust_unify_type(param_type->data.reference.elem, arg_type, type_param_names, inferred,
                        param_count);
        return;
    }
    if (param_type->kind == CBM_TYPE_SLICE && arg_type->kind == CBM_TYPE_SLICE) {
        rust_unify_type(param_type->data.slice.elem, arg_type->data.slice.elem, type_param_names,
                        inferred, param_count);
        return;
    }
    if (param_type->kind == CBM_TYPE_TEMPLATE && arg_type->kind == CBM_TYPE_TEMPLATE) {
        if (param_type->data.template_type.arg_count == arg_type->data.template_type.arg_count) {
            int ac = param_type->data.template_type.arg_count;
            for (int i = 0; i < ac; i++) {
                rust_unify_type(param_type->data.template_type.template_args[i],
                                arg_type->data.template_type.template_args[i], type_param_names,
                                inferred, param_count);
            }
        }
        return;
    }
    /* TUPLE unification — needed for tuple-return generics like
     * `fn pair<A, B>(a: A, b: B) -> (A, B)`. */
    if (param_type->kind == CBM_TYPE_TUPLE && arg_type->kind == CBM_TYPE_TUPLE) {
        int pc = param_type->data.tuple.count;
        int ac = arg_type->data.tuple.count;
        int min_ = pc < ac ? pc : ac;
        for (int i = 0; i < min_; i++) {
            rust_unify_type(param_type->data.tuple.elems[i], arg_type->data.tuple.elems[i],
                            type_param_names, inferred, param_count);
        }
        return;
    }
    /* POINTER unification. */
    if (param_type->kind == CBM_TYPE_POINTER && arg_type->kind == CBM_TYPE_POINTER) {
        rust_unify_type(param_type->data.pointer.elem, arg_type->data.pointer.elem,
                        type_param_names, inferred, param_count);
        return;
    }
    /* Bidirectional fallback: if `arg_type` (rather than `param_type`)
     * carries the type-param marker, swap and retry. This lets
     * `unify(known_concrete, fresh_var)` solve the var. */
    if (arg_type->kind == CBM_TYPE_TYPE_PARAM) {
        rust_unify_type(arg_type, param_type, type_param_names, inferred, param_count);
        return;
    }
}

/* Apply a solved type-param environment to a type, recursively
 * substituting bound param names with their concrete types. Returns
 * the substituted type (arena-allocated when new structure is built).
 *
 * This is the post-solve step of HM-lite: after `rust_unify_type` has
 * filled the `inferred` array, this helper walks a target type and
 * rewrites every `TYPE_PARAM` reference. */
static const CBMType *rust_apply_subst(CBMArena *arena, const CBMType *t, const char **names,
                                       const CBMType **inferred, int count) {
    if (!t)
        return t;
    switch (t->kind) {
    case CBM_TYPE_TYPE_PARAM:
        for (int i = 0; i < count; i++) {
            if (inferred[i] && names[i] && strcmp(t->data.type_param.name, names[i]) == 0) {
                return inferred[i];
            }
        }
        return t;
    case CBM_TYPE_REFERENCE:
        return cbm_type_reference(
            arena, rust_apply_subst(arena, t->data.reference.elem, names, inferred, count));
    case CBM_TYPE_POINTER:
        return cbm_type_pointer(
            arena, rust_apply_subst(arena, t->data.pointer.elem, names, inferred, count));
    case CBM_TYPE_SLICE:
        return cbm_type_slice(arena,
                              rust_apply_subst(arena, t->data.slice.elem, names, inferred, count));
    case CBM_TYPE_TEMPLATE: {
        int n = t->data.template_type.arg_count;
        if (n <= 0)
            return t;
        const CBMType **new_args = NULL;
        size_t capacity = 0;
        if (!cbm_lsp_semantic_array_reserve(arena, (void **)&new_args, 0, &capacity,
                                            sizeof(*new_args), (size_t)n,
                                            "rust applied generic substitutions")) {
            return cbm_type_unknown();
        }
        for (int i = 0; i < n; i++) {
            new_args[i] = rust_apply_subst(arena, t->data.template_type.template_args[i], names,
                                           inferred, count);
        }
        return cbm_type_template(arena, t->data.template_type.template_name, new_args, n);
    }
    case CBM_TYPE_TUPLE: {
        int n = t->data.tuple.count;
        if (n <= 0)
            return t;
        const CBMType **new_elems = NULL;
        size_t capacity = 0;
        if (!cbm_lsp_semantic_array_reserve(arena, (void **)&new_elems, 0, &capacity,
                                            sizeof(*new_elems), (size_t)n,
                                            "rust applied tuple substitutions")) {
            return cbm_type_unknown();
        }
        for (int i = 0; i < n; i++) {
            new_elems[i] = rust_apply_subst(arena, t->data.tuple.elems[i], names, inferred, count);
        }
        return cbm_type_tuple(arena, new_elems, n);
    }
    default:
        return t;
    }
}

/* ════════════════════════════════════════════════════════════════════
 * 6. Expression evaluator
 * ════════════════════════════════════════════════════════════════════ */

/* Evaluate the type of a literal child like `integer_literal`, `float_literal`,
 * `string_literal`, `char_literal`, `boolean_literal`. */
static const CBMType *rust_eval_literal_type(RustLSPContext *ctx, const char *kind, TSNode node) {
    if (strcmp(kind, "integer_literal") == 0) {
        char *text = rust_node_text(ctx, node);
        /* Look at suffix. */
        if (text) {
            /* Strip leading `-` if any. */
            const char *p = text;
            if (*p == '-')
                p++;
            /* Find suffix start (first non-digit/non-_/non-x/non-X/non-hex). */
            while (*p && (isdigit((unsigned char)*p) || *p == '_' || *p == '.' || *p == 'x' ||
                          *p == 'X' || *p == 'b' || *p == 'B' || *p == 'o' || *p == 'O' ||
                          (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) {
                p++;
            }
            if (*p) {
                return cbm_type_builtin(ctx->arena, p);
            }
        }
        return cbm_type_builtin(ctx->arena, "i32");
    }
    if (strcmp(kind, "float_literal") == 0) {
        char *text = rust_node_text(ctx, node);
        if (text) {
            const char *p = text;
            while (*p && (isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' ||
                          *p == '+' || *p == '-' || *p == '_')) {
                p++;
            }
            if (*p) {
                return cbm_type_builtin(ctx->arena, p);
            }
        }
        return cbm_type_builtin(ctx->arena, "f64");
    }
    if (strcmp(kind, "string_literal") == 0 || strcmp(kind, "raw_string_literal") == 0) {
        /* &'static str — represented as &str */
        return cbm_type_reference(ctx->arena, cbm_type_builtin(ctx->arena, "str"));
    }
    if (strcmp(kind, "char_literal") == 0) {
        return cbm_type_builtin(ctx->arena, "char");
    }
    if (strcmp(kind, "boolean_literal") == 0 || strcmp(kind, "true") == 0 ||
        strcmp(kind, "false") == 0) {
        return cbm_type_builtin(ctx->arena, "bool");
    }
    return cbm_type_unknown();
}

/* Look up the registered method or field type for a field/method-style
 * access. Order: inherent method → field → trait method (with single-impl
 * preference). */
static const CBMType *rust_eval_member_access(RustLSPContext *ctx, const CBMType *recv,
                                              const char *member);

const CBMType *rust_eval_expr_type(RustLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node)) {
        return cbm_type_unknown();
    }
    const char *kind = ts_node_type(node);

    /* Identifier: scope or registered symbol. */
    if (strcmp(kind, "identifier") == 0) {
        char *name = rust_node_text(ctx, node);
        if (!name) {
            return cbm_type_unknown();
        }
        const CBMType *t = cbm_scope_lookup(ctx->current_scope, name);
        if (!cbm_type_is_unknown(t)) {
            return t;
        }
        /* Module-level function. */
        const CBMRegisteredFunc *f =
            cbm_registry_lookup_symbol(ctx->registry, ctx->module_qn, name);
        if (f && f->signature) {
            return f->signature;
        }
        /* Use-aliased symbol: resolve path then look up. */
        const char *full = rust_resolve_use(ctx, name);
        if (full) {
            const char *qn = convert_path_to_qn(ctx->arena, full);
            const CBMRegisteredFunc *uf = cbm_registry_lookup_func(ctx->registry, qn);
            if (uf && uf->signature) {
                return uf->signature;
            }
            const CBMRegisteredType *ut = cbm_registry_lookup_type(ctx->registry, qn);
            if (ut) {
                return cbm_type_named(ctx->arena, qn);
            }
        }
        /* Same-module type? */
        const char *type_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, name);
        if (cbm_registry_lookup_type(ctx->registry, type_qn)) {
            return cbm_type_named(ctx->arena, type_qn);
        }
        return cbm_type_unknown();
    }

    /* self_parameter token: bound in scope as `self`. */
    if (strcmp(kind, "self") == 0 || strcmp(kind, "self_parameter") == 0) {
        return cbm_scope_lookup(ctx->current_scope, "self");
    }

    /* scoped_identifier: A::B::C — could be a function or a type. */
    if (strcmp(kind, "scoped_identifier") == 0) {
        char *path = rust_node_text(ctx, node);
        if (!path) {
            return cbm_type_unknown();
        }
        const char *qn = rust_resolve_path_expr(ctx, path);
        if (!qn) {
            return cbm_type_unknown();
        }
        const CBMRegisteredFunc *f = cbm_registry_lookup_func(ctx->registry, qn);
        if (f && f->signature) {
            return f->signature;
        }
        if (cbm_registry_lookup_type(ctx->registry, qn)) {
            return cbm_type_named(ctx->arena, qn);
        }
        return cbm_type_unknown();
    }

    /* generic_function: foo::<T> */
    if (strcmp(kind, "generic_function") == 0) {
        TSNode fn = ts_node_child_by_field_name(node, "function", 8);
        if (!ts_node_is_null(fn)) {
            return rust_eval_expr_type(ctx, fn);
        }
    }

    /* field_expression: obj.field or obj.0 (tuple) */
    if (strcmp(kind, "field_expression") == 0) {
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        TSNode field = ts_node_child_by_field_name(node, "field", 5);
        if (ts_node_is_null(value) || ts_node_is_null(field)) {
            return cbm_type_unknown();
        }
        const CBMType *recv = rust_eval_expr_type(ctx, value);
        const char *fk = ts_node_type(field);
        if (strcmp(fk, "integer_literal") == 0) {
            /* Tuple field access. */
            if (recv) {
                const CBMType *base = recv;
                while (base && base->kind == CBM_TYPE_REFERENCE) {
                    base = base->data.reference.elem;
                }
                if (base && base->kind == CBM_TYPE_TUPLE) {
                    char *idx_text = rust_node_text(ctx, field);
                    int idx = atoi(idx_text);
                    if (idx >= 0 && idx < base->data.tuple.count) {
                        return base->data.tuple.elems[idx];
                    }
                }
            }
            return cbm_type_unknown();
        }
        char *fname = rust_node_text(ctx, field);
        if (!fname) {
            return cbm_type_unknown();
        }
        return rust_eval_member_access(ctx, recv, fname);
    }

    /* call_expression: any callable invocation. */
    if (strcmp(kind, "call_expression") == 0) {
        TSNode func_node = ts_node_child_by_field_name(node, "function", 8);
        TSNode args_node = ts_node_child_by_field_name(node, "arguments", 9);
        if (ts_node_is_null(func_node)) {
            return cbm_type_unknown();
        }
        const char *fk = ts_node_type(func_node);

        /* Constructor of a tuple struct, unit-like struct, or stdlib
         * factory invoked via path. Try the registry; on miss, also try
         * UFCS-style method lookup to catch `String::new()`,
         * `Vec::new()`, etc. */
        if (strcmp(fk, "identifier") == 0 || strcmp(fk, "scoped_identifier") == 0) {
            char *path = rust_node_text(ctx, func_node);
            if (path) {
                /* Strip ALL turbofish (`::<...>`) so the lookup below
                 * ignores explicit type arguments — handles forms like
                 * `Vec::<i32>::new` and `parse::<u32>`. */
                rust_strip_turbofish(path);
                const char *qn = rust_resolve_path_expr(ctx, path);
                if (qn) {
                    const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, qn);
                    if (rt) {
                        return cbm_type_named(ctx->arena, qn);
                    }
                    const CBMRegisteredFunc *f = cbm_registry_lookup_func(ctx->registry, qn);
                    if (f && f->signature && f->signature->kind == CBM_TYPE_FUNC) {
                        const CBMType *const *rt_arr = f->signature->data.func.return_types;
                        if (rt_arr && rt_arr[0]) {
                            const CBMType *ret = rt_arr[0];
                            /* Constructor-style on a stdlib receiver with
                             * `unknown` return — substitute the receiver
                             * type so chains keep typing. The heuristic
                             * matches `new`, `default`, anything starting
                             * with `from_` / `with_`, plus a small list of
                             * common factory verbs.
                             *
                             * For smart-pointer factories (`Box::new`,
                             * `Rc::new`, `Arc::new`, `RefCell::new`,
                             * `Pin::new`, `Mutex::new`, `RwLock::new`)
                             * we also try to capture the first call
                             * argument's type as a TEMPLATE arg so the
                             * Deref chain has something to peel. */
                            if (f->receiver_type && cbm_type_is_unknown(ret) && f->short_name &&
                                (strcmp(f->short_name, "new") == 0 ||
                                 strcmp(f->short_name, "default") == 0 ||
                                 strcmp(f->short_name, "open") == 0 ||
                                 strcmp(f->short_name, "create") == 0 ||
                                 strcmp(f->short_name, "create_new") == 0 ||
                                 strcmp(f->short_name, "bind") == 0 ||
                                 strcmp(f->short_name, "connect") == 0 ||
                                 strcmp(f->short_name, "spawn") == 0 ||
                                 strcmp(f->short_name, "now") == 0 ||
                                 strncmp(f->short_name, "from_", 5) == 0 ||
                                 strncmp(f->short_name, "with_", 5) == 0 ||
                                 strcmp(f->short_name, "from") == 0)) {
                                /* Detect smart-pointer wrappers and
                                 * capture the first arg's type so
                                 * `let b = Box::new(x); b.method()`
                                 * dispatches via Deref. */
                                bool is_wrapper = strcmp(f->short_name, "new") == 0 &&
                                                  rust_type_derefs_to_first_arg(f->receiver_type);
                                if (is_wrapper && !ts_node_is_null(args_node)) {
                                    uint32_t anc = ts_node_named_child_count(args_node);
                                    if (anc > 0) {
                                        const CBMType *arg_t = rust_eval_expr_type(
                                            ctx, ts_node_named_child(args_node, 0));
                                        if (arg_t && !cbm_type_is_unknown(arg_t)) {
                                            return cbm_type_template(ctx->arena, f->receiver_type,
                                                                     &arg_t, 1);
                                        }
                                    }
                                }
                                return cbm_type_named(ctx->arena, f->receiver_type);
                            }
                            /* Self -> receiver_type substitution. */
                            if (f->receiver_type && ret->kind == CBM_TYPE_NAMED &&
                                strcmp(ret->data.named.qualified_name, "Self") == 0) {
                                return cbm_type_named(ctx->arena, f->receiver_type);
                            }
                            return ret;
                        }
                    }
                    /* UFCS path lookup: split off short name and try
                     * `cbm_registry_lookup_method`. */
                    const char *dot = strrchr(qn, '.');
                    if (dot) {
                        char *head = cbm_arena_strndup(ctx->arena, qn, (size_t)(dot - qn));
                        const char *short_name = dot + 1;
                        const CBMRegisteredFunc *m =
                            rust_lookup_method_depth(ctx, head, short_name, 0);
                        if (!m && ctx->module_qn) {
                            const char *full_head =
                                cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, head);
                            m = rust_lookup_method_depth(ctx, full_head, short_name, 0);
                            if (m)
                                head = (char *)full_head;
                        }
                        if (m && m->signature && m->signature->kind == CBM_TYPE_FUNC &&
                            m->signature->data.func.return_types &&
                            m->signature->data.func.return_types[0]) {
                            const CBMType *ret = m->signature->data.func.return_types[0];
                            /* Substitute Self / unknown returns with the
                             * receiver type so chained calls keep typing. */
                            if (ret->kind == CBM_TYPE_NAMED &&
                                strcmp(ret->data.named.qualified_name, "Self") == 0) {
                                return cbm_type_named(ctx->arena, head);
                            }
                            if (cbm_type_is_unknown(ret) &&
                                (strcmp(short_name, "new") == 0 ||
                                 strcmp(short_name, "default") == 0 ||
                                 strcmp(short_name, "with_capacity") == 0 ||
                                 strcmp(short_name, "from") == 0)) {
                                /* Smart-pointer wrap: capture first arg
                                 * type into a TEMPLATE so Deref can peel. */
                                if (strcmp(short_name, "new") == 0 &&
                                    rust_type_derefs_to_first_arg(head) &&
                                    !ts_node_is_null(args_node)) {
                                    uint32_t anc = ts_node_named_child_count(args_node);
                                    if (anc > 0) {
                                        const CBMType *arg_t = rust_eval_expr_type(
                                            ctx, ts_node_named_child(args_node, 0));
                                        if (arg_t && !cbm_type_is_unknown(arg_t)) {
                                            return cbm_type_template(ctx->arena, head, &arg_t, 1);
                                        }
                                    }
                                }
                                return cbm_type_named(ctx->arena, head);
                            }
                            return ret;
                        }
                    }
                }
            }
        }

        /* Method call expressed as field_expression callee. */
        if (strcmp(fk, "field_expression") == 0) {
            TSNode value = ts_node_child_by_field_name(func_node, "value", 5);
            TSNode field = ts_node_child_by_field_name(func_node, "field", 5);
            if (!ts_node_is_null(value) && !ts_node_is_null(field)) {
                const CBMType *recv = rust_eval_expr_type(ctx, value);
                char *mname = rust_node_text(ctx, field);
                if (mname && recv) {
                    const CBMType *base = recv;
                    while (base && base->kind == CBM_TYPE_REFERENCE) {
                        base = base->data.reference.elem;
                    }
                    /* Template Vec<T> method handling */
                    if (base && base->kind == CBM_TYPE_TEMPLATE) {
                        const char *tname = base->data.template_type.template_name;
                        /* Iterator-producing methods on Vec/&[T]/Option/Result/HashMap. */
                        if (strstr(tname, "Vec") || strstr(tname, "VecDeque") ||
                            strstr(tname, "HashSet") || strstr(tname, "BTreeSet")) {
                            if (strcmp(mname, "iter") == 0 || strcmp(mname, "iter_mut") == 0 ||
                                strcmp(mname, "into_iter") == 0 || strcmp(mname, "drain") == 0) {
                                /* Iterator<Item=T> — represent loosely as the elem type for our
                                 * downstream chain calls. Even when the elem type is not
                                 * known, return Iterator (with no args) so further chain calls
                                 * can still attribute via Iterator's registered methods. */
                                if (base->data.template_type.arg_count > 0) {
                                    return cbm_type_template(
                                        ctx->arena, "core.iter.Iterator",
                                        &base->data.template_type.template_args[0], 1);
                                }
                                return cbm_type_template(ctx->arena, "core.iter.Iterator", NULL, 0);
                            }
                            /* Methods returning the element type directly. */
                            if (strcmp(mname, "remove") == 0 || strcmp(mname, "swap_remove") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    return base->data.template_type.template_args[0];
                                }
                            }
                            if (strcmp(mname, "len") == 0 || strcmp(mname, "capacity") == 0) {
                                return cbm_type_builtin(ctx->arena, "usize");
                            }
                            if (strcmp(mname, "is_empty") == 0 || strcmp(mname, "contains") == 0) {
                                return cbm_type_builtin(ctx->arena, "bool");
                            }
                            if (strcmp(mname, "first") == 0 || strcmp(mname, "last") == 0 ||
                                strcmp(mname, "get") == 0 || strcmp(mname, "pop") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    const CBMType *opt_args[1] = {
                                        base->data.template_type.template_args[0]};
                                    return cbm_type_template(ctx->arena, "core.option.Option",
                                                             opt_args, 1);
                                }
                            }
                            if (strcmp(mname, "as_slice") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    return cbm_type_reference(
                                        ctx->arena,
                                        cbm_type_slice(ctx->arena,
                                                       base->data.template_type.template_args[0]));
                                }
                            }
                        }
                        if (strstr(tname, "Option")) {
                            if (strcmp(mname, "unwrap") == 0 || strcmp(mname, "expect") == 0 ||
                                strcmp(mname, "unwrap_or") == 0 ||
                                strcmp(mname, "unwrap_or_default") == 0 ||
                                strcmp(mname, "unwrap_or_else") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    return base->data.template_type.template_args[0];
                                }
                            }
                            if (strcmp(mname, "is_some") == 0 || strcmp(mname, "is_none") == 0) {
                                return cbm_type_builtin(ctx->arena, "bool");
                            }
                            if (strcmp(mname, "as_ref") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    const CBMType *arg0 = cbm_type_reference(
                                        ctx->arena, base->data.template_type.template_args[0]);
                                    return cbm_type_template(ctx->arena, "core.option.Option",
                                                             &arg0, 1);
                                }
                            }
                        }
                        if (strstr(tname, "Result")) {
                            if (strcmp(mname, "unwrap") == 0 || strcmp(mname, "expect") == 0 ||
                                strcmp(mname, "unwrap_or") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    return base->data.template_type.template_args[0];
                                }
                            }
                            if (strcmp(mname, "ok") == 0 &&
                                base->data.template_type.arg_count > 0) {
                                const CBMType *a0 = base->data.template_type.template_args[0];
                                return cbm_type_template(ctx->arena, "core.option.Option", &a0, 1);
                            }
                            if (strcmp(mname, "err") == 0 &&
                                base->data.template_type.arg_count > 1) {
                                const CBMType *a1 = base->data.template_type.template_args[1];
                                return cbm_type_template(ctx->arena, "core.option.Option", &a1, 1);
                            }
                            if (strcmp(mname, "is_ok") == 0 || strcmp(mname, "is_err") == 0) {
                                return cbm_type_builtin(ctx->arena, "bool");
                            }
                        }
                        if (strstr(tname, "Iterator")) {
                            /* map/filter/take/skip/rev/chain → Iterator (with the relevant elem) */
                            if (strcmp(mname, "collect") == 0) {
                                /* Often Vec<Item>; without turbofish info we model as Vec<elem>. */
                                if (base->data.template_type.arg_count > 0) {
                                    return cbm_type_template(ctx->arena, "alloc.vec.Vec",
                                                             base->data.template_type.template_args,
                                                             base->data.template_type.arg_count);
                                }
                            }
                            if (strcmp(mname, "count") == 0 || strcmp(mname, "len") == 0) {
                                return cbm_type_builtin(ctx->arena, "usize");
                            }
                            if (strcmp(mname, "next") == 0 || strcmp(mname, "last") == 0 ||
                                strcmp(mname, "nth") == 0 || strcmp(mname, "find") == 0 ||
                                strcmp(mname, "max") == 0 || strcmp(mname, "min") == 0 ||
                                strcmp(mname, "max_by") == 0 || strcmp(mname, "min_by") == 0) {
                                if (base->data.template_type.arg_count > 0) {
                                    const CBMType *a0 = base->data.template_type.template_args[0];
                                    return cbm_type_template(ctx->arena, "core.option.Option", &a0,
                                                             1);
                                }
                            }
                            if (strcmp(mname, "filter") == 0 || strcmp(mname, "take") == 0 ||
                                strcmp(mname, "skip") == 0 || strcmp(mname, "rev") == 0 ||
                                strcmp(mname, "cloned") == 0 || strcmp(mname, "copied") == 0 ||
                                strcmp(mname, "step_by") == 0 || strcmp(mname, "fuse") == 0 ||
                                strcmp(mname, "peekable") == 0 || strcmp(mname, "by_ref") == 0 ||
                                strcmp(mname, "take_while") == 0 ||
                                strcmp(mname, "skip_while") == 0 || strcmp(mname, "inspect") == 0) {
                                return base; /* preserves Iterator<Item> */
                            }
                            if ((strcmp(mname, "sum") == 0 || strcmp(mname, "product") == 0 ||
                                 strcmp(mname, "fold") == 0 || strcmp(mname, "reduce") == 0) &&
                                base->data.template_type.arg_count > 0) {
                                return base->data.template_type.template_args[0];
                            }
                            if (strcmp(mname, "any") == 0 || strcmp(mname, "all") == 0) {
                                return cbm_type_builtin(ctx->arena, "bool");
                            }
                            if (strcmp(mname, "position") == 0) {
                                const CBMType *usize = cbm_type_builtin(ctx->arena, "usize");
                                return cbm_type_template(ctx->arena, "core.option.Option", &usize,
                                                         1);
                            }
                            if (strcmp(mname, "enumerate") == 0 &&
                                base->data.template_type.arg_count > 0) {
                                /* Iterator<(usize, T)>. */
                                const CBMType *pair[2] = {
                                    cbm_type_builtin(ctx->arena, "usize"),
                                    base->data.template_type.template_args[0]};
                                const CBMType *tup = cbm_type_tuple(ctx->arena, pair, 2);
                                return cbm_type_template(ctx->arena, "core.iter.Iterator", &tup, 1);
                            }
                        }
                        /* HashMap<K, V> / BTreeMap<K, V> generics. */
                        if (strstr(tname, "HashMap") || strstr(tname, "BTreeMap")) {
                            if (strcmp(mname, "len") == 0) {
                                return cbm_type_builtin(ctx->arena, "usize");
                            }
                            if (strcmp(mname, "is_empty") == 0 ||
                                strcmp(mname, "contains_key") == 0) {
                                return cbm_type_builtin(ctx->arena, "bool");
                            }
                            if (strcmp(mname, "get") == 0 || strcmp(mname, "get_mut") == 0 ||
                                strcmp(mname, "remove") == 0) {
                                if (base->data.template_type.arg_count > 1) {
                                    const CBMType *v = base->data.template_type.template_args[1];
                                    return cbm_type_template(ctx->arena, "core.option.Option", &v,
                                                             1);
                                }
                            }
                            if (strcmp(mname, "iter") == 0 || strcmp(mname, "iter_mut") == 0) {
                                /* Iterator<(K, V)>. */
                                if (base->data.template_type.arg_count > 1) {
                                    const CBMType *pair[2] = {
                                        base->data.template_type.template_args[0],
                                        base->data.template_type.template_args[1]};
                                    const CBMType *tup = cbm_type_tuple(ctx->arena, pair, 2);
                                    return cbm_type_template(ctx->arena, "core.iter.Iterator", &tup,
                                                             1);
                                }
                            }
                            if (strcmp(mname, "keys") == 0 &&
                                base->data.template_type.arg_count > 0) {
                                return cbm_type_template(ctx->arena, "core.iter.Iterator",
                                                         &base->data.template_type.template_args[0],
                                                         1);
                            }
                            if (strcmp(mname, "values") == 0 &&
                                base->data.template_type.arg_count > 1) {
                                return cbm_type_template(ctx->arena, "core.iter.Iterator",
                                                         &base->data.template_type.template_args[1],
                                                         1);
                            }
                        }
                    }
                    /* Fall through: registered method on the named type.
                     * Unwrap the resulting FUNC signature to its first
                     * return type so chains like
                     * `String::new().to_uppercase().len()` keep typing
                     * across each link. */
                    const CBMType *t = rust_eval_member_access(ctx, recv, mname);
                    if (t && t->kind == CBM_TYPE_FUNC && t->data.func.return_types &&
                        t->data.func.return_types[0]) {
                        const CBMType *ret = t->data.func.return_types[0];
                        /* Self -> receiver. */
                        if (ret->kind == CBM_TYPE_NAMED &&
                            strcmp(ret->data.named.qualified_name, "Self") == 0) {
                            const CBMType *rb = recv;
                            while (rb && rb->kind == CBM_TYPE_REFERENCE)
                                rb = rb->data.reference.elem;
                            if (rb && rb->kind == CBM_TYPE_NAMED) {
                                return cbm_type_named(ctx->arena, rb->data.named.qualified_name);
                            }
                        }
                        return ret;
                    }
                    return t;
                }
            }
        }

        /* Fallback: function expression's return type. */
        const CBMType *func_type = rust_eval_expr_type(ctx, func_node);
        if (func_type && func_type->kind == CBM_TYPE_FUNC && func_type->data.func.return_types &&
            func_type->data.func.return_types[0]) {
            return func_type->data.func.return_types[0];
        }
        if (func_type && func_type->kind == CBM_TYPE_NAMED) {
            return func_type;
        }
        return cbm_type_unknown();
    }

    /* macro_invocation: vec!, format!, … */
    if (strcmp(kind, "macro_invocation") == 0) {
        TSNode mname = ts_node_child_by_field_name(node, "macro", 5);
        if (ts_node_is_null(mname) && ts_node_named_child_count(node) > 0) {
            mname = ts_node_named_child(node, 0);
        }
        char *name = rust_node_text(ctx, mname);
        if (!name) {
            return cbm_type_unknown();
        }
        if (strcmp(name, "vec") == 0) {
            /* vec![T] — peek first argument's type. */
            TSNode args = ts_node_child_by_field_name(node, "arguments", 9);
            if (!ts_node_is_null(args)) {
                /* args is a token_tree; skim its named children for the first
                 * expression token. */
                uint32_t nc = ts_node_named_child_count(args);
                for (uint32_t i = 0; i < nc; i++) {
                    TSNode c = ts_node_named_child(args, i);
                    const CBMType *elem = rust_eval_expr_type(ctx, c);
                    if (elem && !cbm_type_is_unknown(elem)) {
                        return cbm_type_template(ctx->arena, "alloc.vec.Vec", &elem, 1);
                    }
                }
            }
            return cbm_type_template(ctx->arena, "alloc.vec.Vec", NULL, 0);
        }
        if (is_string_macro(name)) {
            return cbm_type_named(ctx->arena, "alloc.string.String");
        }
        if (is_void_macro(name)) {
            return cbm_type_builtin(ctx->arena, "()");
        }
        return cbm_type_unknown();
    }

    /* reference_expression: &x or &mut x */
    if (strcmp(kind, "reference_expression") == 0) {
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        if (ts_node_is_null(value) && ts_node_named_child_count(node) > 0) {
            value = ts_node_named_child(node, 0);
        }
        return cbm_type_reference(ctx->arena, rust_eval_expr_type(ctx, value));
    }

    /* unary_expression — *x dereferences, !x is bool, -x same as operand */
    if (strcmp(kind, "unary_expression") == 0) {
        TSNode operand = ts_node_named_child_count(node) > 0
                             ? ts_node_named_child(node, ts_node_named_child_count(node) - 1)
                             : (TSNode){0};
        char *op = NULL;
        for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
            TSNode c = ts_node_child(node, i);
            if (!ts_node_is_named(c)) {
                op = rust_node_text(ctx, c);
                if (op)
                    break;
            }
        }
        const CBMType *inner =
            ts_node_is_null(operand) ? cbm_type_unknown() : rust_eval_expr_type(ctx, operand);
        if (op && strcmp(op, "*") == 0) {
            if (inner && inner->kind == CBM_TYPE_REFERENCE) {
                return inner->data.reference.elem;
            }
            if (inner && inner->kind == CBM_TYPE_POINTER) {
                return inner->data.pointer.elem;
            }
            return inner;
        }
        if (op && strcmp(op, "!") == 0) {
            return cbm_type_builtin(ctx->arena, "bool");
        }
        return inner;
    }

    /* binary_expression — comparisons → bool, logical → bool, arith → left */
    if (strcmp(kind, "binary_expression") == 0) {
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
            TSNode c = ts_node_child(node, i);
            if (ts_node_is_named(c))
                continue;
            char *op = rust_node_text(ctx, c);
            if (!op)
                continue;
            if (strcmp(op, "==") == 0 || strcmp(op, "!=") == 0 || strcmp(op, "<") == 0 ||
                strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 || strcmp(op, ">=") == 0 ||
                strcmp(op, "&&") == 0 || strcmp(op, "||") == 0) {
                return cbm_type_builtin(ctx->arena, "bool");
            }
            break;
        }
        if (!ts_node_is_null(left)) {
            return rust_eval_expr_type(ctx, left);
        }
        return cbm_type_unknown();
    }

    /* index_expression */
    if (strcmp(kind, "index_expression") == 0) {
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        if (ts_node_is_null(value) && ts_node_named_child_count(node) > 0) {
            value = ts_node_named_child(node, 0);
        }
        const CBMType *op_type = rust_eval_expr_type(ctx, value);
        const CBMType *base = op_type;
        while (base && base->kind == CBM_TYPE_REFERENCE)
            base = base->data.reference.elem;
        if (base && base->kind == CBM_TYPE_SLICE) {
            return base->data.slice.elem;
        }
        if (base && base->kind == CBM_TYPE_TEMPLATE) {
            const char *nm = base->data.template_type.template_name;
            if ((strstr(nm, "Vec") || strstr(nm, "VecDeque")) &&
                base->data.template_type.arg_count > 0) {
                return base->data.template_type.template_args[0];
            }
            if ((strstr(nm, "HashMap") || strstr(nm, "BTreeMap")) &&
                base->data.template_type.arg_count > 1) {
                return base->data.template_type.template_args[1];
            }
        }
        return cbm_type_unknown();
    }

    /* parenthesized_expression */
    if (strcmp(kind, "parenthesized_expression") == 0 && ts_node_named_child_count(node) > 0) {
        return rust_eval_expr_type(ctx, ts_node_named_child(node, 0));
    }

    /* try_expression: e? — peel one Result<T, _> / Option<T> layer. */
    if (strcmp(kind, "try_expression") == 0 && ts_node_named_child_count(node) > 0) {
        const CBMType *inner = rust_eval_expr_type(ctx, ts_node_named_child(node, 0));
        if (inner && inner->kind == CBM_TYPE_TEMPLATE) {
            const char *nm = inner->data.template_type.template_name;
            if ((strstr(nm, "Result") || strstr(nm, "Option")) &&
                inner->data.template_type.arg_count > 0) {
                return inner->data.template_type.template_args[0];
            }
        }
        return inner;
    }

    /* await_expression: future.await — peel one Future / Poll layer naively. */
    if (strcmp(kind, "await_expression") == 0 && ts_node_named_child_count(node) > 0) {
        const CBMType *inner = rust_eval_expr_type(ctx, ts_node_named_child(node, 0));
        if (inner && inner->kind == CBM_TYPE_TEMPLATE && inner->data.template_type.arg_count > 0) {
            return inner->data.template_type.template_args[0];
        }
        return inner;
    }

    /* type_cast_expression: x as T */
    if (strcmp(kind, "type_cast_expression") == 0) {
        TSNode tn = ts_node_child_by_field_name(node, "type", 4);
        if (!ts_node_is_null(tn)) {
            return rust_parse_type_node(ctx, tn);
        }
    }

    /* tuple_expression */
    if (strcmp(kind, "tuple_expression") == 0) {
        const CBMType **elems = NULL;
        size_t count = 0;
        size_t capacity = 0;
        uint32_t nc = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < nc; i++) {
            if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&elems, count, &capacity,
                                                sizeof(*elems), count + 1,
                                                "rust tuple expression elements")) {
                return cbm_type_unknown();
            }
            elems[count++] = rust_eval_expr_type(ctx, ts_node_named_child(node, i));
        }
        if (count == 0) {
            return cbm_type_builtin(ctx->arena, "()");
        }
        if (count == 1) {
            return elems[0];
        }
        return cbm_type_tuple(ctx->arena, elems, (int)count);
    }

    /* array_expression: [a, b, c] */
    if (strcmp(kind, "array_expression") == 0) {
        if (ts_node_named_child_count(node) > 0) {
            const CBMType *elem = rust_eval_expr_type(ctx, ts_node_named_child(node, 0));
            return cbm_type_slice(ctx->arena, elem);
        }
        return cbm_type_unknown();
    }

    /* range_expression: a..b, a..=b, a.., ..b, .. — model as
     * Iterator<elem> so chains like `(0..n).map(...).count()` keep
     * typing. The element type is the type of the start/end expr. */
    if (strcmp(kind, "range_expression") == 0) {
        const CBMType *elem_type = NULL;
        uint32_t nc = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode c = ts_node_named_child(node, i);
            const CBMType *t = rust_eval_expr_type(ctx, c);
            if (t && !cbm_type_is_unknown(t)) {
                elem_type = t;
                break;
            }
        }
        if (elem_type) {
            return cbm_type_template(ctx->arena, "core.iter.Iterator", &elem_type, 1);
        }
        return cbm_type_template(ctx->arena, "core.iter.Iterator", NULL, 0);
    }

    /* unit_expression */
    if (strcmp(kind, "unit_expression") == 0) {
        return cbm_type_builtin(ctx->arena, "()");
    }

    /* struct_expression: Foo { … } */
    if (strcmp(kind, "struct_expression") == 0) {
        TSNode name_node = ts_node_child_by_field_name(node, "name", 4);
        if (ts_node_is_null(name_node) && ts_node_named_child_count(node) > 0) {
            name_node = ts_node_named_child(node, 0);
        }
        if (!ts_node_is_null(name_node)) {
            char *path = rust_node_text(ctx, name_node);
            if (path) {
                return cbm_type_named(ctx->arena, rust_resolve_path_expr(ctx, path));
            }
        }
        return cbm_type_unknown();
    }

    /* if_expression / match_expression / block / loop_expression — value of
     * the trailing expression in the consequence. */
    if (strcmp(kind, "if_expression") == 0) {
        TSNode cons = ts_node_child_by_field_name(node, "consequence", 11);
        if (!ts_node_is_null(cons)) {
            return rust_eval_expr_type(ctx, cons);
        }
    }
    if (strcmp(kind, "match_expression") == 0) {
        /* Take the type of the first arm's value if available. */
        TSNode body = ts_node_child_by_field_name(node, "body", 4);
        if (!ts_node_is_null(body)) {
            uint32_t nc = ts_node_named_child_count(body);
            for (uint32_t i = 0; i < nc; i++) {
                TSNode arm = ts_node_named_child(body, i);
                if (strcmp(ts_node_type(arm), "match_arm") == 0) {
                    TSNode v = ts_node_child_by_field_name(arm, "value", 5);
                    if (!ts_node_is_null(v)) {
                        return rust_eval_expr_type(ctx, v);
                    }
                }
            }
        }
    }
    if (strcmp(kind, "block") == 0) {
        /* Find the last expression child (the trailing expression of the block). */
        uint32_t nc = ts_node_named_child_count(node);
        TSNode last = {0};
        bool found = false;
        for (uint32_t i = nc; i > 0; i--) {
            TSNode c = ts_node_named_child(node, i - 1);
            const char *ck = ts_node_type(c);
            if (strcmp(ck, "expression_statement") != 0 && strcmp(ck, "let_declaration") != 0 &&
                strcmp(ck, "empty_statement") != 0 && strcmp(ck, "line_comment") != 0 &&
                strcmp(ck, "block_comment") != 0) {
                last = c;
                found = true;
                break;
            }
        }
        if (found) {
            return rust_eval_expr_type(ctx, last);
        }
        return cbm_type_builtin(ctx->arena, "()");
    }
    if (strcmp(kind, "loop_expression") == 0) {
        return cbm_type_builtin(ctx->arena, "()");
    }

    /* closure_expression: |a, b| body — best effort. Return type comes from
     * the body's last expression if present. */
    if (strcmp(kind, "closure_expression") == 0) {
        TSNode body = ts_node_child_by_field_name(node, "body", 4);
        if (ts_node_is_null(body)) {
            return cbm_type_func(ctx->arena, NULL, NULL, NULL);
        }
        return cbm_type_func(ctx->arena, NULL, NULL, NULL);
    }

    /* Literals fall through. */
    if (strcmp(kind, "integer_literal") == 0 || strcmp(kind, "float_literal") == 0 ||
        strcmp(kind, "string_literal") == 0 || strcmp(kind, "raw_string_literal") == 0 ||
        strcmp(kind, "char_literal") == 0 || strcmp(kind, "boolean_literal") == 0 ||
        strcmp(kind, "true") == 0 || strcmp(kind, "false") == 0) {
        return rust_eval_literal_type(ctx, kind, node);
    }

    /* break / continue / return — expressions with no useful type for callers. */
    if (strcmp(kind, "return_expression") == 0 || strcmp(kind, "break_expression") == 0 ||
        strcmp(kind, "continue_expression") == 0 || strcmp(kind, "yield_expression") == 0) {
        return cbm_type_builtin(ctx->arena, "!");
    }

    return cbm_type_unknown();
}

/* Bidirectional wrapper. Evaluate `node` with an `expected` hint. The
 * hint is used post-synthesis: if synthesis returned an under-specified
 * type (unknown, or a TEMPLATE without args, or a NAMED that the hint
 * refines), we substitute the hint when it matches structurally. */
const CBMType *rust_eval_expr_typed(RustLSPContext *ctx, TSNode node, const CBMType *expected) {
    const CBMType *synth = rust_eval_expr_type(ctx, node);
    if (!expected)
        return synth;
    if (!synth || cbm_type_is_unknown(synth)) {
        return expected;
    }
    /* Template with same head and missing args -> use expected. */
    if (synth->kind == CBM_TYPE_TEMPLATE && expected->kind == CBM_TYPE_TEMPLATE &&
        synth->data.template_type.template_name && expected->data.template_type.template_name &&
        strcmp(synth->data.template_type.template_name,
               expected->data.template_type.template_name) == 0 &&
        synth->data.template_type.arg_count == 0 && expected->data.template_type.arg_count > 0) {
        return expected;
    }
    /* NAMED matches expected NAMED — no refinement needed. */
    if (synth->kind == CBM_TYPE_NAMED && expected->kind == CBM_TYPE_TEMPLATE &&
        synth->data.named.qualified_name && expected->data.template_type.template_name &&
        strcmp(synth->data.named.qualified_name, expected->data.template_type.template_name) == 0) {
        return expected; /* refine NAMED → TEMPLATE with args */
    }
    return synth;
}

/* Member access type: returns the CBMType for `recv.field_or_method`.
 * Methods return their FUNC signature; fields return the field type. */
static const CBMType *rust_eval_member_access(RustLSPContext *ctx, const CBMType *recv,
                                              const char *member) {
    if (!recv || !member)
        return cbm_type_unknown();
    /* Auto-deref through references. */
    const CBMType *base = recv;
    while (base && (base->kind == CBM_TYPE_REFERENCE || base->kind == CBM_TYPE_POINTER)) {
        base = (base->kind == CBM_TYPE_REFERENCE) ? base->data.reference.elem
                                                  : base->data.pointer.elem;
    }
    if (!base)
        return cbm_type_unknown();

    const char *type_qn = NULL;
    const CBMType **template_args = NULL;
    int template_count = 0;
    const char **template_params = NULL;

    if (base->kind == CBM_TYPE_NAMED) {
        type_qn = base->data.named.qualified_name;
    } else if (base->kind == CBM_TYPE_TEMPLATE) {
        type_qn = base->data.template_type.template_name;
        template_args = (const CBMType **)base->data.template_type.template_args;
        template_count = base->data.template_type.arg_count;
    } else if (base->kind == CBM_TYPE_BUILTIN) {
        /* Map a few primitives into stdlib QNs so registered methods on
         * `str`/`String`/integers are findable. */
        const char *nm = base->data.builtin.name;
        if (strcmp(nm, "str") == 0)
            type_qn = "core.str";
        else if (strcmp(nm, "String") == 0)
            type_qn = "alloc.string.String";
        else
            type_qn = nm;
    } else if (base->kind == CBM_TYPE_SLICE) {
        type_qn = "core.slice";
    } else {
        return cbm_type_unknown();
    }
    if (!type_qn)
        return cbm_type_unknown();

    /* Check inherent method first. */
    const CBMRegisteredFunc *method = rust_lookup_method(ctx, type_qn, member);
    if (method && method->signature) {
        if (template_args && method->type_param_names) {
            template_params = method->type_param_names;
            const CBMType *sub =
                rust_substitute_type(ctx->arena, method->signature, template_params, template_args);
            return sub;
        }
        /* Substitute any Self placeholder on the return type. */
        const CBMType *sig = method->signature;
        if (sig && sig->kind == CBM_TYPE_FUNC && sig->data.func.return_types &&
            sig->data.func.return_types[0]) {
            const CBMType *ret = sig->data.func.return_types[0];
            if (ret && ret->kind == CBM_TYPE_NAMED &&
                strcmp(ret->data.named.qualified_name, "Self") == 0) {
                return cbm_type_named(ctx->arena, type_qn);
            }
        }
        return method->signature;
    }

    /* Field on the type's RegisteredType. */
    const CBMType *ft = rust_lookup_field(ctx, type_qn, member, 0);
    if (ft) {
        if (template_args && template_params) {
            return rust_substitute_type(ctx->arena, ft, template_params, template_args);
        }
        return ft;
    }
    return cbm_type_unknown();
}

/* ════════════════════════════════════════════════════════════════════
 * 7. Method dispatch + field lookup
 * ════════════════════════════════════════════════════════════════════ */

static const CBMType *rust_lookup_field(RustLSPContext *ctx, const char *type_qn,
                                        const char *field_name, int depth) {
    if (!type_qn || !field_name)
        return NULL;
    if (depth >= ctx->lookup_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_field_lookup_depth", (size_t)ctx->lookup_depth_limit);
        return NULL;
    }
    const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, type_qn);
    if (!rt)
        return NULL;
    if (rt->alias_of)
        return rust_lookup_field(ctx, rt->alias_of, field_name, depth + 1);
    if (rt->field_names) {
        for (int i = 0; rt->field_names[i]; i++) {
            if (strcmp(rt->field_names[i], field_name) == 0 && rt->field_types &&
                rt->field_types[i]) {
                return rt->field_types[i];
            }
        }
    }
    if (rt->embedded_types) {
        for (int i = 0; rt->embedded_types[i]; i++) {
            const CBMType *f = rust_lookup_field(ctx, rt->embedded_types[i], field_name, depth + 1);
            if (f)
                return f;
        }
    }
    return NULL;
}

/* Hardcoded Deref<Target=U> map for stdlib smart pointers + guards. The
 * format mirrors the de-facto rule: `<smart-pointer-QN-prefix>` →
 * `<inner-type position>` where inner is taken from the receiver's
 * template args. We don't store U literally; instead we let the call
 * site pass `template_args[idx]` as the new receiver type for retry. */
static bool rust_type_derefs_to_first_arg(const char *type_qn) {
    if (!type_qn)
        return false;
    static const char *derefable[] = {"alloc.boxed.Box",
                                      "std.boxed.Box",
                                      "alloc.rc.Rc",
                                      "std.rc.Rc",
                                      "alloc.sync.Arc",
                                      "std.sync.Arc",
                                      "core.cell.RefCell",
                                      "std.cell.RefCell",
                                      "core.cell.Cell",
                                      "std.cell.Cell",
                                      "std.sync.MutexGuard",
                                      "std.sync.RwLockReadGuard",
                                      "std.sync.RwLockWriteGuard",
                                      "core.pin.Pin",
                                      NULL};
    for (const char **p = derefable; *p; p++) {
        if (strcmp(*p, type_qn) == 0)
            return true;
    }
    return false;
}

/* Returns the inner type after one Deref step. For NAMED types we check
 * for a registered `embedded_types` entry whose tail is "Target=<U>" or,
 * for stdlib smart pointers, peel the first template arg. Returns NULL
 * if no Deref relationship is known. */
static const CBMType *rust_deref_step(RustLSPContext *ctx, const CBMType *t) {
    if (!t)
        return NULL;
    /* Smart pointers: Box<T>, Rc<T>, Arc<T>, etc. The grammar gives us a
     * TEMPLATE; the inner type is the first template arg. */
    if (t->kind == CBM_TYPE_TEMPLATE && t->data.template_type.template_name) {
        if (rust_type_derefs_to_first_arg(t->data.template_type.template_name)) {
            if (t->data.template_type.arg_count > 0) {
                return t->data.template_type.template_args[0];
            }
            return NULL;
        }
    }
    /* NAMED smart-pointer (rare — only when the user wrote `Rc` without
     * type arg) — no inner to peel. */
    if (t->kind == CBM_TYPE_NAMED && t->data.named.qualified_name) {
        if (rust_type_derefs_to_first_arg(t->data.named.qualified_name)) {
            return NULL;
        }
        /* Project type with a registered Deref impl. We approximate this
         * by checking `embedded_types` for an entry of the form
         * `<TraitQN>:DerefTarget:<U>` — set up by `impl Deref for X`
         * post-processing. (Currently not produced by extract_defs; the
         * call still works for stdlib types.) */
        const CBMRegisteredType *rt =
            cbm_registry_lookup_type(ctx->registry, t->data.named.qualified_name);
        if (rt && rt->embedded_types) {
            for (int i = 0; rt->embedded_types[i]; i++) {
                const char *e = rt->embedded_types[i];
                static const char prefix[] = "DerefTarget:";
                if (strncmp(e, prefix, sizeof(prefix) - 1) == 0) {
                    return cbm_type_named(ctx->arena, e + sizeof(prefix) - 1);
                }
            }
        }
    }
    return NULL;
}

static const CBMRegisteredFunc *rust_lookup_method_depth(RustLSPContext *ctx, const char *type_qn,
                                                         const char *member_name, int depth) {
    if (!type_qn || !member_name)
        return NULL;
    if (depth >= ctx->lookup_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_method_lookup_depth", (size_t)ctx->lookup_depth_limit);
        return NULL;
    }

    /* Direct inherent method lookup. */
    const CBMRegisteredFunc *f = cbm_registry_lookup_method(ctx->registry, type_qn, member_name);
    if (f)
        return f;

    /* Follow alias / embedded chain. */
    const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, type_qn);
    if (rt) {
        if (rt->alias_of) {
            f = rust_lookup_method_depth(ctx, rt->alias_of, member_name, depth + 1);
            if (f)
                return f;
        }
        if (rt->embedded_types) {
            for (int i = 0; rt->embedded_types[i]; i++) {
                /* Skip the synthetic DerefTarget marker — handled by the
                 * caller in the receiver-walk loop. */
                if (strncmp(rt->embedded_types[i], "DerefTarget:", 12) == 0)
                    continue;
                /* Skip bound markers used for type-param trait bound
                 * recording — those live under "Bound:<TraitQN>". */
                if (strncmp(rt->embedded_types[i], "Bound:", 6) == 0) {
                    /* Dispatch through the bound trait. */
                    f = rust_lookup_method_depth(ctx, rt->embedded_types[i] + 6, member_name,
                                                 depth + 1);
                    if (f)
                        return f;
                    continue;
                }
                f = rust_lookup_method_depth(ctx, rt->embedded_types[i], member_name, depth + 1);
                if (f)
                    return f;
            }
        }
    }
    return NULL;
}

const CBMRegisteredFunc *rust_lookup_method(RustLSPContext *ctx, const char *type_qn,
                                            const char *member_name) {
    return rust_lookup_method_depth(ctx, type_qn, member_name, 0);
}

/* Walk the registry for any method named `member_name` on a type that
 * implements `trait_qn`. We approximate trait impl membership by checking
 * whether the type's `embedded_types` contains `trait_qn` (we treat
 * `impl Trait for Type` as registering the trait QN as an embedded type
 * of the receiver). */
static const CBMRegisteredFunc *rust_lookup_method_in_trait(RustLSPContext *ctx,
                                                            const char *trait_qn,
                                                            const char *method_name) {
    if (!ctx || !trait_qn || !method_name)
        return NULL;
    const CBMTypeRegistry *reg = ctx->registry;
    /* Trait method is also registered on the trait itself with `receiver_type`
     * set to the trait QN (default impls / signatures). */
    return cbm_registry_lookup_method(reg, trait_qn, method_name);
}

/* For a method call where the receiver is a `dyn Trait` or `impl Trait`,
 * try to resolve through the trait's known impls. Returns the chosen
 * concrete method, the trait method (default impl), or NULL. */
static const CBMRegisteredFunc *rust_resolve_trait_method(RustLSPContext *ctx,
                                                          const char *receiver_type_qn,
                                                          const char *method_name,
                                                          int *out_impl_count) {
    if (out_impl_count)
        *out_impl_count = 0;
    if (!ctx || !receiver_type_qn || !method_name)
        return NULL;
    const CBMTypeRegistry *reg = ctx->registry;

    /* First try inherent method on the receiver itself, following any
     * type aliases (so `std.sync.Arc.clone` resolves through to
     * `alloc.sync.Arc.clone` in the registry). Stays BEFORE the memo check —
     * a colliding real hit is always found (collision guard). */
    const CBMRegisteredFunc *inh = rust_lookup_method_depth(ctx, receiver_type_qn, method_name, 0);
    if (inh) {
        if (out_impl_count)
            *out_impl_count = 1;
        return inh;
    }

    /* Negative memo (sealed registry only): this whole cascade — embedded-
     * impl walk + trait-default tail — reads nothing but the registry and the
     * two query strings, so under read_only a miss is a pure fact. Macro-
     * expanded kernel rust asks the same failing (receiver, method) question
     * thousands of times per file; without the memo each repeat re-paid the
     * full walk (~63 s per trait-heavy file). Only the full miss (0 impls,
     * no trait default) is memoized, preserving out_impl_count fidelity for
     * the ambiguous (>=2 impls) case. */
    bool nm_active = reg && reg->read_only;
    uint64_t nm_key = 0;
    if (nm_active) {
        nm_key = cbm_negmemo_key(1, receiver_type_qn, method_name);
        if (cbm_negmemo_contains(&ctx->neg_memo, nm_key)) {
            return NULL;
        }
    }

    /* Look at every type whose embedded_types include the receiver_type_qn
     * (treated as a trait): pick the single-impl case. Prefilter to the types whose
     * embedded_types carry a matching BARE name via the registry index; the exact
     * full-QN check below is unchanged, so the result set is identical. */
    const CBMRegisteredFunc *unique = NULL;
    int impls = 0;
    const char *rdot = strrchr(receiver_type_qn, '.');
    const char *rbare = rdot ? rdot + 1 : receiver_type_qn;
    CBMTypeEmbedIter eit;
    cbm_registry_types_by_embedded_bare(reg, rbare, &eit);
    for (int ti; impls < 3 && (ti = cbm_type_embed_iter_next(&eit)) >= 0;) {
        const CBMRegisteredType *t = &reg->types[ti];
        if (!t->embedded_types)
            continue;
        for (int j = 0; t->embedded_types[j]; j++) {
            if (strcmp(t->embedded_types[j], receiver_type_qn) == 0) {
                const CBMRegisteredFunc *mf =
                    cbm_registry_lookup_method(reg, t->qualified_name, method_name);
                if (mf) {
                    impls++;
                    if (impls == 1)
                        unique = mf;
                }
                break;
            }
        }
    }
    if (out_impl_count)
        *out_impl_count = impls;
    if (impls == 1)
        return unique;
    const CBMRegisteredFunc *tm = rust_lookup_method_in_trait(ctx, receiver_type_qn, method_name);
    if (nm_active && !tm && impls == 0) {
        cbm_negmemo_insert(&ctx->neg_memo, ctx->arena, nm_key);
    }
    return tm;
}

// True if `type_qn` implements a trait that declares `method_name` — i.e. a
// method resolved inherently on the receiver is actually a trait-impl method
// (lsp_trait_dispatch) rather than a plain inherent one (lsp_method_dispatch).
// A struct's embedded_types are the traits it implements (the impl-link model
// rust_resolve_trait_method already relies on), so a declaring trait among them
// means the method came from `impl Trait for Type`.
static bool rust_method_is_trait_impl(RustLSPContext *ctx, const char *type_qn,
                                      const char *method_name) {
    if (!ctx || !type_qn || !method_name)
        return false;
    const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, type_qn);
    if (!rt || !rt->embedded_types)
        return false;
    for (int i = 0; rt->embedded_types[i]; i++) {
        if (cbm_registry_lookup_method(ctx->registry, rt->embedded_types[i], method_name))
            return true;
    }
    return false;
}

// Find the sole concrete implementer of trait `trait_qn` that declares
// `method_name`, returning that impl's method (NULL if none or 2+), setting
// *out_n to the count (capped at 2). Used for `Trait::method` UFCS so it
// resolves to the concrete impl rather than the trait's own abstract method.
// Matches the embedded (impl-link) entry by full QN OR bare name, since the
// link is recorded short in some registry entries and fully-qualified in
// others; dedups implementers by QN.
static const CBMRegisteredFunc *rust_find_sole_trait_impl(RustLSPContext *ctx, const char *trait_qn,
                                                          const char *method_name, int *out_n) {
    if (out_n)
        *out_n = 0;
    if (!ctx || !trait_qn || !method_name)
        return NULL;
    const CBMTypeRegistry *reg = ctx->registry;
    /* Negative memo (sealed registry only) — registry-pure cascade; only the
     * zero-implementer miss is memoized (out_n fidelity for the 2+ case). */
    bool nm_active = reg && reg->read_only;
    uint64_t nm_key = 0;
    if (nm_active) {
        nm_key = cbm_negmemo_key(2, trait_qn, method_name);
        if (cbm_negmemo_contains(&ctx->neg_memo, nm_key)) {
            return NULL;
        }
    }
    const char *tdot = strrchr(trait_qn, '.');
    const char *tbare = tdot ? tdot + 1 : trait_qn;
    const CBMRegisteredFunc *first = NULL;
    const char *first_qn = NULL;
    int n = 0;
    /* Prefilter to types whose embedded_types carry the trait's BARE name; the
     * exact (full-QN OR bare) check below is unchanged. tbare-keyed index captures
     * every original match (a full-QN match implies a bare-name match). */
    CBMTypeEmbedIter eit;
    cbm_registry_types_by_embedded_bare(reg, tbare, &eit);
    for (int ti; n < 2 && (ti = cbm_type_embed_iter_next(&eit)) >= 0;) {
        const CBMRegisteredType *t = &reg->types[ti];
        if (!t->embedded_types || !t->qualified_name)
            continue;
        bool impls = false;
        for (int j = 0; t->embedded_types[j]; j++) {
            const char *e = t->embedded_types[j];
            const char *edot = strrchr(e, '.');
            const char *ebare = edot ? edot + 1 : e;
            if (strcmp(e, trait_qn) == 0 || strcmp(ebare, tbare) == 0) {
                impls = true;
                break;
            }
        }
        if (!impls)
            continue;
        const CBMRegisteredFunc *mf =
            cbm_registry_lookup_method(reg, t->qualified_name, method_name);
        if (!mf)
            continue;
        if (!first_qn) {
            first = mf;
            first_qn = t->qualified_name;
            n = 1;
        } else if (strcmp(first_qn, t->qualified_name) != 0) {
            n = 2;
        }
    }
    if (out_n)
        *out_n = n;
    if (nm_active && n == 0) {
        cbm_negmemo_insert(&ctx->neg_memo, ctx->arena, nm_key);
    }
    return n == 1 ? first : NULL;
}

/* ════════════════════════════════════════════════════════════════════
 * 8. Macro handling
 * ════════════════════════════════════════════════════════════════════ */

/* Map a Rust infix/index operator token to the std::ops trait method that
 * the compiler desugars it to. `a + b` calls `Add::add`, `a[i]` calls
 * `Index::index`, etc. Returns NULL for operators with no overloadable
 * trait method (comparison/logical operators route through PartialEq /
 * PartialOrd whose methods we don't model here — sound to skip). */
static const char *rust_binop_trait_method(const char *op_text) {
    if (!op_text)
        return NULL;
    if (strcmp(op_text, "+") == 0)
        return "add";
    if (strcmp(op_text, "-") == 0)
        return "sub";
    if (strcmp(op_text, "*") == 0)
        return "mul";
    if (strcmp(op_text, "/") == 0)
        return "div";
    if (strcmp(op_text, "%") == 0)
        return "rem";
    if (strcmp(op_text, "&") == 0)
        return "bitand";
    if (strcmp(op_text, "|") == 0)
        return "bitor";
    if (strcmp(op_text, "^") == 0)
        return "bitxor";
    if (strcmp(op_text, "<<") == 0)
        return "shl";
    if (strcmp(op_text, ">>") == 0)
        return "shr";
    return NULL;
}

/* If `recv` is a user-defined NAMED type that defines operator method
 * `method` (via inherent impl or `impl <trait> for T`), emit a CALLS edge to
 * it. Models Rust operator-overload desugaring (`a + b` → T::add, `a[i]` →
 * T::index). Sound-only: we emit nothing when the operand type is unknown,
 * primitive, or the type has no such method registered — so we never guess on
 * built-in arithmetic. */
static void rust_emit_operator_call(RustLSPContext *ctx, const CBMType *recv, const char *method,
                                    TSNode source_node) {
    if (!recv || !method)
        return;
    const CBMType *base = recv;
    while (base && (base->kind == CBM_TYPE_REFERENCE || base->kind == CBM_TYPE_POINTER)) {
        base = (base->kind == CBM_TYPE_REFERENCE) ? base->data.reference.elem
                                                  : base->data.pointer.elem;
    }
    /* Only user-defined named types — built-in arithmetic must not emit. */
    if (!base || base->kind != CBM_TYPE_NAMED)
        return;
    const char *type_qn = base->data.named.qualified_name;
    if (!type_qn || is_rust_primitive(type_qn))
        return;
    int impl_count = 0;
    const CBMRegisteredFunc *m = rust_resolve_trait_method(ctx, type_qn, method, &impl_count);
    if (m && m->qualified_name) {
        rust_emit_resolved_call(ctx, m->qualified_name, "lsp_operator_trait",
                                CBM_RUST_CONF_OPERATOR);
        /* `a + b` is a binary_expression, never a syntactic call node, so the
         * extractor produced no CBMCall to pair with the resolved_call above.
         * Inject one so the pipeline emits the CALLS edge. */
        if (ctx->inject_syn_calls == 0) {
            rust_inject_syn_call(ctx, m->qualified_name,
                                 (int)ts_node_start_point(source_node).row + 1);
        }
    }
}

/* ── User-defined macro_rules! support ────────────────────────────
 *
 * Strategy: collect every `macro_rules!` definition in the file
 * during the pre-walk, store each rule's transcriber text, and on
 * `macro_invocation` re-parse the transcriber as a synthetic Rust
 * function body so any calls inside the body are attributed to the
 * enclosing function of the invocation site.
 *
 * Expansion is bounded by explicit per-file work, matcher-depth, and
 * expansion-depth budgets.  These are analysis safety limits, separate from
 * rustc's crate-level recursion_limit. */

typedef struct RustMacroRule {
    const char *macro_name;
    const char *pattern_text; /* left-hand side (without outer brackets) */
    int pattern_len;
    const char *transcriber_text;
    int transcriber_len;
    uint32_t definition_start_byte;
    uint32_t scope_start_byte;
    uint32_t scope_end_byte;
} RustMacroRule;

/* Strip a single outer pair of matching brackets from a token-tree
 * text representation. Returns the inner span via out_text/out_len.
 * If no brackets, returns the original. */
static void rust_macro_strip_outer(const char *tt, int len, const char **out_text, int *out_len) {
    if (len >= 2 && ((tt[0] == '{' && tt[len - 1] == '}') || (tt[0] == '(' && tt[len - 1] == ')') ||
                     (tt[0] == '[' && tt[len - 1] == ']'))) {
        *out_text = tt + 1;
        *out_len = len - 2;
    } else {
        *out_text = tt;
        *out_len = len;
    }
}

static void rust_record_macro_rule(RustLSPContext *ctx, const char *macro_name, TSNode pattern,
                                   TSNode transcriber, uint32_t definition_start_byte,
                                   uint32_t scope_start_byte, uint32_t scope_end_byte) {
    if (!ctx || !macro_name || ts_node_is_null(transcriber))
        return;
    if (ctx->macro_rules_count % 16 == 0) {
        int new_cap = ctx->macro_rules_count + 16;
        struct RustMacroRule **narr = (struct RustMacroRule **)cbm_arena_alloc(
            ctx->arena, new_cap * sizeof(struct RustMacroRule *));
        if (!narr)
            return;
        if (ctx->macro_rules_arr && ctx->macro_rules_count > 0) {
            memcpy(narr, ctx->macro_rules_arr,
                   ctx->macro_rules_count * sizeof(struct RustMacroRule *));
        }
        ctx->macro_rules_arr = narr;
    }
    RustMacroRule *r = (RustMacroRule *)cbm_arena_alloc(ctx->arena, sizeof(*r));
    if (!r)
        return;
    memset(r, 0, sizeof(*r));
    r->macro_name = cbm_arena_strdup(ctx->arena, macro_name);
    r->definition_start_byte = definition_start_byte;
    r->scope_start_byte = scope_start_byte;
    r->scope_end_byte = scope_end_byte;

    /* Cache pattern text for matching at invocation time. */
    if (!ts_node_is_null(pattern)) {
        char *pt = cbm_node_text(ctx->arena, pattern, ctx->source);
        if (pt) {
            const char *inner;
            int inner_len;
            rust_macro_strip_outer(pt, (int)strlen(pt), &inner, &inner_len);
            r->pattern_text = cbm_arena_strndup(ctx->arena, inner, (size_t)inner_len);
            r->pattern_len = inner_len;
        }
    }

    char *tt = cbm_node_text(ctx->arena, transcriber, ctx->source);
    if (tt) {
        int len = (int)strlen(tt);
        const char *inner;
        int inner_len;
        rust_macro_strip_outer(tt, len, &inner, &inner_len);
        r->transcriber_text = cbm_arena_strndup(ctx->arena, inner, (size_t)inner_len);
        r->transcriber_len = inner_len;
    }
    ctx->macro_rules_arr[ctx->macro_rules_count++] = r;
}

static bool rust_macro_lexical_scope(const char *kind) {
    return strcmp(kind, "source_file") == 0 || strcmp(kind, "declaration_list") == 0 ||
           strcmp(kind, "block") == 0;
}

static void rust_collect_macro_rules_in_scope(RustLSPContext *ctx, TSNode node,
                                              uint32_t scope_start_byte, uint32_t scope_end_byte) {
    if (ts_node_is_null(node) || cbm_arena_failed(ctx->arena))
        return;
    const char *node_kind = ts_node_type(node);
    if (rust_macro_lexical_scope(node_kind)) {
        scope_start_byte = ts_node_start_byte(node);
        scope_end_byte = ts_node_end_byte(node);
    }
    if (strcmp(node_kind, "macro_definition") == 0) {
        TSNode name_node = ts_node_child_by_field_name(node, "name", 4);
        if (ts_node_is_null(name_node))
            return;
        char *macro_name = rust_node_text(ctx, name_node);
        if (!macro_name)
            return;
        uint32_t definition_start_byte = ts_node_start_byte(node);
        uint32_t rule_count = ts_node_child_count(node);
        for (uint32_t i = 0; i < rule_count; i++) {
            TSNode rule = ts_node_child(node, i);
            if (ts_node_is_null(rule) || !ts_node_is_named(rule) ||
                strcmp(ts_node_type(rule), "macro_rule") != 0) {
                continue;
            }
            TSNode left = ts_node_child_by_field_name(rule, "left", 4);
            TSNode right = ts_node_child_by_field_name(rule, "right", 5);
            if (!ts_node_is_null(right)) {
                rust_record_macro_rule(ctx, macro_name, left, right, definition_start_byte,
                                       scope_start_byte, scope_end_byte);
            }
        }
        return;
    }
    uint32_t nc = ts_node_child_count(node);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode child = ts_node_child(node, i);
        if (!ts_node_is_null(child) && ts_node_is_named(child)) {
            rust_collect_macro_rules_in_scope(ctx, child, scope_start_byte, scope_end_byte);
        }
    }
}

static void rust_collect_macro_rules(RustLSPContext *ctx, TSNode root) {
    if (ts_node_is_null(root))
        return;
    rust_collect_macro_rules_in_scope(ctx, root, ts_node_start_byte(root), ts_node_end_byte(root));
}

/* ── Metavar matching + substitution ─────────────────────────────
 *
 * This is a deterministic, fail-closed macro_rules! subset.  The lexer keeps
 * Rust token trees intact, the matcher validates every non-terminal with the
 * Rust grammar, captures are invocation-local arena records, and repetition
 * cardinality and nesting are preserved exactly.  Metavariable expressions
 * remain deliberately rejected until implemented; rejecting a file is
 * preferable to publishing a plausible but false graph. */

typedef enum {
    MACRO_NO_MATCH = 0,
    MACRO_MATCH = 1,
    MACRO_FATAL = -1,
} MacroMatchStatus;

typedef enum {
    MACRO_MISS_NONE = 0,
    MACRO_MISS_TOKEN = 1,
    MACRO_MISS_FRAGMENT = 2,
} MacroMissKind;

typedef struct MacroToken {
    const char *text;
    size_t len;
    char open;
    char close;
    bool desugared_doc_comment;
    struct MacroToken *children;
    struct MacroToken *next;
} MacroToken;

typedef struct MacroNesting {
    const MacroToken *repetition;
    size_t iteration;
    size_t depth;
    bool require_end;
    const struct MacroNesting *parent;
} MacroNesting;

typedef struct MacroRepeatShape {
    const MacroToken *repetition;
    size_t depth;
    const struct MacroRepeatShape *parent;
} MacroRepeatShape;

typedef struct MacroBinding {
    const char *name;
    size_t name_len;
    const MacroRepeatShape *shape;
    struct MacroBinding *previous;
} MacroBinding;

typedef struct MacroCapture {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
    const MacroNesting *nesting;
    struct MacroCapture *previous;
} MacroCapture;

typedef struct MacroCardinality {
    const MacroToken *repetition;
    const MacroNesting *parent;
    size_t count;
    struct MacroCardinality *previous;
} MacroCardinality;

typedef struct {
    RustLSPContext *ctx;
    TSParser *fragment_parser;
    MacroBinding *bindings;
    MacroCapture *captures;
    MacroCardinality *cardinalities;
    const char *macro_name;
    uint32_t invocation_byte;
    const char *input_text;
    size_t input_len;
    const char *pattern_text;
    size_t pattern_len;
    MacroMissKind miss_kind;
    size_t furthest_input_byte;
    size_t furthest_matcher_byte;
    size_t candidate_start_byte;
    size_t candidate_end_byte;
    const char *candidate_fragment;
    size_t candidate_fragment_len;
    size_t fragment_parse_count;
    size_t fragment_parse_bytes;
    size_t fragment_parse_largest_bytes;
    size_t fragment_parse_largest_start_byte;
    const char *fragment_parse_largest_fragment;
    size_t fragment_parse_largest_fragment_len;
    bool fragment_parse_largest_in_invocation;
    bool fragment_parse_failure_logged;
} MacroEnv;

typedef struct MacroRepeatState {
    const MacroToken *input;
    MacroCapture *captures;
    MacroCardinality *cardinalities;
    size_t count;
    struct MacroRepeatState *previous;
} MacroRepeatState;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} MacroOutput;

static void *macro_arena_zalloc(RustLSPContext *ctx, size_t size, const char *operation) {
    if (!ctx || size == 0) {
        if (ctx) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_ALLOCATION_INVALID", operation, size);
        }
        return NULL;
    }
    void *memory = cbm_arena_alloc(ctx->arena, size);
    if (!memory) {
        return NULL;
    }
    memset(memory, 0, size);
    return memory;
}

static bool macro_work(RustLSPContext *ctx, size_t units, const char *operation) {
    if (!ctx || cbm_arena_failed(ctx->arena)) {
        return false;
    }
    size_t used = ctx->macro_work_count < 0 ? 0 : (size_t)ctx->macro_work_count;
    size_t limit = ctx->macro_work_limit < 0 ? 0 : (size_t)ctx->macro_work_limit;
    if (units > limit || used > limit - units || units > (size_t)INT_MAX) {
        fprintf(stderr,
                "ERROR level=error msg=rust_macro.work_limit_exhausted "
                "code=CBM_RUST_MACRO_WORK_LIMIT_EXCEEDED operation=%s used=%zu limit=%zu "
                "requested=%zu source_bytes=%d expansion_depth=%d\n",
                operation ? operation : "none", used, limit, units, ctx->source_len,
                ctx->macro_expand_depth);
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_WORK_LIMIT_EXCEEDED", operation, units);
        return false;
    }
    ctx->macro_work_count += (int)units;
    return true;
}

typedef enum {
    MACRO_DOC_COMMENT_NONE = 0,
    MACRO_DOC_COMMENT_OUTER_LINE,
    MACRO_DOC_COMMENT_INNER_LINE,
    MACRO_DOC_COMMENT_OUTER_BLOCK,
    MACRO_DOC_COMMENT_INNER_BLOCK,
} MacroDocCommentKind;

static MacroDocCommentKind macro_doc_comment_kind(const char *source, size_t len, size_t pos) {
    if (!source || pos > len || len - pos < 3 || source[pos] != '/') {
        return MACRO_DOC_COMMENT_NONE;
    }
    if (source[pos + 1] == '/') {
        if (source[pos + 2] == '!') {
            return MACRO_DOC_COMMENT_INNER_LINE;
        }
        if (source[pos + 2] == '/' && (len - pos == 3 || source[pos + 3] != '/')) {
            return MACRO_DOC_COMMENT_OUTER_LINE;
        }
        return MACRO_DOC_COMMENT_NONE;
    }
    if (source[pos + 1] != '*') {
        return MACRO_DOC_COMMENT_NONE;
    }
    if (source[pos + 2] == '!') {
        return MACRO_DOC_COMMENT_INNER_BLOCK;
    }
    if (source[pos + 2] == '*' && (len - pos == 3 || source[pos + 3] != '*')) {
        return MACRO_DOC_COMMENT_OUTER_BLOCK;
    }
    return MACRO_DOC_COMMENT_NONE;
}

static bool macro_scan_doc_comment(RustLSPContext *ctx, const char *source, size_t len,
                                   size_t start, MacroDocCommentKind kind, size_t *content_start,
                                   size_t *content_end, size_t *comment_end) {
    if (!ctx || !source || !content_start || !content_end || !comment_end ||
        kind == MACRO_DOC_COMMENT_NONE) {
        if (ctx) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                  "rust_lsp_macro_doc_comment_arguments", start);
        }
        return false;
    }
    bool line = kind == MACRO_DOC_COMMENT_OUTER_LINE || kind == MACRO_DOC_COMMENT_INNER_LINE;
    if (line) {
        size_t cursor = start + 3;
        while (cursor < len && source[cursor] != '\n') {
            if (source[cursor] == '\r') {
                if (cursor + 1 < len && source[cursor + 1] == '\n') {
                    break;
                }
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                      "rust_lsp_macro_doc_comment_carriage_return", cursor);
                return false;
            }
            cursor++;
        }
        *content_start = start + 3;
        *content_end = cursor;
        *comment_end = cursor;
        return true;
    }

    size_t cursor = start + 2;
    size_t depth = 1;
    size_t closing_start = 0;
    while (cursor < len && depth > 0) {
        if (cursor + 1 < len && source[cursor] == '/' && source[cursor + 1] == '*') {
            depth++;
            cursor += 2;
        } else if (cursor + 1 < len && source[cursor] == '*' && source[cursor + 1] == '/') {
            depth--;
            closing_start = cursor;
            cursor += 2;
        } else {
            if (source[cursor] == '\r') {
                if (cursor + 1 >= len || source[cursor + 1] != '\n') {
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                          "rust_lsp_macro_doc_comment_carriage_return", cursor);
                    return false;
                }
            }
            cursor++;
        }
    }
    if (depth != 0) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                              "rust_lsp_macro_unterminated_comment", len);
        return false;
    }
    size_t body_start = start + 3;
    if (body_start > closing_start) {
        body_start = closing_start;
    }
    *content_start = body_start;
    *content_end = closing_start;
    *comment_end = cursor;
    return true;
}

static bool macro_doc_escaped_length(RustLSPContext *ctx, const char *source, size_t start,
                                     size_t end, size_t *escaped_len) {
    size_t total = 0;
    for (size_t i = start; i < end; i++) {
        unsigned char c = (unsigned char)source[i];
        if (c == '\r' && i + 1 < end && source[i + 1] == '\n') {
            continue;
        }
        size_t additional = 1;
        if (c == '\\' || c == '"' || c == '\n' || c == '\t') {
            additional = 2;
        } else if (c < 0x20 || c == 0x7f) {
            additional = 4;
        }
        if (additional > SIZE_MAX - total) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                                  "rust_lsp_macro_doc_comment_size", end - start);
            return false;
        }
        total += additional;
    }
    *escaped_len = total;
    return true;
}

static bool macro_lex_doc_comment(RustLSPContext *ctx, const char *source, size_t len, size_t *pos,
                                  MacroDocCommentKind kind, MacroToken **first, MacroToken **last) {
    size_t content_start = 0;
    size_t content_end = 0;
    size_t comment_end = 0;
    if (!macro_scan_doc_comment(ctx, source, len, *pos, kind, &content_start, &content_end,
                                &comment_end)) {
        return false;
    }
    size_t escaped_len = 0;
    if (!macro_doc_escaped_length(ctx, source, content_start, content_end, &escaped_len)) {
        return false;
    }
    bool inner = kind == MACRO_DOC_COMMENT_INNER_LINE || kind == MACRO_DOC_COMMENT_INNER_BLOCK;
    size_t fixed_len = inner ? 10 : 9; /* #![doc=""] or #[doc=""] */
    if (escaped_len > SIZE_MAX - fixed_len - 1 ||
        !macro_work(ctx, escaped_len + fixed_len, "rust_lsp_macro_doc_comment_desugar")) {
        if (!cbm_arena_failed(ctx->arena)) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                                  "rust_lsp_macro_doc_comment_size", escaped_len);
        }
        return false;
    }
    size_t synthetic_len = fixed_len + escaped_len;
    char *synthetic = (char *)cbm_arena_alloc(ctx->arena, synthetic_len + 1);
    if (!synthetic) {
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    size_t cursor = 0;
    synthetic[cursor++] = '#';
    if (inner) {
        synthetic[cursor++] = '!';
    }
    size_t group_start = cursor;
    synthetic[cursor++] = '[';
    size_t doc_start = cursor;
    memcpy(synthetic + cursor, "doc", 3);
    cursor += 3;
    size_t equals_start = cursor;
    synthetic[cursor++] = '=';
    size_t literal_start = cursor;
    synthetic[cursor++] = '"';
    for (size_t i = content_start; i < content_end; i++) {
        unsigned char c = (unsigned char)source[i];
        if (c == '\r' && i + 1 < content_end && source[i + 1] == '\n') {
            continue;
        }
        if (c == '\\' || c == '"') {
            synthetic[cursor++] = '\\';
            synthetic[cursor++] = (char)c;
        } else if (c == '\n') {
            synthetic[cursor++] = '\\';
            synthetic[cursor++] = 'n';
        } else if (c == '\t') {
            synthetic[cursor++] = '\\';
            synthetic[cursor++] = 't';
        } else if (c < 0x20 || c == 0x7f) {
            synthetic[cursor++] = '\\';
            synthetic[cursor++] = 'x';
            synthetic[cursor++] = hex[c >> 4];
            synthetic[cursor++] = hex[c & 0x0f];
        } else {
            synthetic[cursor++] = (char)c;
        }
    }
    synthetic[cursor++] = '"';
    size_t literal_end = cursor;
    synthetic[cursor++] = ']';
    synthetic[cursor] = '\0';
    if (cursor != synthetic_len) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_CORRUPT",
                              "rust_lsp_macro_doc_comment_layout", cursor);
        return false;
    }

    MacroToken *hash =
        (MacroToken *)macro_arena_zalloc(ctx, sizeof(*hash), "rust_lsp_macro_doc_hash_token");
    MacroToken *bang = inner ? (MacroToken *)macro_arena_zalloc(ctx, sizeof(*bang),
                                                                "rust_lsp_macro_doc_bang_token")
                             : NULL;
    MacroToken *group =
        (MacroToken *)macro_arena_zalloc(ctx, sizeof(*group), "rust_lsp_macro_doc_group_token");
    MacroToken *doc =
        (MacroToken *)macro_arena_zalloc(ctx, sizeof(*doc), "rust_lsp_macro_doc_name_token");
    MacroToken *equals =
        (MacroToken *)macro_arena_zalloc(ctx, sizeof(*equals), "rust_lsp_macro_doc_equals_token");
    MacroToken *literal =
        (MacroToken *)macro_arena_zalloc(ctx, sizeof(*literal), "rust_lsp_macro_doc_literal_token");
    if (!hash || (inner && !bang) || !group || !doc || !equals || !literal) {
        return false;
    }
    hash->text = synthetic;
    hash->len = 1;
    hash->desugared_doc_comment = true;
    if (inner) {
        hash->next = bang;
        bang->text = synthetic + 1;
        bang->len = 1;
        bang->next = group;
    } else {
        hash->next = group;
    }
    group->text = synthetic + group_start;
    group->len = synthetic_len - group_start;
    group->open = '[';
    group->close = ']';
    group->children = doc;
    doc->text = synthetic + doc_start;
    doc->len = 3;
    doc->next = equals;
    equals->text = synthetic + equals_start;
    equals->len = 1;
    equals->next = literal;
    literal->text = synthetic + literal_start;
    literal->len = literal_end - literal_start;
    *first = hash;
    *last = group;
    *pos = comment_end;
    return true;
}

static bool macro_token_text_is(const MacroToken *token, const char *text) {
    size_t len = strlen(text);
    return token && !token->open && token->len == len && memcmp(token->text, text, len) == 0;
}

static bool macro_identifier_start(unsigned char c) {
    return c == '_' || isalpha(c) || c >= 0x80;
}

static bool macro_identifier_continue(unsigned char c) {
    return c == '_' || isalnum(c) || c >= 0x80;
}

static bool macro_skip_trivia(RustLSPContext *ctx, const char *source, size_t len, size_t *pos) {
    while (*pos < len) {
        unsigned char c = (unsigned char)source[*pos];
        if (isspace(c)) {
            (*pos)++;
            continue;
        }
        if (c == '/' && *pos + 1 < len && source[*pos + 1] == '/') {
            if (macro_doc_comment_kind(source, len, *pos) != MACRO_DOC_COMMENT_NONE) {
                break;
            }
            *pos += 2;
            while (*pos < len && source[*pos] != '\n') {
                (*pos)++;
            }
            continue;
        }
        if (c == '/' && *pos + 1 < len && source[*pos + 1] == '*') {
            if (macro_doc_comment_kind(source, len, *pos) != MACRO_DOC_COMMENT_NONE) {
                break;
            }
            size_t depth = 1;
            *pos += 2;
            while (*pos < len && depth > 0) {
                if (*pos + 1 < len && source[*pos] == '/' && source[*pos + 1] == '*') {
                    depth++;
                    *pos += 2;
                } else if (*pos + 1 < len && source[*pos] == '*' && source[*pos + 1] == '/') {
                    depth--;
                    *pos += 2;
                } else {
                    (*pos)++;
                }
            }
            if (depth != 0) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                      "rust_lsp_macro_unterminated_comment", len);
                return false;
            }
            continue;
        }
        break;
    }
    return true;
}

static size_t macro_scan_literal_suffix(const char *source, size_t len, size_t pos) {
    if (pos >= len || !macro_identifier_start((unsigned char)source[pos])) {
        return pos;
    }
    pos++;
    while (pos < len && macro_identifier_continue((unsigned char)source[pos])) {
        pos++;
    }
    return pos;
}

static size_t macro_scan_quoted(const char *source, size_t len, size_t start, char quote) {
    size_t pos = start + 1;
    while (pos < len) {
        if (source[pos] == '\\' && pos + 1 < len) {
            pos += 2;
        } else if (source[pos] == quote) {
            return macro_scan_literal_suffix(source, len, pos + 1);
        } else {
            pos++;
        }
    }
    return start;
}

static size_t macro_scan_raw_string(const char *source, size_t len, size_t start) {
    size_t pos = start;
    if (pos < len && (source[pos] == 'b' || source[pos] == 'c')) {
        pos++;
    }
    if (pos >= len || source[pos] != 'r') {
        return start;
    }
    pos++;
    size_t hashes = 0;
    while (pos < len && source[pos] == '#') {
        hashes++;
        pos++;
    }
    if (pos >= len || source[pos] != '"') {
        return start;
    }
    pos++;
    while (pos < len) {
        if (source[pos] != '"') {
            pos++;
            continue;
        }
        size_t end = pos + 1;
        size_t seen = 0;
        while (end < len && seen < hashes && source[end] == '#') {
            seen++;
            end++;
        }
        if (seen == hashes) {
            return macro_scan_literal_suffix(source, len, end);
        }
        pos++;
    }
    return start;
}

static bool macro_hex_digit(unsigned char c, uint32_t *value) {
    if (c >= '0' && c <= '9') {
        *value = (uint32_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *value = (uint32_t)(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *value = (uint32_t)(c - 'A' + 10);
        return true;
    }
    return false;
}

static size_t macro_utf8_scalar_width(const char *source, size_t len, size_t start) {
    if (start >= len) {
        return 0;
    }
    unsigned char first = (unsigned char)source[start];
    if (first < 0x80) {
        return 1;
    }
    size_t width = 0;
    uint32_t value = 0;
    if (first >= 0xc2 && first <= 0xdf) {
        width = 2;
        value = (uint32_t)(first & 0x1f);
    } else if (first >= 0xe0 && first <= 0xef) {
        width = 3;
        value = (uint32_t)(first & 0x0f);
    } else if (first >= 0xf0 && first <= 0xf4) {
        width = 4;
        value = (uint32_t)(first & 0x07);
    } else {
        return 0;
    }
    if (width > len - start) {
        return 0;
    }
    for (size_t i = 1; i < width; i++) {
        unsigned char next = (unsigned char)source[start + i];
        if ((next & 0xc0) != 0x80) {
            return 0;
        }
        value = (value << 6) | (uint32_t)(next & 0x3f);
    }
    uint32_t minimum = width == 2 ? 0x80 : (width == 3 ? 0x800 : 0x10000);
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
        return 0;
    }
    return width;
}

static size_t macro_scan_lifetime(const char *source, size_t len, size_t start) {
    if (start >= len || source[start] != '\'' || start + 1 >= len) {
        return start;
    }
    size_t pos = start + 1;
    if (source[pos] == 'r' && pos + 2 < len && source[pos + 1] == '#' &&
        macro_identifier_start((unsigned char)source[pos + 2])) {
        pos += 3;
    } else {
        size_t first_width = macro_utf8_scalar_width(source, len, pos);
        if (first_width == 0 || (!macro_identifier_start((unsigned char)source[pos]) &&
                                 !isdigit((unsigned char)source[pos]))) {
            return start;
        }
        pos += first_width;
    }
    while (pos < len && macro_identifier_continue((unsigned char)source[pos])) {
        pos++;
    }
    /* A closing quote turns the complete span into a character-literal
     * candidate (`'a'`), never a lifetime followed by punctuation. */
    return pos < len && source[pos] == '\'' ? start : pos;
}

static size_t macro_scan_character_literal(const char *source, size_t len, size_t start,
                                           bool byte_literal) {
    if (start >= len || source[start] != '\'' || start + 1 >= len) {
        return start;
    }
    size_t pos = start + 1;
    unsigned char first = (unsigned char)source[pos];
    if (first == '\\') {
        if (pos + 1 >= len) {
            return start;
        }
        unsigned char escape = (unsigned char)source[pos + 1];
        if (escape == '\'' || escape == '"' || escape == 'n' || escape == 'r' || escape == 't' ||
            escape == '\\' || escape == '0') {
            pos += 2;
        } else if (escape == 'x') {
            uint32_t high = 0;
            uint32_t low = 0;
            if (pos + 3 >= len || !macro_hex_digit((unsigned char)source[pos + 2], &high) ||
                !macro_hex_digit((unsigned char)source[pos + 3], &low) ||
                (!byte_literal && high > 7)) {
                return start;
            }
            pos += 4;
        } else if (!byte_literal && escape == 'u') {
            if (pos + 2 >= len || source[pos + 2] != '{') {
                return start;
            }
            size_t cursor = pos + 3;
            uint32_t value = 0;
            size_t digits = 0;
            while (cursor < len && source[cursor] != '}') {
                if (source[cursor] == '_') {
                    if (digits == 0) {
                        return start;
                    }
                    cursor++;
                    continue;
                }
                uint32_t digit = 0;
                if (!macro_hex_digit((unsigned char)source[cursor], &digit) || digits == 6) {
                    return start;
                }
                value = (value << 4) | digit;
                digits++;
                cursor++;
            }
            if (cursor >= len || digits == 0 || value > 0x10ffff ||
                (value >= 0xd800 && value <= 0xdfff)) {
                return start;
            }
            pos = cursor + 1;
        } else {
            return start;
        }
    } else {
        size_t width = macro_utf8_scalar_width(source, len, pos);
        if (width == 0 || first == '\'' || first == '\n' || first == '\r' || first == '\t' ||
            (byte_literal && (width != 1 || first >= 0x80))) {
            return start;
        }
        pos += width;
    }
    if (pos >= len || source[pos] != '\'') {
        return start;
    }
    return macro_scan_literal_suffix(source, len, pos + 1);
}

static size_t macro_scan_leaf(const char *source, size_t len, size_t start) {
    static const char *const punctuation[] = {
        "<<=", ">>=", "...", "..=", "::", "=>", "->", "==", "!=", "<=", ">=", "&&",
        "||",  "+=",  "-=",  "*=",  "/=", "%=", "^=", "&=", "|=", "<<", ">>", "..",
    };
    size_t raw_end = macro_scan_raw_string(source, len, start);
    if (raw_end > start) {
        return raw_end;
    }
    size_t prefix = start;
    if (prefix + 1 < len && (source[prefix] == 'b' || source[prefix] == 'c') &&
        source[prefix + 1] == '"') {
        size_t end = macro_scan_quoted(source, len, prefix + 1, '"');
        return end > prefix + 1 ? end : start;
    }
    if (prefix + 1 < len && source[prefix] == 'b' && source[prefix + 1] == '\'') {
        size_t end = macro_scan_character_literal(source, len, prefix + 1, true);
        return end > prefix + 1 ? end : start;
    }
    if (source[start] == '"') {
        return macro_scan_quoted(source, len, start, '"');
    }
    if (source[start] == '\'') {
        size_t lifetime_end = macro_scan_lifetime(source, len, start);
        return lifetime_end > start ? lifetime_end
                                    : macro_scan_character_literal(source, len, start, false);
    }
    if (macro_identifier_start((unsigned char)source[start])) {
        size_t pos = start + 1;
        if (source[start] == 'r' && pos < len && source[pos] == '#' && pos + 1 < len &&
            macro_identifier_start((unsigned char)source[pos + 1])) {
            pos += 2;
        }
        while (pos < len && macro_identifier_continue((unsigned char)source[pos])) {
            pos++;
        }
        return pos;
    }
    if (isdigit((unsigned char)source[start])) {
        size_t pos = start + 1;
        while (pos < len) {
            unsigned char c = (unsigned char)source[pos];
            if (isalnum(c) || c == '_') {
                pos++;
            } else if (c == '.' && pos + 1 < len && source[pos + 1] != '.') {
                pos++;
            } else {
                break;
            }
        }
        return pos;
    }
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(punctuation[0]); i++) {
        size_t plen = strlen(punctuation[i]);
        if (start <= len && plen <= len - start &&
            memcmp(source + start, punctuation[i], plen) == 0) {
            return start + plen;
        }
    }
    return start + 1;
}

static bool macro_lex_list(RustLSPContext *ctx, const char *source, size_t len, size_t *pos,
                           char expected_close, MacroToken **out) {
    MacroToken *head = NULL;
    MacroToken **tail = &head;
    while (*pos < len) {
        if (!macro_skip_trivia(ctx, source, len, pos)) {
            return false;
        }
        if (*pos >= len) {
            break;
        }
        char c = source[*pos];
        if (c == ')' || c == ']' || c == '}') {
            if (c != expected_close) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                      "rust_lsp_macro_mismatched_delimiter", *pos);
                return false;
            }
            (*pos)++;
            *out = head;
            return true;
        }
        if (!macro_work(ctx, 1, "rust_lsp_macro_tokenize")) {
            return false;
        }
        MacroDocCommentKind doc_kind = macro_doc_comment_kind(source, len, *pos);
        if (doc_kind != MACRO_DOC_COMMENT_NONE) {
            MacroToken *doc_first = NULL;
            MacroToken *doc_last = NULL;
            if (!macro_lex_doc_comment(ctx, source, len, pos, doc_kind, &doc_first, &doc_last)) {
                return false;
            }
            *tail = doc_first;
            tail = &doc_last->next;
            continue;
        }
        MacroToken *token =
            (MacroToken *)macro_arena_zalloc(ctx, sizeof(*token), "rust_lsp_macro_token");
        if (!token) {
            return false;
        }
        size_t start = *pos;
        if (c == '(' || c == '[' || c == '{') {
            token->open = c;
            token->close = c == '(' ? ')' : (c == '[' ? ']' : '}');
            (*pos)++;
            if (!macro_lex_list(ctx, source, len, pos, token->close, &token->children)) {
                return false;
            }
            token->text = source + start;
            token->len = *pos - start;
        } else {
            size_t end = macro_scan_leaf(source, len, start);
            if (end <= start || end > len) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                                      "rust_lsp_macro_leaf", start);
                return false;
            }
            token->text = source + start;
            token->len = end - start;
            *pos = end;
        }
        *tail = token;
        tail = &token->next;
    }
    if (expected_close) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TOKEN_INVALID",
                              "rust_lsp_macro_unclosed_delimiter", len);
        return false;
    }
    *out = head;
    return true;
}

static bool macro_lex_raw(RustLSPContext *ctx, const char *source, size_t len, MacroToken **out) {
    size_t pos = 0;
    return macro_lex_list(ctx, source, len, &pos, 0, out) && pos == len;
}

static bool macro_tokens_have_desugared_doc_comment(const MacroToken *tokens) {
    for (const MacroToken *token = tokens; token; token = token->next) {
        if (token->desugared_doc_comment ||
            (token->open && macro_tokens_have_desugared_doc_comment(token->children))) {
            return true;
        }
    }
    return false;
}

static bool macro_canonical_length(RustLSPContext *ctx, const MacroToken *tokens, size_t *length) {
    size_t total = 0;
    bool first = true;
    for (const MacroToken *token = tokens; token; token = token->next) {
        size_t token_len = token->len;
        if (token->open) {
            size_t children_len = 0;
            if (!macro_canonical_length(ctx, token->children, &children_len) ||
                children_len > SIZE_MAX - 2) {
                if (!cbm_arena_failed(ctx->arena)) {
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                                          "rust_lsp_macro_canonical_token_tree", children_len);
                }
                return false;
            }
            token_len = children_len + 2;
        }
        size_t separator_len = first ? 0 : 1;
        if (separator_len > SIZE_MAX - total || token_len > SIZE_MAX - total - separator_len) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                                  "rust_lsp_macro_canonical_token_stream", token_len);
            return false;
        }
        total += separator_len + token_len;
        first = false;
    }
    *length = total;
    return true;
}

static void macro_canonical_write(const MacroToken *tokens, char *buffer, size_t *cursor) {
    bool first = true;
    for (const MacroToken *token = tokens; token; token = token->next) {
        if (!first) {
            buffer[(*cursor)++] = ' ';
        }
        if (token->open) {
            buffer[(*cursor)++] = token->open;
            macro_canonical_write(token->children, buffer, cursor);
            buffer[(*cursor)++] = token->close;
        } else if (token->len) {
            memcpy(buffer + *cursor, token->text, token->len);
            *cursor += token->len;
        }
        first = false;
    }
}

/* Doc comments are tokenized into arena-owned synthetic attributes.  A stream
 * containing both source-backed and synthetic token pointers cannot safely use
 * pointer subtraction for fragment captures or transcriber spans.  Canonicalize
 * that stream once and re-lex it so every token in the operation shares one
 * contiguous address domain.  Ordinary streams retain their exact source. */
static bool macro_lex(RustLSPContext *ctx, const char *source, size_t len, MacroToken **out,
                      const char **canonical_source, size_t *canonical_len) {
    MacroToken *tokens = NULL;
    if (!macro_lex_raw(ctx, source, len, &tokens)) {
        return false;
    }
    const char *selected_source = source;
    size_t selected_len = len;
    if (macro_tokens_have_desugared_doc_comment(tokens)) {
        size_t normalized_len = 0;
        if (!macro_canonical_length(ctx, tokens, &normalized_len) ||
            !macro_work(ctx, normalized_len ? normalized_len : 1,
                        "rust_lsp_macro_doc_comment_canonicalize")) {
            return false;
        }
        char *normalized = (char *)cbm_arena_alloc(ctx->arena, normalized_len + 1);
        if (!normalized) {
            return false;
        }
        size_t cursor = 0;
        macro_canonical_write(tokens, normalized, &cursor);
        if (cursor != normalized_len) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_CORRUPT",
                                  "rust_lsp_macro_canonical_token_layout", cursor);
            return false;
        }
        normalized[cursor] = '\0';
        if (!macro_lex_raw(ctx, normalized, normalized_len, &tokens) ||
            macro_tokens_have_desugared_doc_comment(tokens)) {
            if (!cbm_arena_failed(ctx->arena)) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_CORRUPT",
                                      "rust_lsp_macro_canonical_token_relex", normalized_len);
            }
            return false;
        }
        selected_source = normalized;
        selected_len = normalized_len;
    }
    *out = tokens;
    if (canonical_source) {
        *canonical_source = selected_source;
    }
    if (canonical_len) {
        *canonical_len = selected_len;
    }
    return true;
}

static bool macro_tokens_equal(const MacroToken *left, const MacroToken *right) {
    if (!left || !right || left->open != right->open || left->close != right->close) {
        return false;
    }
    if (!left->open) {
        return left->len == right->len && memcmp(left->text, right->text, left->len) == 0;
    }
    const MacroToken *lc = left->children;
    const MacroToken *rc = right->children;
    while (lc && rc) {
        if (!macro_tokens_equal(lc, rc)) {
            return false;
        }
        lc = lc->next;
        rc = rc->next;
    }
    return !lc && !rc;
}

static bool macro_name_equal(const MacroCapture *capture, const MacroToken *name) {
    return capture && name && !name->open && capture->name_len == name->len &&
           memcmp(capture->name, name->text, name->len) == 0;
}

static bool macro_binding_name_equal(const MacroBinding *binding, const MacroToken *name) {
    return binding && name && !name->open && binding->name_len == name->len &&
           memcmp(binding->name, name->text, name->len) == 0;
}

static const MacroNesting *macro_nesting_at_depth(const MacroNesting *nesting, size_t depth) {
    while (nesting && nesting->depth > depth) {
        nesting = nesting->parent;
    }
    return nesting && nesting->depth == depth ? nesting : NULL;
}

static const MacroRepeatShape *macro_shape_at_depth(const MacroRepeatShape *shape, size_t depth) {
    while (shape && shape->depth > depth) {
        shape = shape->parent;
    }
    return shape && shape->depth == depth ? shape : NULL;
}

static bool macro_nesting_equal(const MacroNesting *left, const MacroNesting *right) {
    size_t left_depth = left ? left->depth : 0;
    size_t right_depth = right ? right->depth : 0;
    if (left_depth != right_depth) {
        return false;
    }
    while (left && right) {
        if (left->repetition != right->repetition || left->iteration != right->iteration) {
            return false;
        }
        left = left->parent;
        right = right->parent;
    }
    return !left && !right;
}

static bool macro_shape_matches_nesting_prefix(const MacroRepeatShape *shape,
                                               const MacroNesting *nesting) {
    size_t nesting_depth = nesting ? nesting->depth : 0;
    size_t shape_depth = shape ? shape->depth : 0;
    if (nesting_depth > shape_depth) {
        return false;
    }
    for (size_t depth = 1; depth <= nesting_depth; depth++) {
        const MacroRepeatShape *shape_frame = macro_shape_at_depth(shape, depth);
        const MacroNesting *nesting_frame = macro_nesting_at_depth(nesting, depth);
        if (!shape_frame || !nesting_frame ||
            shape_frame->repetition != nesting_frame->repetition) {
            return false;
        }
    }
    return true;
}

static bool macro_shape_matches_nesting_exact(const MacroRepeatShape *shape,
                                              const MacroNesting *nesting) {
    size_t shape_depth = shape ? shape->depth : 0;
    size_t nesting_depth = nesting ? nesting->depth : 0;
    return shape_depth == nesting_depth && macro_shape_matches_nesting_prefix(shape, nesting);
}

static MacroBinding *macro_find_binding(const MacroEnv *env, const MacroToken *name) {
    for (MacroBinding *binding = env->bindings; binding; binding = binding->previous) {
        if (macro_binding_name_equal(binding, name)) {
            return binding;
        }
    }
    return NULL;
}

static MacroCapture *macro_find_capture(const MacroEnv *env, const MacroToken *name,
                                        const MacroNesting *nesting) {
    for (MacroCapture *capture = env->captures; capture; capture = capture->previous) {
        if (macro_name_equal(capture, name) && macro_nesting_equal(capture->nesting, nesting)) {
            return capture;
        }
    }
    return NULL;
}

static bool macro_nesting_coordinates_equal(const MacroNesting *left, const MacroNesting *right) {
    size_t left_depth = left ? left->depth : 0;
    size_t right_depth = right ? right->depth : 0;
    if (left_depth != right_depth) {
        return false;
    }
    while (left && right) {
        if (left->iteration != right->iteration) {
            return false;
        }
        left = left->parent;
        right = right->parent;
    }
    return !left && !right;
}

static MacroCapture *macro_find_capture_at_selection(const MacroEnv *env,
                                                     const MacroBinding *binding,
                                                     const MacroToken *name,
                                                     const MacroNesting *selection) {
    size_t binding_depth = binding && binding->shape ? binding->shape->depth : 0;
    size_t selection_depth = selection ? selection->depth : 0;
    if (!binding || binding_depth > selection_depth) {
        return NULL;
    }
    for (MacroCapture *capture = env->captures; capture; capture = capture->previous) {
        if (!macro_name_equal(capture, name)) {
            continue;
        }
        const MacroNesting *capture_frame = capture->nesting;
        bool matches = (capture_frame ? capture_frame->depth : 0) == binding_depth;
        for (size_t depth = binding_depth; matches && depth > 0; depth--) {
            const MacroRepeatShape *shape_frame = macro_shape_at_depth(binding->shape, depth);
            const MacroNesting *selection_frame = macro_nesting_at_depth(selection, depth);
            if (!shape_frame || !capture_frame || !selection_frame ||
                capture_frame->repetition != shape_frame->repetition ||
                capture_frame->iteration != selection_frame->iteration) {
                matches = false;
                break;
            }
            capture_frame = capture_frame->parent;
        }
        if (matches && !capture_frame) {
            return capture;
        }
    }
    return NULL;
}

static MacroCardinality *macro_find_cardinality(const MacroEnv *env, const MacroToken *repetition,
                                                const MacroNesting *parent) {
    for (MacroCardinality *cardinality = env->cardinalities; cardinality;
         cardinality = cardinality->previous) {
        if (cardinality->repetition == repetition &&
            macro_nesting_equal(cardinality->parent, parent)) {
            return cardinality;
        }
    }
    return NULL;
}

static MacroCardinality *macro_find_cardinality_at_selection(const MacroEnv *env,
                                                             const MacroToken *repetition,
                                                             const MacroNesting *selection) {
    for (MacroCardinality *cardinality = env->cardinalities; cardinality;
         cardinality = cardinality->previous) {
        if (cardinality->repetition == repetition &&
            macro_nesting_coordinates_equal(cardinality->parent, selection)) {
            return cardinality;
        }
    }
    return NULL;
}

static bool macro_record_cardinality(MacroEnv *env, const MacroToken *repetition,
                                     const MacroNesting *parent, size_t count) {
    if (macro_find_cardinality(env, repetition, parent)) {
        cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_DUPLICATE_BINDING",
                              "rust_lsp_macro_repetition_cardinality", count);
        return false;
    }
    MacroCardinality *cardinality = (MacroCardinality *)macro_arena_zalloc(
        env->ctx, sizeof(*cardinality), "rust_lsp_macro_cardinality");
    if (!cardinality) {
        return false;
    }
    cardinality->repetition = repetition;
    cardinality->parent = parent;
    cardinality->count = count;
    cardinality->previous = env->cardinalities;
    env->cardinalities = cardinality;
    return true;
}

static bool macro_bind_capture(MacroEnv *env, const MacroToken *name, const char *value,
                               size_t value_len, const MacroNesting *nesting) {
    if (!name || name->open || name->len == 0) {
        cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                              "rust_lsp_macro_empty_metavariable", 0);
        return false;
    }
    MacroBinding *binding = macro_find_binding(env, name);
    if (!binding || !macro_shape_matches_nesting_exact(binding->shape, nesting)) {
        cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_DUPLICATE_BINDING",
                              "rust_lsp_macro_matcher_nesting", name->len);
        return false;
    }
    if (macro_find_capture(env, name, nesting)) {
        cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_DUPLICATE_BINDING",
                              "rust_lsp_macro_matcher_binding", name->len);
        return false;
    }
    MacroCapture *capture =
        (MacroCapture *)macro_arena_zalloc(env->ctx, sizeof(*capture), "rust_lsp_macro_capture");
    if (!capture) {
        return false;
    }
    capture->name = name->text;
    capture->name_len = name->len;
    capture->value = value;
    capture->value_len = value_len;
    capture->nesting = nesting;
    capture->previous = env->captures;
    env->captures = capture;
    return true;
}

static bool macro_is_fragment(const MacroToken *fragment, const char *name) {
    return macro_token_text_is(fragment, name);
}

static bool macro_fragment_supported(const MacroToken *fragment) {
    static const char *const supported[] = {
        "block", "expr",      "expr_2021", "ident", "item", "lifetime", "literal", "meta",
        "pat",   "pat_param", "path",      "stmt",  "tt",   "ty",       "vis",
    };
    for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
        if (macro_is_fragment(fragment, supported[i])) {
            return true;
        }
    }
    return false;
}

static bool macro_token_is_identifier(const MacroToken *token) {
    if (!token || token->open || token->len == 0) {
        return false;
    }
    size_t pos = 0;
    if (token->len > 2 && token->text[0] == 'r' && token->text[1] == '#') {
        pos = 2;
    }
    if (pos >= token->len || !macro_identifier_start((unsigned char)token->text[pos])) {
        return false;
    }
    for (pos++; pos < token->len; pos++) {
        if (!macro_identifier_continue((unsigned char)token->text[pos])) {
            return false;
        }
    }
    return true;
}

static bool macro_token_is_lifetime(const MacroToken *token) {
    return token && !token->open && token->len > 1 &&
           macro_scan_lifetime(token->text, token->len, 0) == token->len;
}

static bool macro_token_is_literal(const MacroToken *token) {
    if (!token || token->open || token->len == 0) {
        return false;
    }
    unsigned char first = (unsigned char)token->text[0];
    bool byte_quoted = token->len > 1 && first == 'b' && token->text[1] == '\'' &&
                       macro_scan_character_literal(token->text, token->len, 1, true) == token->len;
    bool prefixed_string = token->len > 1 && (first == 'b' || first == 'c') &&
                           ((token->text[1] == '"' &&
                             macro_scan_quoted(token->text, token->len, 1, '"') == token->len) ||
                            macro_scan_raw_string(token->text, token->len, 0) == token->len);
    bool raw_quoted =
        first == 'r' && macro_scan_raw_string(token->text, token->len, 0) == token->len;
    bool quoted = first == '"' && macro_scan_quoted(token->text, token->len, 0, '"') == token->len;
    bool character = first == '\'' &&
                     macro_scan_character_literal(token->text, token->len, 0, false) == token->len;
    return isdigit(first) || quoted || character || byte_quoted || prefixed_string || raw_quoted ||
           macro_token_text_is(token, "true") || macro_token_text_is(token, "false");
}

static bool macro_node_is_comment(TSNode node) {
    const char *type = ts_node_type(node);
    return strcmp(type, "line_comment") == 0 || strcmp(type, "block_comment") == 0;
}

static bool macro_node_type_is(TSNode node, const char *type) {
    return !ts_node_is_null(node) && strcmp(ts_node_type(node), type) == 0;
}

static uint32_t macro_semantic_child_count(TSNode node) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        if (!macro_node_is_comment(ts_node_named_child(node, i)))
            count++;
    }
    return count;
}

static TSNode macro_semantic_child(TSNode node, uint32_t wanted) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode child = ts_node_named_child(node, i);
        if (macro_node_is_comment(child))
            continue;
        if (count == wanted)
            return child;
        count++;
    }
    return (TSNode){0};
}

static bool macro_node_spans(TSNode node, size_t start, size_t end) {
    return !ts_node_is_null(node) && ts_node_start_byte(node) == start &&
           ts_node_end_byte(node) == end;
}

static int macro_active_edition(const MacroEnv *env);

static bool macro_keyword_text_is(const char *text, size_t len, const char *keyword) {
    size_t keyword_len = strlen(keyword);
    return len == keyword_len && memcmp(text, keyword, len) == 0;
}

static bool macro_keyword_text_in(const char *text, size_t len, const char *const *keywords,
                                  size_t keyword_count) {
    for (size_t i = 0; i < keyword_count; i++) {
        if (macro_keyword_text_is(text, len, keywords[i]))
            return true;
    }
    return false;
}

/* tree-sitter-rust intentionally uses context-aware lexing. In a state that
 * accepts an identifier it can consequently alias a strict Rust keyword to an
 * `identifier` node (for example the compiler-invalid expression `let`). Tree
 * shape and exact byte bounds remain necessary, but are not sufficient to prove
 * Rust's NON_KEYWORD_IDENTIFIER lexical production. Enforce that production
 * over every identifier-like leaf inside the candidate span. The `ident` macro
 * fragment does not call this parser path: per the Rust Reference it accepts
 * IDENTIFIER_OR_KEYWORD (except `_`), which is deliberately broader. */
static bool macro_identifier_keyword_allowed(MacroEnv *env, const char *text, size_t len) {
    static const char *const all_edition_keywords[] = {
        "as",       "break",  "const",    "continue", "crate",   "else",  "enum",   "extern",
        "false",    "fn",     "for",      "if",       "impl",    "in",    "let",    "loop",
        "match",    "mod",    "move",     "mut",      "pub",     "ref",   "return", "self",
        "static",   "struct", "super",    "trait",    "true",    "type",  "unsafe", "use",
        "where",    "while",  "abstract", "become",   "box",     "do",    "final",  "macro",
        "override", "priv",   "typeof",   "unsized",  "virtual", "yield",
    };
    static const char *const edition_2018_keywords[] = {"async", "await", "dyn", "try"};

    if (len > 2 && text[0] == 'r' && text[1] == '#') {
        const char *raw = text + 2;
        size_t raw_len = len - 2;
        return !(macro_keyword_text_is(raw, raw_len, "_") ||
                 macro_keyword_text_is(raw, raw_len, "crate") ||
                 macro_keyword_text_is(raw, raw_len, "self") ||
                 macro_keyword_text_is(raw, raw_len, "Self") ||
                 macro_keyword_text_is(raw, raw_len, "super"));
    }

    /* `Self` is a strict keyword, but is also a valid type/value path and
     * constructor-pattern head. The grammar owns those contextual shapes. */
    if (macro_keyword_text_is(text, len, "Self"))
        return true;
    if (macro_keyword_text_in(text, len, all_edition_keywords,
                              sizeof(all_edition_keywords) / sizeof(all_edition_keywords[0]))) {
        return false;
    }

    int edition = macro_active_edition(env);
    int required_edition = 0;
    if (macro_keyword_text_in(text, len, edition_2018_keywords,
                              sizeof(edition_2018_keywords) / sizeof(edition_2018_keywords[0]))) {
        required_edition = 2018;
    } else if (macro_keyword_text_is(text, len, "gen")) {
        required_edition = 2024;
    } else {
        return true;
    }
    if (edition != 0)
        return edition < required_edition;

    fprintf(stderr,
            "ERROR level=error msg=rust_macro.edition_unknown "
            "code=CBM_RUST_MACRO_EDITION_UNKNOWN macro=%s invocation_byte=%u "
            "keyword=%.*s required_edition=%d\n",
            env->macro_name ? env->macro_name : "none", env->invocation_byte, (int)len, text,
            required_edition);
    cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_EDITION_UNKNOWN",
                          "rust_lsp_macro_keyword_edition", len);
    return false;
}

/* A lifetime has a different lexical contract from an ordinary identifier.
 * In particular, `'static` and `'_` are explicit Lifetime productions, while
 * raw lifetimes admit keywords but exclude a small reserved set and require
 * Rust 2021 or later.  Validate the complete lifetime token here so the
 * context-aware grammar's identifier child is never reclassified as a
 * standalone NON_KEYWORD_IDENTIFIER. */
static bool macro_lifetime_keyword_allowed(MacroEnv *env, const char *text, size_t len) {
    MacroToken token = {.text = text, .len = len};
    if (!macro_token_is_lifetime(&token) || len < 2) {
        return false;
    }

    const char *name = text + 1;
    size_t name_len = len - 1;
    if (macro_keyword_text_is(name, name_len, "static") ||
        macro_keyword_text_is(name, name_len, "_")) {
        return true;
    }

    if (name_len > 2 && name[0] == 'r' && name[1] == '#') {
        int edition = macro_active_edition(env);
        if (edition == 0) {
            fprintf(stderr,
                    "ERROR level=error msg=rust_macro.edition_unknown "
                    "code=CBM_RUST_MACRO_EDITION_UNKNOWN macro=%s invocation_byte=%u "
                    "lifetime=%.*s required_edition=2021\n",
                    env->macro_name ? env->macro_name : "none", env->invocation_byte, (int)len,
                    text);
            cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_EDITION_UNKNOWN",
                                  "rust_lsp_macro_lifetime_edition", len);
            return false;
        }
        return edition >= 2021 && macro_identifier_keyword_allowed(env, name, name_len);
    }

    /* `Self` is grammar-owned in type/value paths, but it is not a legal
     * non-raw lifetime name. */
    return !macro_keyword_text_is(name, name_len, "Self") &&
           macro_identifier_keyword_allowed(env, name, name_len);
}

static bool macro_fragment_identifiers_valid(MacroEnv *env, TSNode root, const char *wrapped,
                                             size_t candidate_start, size_t candidate_end) {
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    bool valid = true;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        size_t node_start = ts_node_start_byte(node);
        size_t node_end = ts_node_end_byte(node);
        bool overlaps = node_end > candidate_start && node_start < candidate_end;
        if (!macro_work(env->ctx, 1, "rust_lsp_macro_fragment_keyword_validation")) {
            valid = false;
            break;
        }
        const char *type = ts_node_type(node);
        bool wholly_inside = overlaps && node_start >= candidate_start && node_end <= candidate_end;
        if (wholly_inside && strcmp(type, "lifetime") == 0 &&
            !macro_lifetime_keyword_allowed(env, wrapped + node_start, node_end - node_start)) {
            valid = false;
            break;
        }
        if (wholly_inside && ts_node_is_named(node) && strstr(type, "identifier") != NULL) {
            TSNode parent = ts_node_parent(node);
            bool lifetime_child =
                !ts_node_is_null(parent) && strcmp(ts_node_type(parent), "lifetime") == 0;
            if (!lifetime_child && !macro_identifier_keyword_allowed(
                                       env, wrapped + node_start, node_end - node_start)) {
                valid = false;
                break;
            }
        }
        if (overlaps && ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor))
                goto complete;
        }
    }

complete:
    ts_tree_cursor_delete(&cursor);
    return valid;
}

static bool macro_parse_wrapped(MacroEnv *env, const char *prefix, const char *value,
                                size_t value_len, const char *suffix, TSTree **out_tree,
                                TSNode *out_root, size_t *out_start, size_t *out_end) {
    RustLSPContext *ctx = env->ctx;
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    if (value_len > UINT32_MAX - prefix_len - suffix_len || value_len > (size_t)INT_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_FRAGMENT_OVERFLOW",
                              "rust_lsp_macro_fragment_length", value_len);
        return false;
    }
    if (!macro_work(ctx, value_len + 1, "rust_lsp_macro_fragment_parse"))
        return false;
    char *wrapped =
        cbm_arena_sprintf(ctx->arena, "%s%.*s%s", prefix, (int)value_len, value, suffix);
    if (!wrapped || cbm_arena_failed(ctx->arena))
        return false;
    size_t wrapped_len = prefix_len + value_len + suffix_len;
    TSTree *tree =
        ts_parser_parse_string(env->fragment_parser, NULL, wrapped, (uint32_t)wrapped_len);
    if (!tree) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_FRAGMENT_PARSE_FAILED",
                              "rust_lsp_macro_fragment_parser", value_len);
        return false;
    }
    TSNode root = ts_tree_root_node(tree);
    if (!ts_node_has_error(root) &&
        !macro_fragment_identifiers_valid(env, root, wrapped, prefix_len, prefix_len + value_len)) {
        ts_tree_delete(tree);
        return false;
    }
    *out_tree = tree;
    *out_root = root;
    *out_start = prefix_len;
    *out_end = prefix_len + value_len;
    return true;
}

static TSNode macro_wrapped_function_body(TSNode root) {
    if (macro_semantic_child_count(root) != 1)
        return (TSNode){0};
    TSNode function = macro_semantic_child(root, 0);
    if (!macro_node_type_is(function, "function_item"))
        return (TSNode){0};
    return ts_node_child_by_field_name(function, "body", 4);
}

static bool macro_node_is_literal(TSNode node) {
    const char *type = ts_node_type(node);
    return strcmp(type, "string_literal") == 0 || strcmp(type, "raw_string_literal") == 0 ||
           strcmp(type, "char_literal") == 0 || strcmp(type, "boolean_literal") == 0 ||
           strcmp(type, "integer_literal") == 0 || strcmp(type, "float_literal") == 0;
}

static bool macro_node_is_literal_fragment(TSNode node) {
    if (macro_node_is_literal(node))
        return true;
    if (strcmp(ts_node_type(node), "unary_expression") != 0 || ts_node_child_count(node) < 2 ||
        ts_node_named_child_count(node) != 1) {
        return false;
    }
    TSNode sign = ts_node_child(node, 0);
    return strcmp(ts_node_type(sign), "-") == 0 &&
           macro_node_is_literal(ts_node_named_child(node, 0));
}

static bool macro_node_is_type_path(TSNode node) {
    const char *type = ts_node_type(node);
    return strcmp(type, "type_identifier") == 0 || strcmp(type, "scoped_type_identifier") == 0 ||
           strcmp(type, "generic_type") == 0 || strcmp(type, "primitive_type") == 0;
}

static bool macro_node_is_item(TSNode node) {
    static const char *const item_types[] = {
        "const_item",
        "macro_invocation",
        "macro_definition",
        "mod_item",
        "foreign_mod_item",
        "struct_item",
        "union_item",
        "enum_item",
        "type_item",
        "function_item",
        "function_signature_item",
        "impl_item",
        "trait_item",
        "associated_type",
        "use_declaration",
        "extern_crate_declaration",
        "static_item",
    };
    const char *type = ts_node_type(node);
    for (size_t i = 0; i < sizeof(item_types) / sizeof(item_types[0]); i++) {
        if (strcmp(type, item_types[i]) == 0)
            return true;
    }
    return false;
}

static bool macro_item_sequence_exact(TSNode container, size_t start, size_t end) {
    uint32_t count = macro_semantic_child_count(container);
    if (count == 0)
        return false;
    uint32_t cursor = 0;
    TSNode first = macro_semantic_child(container, 0);
    while (cursor < count &&
           strcmp(ts_node_type(macro_semantic_child(container, cursor)), "attribute_item") == 0) {
        cursor++;
    }
    if (cursor >= count)
        return false;
    TSNode item = macro_semantic_child(container, cursor++);
    if (!macro_node_is_item(item))
        return false;
    TSNode last = item;
    if (cursor < count && strcmp(ts_node_type(item), "macro_invocation") == 0 &&
        strcmp(ts_node_type(macro_semantic_child(container, cursor)), "empty_statement") == 0) {
        last = macro_semantic_child(container, cursor++);
    }
    return cursor == count && !ts_node_is_null(first) && ts_node_start_byte(first) == start &&
           ts_node_end_byte(last) == end;
}

static int macro_active_edition(const MacroEnv *env) {
    if (!env || !env->ctx || !env->ctx->cargo_manifest)
        return 0;
    const CBMCargoManifest *manifest = (const CBMCargoManifest *)env->ctx->cargo_manifest;
    const char *edition = manifest->active_edition;
    if (!edition)
        return 0;
    if (strcmp(edition, "2015") == 0)
        return 2015;
    if (strcmp(edition, "2018") == 0)
        return 2018;
    if (strcmp(edition, "2021") == 0)
        return 2021;
    if (strcmp(edition, "2024") == 0)
        return 2024;
    return 0;
}

static bool macro_require_edition(MacroEnv *env, int minimum, const MacroToken *fragment,
                                  size_t value_len) {
    int edition = macro_active_edition(env);
    if (edition != 0)
        return edition >= minimum;
    fprintf(stderr,
            "ERROR level=error msg=rust_macro.edition_unknown "
            "code=CBM_RUST_MACRO_EDITION_UNKNOWN macro=%s invocation_byte=%u "
            "fragment=%.*s candidate_bytes=%zu required_edition=%d\n",
            env->macro_name ? env->macro_name : "none", env->invocation_byte, (int)fragment->len,
            fragment->text, value_len, minimum);
    cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_EDITION_UNKNOWN",
                          "rust_lsp_macro_fragment_edition", value_len);
    return false;
}

static bool macro_parse_expression_fragment(MacroEnv *env, const MacroToken *fragment,
                                            const char *value, size_t value_len, TSNode *out_value,
                                            TSTree **out_tree) {
    TSTree *tree = NULL;
    TSNode root = {0};
    size_t start = 0;
    size_t end = 0;
    if (!macro_parse_wrapped(env, "fn __cbm_fragment(){let __cbm_fragment_value=", value, value_len,
                             ";}", &tree, &root, &start, &end)) {
        return false;
    }
    TSNode body = macro_wrapped_function_body(root);
    TSNode declaration =
        macro_semantic_child_count(body) == 1 ? macro_semantic_child(body, 0) : (TSNode){0};
    TSNode parsed = ts_node_is_null(declaration)
                        ? (TSNode){0}
                        : ts_node_child_by_field_name(declaration, "value", 5);
    bool exact = !ts_node_has_error(root) && macro_node_type_is(declaration, "let_declaration") &&
                 macro_node_spans(parsed, start, end);
    if (exact && strcmp(ts_node_type(parsed), "const_block") == 0) {
        if (macro_is_fragment(fragment, "expr_2021")) {
            exact = false;
        } else {
            exact = macro_require_edition(env, 2024, fragment, value_len);
        }
    }
    if (!exact || cbm_arena_failed(env->ctx->arena)) {
        ts_tree_delete(tree);
        return false;
    }
    *out_value = parsed;
    *out_tree = tree;
    return true;
}

static bool macro_parse_type_fragment(MacroEnv *env, const char *value, size_t value_len,
                                      TSNode *out_type, TSTree **out_tree) {
    TSTree *tree = NULL;
    TSNode root = {0};
    size_t start = 0;
    size_t end = 0;
    if (!macro_parse_wrapped(env, "type __CbmFragment=", value, value_len, ";", &tree, &root,
                             &start, &end)) {
        return false;
    }
    TSNode item =
        macro_semantic_child_count(root) == 1 ? macro_semantic_child(root, 0) : (TSNode){0};
    TSNode parsed =
        ts_node_is_null(item) ? (TSNode){0} : ts_node_child_by_field_name(item, "type", 4);
    bool exact = !ts_node_has_error(root) && macro_node_type_is(item, "type_item") &&
                 macro_node_spans(parsed, start, end);
    if (!exact) {
        ts_tree_delete(tree);
        return false;
    }
    *out_type = parsed;
    *out_tree = tree;
    return true;
}

static bool macro_parse_pattern_fragment(MacroEnv *env, const MacroToken *fragment,
                                         const char *value, size_t value_len) {
    TSTree *tree = NULL;
    TSNode root = {0};
    size_t start = 0;
    size_t end = 0;
    if (!macro_parse_wrapped(env, "fn __cbm_fragment(){let ", value, value_len, "=();}", &tree,
                             &root, &start, &end)) {
        return false;
    }
    TSNode body = macro_wrapped_function_body(root);
    TSNode declaration =
        macro_semantic_child_count(body) == 1 ? macro_semantic_child(body, 0) : (TSNode){0};
    TSNode pattern = ts_node_is_null(declaration)
                         ? (TSNode){0}
                         : ts_node_child_by_field_name(declaration, "pattern", 7);
    bool exact = !ts_node_has_error(root) && macro_node_type_is(declaration, "let_declaration") &&
                 macro_node_spans(pattern, start, end);
    if (exact && strcmp(ts_node_type(pattern), "or_pattern") == 0) {
        if (macro_is_fragment(fragment, "pat_param")) {
            exact = false;
        } else {
            exact = macro_require_edition(env, 2021, fragment, value_len);
        }
    }
    ts_tree_delete(tree);
    return exact && !cbm_arena_failed(env->ctx->arena);
}

static bool macro_value_ends_with_semicolon(const char *value, size_t value_len) {
    while (value_len > 0 && isspace((unsigned char)value[value_len - 1]))
        value_len--;
    return value_len > 0 && value[value_len - 1] == ';';
}

static bool macro_parse_statement_fragment(MacroEnv *env, const char *value, size_t value_len) {
    static const char *const prefix = "fn __cbm_fragment(){";
    TSTree *tree = NULL;
    TSNode root = {0};
    size_t start = 0;
    size_t end = 0;
    if (!macro_parse_wrapped(env, prefix, value, value_len, "}", &tree, &root, &start, &end)) {
        return false;
    }
    TSNode body = macro_wrapped_function_body(root);
    bool exact = false;
    uint32_t count = macro_semantic_child_count(body);
    if (!ts_node_has_error(root) && count == 1) {
        TSNode statement = macro_semantic_child(body, 0);
        const char *type = ts_node_type(statement);
        exact = macro_node_spans(statement, start, end);
        if (exact &&
            (strcmp(type, "let_declaration") == 0 || strcmp(type, "expression_statement") == 0) &&
            macro_value_ends_with_semicolon(value, value_len)) {
            exact = false;
        }
    } else if (!ts_node_has_error(root) && count == 2) {
        exact = macro_item_sequence_exact(body, start, end);
    }
    ts_tree_delete(tree);
    if (exact)
        return true;

    if (!macro_parse_wrapped(env, prefix, value, value_len, ";}", &tree, &root, &start, &end)) {
        return false;
    }
    body = macro_wrapped_function_body(root);
    TSNode statement =
        macro_semantic_child_count(body) == 1 ? macro_semantic_child(body, 0) : (TSNode){0};
    const char *type = ts_node_is_null(statement) ? "" : ts_node_type(statement);
    exact = !ts_node_has_error(root) &&
            (strcmp(type, "let_declaration") == 0 || strcmp(type, "expression_statement") == 0) &&
            macro_node_spans(statement, start, end + 1) &&
            !macro_value_ends_with_semicolon(value, value_len);
    ts_tree_delete(tree);
    return exact;
}

static bool macro_fragment_parse_uncached(MacroEnv *env, const MacroToken *fragment,
                                          const char *value, size_t value_len) {
    RustLSPContext *ctx = env->ctx;
    if (!macro_fragment_supported(fragment)) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_FRAGMENT_UNSUPPORTED",
                              "rust_lsp_macro_fragment", fragment ? fragment->len : 0);
        return false;
    }
    if (value_len > (size_t)INT_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_FRAGMENT_OVERFLOW",
                              "rust_lsp_macro_fragment_length", value_len);
        return false;
    }
    if (macro_is_fragment(fragment, "vis") && value_len == 0)
        return true;
    if (macro_is_fragment(fragment, "tt"))
        return value_len > 0;
    if (macro_is_fragment(fragment, "ident")) {
        MacroToken token = {.text = value, .len = value_len};
        return !(value_len == 1 && value[0] == '_') && macro_token_is_identifier(&token);
    }
    if (macro_is_fragment(fragment, "lifetime")) {
        MacroToken token = {.text = value, .len = value_len};
        return macro_token_is_lifetime(&token);
    }
    if ((macro_is_fragment(fragment, "expr") || macro_is_fragment(fragment, "expr_2021")) &&
        value_len == 1 && value[0] == '_') {
        return !macro_is_fragment(fragment, "expr_2021") &&
               macro_require_edition(env, 2024, fragment, value_len);
    }
    if (macro_is_fragment(fragment, "expr") || macro_is_fragment(fragment, "expr_2021") ||
        macro_is_fragment(fragment, "literal") || macro_is_fragment(fragment, "block")) {
        TSNode parsed = {0};
        TSTree *tree = NULL;
        if (!macro_parse_expression_fragment(env, fragment, value, value_len, &parsed, &tree)) {
            return false;
        }
        bool exact = true;
        if (macro_is_fragment(fragment, "literal")) {
            exact = macro_node_is_literal_fragment(parsed);
        } else if (macro_is_fragment(fragment, "block")) {
            exact = strcmp(ts_node_type(parsed), "block") == 0;
        }
        ts_tree_delete(tree);
        return exact;
    }
    if (macro_is_fragment(fragment, "ty") || macro_is_fragment(fragment, "path")) {
        TSNode parsed = {0};
        TSTree *tree = NULL;
        if (!macro_parse_type_fragment(env, value, value_len, &parsed, &tree))
            return false;
        bool exact = !macro_is_fragment(fragment, "path") || macro_node_is_type_path(parsed);
        ts_tree_delete(tree);
        return exact;
    }
    if (macro_is_fragment(fragment, "pat") || macro_is_fragment(fragment, "pat_param")) {
        return macro_parse_pattern_fragment(env, fragment, value, value_len);
    }
    if (macro_is_fragment(fragment, "stmt")) {
        return macro_parse_statement_fragment(env, value, value_len);
    }

    const char *prefix = "";
    const char *suffix = "";
    if (macro_is_fragment(fragment, "meta")) {
        prefix = "#[";
        suffix = "] fn __cbm_fragment(){}";
    } else if (macro_is_fragment(fragment, "vis")) {
        suffix = " fn __cbm_fragment(){}";
    }
    TSTree *tree = NULL;
    TSNode root = {0};
    size_t start = 0;
    size_t end = 0;
    if (!macro_parse_wrapped(env, prefix, value, value_len, suffix, &tree, &root, &start, &end)) {
        return false;
    }
    bool exact = !ts_node_has_error(root);
    if (exact && macro_is_fragment(fragment, "item")) {
        exact = macro_item_sequence_exact(root, start, end);
    } else if (exact && macro_is_fragment(fragment, "meta")) {
        TSNode attribute_item =
            macro_semantic_child_count(root) == 2 ? macro_semantic_child(root, 0) : (TSNode){0};
        TSNode attribute = ts_node_is_null(attribute_item) ||
                                   strcmp(ts_node_type(attribute_item), "attribute_item") != 0
                               ? (TSNode){0}
                               : macro_semantic_child(attribute_item, 0);
        exact =
            macro_node_type_is(attribute, "attribute") && macro_node_spans(attribute, start, end);
    } else if (exact && macro_is_fragment(fragment, "vis")) {
        TSNode function =
            macro_semantic_child_count(root) == 1 ? macro_semantic_child(root, 0) : (TSNode){0};
        TSNode visibility = macro_semantic_child(function, 0);
        exact = macro_node_type_is(function, "function_item") &&
                macro_node_type_is(visibility, "visibility_modifier") &&
                macro_node_spans(visibility, start, end);
    }
    ts_tree_delete(tree);
    return exact;
}

static size_t macro_size_saturating_add(size_t left, size_t right) {
    return right > SIZE_MAX - left ? SIZE_MAX : left + right;
}

static bool macro_fragment_candidate_offset(const MacroEnv *env, const char *value,
                                            size_t value_len, size_t *offset) {
    if (!env || !env->input_text || !value) {
        return false;
    }
    uintptr_t base = (uintptr_t)env->input_text;
    uintptr_t candidate = (uintptr_t)value;
    if (candidate < base) {
        return false;
    }
    uintptr_t distance = candidate - base;
    size_t start = (size_t)distance;
    if (start > env->input_len || value_len > env->input_len - start) {
        return false;
    }
    *offset = start;
    return true;
}

static void macro_log_fragment_parse_work(MacroEnv *env, const char *outcome) {
    if (!env || env->fragment_parse_failure_logged || env->fragment_parse_count == 0 ||
        (env->fragment_parse_count < 64 && strcmp(outcome, "fatal") != 0)) {
        return;
    }
    CBMArena *arena = env->ctx ? env->ctx->arena : NULL;
    const char *code = arena && cbm_arena_failed(arena) ? cbm_arena_failure_code(arena) : "none";
    const char *operation =
        arena && cbm_arena_failed(arena) ? cbm_arena_failure_operation(arena) : "none";
    fprintf(stderr,
            "INFO level=info msg=rust_macro.fragment_parse_work outcome=%s code=%s operation=%s "
            "macro=%s invocation_byte=%u invocation_bytes=%zu parse_count=%zu "
            "parsed_candidate_bytes=%zu largest_candidate_bytes=%zu "
            "largest_candidate_in_invocation=%s largest_candidate_start_byte=%zu "
            "largest_candidate_fragment=%.*s furthest_input_byte=%zu furthest_matcher_byte=%zu "
            "furthest_candidate_start_byte=%zu furthest_candidate_end_byte=%zu "
            "furthest_candidate_fragment=%.*s\n",
            outcome, code ? code : "none", operation ? operation : "none",
            env->macro_name ? env->macro_name : "none", env->invocation_byte, env->input_len,
            env->fragment_parse_count, env->fragment_parse_bytes,
            env->fragment_parse_largest_bytes,
            env->fragment_parse_largest_in_invocation ? "true" : "false",
            env->fragment_parse_largest_start_byte, (int)env->fragment_parse_largest_fragment_len,
            env->fragment_parse_largest_fragment ? env->fragment_parse_largest_fragment : "",
            env->furthest_input_byte, env->furthest_matcher_byte, env->candidate_start_byte,
            env->candidate_end_byte, (int)env->candidate_fragment_len,
            env->candidate_fragment ? env->candidate_fragment : "");
    if (arena && cbm_arena_failed(arena)) {
        env->fragment_parse_failure_logged = true;
    }
}

static bool macro_fragment_uses_parser(const MacroToken *fragment, const char *value,
                                       size_t value_len) {
    if ((macro_is_fragment(fragment, "vis") && value_len == 0) ||
        macro_is_fragment(fragment, "tt") || macro_is_fragment(fragment, "ident") ||
        macro_is_fragment(fragment, "lifetime")) {
        return false;
    }
    return !((macro_is_fragment(fragment, "expr") || macro_is_fragment(fragment, "expr_2021")) &&
             value_len == 1 && value[0] == '_');
}

static bool macro_fragment_parse_clean(MacroEnv *env, const MacroToken *fragment,
                                       const char *value, size_t value_len) {
    if (!macro_fragment_uses_parser(fragment, value, value_len)) {
        return macro_fragment_parse_uncached(env, fragment, value, value_len);
    }
    env->fragment_parse_count++;
    env->fragment_parse_bytes = macro_size_saturating_add(env->fragment_parse_bytes, value_len);
    if (value_len > env->fragment_parse_largest_bytes) {
        size_t start = 0;
        env->fragment_parse_largest_bytes = value_len;
        env->fragment_parse_largest_in_invocation =
            macro_fragment_candidate_offset(env, value, value_len, &start);
        env->fragment_parse_largest_start_byte = start;
        env->fragment_parse_largest_fragment = fragment->text;
        env->fragment_parse_largest_fragment_len = fragment->len;
    }
    bool exact = macro_fragment_parse_uncached(env, fragment, value, value_len);
    if (cbm_arena_failed(env->ctx->arena)) {
        macro_log_fragment_parse_work(env, "fatal");
        return false;
    }
    return exact;
}

static const char *macro_capture_start(const MacroToken *first) {
    return first ? first->text : "";
}

static size_t macro_capture_length(const MacroToken *first, const MacroToken *last) {
    if (!first || !last) {
        return 0;
    }
    return (size_t)((last->text + last->len) - first->text);
}

static size_t macro_text_offset(const char *base, size_t len, const char *text,
                                size_t absent_offset) {
    if (!text)
        return absent_offset;
    uintptr_t base_address = (uintptr_t)base;
    uintptr_t text_address = (uintptr_t)text;
    if (!base || text_address < base_address || text_address > base_address + len) {
        return absent_offset;
    }
    return (size_t)(text_address - base_address);
}

static void macro_record_miss(MacroEnv *env, MacroMissKind kind, const MacroToken *pattern,
                              const MacroToken *input, const char *candidate, size_t candidate_len,
                              const MacroToken *fragment) {
    size_t input_offset = macro_text_offset(env->input_text, env->input_len,
                                            input ? input->text : NULL, env->input_len);
    size_t matcher_offset = macro_text_offset(env->pattern_text, env->pattern_len,
                                              pattern ? pattern->text : NULL, env->pattern_len);
    size_t candidate_start =
        macro_text_offset(env->input_text, env->input_len, candidate, input_offset);
    size_t candidate_end = candidate_len > env->input_len - candidate_start
                               ? env->input_len
                               : candidate_start + candidate_len;
    bool replace =
        env->miss_kind == MACRO_MISS_NONE || input_offset > env->furthest_input_byte ||
        (input_offset == env->furthest_input_byte && candidate_end > env->candidate_end_byte) ||
        (input_offset == env->furthest_input_byte && candidate_end == env->candidate_end_byte &&
         kind > env->miss_kind);
    if (!replace)
        return;
    env->miss_kind = kind;
    env->furthest_input_byte = input_offset;
    env->furthest_matcher_byte = matcher_offset;
    env->candidate_start_byte = candidate_start;
    env->candidate_end_byte = candidate_end;
    env->candidate_fragment = fragment ? fragment->text : NULL;
    env->candidate_fragment_len = fragment ? fragment->len : 0;
}

static MacroMatchStatus macro_match_sequence(MacroEnv *env, const MacroToken *pattern,
                                             const MacroToken *input, const MacroNesting *nesting,
                                             bool require_end, const MacroToken **out_input);

static bool macro_repeat_operator(const MacroToken *token) {
    return macro_token_text_is(token, "*") || macro_token_text_is(token, "+") ||
           macro_token_text_is(token, "?");
}

static bool macro_repetition_parts(const MacroToken *group, const MacroToken **separator,
                                   const MacroToken **operator_token) {
    *separator = NULL;
    *operator_token = group ? group->next : NULL;
    if (*operator_token && !macro_repeat_operator(*operator_token)) {
        *separator = *operator_token;
        *operator_token = (*operator_token)->next;
    }
    return group && group->open == '(' && *operator_token &&
           macro_repeat_operator(*operator_token) && !(*separator && (*separator)->open);
}

static bool macro_register_binding(MacroEnv *env, const MacroToken *name,
                                   const MacroRepeatShape *shape) {
    if (macro_find_binding(env, name)) {
        cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_DUPLICATE_BINDING",
                              "rust_lsp_macro_matcher_declaration", name ? name->len : 0);
        return false;
    }
    MacroBinding *binding =
        (MacroBinding *)macro_arena_zalloc(env->ctx, sizeof(*binding), "rust_lsp_macro_binding");
    if (!binding) {
        return false;
    }
    binding->name = name->text;
    binding->name_len = name->len;
    binding->shape = shape;
    binding->previous = env->bindings;
    env->bindings = binding;
    return true;
}

static bool macro_register_matcher_bindings(MacroEnv *env, const MacroToken *tokens,
                                            const MacroRepeatShape *shape) {
    for (const MacroToken *token = tokens; token;) {
        if (macro_token_text_is(token, "$")) {
            const MacroToken *name_or_group = token->next;
            if (!name_or_group) {
                cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                      "rust_lsp_macro_dangling_dollar", token->len);
                return false;
            }
            if (name_or_group->open == '(') {
                const MacroToken *separator = NULL;
                const MacroToken *operator_token = NULL;
                if (!macro_repetition_parts(name_or_group, &separator, &operator_token)) {
                    cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                          "rust_lsp_macro_repetition_operator", name_or_group->len);
                    return false;
                }
                if (macro_token_text_is(operator_token, "?") && separator) {
                    cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                          "rust_lsp_macro_question_separator", separator->len);
                    return false;
                }
                MacroRepeatShape *inner_shape = (MacroRepeatShape *)macro_arena_zalloc(
                    env->ctx, sizeof(*inner_shape), "rust_lsp_macro_repeat_shape");
                if (!inner_shape) {
                    return false;
                }
                inner_shape->repetition = name_or_group;
                inner_shape->depth = shape ? shape->depth + 1 : 1;
                inner_shape->parent = shape;
                if (!macro_register_matcher_bindings(env, name_or_group->children, inner_shape)) {
                    return false;
                }
                token = operator_token->next;
                continue;
            }
            if (name_or_group->open || !macro_token_is_identifier(name_or_group) ||
                !name_or_group->next || !macro_token_text_is(name_or_group->next, ":") ||
                !name_or_group->next->next || name_or_group->next->next->open) {
                cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                      "rust_lsp_macro_metavariable_syntax", name_or_group->len);
                return false;
            }
            const MacroToken *fragment = name_or_group->next->next;
            if (!macro_fragment_supported(fragment)) {
                cbm_arena_mark_failed(env->ctx->arena, "CBM_RUST_MACRO_FRAGMENT_UNSUPPORTED",
                                      "rust_lsp_macro_matcher_fragment", fragment->len);
                return false;
            }
            if (!macro_register_binding(env, name_or_group, shape)) {
                return false;
            }
            token = fragment->next;
            continue;
        }
        if (token->open && !macro_register_matcher_bindings(env, token->children, shape)) {
            return false;
        }
        token = token->next;
    }
    return true;
}

static bool macro_boundary_token_matches(const MacroToken *pattern, const MacroToken *input) {
    if (!pattern || !input) {
        return false;
    }
    if (pattern->open || input->open) {
        return pattern->open && input->open && pattern->open == input->open &&
               pattern->close == input->close;
    }
    return macro_tokens_equal(pattern, input);
}

static bool macro_token_is_raw_identifier(const MacroToken *token) {
    return macro_token_is_identifier(token) && token->len > 2 && token->text[0] == 'r' &&
           token->text[1] == '#';
}

static bool macro_identifier_text_in(const MacroToken *token, const char *const *values,
                                     size_t value_count) {
    if (!macro_token_is_identifier(token) || macro_token_is_raw_identifier(token)) {
        return false;
    }
    for (size_t i = 0; i < value_count; i++) {
        if (macro_token_text_is(token, values[i])) {
            return true;
        }
    }
    return false;
}

static bool macro_identifier_is_reserved(MacroEnv *env, const MacroToken *token) {
    /* Strict and always-reserved identifiers from the pinned host parser.
     * Weak keywords remain ordinary identifiers.  Raw identifiers bypass all
     * keyword classification, and edition-conditional keywords use the macro
     * definition's active Cargo edition. */
    static const char *const always_reserved[] = {
        "_",        "abstract", "as",       "become", "box",      "break",
        "const",    "continue", "crate",    "do",     "else",     "enum",
        "extern",   "false",    "final",    "fn",     "for",      "if",
        "impl",     "in",       "let",      "loop",   "macro",   "match",
        "mod",      "move",     "mut",      "override", "priv", "pub",
        "ref",      "return",   "self",     "Self",   "static",  "struct",
        "super",    "trait",    "true",     "type",   "typeof",  "unsafe",
        "unsized",  "use",      "virtual",  "where",  "while",   "yield",
    };
    if (macro_identifier_text_in(token, always_reserved,
                                 sizeof(always_reserved) / sizeof(always_reserved[0]))) {
        return true;
    }
    int edition = macro_active_edition(env);
    if (edition >= 2018 && (macro_token_text_is(token, "async") ||
                            macro_token_text_is(token, "await") ||
                            macro_token_text_is(token, "dyn") ||
                            macro_token_text_is(token, "try"))) {
        return true;
    }
    return edition >= 2024 && macro_token_text_is(token, "gen");
}

static bool macro_identifier_can_begin_expr(MacroEnv *env, const MacroToken *token) {
    static const char *const allowed_reserved[] = {
        "self",  "Self",   "super", "crate", "async", "do",     "box",   "break",
        "const", "continue", "false", "for",   "gen",   "if",     "let",   "loop",
        "match", "move",   "return", "true",  "try",   "unsafe", "while", "yield",
        "safe",  "static",
    };
    if (!macro_token_is_identifier(token)) {
        return false;
    }
    if (macro_token_is_raw_identifier(token) || !macro_identifier_is_reserved(env, token)) {
        return true;
    }
    return macro_identifier_text_in(token, allowed_reserved,
                                    sizeof(allowed_reserved) / sizeof(allowed_reserved[0]));
}

static bool macro_identifier_can_begin_type(MacroEnv *env, const MacroToken *token) {
    static const char *const allowed_reserved[] = {
        "self", "Self", "super", "crate", "_",      "for", "impl",
        "fn",   "unsafe", "extern", "typeof", "dyn",
    };
    if (!macro_token_is_identifier(token)) {
        return false;
    }
    if (macro_token_is_raw_identifier(token) || !macro_identifier_is_reserved(env, token)) {
        return true;
    }
    return macro_identifier_text_in(token, allowed_reserved,
                                    sizeof(allowed_reserved) / sizeof(allowed_reserved[0]));
}

static bool macro_token_can_begin_expression(MacroEnv *env, const MacroToken *fragment,
                                             const MacroToken *input) {
    if (!input) {
        return false;
    }
    if (input->open == '(' || input->open == '{' || input->open == '[' ||
        macro_token_is_literal(input) || macro_token_is_lifetime(input)) {
        return true;
    }
    static const char *const punctuation[] = {
        "!", "-", "*", "|", "||", "&", "&&", "..", "...", "..=", "<", "<<", "::", "#",
    };
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(punctuation[0]); i++) {
        if (macro_token_text_is(input, punctuation[i])) {
            return true;
        }
    }
    int edition = macro_active_edition(env);
    bool current_expr = macro_is_fragment(fragment, "expr") && (edition == 0 || edition >= 2024);
    if (macro_token_text_is(input, "_")) {
        return current_expr;
    }
    if (!macro_identifier_can_begin_expr(env, input) || macro_token_text_is(input, "let")) {
        return false;
    }
    if (macro_token_text_is(input, "const")) {
        return current_expr;
    }
    return true;
}

static bool macro_token_can_begin_pattern(const MacroToken *fragment, const MacroToken *input) {
    if (!input) {
        return false;
    }
    if (macro_token_is_identifier(input) || macro_token_is_literal(input) || input->open == '(' ||
        input->open == '[') {
        return true;
    }
    static const char *const punctuation[] = {
        "&", "&&", "-", "..", "...", "::", "<", "<<",
    };
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(punctuation[0]); i++) {
        if (macro_token_text_is(input, punctuation[i])) {
            return true;
        }
    }
    return macro_is_fragment(fragment, "pat") && macro_token_text_is(input, "|");
}

static bool macro_token_can_begin_type(MacroEnv *env, const MacroToken *input) {
    if (!input) {
        return false;
    }
    if (macro_identifier_can_begin_type(env, input) || macro_token_is_lifetime(input) ||
        input->open == '(' || input->open == '[') {
        return true;
    }
    static const char *const punctuation[] = {
        "!", "*", "&", "&&", "?", "<", "<<", "::",
    };
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(punctuation[0]); i++) {
        if (macro_token_text_is(input, punctuation[i])) {
            return true;
        }
    }
    return false;
}

/* Mirror rustc Parser::nonterminal_may_begin_with before retaining a named-NT
 * NFA state.  This is a constant-time token classification and a stability
 * boundary: it may conservatively retain a viable state, but it never invokes
 * the full fragment parser or scans candidate prefixes. */
static bool macro_fragment_may_begin_with(MacroEnv *env, const MacroToken *fragment,
                                          const MacroToken *input) {
    if (!fragment || !input) {
        return false;
    }
    if (macro_is_fragment(fragment, "tt") || macro_is_fragment(fragment, "item") ||
        macro_is_fragment(fragment, "stmt")) {
        return true;
    }
    if (macro_is_fragment(fragment, "ident")) {
        return !macro_token_text_is(input, "_") && macro_token_is_identifier(input);
    }
    if (macro_is_fragment(fragment, "lifetime")) {
        return macro_token_is_lifetime(input);
    }
    if (macro_is_fragment(fragment, "block")) {
        return input->open == '{';
    }
    if (macro_is_fragment(fragment, "literal")) {
        return macro_token_is_literal(input) || macro_token_text_is(input, "-");
    }
    if (macro_is_fragment(fragment, "expr") || macro_is_fragment(fragment, "expr_2021")) {
        return macro_token_can_begin_expression(env, fragment, input);
    }
    if (macro_is_fragment(fragment, "pat") || macro_is_fragment(fragment, "pat_param")) {
        return macro_token_can_begin_pattern(fragment, input);
    }
    if (macro_is_fragment(fragment, "ty")) {
        return macro_token_can_begin_type(env, input);
    }
    if (macro_is_fragment(fragment, "path") || macro_is_fragment(fragment, "meta")) {
        return macro_token_text_is(input, "::") || macro_token_is_identifier(input);
    }
    if (macro_is_fragment(fragment, "vis")) {
        return macro_token_text_is(input, ",") || macro_token_is_identifier(input) ||
               macro_token_can_begin_type(env, input);
    }
    return false;
}

/* Return whether `input` is in FIRST(pattern), and report epsilon membership
 * separately.  A leading `$` is not sufficient to mean ANYTOKEN: a complex
 * NT such as `$(;)*` has FIRST={';', epsilon}.  Rust's formal macro matcher
 * grammar computes FIRST recursively through nullable repetitions, and rustc's
 * NFA follows the same epsilon transitions.  Mirroring that distinction keeps
 * a path prefix such as `MouseAction` from being accepted as a complete expr
 * merely because the eventual suffix begins with a nullable repetition. */
static bool macro_matcher_first_possible(MacroEnv *env, const MacroToken *pattern,
                                         const MacroToken *input, bool *nullable) {
    *nullable = false;
    if (!macro_work(env->ctx, 1, "rust_lsp_macro_matcher_first")) {
        return false;
    }
    if (!pattern) {
        *nullable = true;
        return false;
    }
    if (!macro_token_text_is(pattern, "$")) {
        return macro_boundary_token_matches(pattern, input);
    }

    const MacroToken *name_or_group = pattern->next;
    if (!name_or_group) {
        /* The normal matcher validator will issue the structured dangling-$
         * failure.  Do not invent a narrower boundary before it does. */
        return input != NULL;
    }
    if (name_or_group->open == '(') {
        const MacroToken *separator = NULL;
        const MacroToken *operator_token = NULL;
        if (!macro_repetition_parts(name_or_group, &separator, &operator_token)) {
            /* Likewise, malformed repetition syntax is owned by the existing
             * fail-closed matcher validation path. */
            return input != NULL;
        }

        bool body_nullable = false;
        if (macro_matcher_first_possible(env, name_or_group->children, input, &body_nullable)) {
            return true;
        }
        if (cbm_arena_failed(env->ctx->arena)) {
            return false;
        }
        if (separator && body_nullable && macro_boundary_token_matches(separator, input)) {
            return true;
        }

        bool repetition_nullable = macro_token_text_is(operator_token, "*") ||
                                   macro_token_text_is(operator_token, "?");
        if (!repetition_nullable) {
            return false;
        }
        return macro_matcher_first_possible(env, operator_token->next, input, nullable);
    }

    const MacroToken *colon = name_or_group->next;
    const MacroToken *fragment =
        colon && macro_token_text_is(colon, ":") ? colon->next : NULL;
    if (!fragment) {
        return input != NULL;
    }
    if (macro_fragment_may_begin_with(env, fragment, input)) {
        return true;
    }
    if (!macro_is_fragment(fragment, "vis")) {
        return false;
    }
    return macro_matcher_first_possible(env, fragment->next, input, nullable);
}

typedef enum {
    MACRO_FIRST_NONE = 0,
    MACRO_FIRST_TOKEN = 1,
    MACRO_FIRST_FRAGMENT = 2,
} MacroFirstKind;

/* Return the kinds of parser states in FIRST(pattern) which are viable at the
 * concrete input token.  This mirrors rustc's NFA boundary: an ordinary token
 * state is viable only when that token matches, while a named NT is retained
 * only when its constant-time nonterminal start predicate accepts the token.
 * The fragment parser is invoked only when one such state is the sole viable
 * path; using it to discover FIRST would repeatedly parse longer prefixes and
 * make ordinary repetitions quadratic.  Multiple ordinary token states may be
 * retained, but a named-fragment state competing with any other viable state
 * is a local ambiguity. */
static unsigned macro_matcher_first_kinds(MacroEnv *env, const MacroToken *pattern,
                                          const MacroToken *input, bool *nullable) {
    *nullable = false;
    if (!macro_work(env->ctx, 1, "rust_lsp_macro_matcher_first_kinds")) {
        return MACRO_FIRST_NONE;
    }
    if (!pattern) {
        *nullable = true;
        return MACRO_FIRST_NONE;
    }
    if (!macro_token_text_is(pattern, "$")) {
        return macro_boundary_token_matches(pattern, input) ? MACRO_FIRST_TOKEN
                                                            : MACRO_FIRST_NONE;
    }

    const MacroToken *name_or_group = pattern->next;
    if (!name_or_group) {
        return MACRO_FIRST_NONE;
    }
    if (name_or_group->open == '(') {
        const MacroToken *separator = NULL;
        const MacroToken *operator_token = NULL;
        if (!macro_repetition_parts(name_or_group, &separator, &operator_token)) {
            return MACRO_FIRST_NONE;
        }

        bool body_nullable = false;
        unsigned kinds = macro_matcher_first_kinds(env, name_or_group->children, input,
                                                   &body_nullable);
        if (cbm_arena_failed(env->ctx->arena)) {
            return MACRO_FIRST_NONE;
        }
        bool repetition_nullable = macro_token_text_is(operator_token, "*") ||
                                   macro_token_text_is(operator_token, "?") || body_nullable;
        if (!repetition_nullable) {
            return kinds;
        }

        bool suffix_nullable = false;
        kinds |= macro_matcher_first_kinds(env, operator_token->next, input, &suffix_nullable);
        *nullable = suffix_nullable;
        return kinds;
    }

    const MacroToken *colon = name_or_group->next;
    const MacroToken *fragment =
        colon && macro_token_text_is(colon, ":") ? colon->next : NULL;
    if (!fragment || !macro_fragment_supported(fragment)) {
        return MACRO_FIRST_NONE;
    }

    unsigned kinds = macro_fragment_may_begin_with(env, fragment, input)
                         ? MACRO_FIRST_FRAGMENT
                         : MACRO_FIRST_NONE;

    if (!macro_is_fragment(fragment, "vis")) {
        return kinds;
    }
    bool suffix_nullable = false;
    kinds |= macro_matcher_first_kinds(env, fragment->next, input, &suffix_nullable);
    *nullable = suffix_nullable;
    return kinds;
}

/* A fragment at the end of a repetition body may be followed by that
 * repetition's separator, the FIRST set of another unseparated iteration, or
 * the repetition suffix.  If the suffix is nullable, the same question moves
 * outward through the nesting chain until a concrete token or the required
 * end of the invocation is reached. */
static bool macro_fragment_endpoint_possible(MacroEnv *env, const MacroToken *pattern_after,
                                             const MacroNesting *nesting, bool require_end,
                                             const MacroToken *after) {
    bool nullable = false;
    if (macro_matcher_first_possible(env, pattern_after, after, &nullable)) {
        return true;
    }
    if (cbm_arena_failed(env->ctx->arena) || !nullable) {
        return false;
    }
    if (!nesting) {
        return require_end ? after == NULL : true;
    }

    const MacroToken *separator = NULL;
    const MacroToken *operator_token = NULL;
    if (!macro_repetition_parts(nesting->repetition, &separator, &operator_token)) {
        return after != NULL;
    }
    if (separator && macro_boundary_token_matches(separator, after)) {
        return true;
    }
    if (!separator) {
        bool body_nullable = false;
        if (macro_matcher_first_possible(env, nesting->repetition->children, after,
                                         &body_nullable)) {
            return true;
        }
        if (cbm_arena_failed(env->ctx->arena)) {
            return false;
        }
    }

    bool suffix_nullable = false;
    if (macro_matcher_first_possible(env, operator_token->next, after, &suffix_nullable)) {
        return true;
    }
    if (cbm_arena_failed(env->ctx->arena) || !suffix_nullable) {
        return false;
    }
    return macro_fragment_endpoint_possible(env, NULL, nesting->parent, nesting->require_end,
                                            after);
}

static MacroMatchStatus macro_match_repetition(
    MacroEnv *env, const MacroToken *group, const MacroToken *separator,
    const MacroToken *operator_token, const MacroToken *pattern_after, const MacroToken *input,
    const MacroNesting *outer_nesting, bool require_end, const MacroToken **out_input) {
    RustLSPContext *ctx = env->ctx;
    if (macro_token_text_is(operator_token, "?") && separator) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                              "rust_lsp_macro_question_separator", separator->len);
        return MACRO_FATAL;
    }
    size_t minimum = macro_token_text_is(operator_token, "+") ? 1 : 0;
    size_t maximum = macro_token_text_is(operator_token, "?") ? 1 : SIZE_MAX;
    MacroRepeatState initial = {
        .input = input,
        .captures = env->captures,
        .cardinalities = env->cardinalities,
        .count = 0,
        .previous = NULL,
    };
    MacroRepeatState *state = &initial;
    const MacroToken *cursor = input;

    while (state->count < maximum && cursor) {
        if (!macro_work(ctx, 1, "rust_lsp_macro_match_repetition")) {
            return MACRO_FATAL;
        }
        if ((pattern_after || require_end) && state->count >= minimum) {
            bool suffix_nullable = false;
            unsigned suffix_kinds =
                macro_matcher_first_kinds(env, pattern_after, cursor, &suffix_nullable);
            if (cbm_arena_failed(ctx->arena)) {
                return MACRO_FATAL;
            }
            if (suffix_kinds != MACRO_FIRST_NONE) {
                bool body_nullable = false;
                unsigned body_kinds = macro_matcher_first_kinds(
                    env, group->children, cursor, &body_nullable);
                if (cbm_arena_failed(ctx->arena)) {
                    return MACRO_FATAL;
                }
                bool competing_fragment =
                    ((body_kinds | suffix_kinds) & MACRO_FIRST_FRAGMENT) != 0;
                if (body_kinds != MACRO_FIRST_NONE && suffix_kinds != MACRO_FIRST_NONE &&
                    competing_fragment) {
                    size_t input_byte = macro_text_offset(
                        env->input_text, env->input_len, cursor->text, env->input_len);
                    size_t matcher_byte = macro_text_offset(
                        env->pattern_text, env->pattern_len, group->text, env->pattern_len);
                    fprintf(stderr,
                            "ERROR level=error msg=rust_macro.local_ambiguity "
                            "code=CBM_RUST_MACRO_LOCAL_AMBIGUITY macro=%s invocation_byte=%u "
                            "input_byte=%zu matcher_byte=%zu repetition_count=%zu "
                            "body_first=%u suffix_first=%u\n",
                            env->macro_name ? env->macro_name : "none", env->invocation_byte,
                            input_byte, matcher_byte, state->count, body_kinds, suffix_kinds);
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_LOCAL_AMBIGUITY",
                                          "rust_lsp_macro_match_ambiguity", input_byte);
                    return MACRO_FATAL;
                }
            }
        }
        env->captures = state->captures;
        env->cardinalities = state->cardinalities;
        MacroNesting *body_nesting = (MacroNesting *)macro_arena_zalloc(ctx, sizeof(*body_nesting),
                                                                        "rust_lsp_macro_nesting");
        if (!body_nesting) {
            return MACRO_FATAL;
        }
        body_nesting->repetition = group;
        body_nesting->iteration = state->count;
        body_nesting->depth = outer_nesting ? outer_nesting->depth + 1 : 1;
        body_nesting->require_end = require_end;
        body_nesting->parent = outer_nesting;
        const MacroToken *body_after = NULL;
        MacroMatchStatus body_status =
            macro_match_sequence(env, group->children, cursor, body_nesting, false, &body_after);
        if (body_status == MACRO_FATAL) {
            return MACRO_FATAL;
        }
        if (body_status != MACRO_MATCH || body_after == cursor) {
            env->captures = state->captures;
            env->cardinalities = state->cardinalities;
            break;
        }
        MacroRepeatState *next = (MacroRepeatState *)macro_arena_zalloc(
            ctx, sizeof(*next), "rust_lsp_macro_repeat_state");
        if (!next) {
            return MACRO_FATAL;
        }
        next->input = body_after;
        next->captures = env->captures;
        next->cardinalities = env->cardinalities;
        next->count = state->count + 1;
        next->previous = state;
        state = next;
        cursor = body_after;
        if (separator) {
            if (!cursor || !macro_tokens_equal(separator, cursor)) {
                break;
            }
            cursor = cursor->next;
        }
    }

    for (MacroRepeatState *candidate = state; candidate; candidate = candidate->previous) {
        if (candidate->count < minimum || candidate->count > maximum) {
            continue;
        }
        env->captures = candidate->captures;
        env->cardinalities = candidate->cardinalities;
        if (!macro_record_cardinality(env, group, outer_nesting, candidate->count)) {
            return MACRO_FATAL;
        }
        MacroMatchStatus suffix = macro_match_sequence(env, pattern_after, candidate->input,
                                                       outer_nesting, require_end, out_input);
        if (suffix == MACRO_MATCH) {
            return MACRO_MATCH;
        }
        if (suffix == MACRO_FATAL) {
            return MACRO_FATAL;
        }
    }
    env->captures = initial.captures;
    env->cardinalities = initial.cardinalities;
    return MACRO_NO_MATCH;
}

static MacroMatchStatus macro_match_sequence(MacroEnv *env, const MacroToken *pattern,
                                             const MacroToken *input, const MacroNesting *nesting,
                                             bool require_end, const MacroToken **out_input) {
    RustLSPContext *ctx = env->ctx;
    if (!macro_work(ctx, 1, "rust_lsp_macro_match")) {
        return MACRO_FATAL;
    }
    if (ctx->macro_match_depth >= ctx->macro_match_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_MATCH_DEPTH_EXCEEDED",
                              "rust_lsp_macro_match_depth", (size_t)ctx->macro_match_depth_limit);
        return MACRO_FATAL;
    }
    ctx->macro_match_depth++;
    MacroCapture *entry_captures = env->captures;
    MacroCardinality *entry_cardinalities = env->cardinalities;
    MacroMatchStatus status = MACRO_NO_MATCH;

    while (pattern) {
        if (macro_token_text_is(pattern, "$")) {
            const MacroToken *name_or_group = pattern->next;
            if (!name_or_group) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                      "rust_lsp_macro_dangling_dollar", pattern->len);
                status = MACRO_FATAL;
                goto done;
            }
            if (name_or_group->open == '(') {
                const MacroToken *separator = NULL;
                const MacroToken *operator_token = name_or_group->next;
                if (operator_token && !macro_repeat_operator(operator_token)) {
                    separator = operator_token;
                    operator_token = operator_token->next;
                }
                if (!operator_token || !macro_repeat_operator(operator_token) ||
                    (separator && separator->open)) {
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                          "rust_lsp_macro_repetition_operator", name_or_group->len);
                    status = MACRO_FATAL;
                    goto done;
                }
                status = macro_match_repetition(env, name_or_group, separator, operator_token,
                                                operator_token->next, input, nesting, require_end,
                                                out_input);
                goto done;
            }
            if (name_or_group->open || !macro_token_is_identifier(name_or_group) ||
                !name_or_group->next || !macro_token_text_is(name_or_group->next, ":") ||
                !name_or_group->next->next || name_or_group->next->next->open) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PATTERN_UNSUPPORTED",
                                      "rust_lsp_macro_metavariable_syntax", name_or_group->len);
                status = MACRO_FATAL;
                goto done;
            }
            const MacroToken *fragment = name_or_group->next->next;
            const MacroToken *pattern_after = fragment->next;
            if (!macro_fragment_supported(fragment)) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_FRAGMENT_UNSUPPORTED",
                                      "rust_lsp_macro_matcher_fragment", fragment->len);
                status = MACRO_FATAL;
                goto done;
            }

            MacroCapture *fragment_entry_captures = env->captures;
            bool fixed_one =
                macro_is_fragment(fragment, "tt") || macro_is_fragment(fragment, "ident") ||
                macro_is_fragment(fragment, "lifetime") || macro_is_fragment(fragment, "block");
            bool had_endpoint = false;
            const MacroToken *cursor = input;
            /* Apply rustc's named-NT start predicate at the consumption point,
             * not only while computing FIRST sets. An impossible start takes
             * the enclosing repetition's epsilon path without scanning or
             * parsing any later endpoint. */
            bool may_begin = macro_fragment_may_begin_with(env, fragment, input);
            while (may_begin && cursor) {
                if (!macro_work(ctx, 1, "rust_lsp_macro_fragment_candidates")) {
                    status = MACRO_FATAL;
                    goto done;
                }
                const MacroToken *after = cursor->next;
                bool endpoint_possible =
                    macro_fragment_endpoint_possible(env, pattern_after, nesting, require_end,
                                                     after);
                if (cbm_arena_failed(ctx->arena)) {
                    status = MACRO_FATAL;
                    goto done;
                }
                if (endpoint_possible) {
                    /* rustc commits to the Rust parser when it reaches a named
                     * non-terminal.  Examine legal follow boundaries in input
                     * order so the first exact fragment is the one the parser
                     * would consume.  If its suffix does not match, continue to
                     * later boundaries without sacrificing backtracking.  The
                     * former prepend-then-walk list reversed this order and
                     * reparsed the entire remaining invocation at every
                     * separator: O(N^2) byte work for ordinary repetitions such
                     * as `$($action:expr);*`. */
                    had_endpoint = true;
                    const char *value = macro_capture_start(input);
                    size_t value_len = macro_capture_length(input, cursor);
                    if (!macro_fragment_parse_clean(env, fragment, value, value_len)) {
                        if (cbm_arena_failed(ctx->arena)) {
                            status = MACRO_FATAL;
                            goto done;
                        }
                        macro_record_miss(env, MACRO_MISS_FRAGMENT, pattern, input, value,
                                          value_len, fragment);
                    } else {
                        env->captures = fragment_entry_captures;
                        if (!macro_bind_capture(env, name_or_group, value, value_len, nesting)) {
                            status = MACRO_FATAL;
                            goto done;
                        }
                        status = macro_match_sequence(env, pattern_after, after, nesting,
                                                      require_end, out_input);
                        if (status != MACRO_NO_MATCH) {
                            goto done;
                        }
                    }
                }
                if (fixed_one) {
                    break;
                }
                cursor = cursor->next;
            }
            if (!had_endpoint) {
                macro_record_miss(env, MACRO_MISS_FRAGMENT, pattern, input,
                                  input ? input->text : NULL, 0, fragment);
            }
            if (macro_is_fragment(fragment, "vis")) {
                env->captures = fragment_entry_captures;
                const char *empty_at = input ? input->text : fragment->text + fragment->len;
                if (!macro_bind_capture(env, name_or_group, empty_at, 0, nesting)) {
                    status = MACRO_FATAL;
                    goto done;
                }
                status = macro_match_sequence(env, pattern_after, input, nesting, require_end,
                                              out_input);
                if (status != MACRO_NO_MATCH) {
                    goto done;
                }
            }
            status = MACRO_NO_MATCH;
            goto done;
        }

        if (!input) {
            macro_record_miss(env, MACRO_MISS_TOKEN, pattern, input, NULL, 0, NULL);
            status = MACRO_NO_MATCH;
            goto done;
        }
        if (pattern->open) {
            if (!input->open || pattern->open != input->open || pattern->close != input->close) {
                macro_record_miss(env, MACRO_MISS_TOKEN, pattern, input, input->text, input->len,
                                  NULL);
                status = MACRO_NO_MATCH;
                goto done;
            }
            const MacroToken *child_after = NULL;
            status = macro_match_sequence(env, pattern->children, input->children, nesting, true,
                                          &child_after);
            if (status != MACRO_MATCH) {
                goto done;
            }
        } else if (!macro_tokens_equal(pattern, input)) {
            macro_record_miss(env, MACRO_MISS_TOKEN, pattern, input, input->text, input->len, NULL);
            status = MACRO_NO_MATCH;
            goto done;
        }
        pattern = pattern->next;
        input = input->next;
    }
    status = (!require_end || !input) ? MACRO_MATCH : MACRO_NO_MATCH;
    if (status == MACRO_NO_MATCH) {
        macro_record_miss(env, MACRO_MISS_TOKEN, pattern, input, input->text, input->len, NULL);
    }
    if (status == MACRO_MATCH && out_input) {
        *out_input = input;
    }

done:
    if (status == MACRO_NO_MATCH) {
        env->captures = entry_captures;
        env->cardinalities = entry_cardinalities;
    }
    ctx->macro_match_depth--;
    return status;
}

static MacroMatchStatus macro_pattern_match(MacroEnv *env, const char *pattern, size_t pattern_len,
                                            const char *input, size_t input_len) {
    MacroToken *pattern_tokens = NULL;
    MacroToken *input_tokens = NULL;
    if (!macro_lex(env->ctx, pattern, pattern_len, &pattern_tokens, NULL, NULL) ||
        !macro_lex(env->ctx, input, input_len, &input_tokens, NULL, NULL)) {
        return MACRO_FATAL;
    }
    env->bindings = NULL;
    env->captures = NULL;
    env->cardinalities = NULL;
    env->pattern_text = pattern;
    env->pattern_len = pattern_len;
    env->input_text = input;
    env->input_len = input_len;
    if (!macro_register_matcher_bindings(env, pattern_tokens, NULL)) {
        return MACRO_FATAL;
    }
    const MacroToken *after = NULL;
    return macro_match_sequence(env, pattern_tokens, input_tokens, NULL, true, &after);
}

static bool macro_output_reserve(RustLSPContext *ctx, MacroOutput *out, size_t additional) {
    if (additional > SIZE_MAX - out->len - 1) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                              "rust_lsp_macro_output_size", additional);
        return false;
    }
    size_t needed = out->len + additional + 1;
    if (needed <= out->cap) {
        return true;
    }
    size_t cap = out->cap ? out->cap : 256;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) {
            cap = needed;
            break;
        }
        cap *= 2;
    }
    char *next = (char *)cbm_arena_alloc(ctx->arena, cap);
    if (!next) {
        return false;
    }
    if (out->data && out->len) {
        memcpy(next, out->data, out->len);
    }
    out->data = next;
    out->cap = cap;
    return true;
}

static bool macro_output_append(RustLSPContext *ctx, MacroOutput *out, const char *text,
                                size_t len) {
    if (!macro_work(ctx, len ? len : 1, "rust_lsp_macro_substitute") ||
        !macro_output_reserve(ctx, out, len)) {
        return false;
    }
    if (len) {
        memcpy(out->data + out->len, text, len);
        out->len += len;
    }
    out->data[out->len] = '\0';
    return true;
}

static void macro_log_repetition_failure(const MacroEnv *env, const char *code,
                                         const char *operation, const MacroToken *metavariable,
                                         size_t binding_depth, size_t selection_depth) {
    fprintf(stderr,
            "ERROR level=error msg=rust_macro.repetition_failure code=%s operation=%s "
            "macro=%s metavariable=%.*s binding_depth=%zu selection_depth=%zu "
            "invocation_byte=%u\n",
            code, operation, env->macro_name ? env->macro_name : "none",
            metavariable ? (int)metavariable->len : 0, metavariable ? metavariable->text : "",
            binding_depth, selection_depth, env->invocation_byte);
}

static bool macro_repetition_driver(RustLSPContext *ctx, const MacroToken *tokens,
                                    const MacroEnv *env, const MacroNesting *selection,
                                    const MacroToken **driver, size_t *count) {
    for (const MacroToken *token = tokens; token; token = token->next) {
        if (macro_token_text_is(token, "$")) {
            const MacroToken *next = token->next;
            if (!next) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TRANSCRIBER_UNSUPPORTED",
                                      "rust_lsp_macro_transcriber_dangling_dollar", token->len);
                return false;
            }
            if (next->open) {
                if (!macro_repetition_driver(ctx, next->children, env, selection, driver, count)) {
                    return false;
                }
                token = next;
                continue;
            }
            if (macro_token_text_is(next, "crate")) {
                token = next;
                continue;
            }
            MacroBinding *binding = macro_find_binding(env, next);
            if (!binding) {
                fprintf(stderr,
                        "ERROR level=error msg=rust_macro.metavariable_unbound "
                        "code=CBM_RUST_MACRO_UNBOUND_METAVARIABLE macro=%s "
                        "metavariable=%.*s invocation_byte=%u phase=repetition_driver\n",
                        env->macro_name ? env->macro_name : "none", (int)next->len, next->text,
                        env->invocation_byte);
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_UNBOUND_METAVARIABLE",
                                      "rust_lsp_macro_transcriber_repetition", next->len);
                return false;
            }
            size_t selection_depth = selection ? selection->depth : 0;
            size_t binding_depth = binding->shape ? binding->shape->depth : 0;
            if (binding_depth <= selection_depth) {
                /* rustc's lockstep iterator treats a MatchedSingle reached
                 * before the active RHS depth as unconstrained.  The capture
                 * remains available to substitution but cannot drive this
                 * repetition. */
                token = next;
                continue;
            }
            const MacroRepeatShape *next_shape =
                macro_shape_at_depth(binding->shape, selection_depth + 1);
            MacroCardinality *cardinality =
                next_shape
                    ? macro_find_cardinality_at_selection(env, next_shape->repetition, selection)
                    : NULL;
            if (!cardinality) {
                macro_log_repetition_failure(env, "CBM_RUST_MACRO_REPETITION_CARDINALITY_MISSING",
                                             "rust_lsp_macro_transcriber_repetition", next,
                                             binding_depth, selection_depth);
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_REPETITION_CARDINALITY_MISSING",
                                      "rust_lsp_macro_transcriber_repetition", next->len);
                return false;
            }
            if (!*driver) {
                *driver = next_shape->repetition;
                *count = cardinality->count;
            } else if (*count != cardinality->count) {
                fprintf(stderr,
                        "ERROR level=error msg=rust_macro.repetition_cardinality_mismatch "
                        "code=CBM_RUST_MACRO_REPETITION_CARDINALITY_MISMATCH macro=%s "
                        "metavariable=%.*s binding_depth=%zu selection_depth=%zu "
                        "expected_count=%zu actual_count=%zu invocation_byte=%u\n",
                        env->macro_name ? env->macro_name : "none", (int)next->len, next->text,
                        binding_depth, selection_depth, *count, cardinality->count,
                        env->invocation_byte);
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_REPETITION_CARDINALITY_MISMATCH",
                                      "rust_lsp_macro_transcriber_repetition", next->len);
                return false;
            }
            token = next;
        } else if (token->open &&
                   !macro_repetition_driver(ctx, token->children, env, selection, driver, count)) {
            return false;
        }
    }
    return true;
}

static bool macro_substitute_span(RustLSPContext *ctx, const MacroToken *tokens,
                                  const char *span_start, const char *span_end, const MacroEnv *env,
                                  const MacroNesting *selection, MacroOutput *out) {
    const char *cursor = span_start;
    for (const MacroToken *token = tokens; token;) {
        if (token->text < cursor || token->text + token->len > span_end) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TRANSCRIBER_INVALID",
                                  "rust_lsp_macro_transcriber_span", token->len);
            return false;
        }
        if (!macro_output_append(ctx, out, cursor, (size_t)(token->text - cursor))) {
            return false;
        }
        if (macro_token_text_is(token, "$")) {
            const MacroToken *name_or_group = token->next;
            if (!name_or_group) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TRANSCRIBER_UNSUPPORTED",
                                      "rust_lsp_macro_transcriber_dangling_dollar", token->len);
                return false;
            }
            if (name_or_group->open) {
                const MacroToken *separator = NULL;
                const MacroToken *operator_token = NULL;
                if (!macro_repetition_parts(name_or_group, &separator, &operator_token)) {
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TRANSCRIBER_UNSUPPORTED",
                                          "rust_lsp_macro_transcriber_operator",
                                          name_or_group->len);
                    return false;
                }
                const MacroToken *driver = NULL;
                size_t count = 0;
                if (!macro_repetition_driver(ctx, name_or_group->children, env, selection, &driver,
                                             &count)) {
                    return false;
                }
                if (!driver) {
                    fprintf(stderr,
                            "ERROR level=error msg=rust_macro.repetition_without_driver "
                            "code=CBM_RUST_MACRO_REPETITION_WITHOUT_DRIVER macro=%s "
                            "selection_depth=%zu invocation_byte=%u group_bytes=%zu\n",
                            env->macro_name ? env->macro_name : "none",
                            selection ? selection->depth : 0, env->invocation_byte,
                            name_or_group->len);
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_REPETITION_WITHOUT_DRIVER",
                                          "rust_lsp_macro_transcriber_repetition",
                                          name_or_group->len);
                    return false;
                }
                if ((macro_token_text_is(operator_token, "+") && count == 0) ||
                    (macro_token_text_is(operator_token, "?") && count > 1)) {
                    cbm_arena_mark_failed(ctx->arena,
                                          "CBM_RUST_MACRO_REPETITION_CARDINALITY_MISMATCH",
                                          "rust_lsp_macro_transcriber_operator", count);
                    return false;
                }
                for (size_t iteration = 0; iteration < count; iteration++) {
                    if (iteration) {
                        if (separator) {
                            if (!macro_output_append(ctx, out, separator->text, separator->len)) {
                                return false;
                            }
                        } else if (!macro_output_append(ctx, out, " ", 1)) {
                            return false;
                        }
                    }
                    const char *inner_start = name_or_group->text + 1;
                    const char *inner_end = name_or_group->text + name_or_group->len - 1;
                    MacroNesting inner_selection = {
                        .repetition = driver,
                        .iteration = iteration,
                        .depth = selection ? selection->depth + 1 : 1,
                        .parent = selection,
                    };
                    if (!macro_substitute_span(ctx, name_or_group->children, inner_start, inner_end,
                                               env, &inner_selection, out)) {
                        return false;
                    }
                }
                cursor = operator_token->text + operator_token->len;
                token = operator_token->next;
                continue;
            }
            if (!macro_token_is_identifier(name_or_group)) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_TRANSCRIBER_UNSUPPORTED",
                                      "rust_lsp_macro_metavariable_expression", name_or_group->len);
                return false;
            }
            if (macro_token_text_is(name_or_group, "crate")) {
                if (!macro_output_append(ctx, out, "crate", 5)) {
                    return false;
                }
            } else {
                MacroBinding *binding = macro_find_binding(env, name_or_group);
                size_t binding_depth = binding && binding->shape ? binding->shape->depth : 0;
                size_t selection_depth = selection ? selection->depth : 0;
                if (!binding || binding_depth > selection_depth) {
                    macro_log_repetition_failure(env, "CBM_RUST_MACRO_REPETITION_NESTING_MISMATCH",
                                                 "rust_lsp_macro_transcriber_nesting",
                                                 name_or_group, binding_depth, selection_depth);
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_REPETITION_NESTING_MISMATCH",
                                          "rust_lsp_macro_transcriber_nesting", name_or_group->len);
                    return false;
                }
                MacroCapture *capture =
                    macro_find_capture_at_selection(env, binding, name_or_group, selection);
                if (!capture) {
                    fprintf(stderr,
                            "ERROR level=error msg=rust_macro.metavariable_unbound "
                            "code=CBM_RUST_MACRO_UNBOUND_METAVARIABLE macro=%s "
                            "metavariable=%.*s invocation_byte=%u phase=transcriber "
                            "binding_depth=%zu selection_depth=%zu active_repetition=%s "
                            "iteration=%zu\n",
                            env->macro_name ? env->macro_name : "none", (int)name_or_group->len,
                            name_or_group->text, env->invocation_byte, binding_depth,
                            selection_depth, selection ? "true" : "false",
                            selection ? selection->iteration : 0);
                    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_UNBOUND_METAVARIABLE",
                                          "rust_lsp_macro_transcriber", name_or_group->len);
                    return false;
                }
                /* A macro expansion is a token stream, not character pasting.  The
                 * lexer deliberately removes trivia, so re-serializing adjacent
                 * captures without a boundary can turn `if` + `self` into the
                 * different token `ifself`.  Spaces around a captured token tree
                 * preserve Rust token boundaries without changing its grammar. */
                if (!macro_output_append(ctx, out, " ", 1) ||
                    !macro_output_append(ctx, out, capture->value, capture->value_len) ||
                    !macro_output_append(ctx, out, " ", 1)) {
                    return false;
                }
            }
            cursor = name_or_group->text + name_or_group->len;
            token = name_or_group->next;
            continue;
        }
        if (token->open) {
            if (!macro_output_append(ctx, out, token->text, 1) ||
                !macro_substitute_span(ctx, token->children, token->text + 1,
                                       token->text + token->len - 1, env, selection, out) ||
                !macro_output_append(ctx, out, token->text + token->len - 1, 1)) {
                return false;
            }
        } else if (!macro_output_append(ctx, out, token->text, token->len)) {
            return false;
        }
        cursor = token->text + token->len;
        token = token->next;
    }
    return macro_output_append(ctx, out, cursor, (size_t)(span_end - cursor));
}

static char *macro_substitute(MacroEnv *env, const char *transcriber, size_t transcriber_len) {
    MacroToken *tokens = NULL;
    const char *canonical_transcriber = NULL;
    size_t canonical_transcriber_len = 0;
    if (!macro_lex(env->ctx, transcriber, transcriber_len, &tokens, &canonical_transcriber,
                   &canonical_transcriber_len)) {
        return NULL;
    }
    MacroOutput out = {0};
    if (!macro_substitute_span(env->ctx, tokens, canonical_transcriber,
                               canonical_transcriber + canonical_transcriber_len, env, NULL,
                               &out)) {
        return NULL;
    }
    if (!out.data && !macro_output_reserve(env->ctx, &out, 0)) {
        return NULL;
    }
    out.data[out.len] = '\0';
    return out.data;
}

typedef enum {
    RUST_MACRO_CONTEXT_EXPRESSION = 0,
    RUST_MACRO_CONTEXT_STATEMENT,
    RUST_MACRO_CONTEXT_ITEM,
    RUST_MACRO_CONTEXT_ASSOCIATED_ITEM,
    RUST_MACRO_CONTEXT_TYPE,
    RUST_MACRO_CONTEXT_PATTERN,
} RustMacroExpansionContext;

static const char *rust_macro_context_name(RustMacroExpansionContext context) {
    switch (context) {
    case RUST_MACRO_CONTEXT_EXPRESSION:
        return "expression";
    case RUST_MACRO_CONTEXT_STATEMENT:
        return "statement";
    case RUST_MACRO_CONTEXT_ITEM:
        return "item";
    case RUST_MACRO_CONTEXT_ASSOCIATED_ITEM:
        return "associated_item";
    case RUST_MACRO_CONTEXT_TYPE:
        return "type";
    case RUST_MACRO_CONTEXT_PATTERN:
        return "pattern";
    }
    return "unknown";
}

static const char *rust_macro_child_field(TSNode parent, TSNode child) {
    uint32_t child_count = ts_node_child_count(parent);
    for (uint32_t i = 0; i < child_count; i++) {
        if (ts_node_eq(ts_node_child(parent, i), child)) {
            return ts_node_field_name_for_child(parent, i);
        }
    }
    return NULL;
}

static bool rust_macro_type_container(const char *kind) {
    if (!kind) {
        return false;
    }
    size_t len = strlen(kind);
    return (len >= 5 && strcmp(kind + len - 5, "_type") == 0) ||
           strcmp(kind, "type_identifier") == 0 || strcmp(kind, "type_arguments") == 0 ||
           strcmp(kind, "type_parameters") == 0 || strcmp(kind, "generic_type") == 0 ||
           strcmp(kind, "scoped_type_identifier") == 0;
}

static bool rust_macro_pattern_container(const char *kind) {
    return kind && (strstr(kind, "pattern") != NULL || strcmp(kind, "match_pattern") == 0 ||
                    strcmp(kind, "or_pattern") == 0);
}

static RustMacroExpansionContext rust_macro_invocation_context(TSNode invocation) {
    TSNode child = invocation;
    TSNode parent = ts_node_parent(child);
    for (int depth = 0; depth < 16 && !ts_node_is_null(parent); depth++) {
        const char *kind = ts_node_type(parent);
        const char *field = rust_macro_child_field(parent, child);
        if (field && strcmp(field, "type") == 0) {
            return RUST_MACRO_CONTEXT_TYPE;
        }
        if (field && strcmp(field, "pattern") == 0) {
            return RUST_MACRO_CONTEXT_PATTERN;
        }
        if (rust_macro_pattern_container(kind)) {
            return RUST_MACRO_CONTEXT_PATTERN;
        }
        if (rust_macro_type_container(kind)) {
            return RUST_MACRO_CONTEXT_TYPE;
        }
        if (strcmp(kind, "source_file") == 0) {
            return RUST_MACRO_CONTEXT_ITEM;
        }
        if (strcmp(kind, "expression_statement") == 0) {
            return RUST_MACRO_CONTEXT_STATEMENT;
        }
        if (strcmp(kind, "declaration_list") == 0) {
            TSNode owner = ts_node_parent(parent);
            if (!ts_node_is_null(owner)) {
                const char *owner_kind = ts_node_type(owner);
                if (strcmp(owner_kind, "impl_item") == 0 || strcmp(owner_kind, "trait_item") == 0) {
                    return RUST_MACRO_CONTEXT_ASSOCIATED_ITEM;
                }
            }
            return RUST_MACRO_CONTEXT_ITEM;
        }
        if (strcmp(kind, "block") == 0) {
            return ts_node_eq(child, invocation) ? RUST_MACRO_CONTEXT_STATEMENT
                                                 : RUST_MACRO_CONTEXT_EXPRESSION;
        }
        if (strcmp(kind, "function_item") == 0 || strcmp(kind, "closure_expression") == 0 ||
            strcmp(kind, "const_item") == 0 || strcmp(kind, "static_item") == 0) {
            break;
        }
        child = parent;
        parent = ts_node_parent(parent);
    }
    return RUST_MACRO_CONTEXT_EXPRESSION;
}

static bool rust_macro_expansion_active(const RustLSPContext *ctx, const char *macro_name,
                                        const char *substituted_body, int *frame_index) {
    if (!ctx || !macro_name || !substituted_body) {
        return false;
    }
    for (int i = 0; i < ctx->macro_expansion_count; i++) {
        const RustMacroExpansionFrame *frame = &ctx->macro_expansion_stack[i];
        if (frame->macro_name && frame->substituted_body &&
            strcmp(frame->macro_name, macro_name) == 0 &&
            strcmp(frame->substituted_body, substituted_body) == 0) {
            if (frame_index) {
                *frame_index = i;
            }
            return true;
        }
    }
    return false;
}

static bool rust_macro_expansion_push(RustLSPContext *ctx, const char *macro_name,
                                      const char *substituted_body) {
    if (!ctx || !macro_name || !substituted_body) {
        if (ctx) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_INVALID",
                                  "rust_lsp_macro_expansion_push", 0);
        }
        return false;
    }
    if (ctx->macro_expansion_count >= ctx->macro_expand_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_macro_expansion_stack",
                              (size_t)ctx->macro_expand_depth_limit);
        return false;
    }
    if (ctx->macro_expansion_count == ctx->macro_expansion_capacity) {
        int new_capacity = 8;
        if (ctx->macro_expansion_capacity > 0) {
            if (ctx->macro_expansion_capacity > INT_MAX / 2) {
                cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_OVERFLOW",
                                      "rust_lsp_macro_expansion_stack",
                                      (size_t)ctx->macro_expansion_capacity);
                return false;
            }
            new_capacity = ctx->macro_expansion_capacity * 2;
        }
        if (new_capacity > ctx->macro_expand_depth_limit) {
            new_capacity = ctx->macro_expand_depth_limit;
        }
        if (new_capacity <= ctx->macro_expansion_count) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_OVERFLOW",
                                  "rust_lsp_macro_expansion_stack", (size_t)new_capacity);
            return false;
        }
        RustMacroExpansionFrame *grown = (RustMacroExpansionFrame *)macro_arena_zalloc(
            ctx, sizeof(*grown) * (size_t)new_capacity, "rust_lsp_macro_expansion_stack");
        if (!grown) {
            return false;
        }
        if (ctx->macro_expansion_stack && ctx->macro_expansion_count > 0) {
            memcpy(grown, ctx->macro_expansion_stack,
                   sizeof(*grown) * (size_t)ctx->macro_expansion_count);
        }
        ctx->macro_expansion_stack = grown;
        ctx->macro_expansion_capacity = new_capacity;
    }
    RustMacroExpansionFrame *frame = &ctx->macro_expansion_stack[ctx->macro_expansion_count++];
    frame->macro_name = macro_name;
    frame->substituted_body = substituted_body;
    return true;
}

static void rust_macro_expansion_pop(RustLSPContext *ctx, const char *macro_name,
                                     const char *substituted_body) {
    if (!ctx || ctx->macro_expansion_count <= 0) {
        if (ctx) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_CORRUPT",
                                  "rust_lsp_macro_expansion_pop_empty", 0);
        }
        return;
    }
    RustMacroExpansionFrame *frame = &ctx->macro_expansion_stack[ctx->macro_expansion_count - 1];
    if (!frame->macro_name || !frame->substituted_body ||
        strcmp(frame->macro_name, macro_name) != 0 ||
        strcmp(frame->substituted_body, substituted_body) != 0) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_STACK_CORRUPT",
                              "rust_lsp_macro_expansion_pop_identity",
                              (size_t)ctx->macro_expansion_count);
        return;
    }
    frame->macro_name = NULL;
    frame->substituted_body = NULL;
    ctx->macro_expansion_count--;
}

static TSNode rust_macro_first_parse_error(TSNode node) {
    if (ts_node_is_null(node) || !ts_node_has_error(node)) {
        TSNode none = {0};
        return none;
    }
    if (ts_node_is_error(node) || ts_node_is_missing(node)) {
        return node;
    }
    uint32_t count = ts_node_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        TSNode found = rust_macro_first_parse_error(ts_node_child(node, i));
        if (!ts_node_is_null(found)) {
            return found;
        }
    }
    return node;
}

static void rust_macro_log_failure(const char *code, const char *macro_name,
                                   RustMacroExpansionContext context, TSNode invocation,
                                   const char *substituted_body, TSNode parse_root,
                                   int active_frame) {
    TSNode parent = ts_node_parent(invocation);
    const char *parent_kind = ts_node_is_null(parent) ? "none" : ts_node_type(parent);
    size_t body_len = substituted_body ? strlen(substituted_body) : 0;
    TSNode error = rust_macro_first_parse_error(parse_root);
    const char *error_kind = ts_node_is_null(error) ? "none" : ts_node_type(error);
    uint32_t error_start = ts_node_is_null(error) ? 0 : ts_node_start_byte(error);
    uint32_t error_end = ts_node_is_null(error) ? 0 : ts_node_end_byte(error);
    fprintf(stderr,
            "ERROR level=error msg=rust_macro.expansion_failed code=%s macro=%s context=%s "
            "invocation_parent=%s invocation_byte=%u substituted_bytes=%zu active_frame=%d "
            "parse_error_kind=%s parse_error_start=%u parse_error_end=%u\n",
            code, macro_name ? macro_name : "none", rust_macro_context_name(context), parent_kind,
            ts_node_start_byte(invocation), body_len, active_frame, error_kind, error_start,
            error_end);
    if (substituted_body) {
        size_t preview_len = body_len < 512 ? body_len : 512;
        fprintf(stderr,
                "ERROR level=error msg=rust_macro.expansion_source code=%s macro=%s "
                "context=%s substituted_preview_bytes=%zu substituted_truncated=%s "
                "substituted_preview_hex=",
                code, macro_name ? macro_name : "none", rust_macro_context_name(context),
                preview_len, preview_len == body_len ? "false" : "true");
        for (size_t i = 0; i < preview_len; i++) {
            fprintf(stderr, "%02x", (unsigned char)substituted_body[i]);
        }
        fputc('\n', stderr);
    }
}

extern const TSLanguage *tree_sitter_rust(void);

static char *rust_macro_wrap_expansion(RustLSPContext *ctx, RustMacroExpansionContext context,
                                       const char *substituted, size_t *expansion_start,
                                       size_t *expansion_end) {
    if (!expansion_start || !expansion_end) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_CONTEXT_INVALID",
                              "rust_lsp_macro_expansion_bounds", 0);
        return NULL;
    }
    *expansion_start = 0;
    *expansion_end = 0;
    switch (context) {
    case RUST_MACRO_CONTEXT_EXPRESSION: {
        static const char prefix[] = "fn __cbm_macro_expand() { let _ = {\n";
        static const char suffix[] = "\n}; }\n";
        size_t body_len = strlen(substituted);
        size_t prefix_len = sizeof(prefix) - 1;
        if (body_len > SIZE_MAX - prefix_len) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                                  "rust_lsp_macro_expression_bounds", body_len);
            return NULL;
        }
        char *wrapped = cbm_arena_sprintf(ctx->arena, "%s%s%s", prefix, substituted, suffix);
        if (wrapped) {
            *expansion_start = prefix_len;
            *expansion_end = prefix_len + body_len;
        }
        return wrapped;
    }
    case RUST_MACRO_CONTEXT_STATEMENT:
        return cbm_arena_sprintf(ctx->arena, "fn __cbm_macro_expand() { %s }\n", substituted);
    case RUST_MACRO_CONTEXT_ITEM:
        return cbm_arena_sprintf(ctx->arena, "%s\n", substituted);
    case RUST_MACRO_CONTEXT_ASSOCIATED_ITEM:
        return cbm_arena_sprintf(ctx->arena, "struct __CbmMacroSelf; impl __CbmMacroSelf { %s }\n",
                                 substituted);
    case RUST_MACRO_CONTEXT_TYPE:
        return cbm_arena_sprintf(ctx->arena, "type __CbmMacroType = %s;\n", substituted);
    case RUST_MACRO_CONTEXT_PATTERN:
        return cbm_arena_sprintf(ctx->arena,
                                 "fn __cbm_macro_expand() { match () { %s => {}, _ => {} } }\n",
                                 substituted);
    }
    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_CONTEXT_INVALID",
                          "rust_lsp_macro_expansion_context", (size_t)context);
    return NULL;
}

static bool rust_macro_node_is_expression(RustLSPContext *ctx, TSNode node, bool *is_expression) {
    if (!ctx || !is_expression || ts_node_is_null(node)) {
        if (ctx) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_GRAMMAR_INVALID",
                                  "rust_lsp_macro_expression_supertype", 0);
        }
        return false;
    }
    *is_expression = false;
    const TSLanguage *language = tree_sitter_rust();
    uint32_t supertype_count = 0;
    const TSSymbol *supertypes = ts_language_supertypes(language, &supertype_count);
    TSSymbol expression_supertype = 0;
    bool found_expression_supertype = false;
    for (uint32_t i = 0; i < supertype_count; i++) {
        const char *name = ts_language_symbol_name(language, supertypes[i]);
        if (name && strcmp(name, "_expression") == 0) {
            expression_supertype = supertypes[i];
            found_expression_supertype = true;
            break;
        }
    }
    if (!found_expression_supertype) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_GRAMMAR_INVALID",
                              "rust_lsp_macro_expression_supertype", supertype_count);
        return false;
    }
    uint32_t subtype_count = 0;
    const TSSymbol *subtypes = ts_language_subtypes(language, expression_supertype, &subtype_count);
    TSSymbol node_symbol = ts_node_grammar_symbol(node);
    for (uint32_t i = 0; i < subtype_count; i++) {
        if (subtypes[i] == node_symbol) {
            *is_expression = true;
            break;
        }
    }
    return true;
}

static TSNode rust_macro_expression_shape_fail(RustLSPContext *ctx, const char *macro_name,
                                               TSNode invocation, const char *substituted,
                                               size_t expansion_start, size_t expansion_end,
                                               const char *reason, TSNode observed) {
    TSNode parent = ts_node_parent(invocation);
    const char *parent_kind = ts_node_is_null(parent) ? "none" : ts_node_type(parent);
    const char *observed_kind = ts_node_is_null(observed) ? "none" : ts_node_type(observed);
    uint32_t observed_start = ts_node_is_null(observed) ? 0 : ts_node_start_byte(observed);
    uint32_t observed_end = ts_node_is_null(observed) ? 0 : ts_node_end_byte(observed);
    size_t body_len = substituted ? strlen(substituted) : 0;
    fprintf(stderr,
            "ERROR level=error msg=rust_macro.expression_shape_invalid "
            "code=CBM_RUST_MACRO_EXPANSION_INVALID macro=%s context=expression "
            "invocation_parent=%s invocation_byte=%u substituted_bytes=%zu "
            "expansion_start=%zu expansion_end=%zu reason=%s observed_kind=%s "
            "observed_start=%u observed_end=%u\n",
            macro_name ? macro_name : "none", parent_kind, ts_node_start_byte(invocation), body_len,
            expansion_start, expansion_end, reason ? reason : "none", observed_kind, observed_start,
            observed_end);
    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_EXPANSION_INVALID",
                          "rust_lsp_macro_expression_shape", body_len);
    TSNode none = {0};
    return none;
}

static TSNode rust_macro_expression_subtree(RustLSPContext *ctx, TSNode root,
                                            const char *macro_name, TSNode invocation,
                                            const char *substituted, size_t expansion_start,
                                            size_t expansion_end) {
    if (expansion_end < expansion_start) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "inverted_expansion_bounds", root);
    }
    if (ts_node_named_child_count(root) != 1) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "wrapper_root_cardinality", root);
    }
    TSNode function = ts_node_named_child(root, 0);
    if (strcmp(ts_node_type(function), "function_item") != 0) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "wrapper_function_missing", function);
    }
    TSNode function_body = ts_node_child_by_field_name(function, "body", 4);
    if (ts_node_is_null(function_body) || strcmp(ts_node_type(function_body), "block") != 0 ||
        ts_node_named_child_count(function_body) != 1) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "wrapper_function_body", function_body);
    }
    TSNode binding = ts_node_named_child(function_body, 0);
    if (strcmp(ts_node_type(binding), "let_declaration") != 0) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "wrapper_binding_missing", binding);
    }
    TSNode value = ts_node_child_by_field_name(binding, "value", 5);
    if (ts_node_is_null(value) || strcmp(ts_node_type(value), "block") != 0 ||
        expansion_start < ts_node_start_byte(value) || expansion_end > ts_node_end_byte(value)) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "wrapper_value_bounds", value);
    }

    TSNode expression = {0};
    uint32_t child_count = ts_node_named_child_count(value);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_named_child(value, i);
        uint32_t child_start = ts_node_start_byte(child);
        uint32_t child_end = ts_node_end_byte(child);
        if (child_end <= expansion_start || child_start >= expansion_end) {
            continue;
        }
        if (child_start < expansion_start || child_end > expansion_end) {
            return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                    expansion_start, expansion_end,
                                                    "partial_expansion_overlap", child);
        }
        const char *kind = ts_node_type(child);
        if (strcmp(kind, "line_comment") == 0 || strcmp(kind, "block_comment") == 0) {
            continue;
        }
        if (strcmp(kind, "attribute_item") == 0 && ts_node_is_null(expression)) {
            continue;
        }

        TSNode candidate = child;
        if (strcmp(kind, "expression_statement") == 0) {
            if (ts_node_named_child_count(child) != 1) {
                return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                        expansion_start, expansion_end,
                                                        "expression_statement_shape", child);
            }
            candidate = ts_node_named_child(child, 0);
            if (ts_node_is_null(candidate) || ts_node_start_byte(candidate) < child_start ||
                ts_node_end_byte(candidate) > child_end) {
                return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                        expansion_start, expansion_end,
                                                        "expression_statement_bounds", child);
            }
        }
        bool is_expression = false;
        if (!rust_macro_node_is_expression(ctx, candidate, &is_expression)) {
            TSNode none = {0};
            return none;
        }
        if (!is_expression || !ts_node_is_null(expression)) {
            return rust_macro_expression_shape_fail(
                ctx, macro_name, invocation, substituted, expansion_start, expansion_end,
                is_expression ? "multiple_expressions" : "non_expression_child", candidate);
        }
        expression = candidate;
    }
    if (ts_node_is_null(expression)) {
        return rust_macro_expression_shape_fail(ctx, macro_name, invocation, substituted,
                                                expansion_start, expansion_end,
                                                "expression_missing", value);
    }
    return expression;
}

static void rust_macro_walk_expansion(RustLSPContext *ctx, RustMacroExpansionContext context,
                                      TSNode root, const char *macro_name, TSNode invocation,
                                      const char *substituted, size_t expansion_start,
                                      size_t expansion_end) {
    if (context == RUST_MACRO_CONTEXT_EXPRESSION) {
        TSNode expression = rust_macro_expression_subtree(
            ctx, root, macro_name, invocation, substituted, expansion_start, expansion_end);
        if (!ts_node_is_null(expression)) {
            rust_resolve_calls_in_node(ctx, expression);
        }
        return;
    }
    if (context == RUST_MACRO_CONTEXT_ITEM) {
        uint32_t count = ts_node_child_count(root);
        for (uint32_t i = 0; i < count; i++) {
            TSNode item = ts_node_child(root, i);
            if (ts_node_is_null(item) || !ts_node_is_named(item)) {
                continue;
            }
            if (strcmp(ts_node_type(item), "function_item") == 0) {
                rust_process_function(ctx, item, NULL);
            } else {
                rust_resolve_calls_in_node(ctx, item);
            }
        }
        return;
    }
    if (context == RUST_MACRO_CONTEXT_ASSOCIATED_ITEM) {
        uint32_t root_count = ts_node_child_count(root);
        for (uint32_t i = 0; i < root_count; i++) {
            TSNode top = ts_node_child(root, i);
            if (ts_node_is_null(top) || strcmp(ts_node_type(top), "impl_item") != 0) {
                continue;
            }
            TSNode body = ts_node_child_by_field_name(top, "body", 4);
            uint32_t body_count = ts_node_child_count(body);
            for (uint32_t j = 0; j < body_count; j++) {
                TSNode item = ts_node_child(body, j);
                if (ts_node_is_null(item) || !ts_node_is_named(item)) {
                    continue;
                }
                if (strcmp(ts_node_type(item), "function_item") == 0) {
                    rust_process_function(ctx, item, ctx->self_type_qn);
                } else {
                    rust_resolve_calls_in_node(ctx, item);
                }
            }
        }
        return;
    }
    rust_resolve_calls_in_node(ctx, root);
}

/* Re-parse a user macro's exact transcriber body in the invocation's Rust
 * grammar context, then walk only the resulting synthetic tree for calls. */
static void rust_expand_user_macro(RustLSPContext *ctx, const char *mname, TSNode invocation) {
    if (!ctx || !mname || !ctx->macro_rules_arr)
        return;
    if (ctx->macro_expand_depth >= ctx->macro_expand_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_macro_expansion_depth",
                              (size_t)ctx->macro_expand_depth_limit);
        return;
    }

    /* Only a locally-defined macro_rules! is in scope for this resolver.
     * Unknown names may be imported/procedural macros and are left to the
     * explicit unresolved-macro path rather than guessed here. */
    uint32_t invocation_byte =
        ctx->macro_origin_valid ? ctx->macro_origin_byte : ts_node_start_byte(invocation);
    bool has_named_rule = false;
    uint32_t selected_definition_start = 0;
    for (int i = 0; i < ctx->macro_rules_count; i++) {
        RustMacroRule *rule = ctx->macro_rules_arr[i];
        if (!rule || !rule->macro_name || strcmp(rule->macro_name, mname) != 0 ||
            rule->definition_start_byte >= invocation_byte ||
            invocation_byte < rule->scope_start_byte || invocation_byte >= rule->scope_end_byte) {
            continue;
        }
        if (!has_named_rule || rule->definition_start_byte > selected_definition_start) {
            has_named_rule = true;
            selected_definition_start = rule->definition_start_byte;
        }
    }
    if (!has_named_rule) {
        return;
    }

    /* Extract the invocation token tree.  The current tree-sitter-rust
     * grammar exposes it as a typed child, not an `arguments` field. */
    TSNode args_tt = {0};
    uint32_t child_count = ts_node_child_count(invocation);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(invocation, i);
        if (!ts_node_is_null(child) && strcmp(ts_node_type(child), "token_tree") == 0) {
            args_tt = child;
            break;
        }
    }
    if (ts_node_is_null(args_tt)) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_INVOCATION_INVALID",
                              "rust_lsp_macro_arguments_missing", 0);
        return;
    }
    char *args_text = cbm_node_text(ctx->arena, args_tt, ctx->source);
    if (!args_text) {
        return;
    }
    const char *inv_args = NULL;
    int inv_args_len = 0;
    rust_macro_strip_outer(args_text, (int)strlen(args_text), &inv_args, &inv_args_len);

    TSParser *parser = ts_parser_new();
    if (!parser) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PARSER_ALLOC_FAILED",
                              "rust_lsp_macro_parser_new", 0);
        return;
    }
    if (!ts_parser_set_language(parser, tree_sitter_rust())) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_GRAMMAR_ABI_MISMATCH",
                              "rust_lsp_macro_parser_language", 0);
        ts_parser_delete(parser);
        return;
    }

    /* Rust tries rules in source order and transcribes only the first exact
     * success.  A mismatch never grants permission to expand another body. */
    RustMacroRule *hit = NULL;
    int candidate_rule_count = 0;
    MacroEnv env = {
        .ctx = ctx,
        .fragment_parser = parser,
        .captures = NULL,
        .macro_name = mname,
        .invocation_byte = invocation_byte,
    };

    for (int i = 0; i < ctx->macro_rules_count; i++) {
        RustMacroRule *r = ctx->macro_rules_arr[i];
        if (!r || !r->macro_name || strcmp(r->macro_name, mname) != 0 ||
            r->definition_start_byte != selected_definition_start)
            continue;
        candidate_rule_count++;
        env.captures = NULL;
        if (!r->pattern_text || !r->transcriber_text) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_RULE_INVALID",
                                  "rust_lsp_macro_rule_text", 0);
            break;
        }
        MacroMatchStatus match = macro_pattern_match(&env, r->pattern_text, (size_t)r->pattern_len,
                                                     inv_args, (size_t)inv_args_len);
        if (match == MACRO_MATCH) {
            hit = r;
            break;
        }
        if (match == MACRO_FATAL) {
            break;
        }
    }
    if (cbm_arena_failed(ctx->arena)) {
        macro_log_fragment_parse_work(&env, "fatal");
        ts_parser_delete(parser);
        return;
    }
    if (!hit) {
        macro_log_fragment_parse_work(&env, "no_match");
        size_t invocation_len = inv_args_len > 0 ? (size_t)inv_args_len : 0;
        size_t preview_len = invocation_len < 512 ? invocation_len : 512;
        bool fragment_invalid = env.miss_kind == MACRO_MISS_FRAGMENT;
        const char *failure_code =
            fragment_invalid ? "CBM_RUST_MACRO_FRAGMENT_INVALID" : "CBM_RUST_MACRO_NO_MATCH";
        const char *failure_kind = fragment_invalid ? "fragment_invalid" : "token_mismatch";
        const char *failure_operation = fragment_invalid ? "rust_lsp_macro_fragment_selection"
                                                         : "rust_lsp_macro_rule_selection";
        fprintf(stderr,
                "ERROR level=error msg=rust_macro.no_rule_match "
                "code=%s macro=%s invocation_byte=%u "
                "invocation_bytes=%zu declared_rules=%d invocation_preview_bytes=%zu "
                "invocation_truncated=%s failure_kind=%s furthest_input_byte=%zu "
                "furthest_matcher_byte=%zu candidate_start_byte=%zu candidate_end_byte=%zu "
                "candidate_fragment=%.*s invocation_preview_hex=",
                failure_code, mname, invocation_byte, invocation_len, candidate_rule_count,
                preview_len, preview_len == invocation_len ? "false" : "true", failure_kind,
                env.furthest_input_byte, env.furthest_matcher_byte, env.candidate_start_byte,
                env.candidate_end_byte, (int)env.candidate_fragment_len,
                env.candidate_fragment ? env.candidate_fragment : "");
        for (size_t i = 0; i < preview_len; i++) {
            fprintf(stderr, "%02x", (unsigned char)inv_args[i]);
        }
        fputc('\n', stderr);
        cbm_arena_mark_failed(ctx->arena, failure_code, failure_operation, (size_t)inv_args_len);
        ts_parser_delete(parser);
        return;
    }
    macro_log_fragment_parse_work(&env, "matched");

    /* Substitute the bound metavars into the transcriber body. */
    char *substituted = macro_substitute(&env, hit->transcriber_text, (size_t)hit->transcriber_len);
    if (!substituted) {
        ts_parser_delete(parser);
        return;
    }

    RustMacroExpansionContext context = rust_macro_invocation_context(invocation);
    int active_frame = -1;
    if (rust_macro_expansion_active(ctx, mname, substituted, &active_frame)) {
        rust_macro_log_failure("CBM_RUST_MACRO_RECURSION_CYCLE", mname, context, invocation,
                               substituted, (TSNode){0}, active_frame);
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_RECURSION_CYCLE",
                              "rust_lsp_macro_expansion_cycle", strlen(substituted));
        ts_parser_delete(parser);
        return;
    }
    if (!rust_macro_expansion_push(ctx, mname, substituted)) {
        ts_parser_delete(parser);
        return;
    }

    size_t expansion_start = 0;
    size_t expansion_end = 0;
    char *wrapped =
        rust_macro_wrap_expansion(ctx, context, substituted, &expansion_start, &expansion_end);
    if (!wrapped) {
        rust_macro_expansion_pop(ctx, mname, substituted);
        ts_parser_delete(parser);
        return;
    }
    size_t wrapped_len = strlen(wrapped);
    if (wrapped_len > UINT32_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_OUTPUT_OVERFLOW",
                              "rust_lsp_macro_synthetic_source", wrapped_len);
        rust_macro_expansion_pop(ctx, mname, substituted);
        ts_parser_delete(parser);
        return;
    }
    if (!macro_work(ctx, wrapped_len, "rust_lsp_macro_expansion_parse")) {
        rust_macro_expansion_pop(ctx, mname, substituted);
        ts_parser_delete(parser);
        return;
    }
    TSTree *tree = ts_parser_parse_string(parser, NULL, wrapped, (uint32_t)wrapped_len);
    if (!tree) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_EXPANSION_PARSE_FAILED",
                              "rust_lsp_macro_expansion_parser", wrapped_len);
        rust_macro_expansion_pop(ctx, mname, substituted);
        ts_parser_delete(parser);
        return;
    }
    TSNode root = ts_tree_root_node(tree);
    if (ts_node_has_error(root)) {
        rust_macro_log_failure("CBM_RUST_MACRO_EXPANSION_INVALID", mname, context, invocation,
                               substituted, root, -1);
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_EXPANSION_INVALID",
                              "rust_lsp_macro_expansion_syntax", wrapped_len);
        ts_tree_delete(tree);
        rust_macro_expansion_pop(ctx, mname, substituted);
        ts_parser_delete(parser);
        return;
    }
    uint32_t saved_origin_byte = ctx->macro_origin_byte;
    int saved_origin_line = ctx->macro_origin_line;
    bool saved_origin_valid = ctx->macro_origin_valid;
    if (!ctx->macro_origin_valid) {
        ctx->macro_origin_byte = invocation_byte;
        ctx->macro_origin_line = (int)ts_node_start_point(invocation).row + 1;
        ctx->macro_origin_valid = true;
    }
    ctx->macro_expand_depth++;
    const char *saved_source = ctx->source;
    int saved_len = ctx->source_len;
    ctx->source = wrapped;
    ctx->source_len = (int)wrapped_len;
    ctx->inject_syn_calls++;
    rust_macro_walk_expansion(ctx, context, root, mname, invocation, substituted, expansion_start,
                              expansion_end);
    ctx->inject_syn_calls--;
    ctx->source = saved_source;
    ctx->source_len = saved_len;
    ctx->macro_expand_depth--;
    ctx->macro_origin_byte = saved_origin_byte;
    ctx->macro_origin_line = saved_origin_line;
    ctx->macro_origin_valid = saved_origin_valid;
    ts_tree_delete(tree);
    rust_macro_expansion_pop(ctx, mname, substituted);
    ts_parser_delete(parser);
}

/* Known standard macros do not share one argument grammar.  Treating every raw
 * token tree as a tuple expression loses valid `vec![value; count]` and named
 * formatting operands, while walking token soup can invent calls in tokens the
 * macro never evaluates.  Reparse the whole input with Rust's expression grammar
 * to recover exact operand spans, validate the selected macro's semantic grammar,
 * and parse each evaluated operand independently.  Any unsupported form or
 * parser failure makes the arena sticky-failed, so an incomplete file can never
 * be published as a complete semantic graph. */
typedef struct {
    const MacroToken *first;
    const MacroToken *last;
    char separator_after;
} RustKnownMacroArg;

typedef struct {
    uint32_t wrapped_start;
    uint32_t wrapped_end;
} RustKnownMacroOperandSpan;

static bool rust_known_macro_fail(RustLSPContext *ctx, const char *operation, size_t requested) {
    cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_FORM_UNSUPPORTED", operation,
                          requested);
    return false;
}

static bool rust_known_macro_parse_args(RustLSPContext *ctx, const char *macro_name,
                                        const char *source, size_t source_len,
                                        RustKnownMacroArg **out_args, size_t *out_count) {
    MacroToken *tokens = NULL;
    const char *canonical_source = NULL;
    size_t canonical_source_len = 0;
    if (!macro_lex(ctx, source, source_len, &tokens, &canonical_source, &canonical_source_len)) {
        return false;
    }
    source = canonical_source;
    source_len = canonical_source_len;

    if (source_len > (size_t)INT_MAX || source_len > UINT32_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_OVERFLOW",
                              "rust_lsp_known_macro_argument_source", source_len);
        return false;
    }
    bool vec_macro = strcmp(macro_name, "vec") == 0;
    const char *prefix =
        vec_macro ? "fn __cbm_macro_args() { let _ = [" : "fn __cbm_macro_args() { __cbm_macro(";
    const char *suffix = vec_macro ? "]; }\n" : "); }\n";
    size_t prefix_len = strlen(prefix);
    size_t wrapper_len = prefix_len + source_len + strlen(suffix);
    if (wrapper_len > UINT32_MAX || wrapper_len > (size_t)INT_MAX ||
        !macro_work(ctx, wrapper_len, "rust_lsp_known_macro_argument_grammar")) {
        if (!cbm_arena_failed(ctx->arena)) {
            cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_OVERFLOW",
                                  "rust_lsp_known_macro_argument_wrapper", wrapper_len);
        }
        return false;
    }
    char *wrapped =
        cbm_arena_sprintf(ctx->arena, "%s%.*s%s", prefix, (int)source_len, source, suffix);
    if (!wrapped) {
        return false;
    }

    TSParser *parser = ts_parser_new();
    if (!parser) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PARSER_ALLOC_FAILED",
                              "rust_lsp_known_macro_argument_parser_new", wrapper_len);
        return false;
    }
    if (!ts_parser_set_language(parser, tree_sitter_rust())) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_GRAMMAR_ABI_MISMATCH",
                              "rust_lsp_known_macro_argument_parser_language", wrapper_len);
        ts_parser_delete(parser);
        return false;
    }
    TSTree *tree = ts_parser_parse_string(parser, NULL, wrapped, (uint32_t)wrapper_len);
    if (!tree) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_PARSE_FAILED",
                              "rust_lsp_known_macro_argument_grammar", source_len);
        ts_parser_delete(parser);
        return false;
    }
    TSNode root = ts_tree_root_node(tree);
    if (ts_node_has_error(root)) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return rust_known_macro_fail(ctx, "rust_lsp_known_macro_argument_grammar", source_len);
    }

    const char *marker = vec_macro ? "[" : "__cbm_macro(";
    const char *marker_at = strstr(prefix, marker);
    if (!marker_at) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return rust_known_macro_fail(ctx, "rust_lsp_known_macro_wrapper_marker", source_len);
    }
    uint32_t outer_start = (uint32_t)(marker_at - prefix);
    uint32_t outer_end = (uint32_t)(prefix_len + source_len + 1);
    TSNode outer = ts_node_named_descendant_for_byte_range(root, outer_start, outer_end);
    const char *expected_type = vec_macro ? "array_expression" : "call_expression";
    if (ts_node_is_null(outer) || strcmp(ts_node_type(outer), expected_type) != 0 ||
        ts_node_start_byte(outer) != outer_start || ts_node_end_byte(outer) != outer_end) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return rust_known_macro_fail(ctx, "rust_lsp_known_macro_wrapper_shape", source_len);
    }
    TSNode operands = outer;
    if (!vec_macro) {
        operands = ts_node_child_by_field_name(outer, "arguments", 9);
        if (ts_node_is_null(operands) || strcmp(ts_node_type(operands), "arguments") != 0) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return rust_known_macro_fail(ctx, "rust_lsp_known_macro_arguments_node", source_len);
        }
    }

    RustKnownMacroOperandSpan *operand_spans = NULL;
    size_t operand_count = 0;
    size_t operand_capacity = 0;
    bool has_pending_attributes = false;
    uint32_t pending_attribute_start = 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(operands); i++) {
        TSNode child = ts_node_named_child(operands, i);
        if (ts_node_is_null(child) || ts_node_is_extra(child)) {
            continue;
        }
        if (strcmp(ts_node_type(child), "attribute_item") == 0) {
            if (!has_pending_attributes) {
                pending_attribute_start = ts_node_start_byte(child);
                has_pending_attributes = true;
            }
            continue;
        }
        if (!cbm_lsp_semantic_array_reserve(
                ctx->arena, (void **)&operand_spans, operand_count, &operand_capacity,
                sizeof(*operand_spans), operand_count + 1, "rust known macro grammar operands")) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return false;
        }
        operand_spans[operand_count++] = (RustKnownMacroOperandSpan){
            .wrapped_start =
                has_pending_attributes ? pending_attribute_start : ts_node_start_byte(child),
            .wrapped_end = ts_node_end_byte(child),
        };
        has_pending_attributes = false;
    }
    if (has_pending_attributes) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return rust_known_macro_fail(ctx, "rust_lsp_known_macro_dangling_attribute",
                                     operand_count);
    }

    RustKnownMacroArg *args = NULL;
    size_t count = 0;
    size_t capacity = 0;
    const MacroToken *cursor = tokens;
    for (size_t i = 0; i < operand_count; i++) {
        uint32_t wrapped_start = operand_spans[i].wrapped_start;
        uint32_t wrapped_end = operand_spans[i].wrapped_end;
        if (wrapped_start < prefix_len || wrapped_end <= wrapped_start ||
            wrapped_end > prefix_len + source_len) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return rust_known_macro_fail(ctx, "rust_lsp_known_macro_operand_range", i);
        }
        const char *operand_start = source + (wrapped_start - (uint32_t)prefix_len);
        const char *operand_end = source + (wrapped_end - (uint32_t)prefix_len);
        if (!cursor || cursor->text != operand_start) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return rust_known_macro_fail(ctx, "rust_lsp_known_macro_operand_start", i);
        }
        const MacroToken *first = cursor;
        const MacroToken *last = NULL;
        while (cursor && cursor->text + cursor->len <= operand_end) {
            last = cursor;
            cursor = cursor->next;
        }
        if (!last || last->text + last->len != operand_end) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return rust_known_macro_fail(ctx, "rust_lsp_known_macro_operand_end", i);
        }
        char separator = 0;
        if (cursor && (macro_token_text_is(cursor, ",") || macro_token_text_is(cursor, ";"))) {
            separator = cursor->text[0];
            cursor = cursor->next;
        }
        if (i + 1 < operand_count) {
            uint32_t next_start = operand_spans[i + 1].wrapped_start;
            const char *expected_next = source + (next_start - (uint32_t)prefix_len);
            if (!separator || !cursor || cursor->text != expected_next) {
                ts_tree_delete(tree);
                ts_parser_delete(parser);
                return rust_known_macro_fail(ctx, "rust_lsp_known_macro_operand_separator", i);
            }
        } else if (cursor) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return rust_known_macro_fail(ctx, "rust_lsp_known_macro_trailing_tokens", i);
        }
        if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&args, count, &capacity,
                                            sizeof(*args), count + 1,
                                            "rust known macro argument spans")) {
            ts_tree_delete(tree);
            ts_parser_delete(parser);
            return false;
        }
        args[count++] = (RustKnownMacroArg){
            .first = first,
            .last = last,
            .separator_after = separator,
        };
    }
    if ((operand_count == 0 && tokens) || cursor) {
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return rust_known_macro_fail(ctx, "rust_lsp_known_macro_unmapped_tokens", source_len);
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    *out_args = args;
    *out_count = count;
    return true;
}

static bool rust_known_macro_comma_list(RustLSPContext *ctx, const RustKnownMacroArg *args,
                                        size_t count, const char *operation) {
    for (size_t i = 0; i < count; i++) {
        char separator = args[i].separator_after;
        if ((i + 1 < count && separator != ',') ||
            (i + 1 == count && separator != 0 && separator != ',')) {
            return rust_known_macro_fail(ctx, operation, count);
        }
    }
    return true;
}

static bool macro_token_is_string_literal(const MacroToken *token) {
    if (!token || token->open || token->len < 2) {
        return false;
    }
    if (token->text[0] == '"') {
        return macro_scan_quoted(token->text, token->len, 0, '"') == token->len;
    }
    return token->text[0] == 'r' && macro_scan_raw_string(token->text, token->len, 0) == token->len;
}

static bool macro_token_is_concat_literal(const MacroToken *token) {
    if (!macro_token_is_literal(token)) {
        return false;
    }
    if (macro_token_is_string_literal(token) || macro_token_text_is(token, "true") ||
        macro_token_text_is(token, "false") || isdigit((unsigned char)token->text[0]) ||
        token->text[0] == '\'') {
        return true;
    }
    /* rustc rejects byte/byte-string and C-string literals in concat!. */
    return false;
}

static bool rust_literal_producer_arg(RustLSPContext *ctx, const RustKnownMacroArg *arg,
                                      size_t depth);

static bool rust_concat_literal_arg(RustLSPContext *ctx, const RustKnownMacroArg *arg,
                                    size_t depth) {
    if (!arg || !arg->first || !arg->last) {
        return false;
    }
    if (arg->first == arg->last && macro_token_is_concat_literal(arg->first)) {
        return true;
    }
    const MacroToken *minus = arg->first;
    const MacroToken *number = minus ? minus->next : NULL;
    if (number && number == arg->last && macro_token_text_is(minus, "-") && !number->open &&
        number->len > 0 && isdigit((unsigned char)number->text[0])) {
        return true;
    }
    return rust_literal_producer_arg(ctx, arg, depth);
}

static bool rust_literal_producer_arg(RustLSPContext *ctx, const RustKnownMacroArg *arg,
                                      size_t depth) {
    if (!ctx || !arg || !arg->first || !arg->last) {
        return false;
    }
    if (arg->first == arg->last && macro_token_is_string_literal(arg->first)) {
        return true;
    }
    if (depth >= (size_t)ctx->macro_expand_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_literal_producer_depth", depth);
        return false;
    }
    const MacroToken *name = arg->first;
    const MacroToken *bang = name->next;
    const MacroToken *group = bang ? bang->next : NULL;
    if (!macro_token_is_identifier(name) || !macro_token_text_is(bang, "!") || !group ||
        !group->open || group != arg->last) {
        return false;
    }

    if (macro_token_text_is(name, "stringify")) {
        /* Rust accepts any balanced token tree, including an empty one. */
        return true;
    }
    if (macro_token_text_is(name, "file") || macro_token_text_is(name, "module_path")) {
        return group->children == NULL;
    }

    bool concat = macro_token_text_is(name, "concat");
    bool env = macro_token_text_is(name, "env");
    bool include_str = macro_token_text_is(name, "include_str");
    if (!concat && !env && !include_str) {
        return false;
    }
    if (group->len < 2) {
        return false;
    }
    RustKnownMacroArg *nested = NULL;
    size_t nested_count = 0;
    const char *inner = group->text + 1;
    size_t inner_len = group->len - 2;
    const char *producer_name = concat ? "concat" : (env ? "env" : "include_str");
    if (!rust_known_macro_parse_args(ctx, producer_name, inner, inner_len, &nested,
                                     &nested_count) ||
        !rust_known_macro_comma_list(ctx, nested, nested_count,
                                     "rust_lsp_literal_producer_separators")) {
        return false;
    }
    if ((env && (nested_count == 0 || nested_count > 2)) || (include_str && nested_count != 1)) {
        return false;
    }
    for (size_t i = 0; i < nested_count; i++) {
        bool valid = concat ? rust_concat_literal_arg(ctx, &nested[i], depth + 1)
                            : rust_literal_producer_arg(ctx, &nested[i], depth + 1);
        if (!valid) {
            return false;
        }
    }
    return true;
}

static bool rust_resolve_known_macro_expr(RustLSPContext *ctx, const RustKnownMacroArg *arg,
                                          const MacroToken *first, const char *operation) {
    const MacroToken *span_first = first ? first : arg->first;
    if (!span_first || !arg->last) {
        return rust_known_macro_fail(ctx, operation, 0);
    }
    size_t expr_len = macro_capture_length(span_first, arg->last);
    if (expr_len == 0 || expr_len > (size_t)INT_MAX || expr_len > UINT32_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_OVERFLOW", operation,
                              expr_len);
        return false;
    }
    if (ctx->macro_expand_depth >= ctx->macro_expand_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_known_macro_argument_depth",
                              (size_t)ctx->macro_expand_depth_limit);
        return false;
    }
    if (!macro_work(ctx, expr_len + 1, operation)) {
        return false;
    }

    char *wrapped = cbm_arena_sprintf(ctx->arena, "fn __cbm_macro_arg() { let _ = [%.*s]; }\n",
                                      (int)expr_len, span_first->text);
    if (!wrapped) {
        return false;
    }
    size_t wrapped_len = strlen(wrapped);
    if (wrapped_len > UINT32_MAX || wrapped_len > (size_t)INT_MAX) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_OVERFLOW",
                              "rust_lsp_known_macro_synthetic_source", wrapped_len);
        return false;
    }

    TSParser *parser = ts_parser_new();
    if (!parser) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_PARSER_ALLOC_FAILED",
                              "rust_lsp_known_macro_parser_new", wrapped_len);
        return false;
    }
    if (!ts_parser_set_language(parser, tree_sitter_rust())) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_MACRO_GRAMMAR_ABI_MISMATCH",
                              "rust_lsp_known_macro_parser_language", wrapped_len);
        ts_parser_delete(parser);
        return false;
    }
    TSTree *tree = ts_parser_parse_string(parser, NULL, wrapped, (uint32_t)wrapped_len);
    if (!tree) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_PARSE_FAILED", operation, expr_len);
        ts_parser_delete(parser);
        return false;
    }
    TSNode root = ts_tree_root_node(tree);
    if (ts_node_has_error(root)) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_INVALID", operation,
                              expr_len);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return false;
    }

    TSNode body = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(root); i++) {
        TSNode top = ts_node_named_child(root, i);
        if (!ts_node_is_null(top) && strcmp(ts_node_type(top), "function_item") == 0) {
            body = ts_node_child_by_field_name(top, "body", 4);
            break;
        }
    }
    if (ts_node_is_null(body)) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_EXPRESSION_INVALID", operation,
                              expr_len);
        ts_tree_delete(tree);
        ts_parser_delete(parser);
        return false;
    }

    const char *saved_source = ctx->source;
    int saved_len = ctx->source_len;
    ctx->source = wrapped;
    ctx->source_len = (int)wrapped_len;
    ctx->macro_expand_depth++;
    ctx->inject_syn_calls++;
    rust_resolve_calls_in_node(ctx, body);
    ctx->inject_syn_calls--;
    ctx->macro_expand_depth--;
    ctx->source = saved_source;
    ctx->source_len = saved_len;

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return !cbm_arena_failed(ctx->arena);
}

static bool rust_resolve_format_macro_args(RustLSPContext *ctx, const char *macro_name,
                                           const RustKnownMacroArg *args, size_t count) {
    bool writer = strcmp(macro_name, "write") == 0 || strcmp(macro_name, "writeln") == 0;
    bool newline = strcmp(macro_name, "println") == 0 || strcmp(macro_name, "eprintln") == 0 ||
                   strcmp(macro_name, "writeln") == 0;
    bool panic_macro = strcmp(macro_name, "panic") == 0;
    if (!rust_known_macro_comma_list(ctx, args, count, "rust_lsp_format_macro_separators")) {
        return false;
    }
    if (count == 0) {
        if (writer) {
            return rust_known_macro_fail(ctx, "rust_lsp_write_macro_missing_destination", 0);
        }
        return newline || panic_macro
                   ? true
                   : rust_known_macro_fail(ctx, "rust_lsp_format_macro_missing_format", 0);
    }

    size_t format_index = 0;
    if (writer) {
        if (!rust_resolve_known_macro_expr(ctx, &args[0], NULL,
                                           "rust_lsp_write_macro_destination")) {
            return false;
        }
        if (count == 1) {
            return strcmp(macro_name, "writeln") == 0
                       ? true
                       : rust_known_macro_fail(ctx, "rust_lsp_write_macro_missing_format", count);
        }
        format_index = 1;
    }

    const RustKnownMacroArg *format_arg = &args[format_index];
    bool format_literal = rust_literal_producer_arg(ctx, format_arg, 0);
    if (!format_literal) {
        if (panic_macro && count == 1) {
            return rust_resolve_known_macro_expr(ctx, format_arg, NULL,
                                                 "rust_lsp_legacy_panic_operand");
        }
        return rust_known_macro_fail(ctx, "rust_lsp_format_macro_literal", count);
    }
    if (!rust_resolve_known_macro_expr(ctx, format_arg, NULL,
                                       "rust_lsp_format_macro_format_string")) {
        return false;
    }

    bool named_started = false;
    for (size_t i = format_index + 1; i < count; i++) {
        const MacroToken *first = args[i].first;
        const MacroToken *equals = first ? first->next : NULL;
        bool named =
            first && macro_token_is_identifier(first) && equals && macro_token_text_is(equals, "=");
        if (named) {
            const MacroToken *value = equals->next;
            if (!value || equals == args[i].last) {
                return rust_known_macro_fail(ctx, "rust_lsp_format_macro_named_operand", i);
            }
            named_started = true;
            if (!rust_resolve_known_macro_expr(ctx, &args[i], value,
                                               "rust_lsp_format_macro_named_operand")) {
                return false;
            }
        } else {
            if (named_started) {
                return rust_known_macro_fail(ctx, "rust_lsp_format_macro_positional_after_named",
                                             i);
            }
            if (!rust_resolve_known_macro_expr(ctx, &args[i], NULL,
                                               "rust_lsp_format_macro_positional_operand")) {
                return false;
            }
        }
    }
    return true;
}

static bool rust_resolve_vec_macro_args(RustLSPContext *ctx, const RustKnownMacroArg *args,
                                        size_t count) {
    if (count == 0) {
        return true;
    }
    if (count == 2 && args[0].separator_after == ';' && args[1].separator_after == 0) {
        return rust_resolve_known_macro_expr(ctx, &args[0], NULL, "rust_lsp_vec_value") &&
               rust_resolve_known_macro_expr(ctx, &args[1], NULL, "rust_lsp_vec_count");
    }
    if (!rust_known_macro_comma_list(ctx, args, count, "rust_lsp_vec_separators")) {
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (!rust_resolve_known_macro_expr(ctx, &args[i], NULL, "rust_lsp_vec_element")) {
            return false;
        }
    }
    return true;
}

static bool rust_resolve_fixed_macro_args(RustLSPContext *ctx, const char *macro_name,
                                          const RustKnownMacroArg *args, size_t count) {
    size_t maximum = strcmp(macro_name, "env") == 0 ? 2 : 1;
    if (count == 0 || count > maximum ||
        !rust_known_macro_comma_list(ctx, args, count, "rust_lsp_fixed_macro_separators")) {
        return rust_known_macro_fail(ctx, "rust_lsp_fixed_macro_cardinality", count);
    }
    for (size_t i = 0; i < count; i++) {
        if (!rust_literal_producer_arg(ctx, &args[i], 0)) {
            return rust_known_macro_fail(ctx, "rust_lsp_fixed_macro_literal_operand", i);
        }
        if (!rust_resolve_known_macro_expr(ctx, &args[i], NULL, "rust_lsp_fixed_macro_operand")) {
            return false;
        }
    }
    return true;
}

static bool rust_resolve_concat_macro_args(RustLSPContext *ctx, const RustKnownMacroArg *args,
                                           size_t count) {
    if (!rust_known_macro_comma_list(ctx, args, count, "rust_lsp_concat_macro_separators")) {
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (!rust_concat_literal_arg(ctx, &args[i], 0)) {
            return rust_known_macro_fail(ctx, "rust_lsp_concat_macro_literal_operand", i);
        }
        if (!rust_resolve_known_macro_expr(ctx, &args[i], NULL, "rust_lsp_concat_macro_operand")) {
            return false;
        }
    }
    return true;
}

static bool rust_resolve_known_macro_args(RustLSPContext *ctx, const char *macro_name,
                                          TSNode invocation) {
    if (!ctx || !macro_name || ts_node_is_null(invocation)) {
        return false;
    }
    TSNode args_tt = {0};
    for (uint32_t i = 0; i < ts_node_child_count(invocation); i++) {
        TSNode child = ts_node_child(invocation, i);
        if (!ts_node_is_null(child) && strcmp(ts_node_type(child), "token_tree") == 0) {
            args_tt = child;
            break;
        }
    }
    if (ts_node_is_null(args_tt)) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_INVOCATION_INVALID",
                              "rust_lsp_known_macro_arguments_missing", 0);
        return false;
    }
    char *text = cbm_node_text(ctx->arena, args_tt, ctx->source);
    if (!text) {
        return false;
    }
    const char *inner = NULL;
    int inner_len = 0;
    rust_macro_strip_outer(text, (int)strlen(text), &inner, &inner_len);
    if (inner_len < 0) {
        cbm_arena_mark_failed(ctx->arena, "CBM_RUST_KNOWN_MACRO_INVOCATION_INVALID",
                              "rust_lsp_known_macro_argument_length", 0);
        return false;
    }

    RustKnownMacroArg *args = NULL;
    size_t count = 0;
    if (!rust_known_macro_parse_args(ctx, macro_name, inner, (size_t)inner_len, &args, &count)) {
        return false;
    }

    uint32_t saved_origin_byte = ctx->macro_origin_byte;
    int saved_origin_line = ctx->macro_origin_line;
    bool saved_origin_valid = ctx->macro_origin_valid;
    if (!ctx->macro_origin_valid) {
        ctx->macro_origin_byte = ts_node_start_byte(invocation);
        ctx->macro_origin_line = (int)ts_node_start_point(invocation).row + 1;
        ctx->macro_origin_valid = true;
    }

    bool resolved = false;
    if (strcmp(macro_name, "vec") == 0) {
        resolved = rust_resolve_vec_macro_args(ctx, args, count);
    } else if (strcmp(macro_name, "concat") == 0) {
        resolved = rust_resolve_concat_macro_args(ctx, args, count);
    } else if (strcmp(macro_name, "include") == 0 || strcmp(macro_name, "include_str") == 0 ||
               strcmp(macro_name, "include_bytes") == 0 || strcmp(macro_name, "env") == 0 ||
               strcmp(macro_name, "option_env") == 0) {
        resolved = rust_resolve_fixed_macro_args(ctx, macro_name, args, count);
    } else {
        resolved = rust_resolve_format_macro_args(ctx, macro_name, args, count);
    }
    ctx->macro_origin_byte = saved_origin_byte;
    ctx->macro_origin_line = saved_origin_line;
    ctx->macro_origin_valid = saved_origin_valid;
    return resolved;
}

/* ════════════════════════════════════════════════════════════════════
 * 9. Statement / pattern binding
 * ════════════════════════════════════════════════════════════════════ */

/* Recursively bind every identifier inside a pattern node to the given
 * fallback type. Handles tuple_pattern, struct_pattern, tuple_struct_pattern,
 * ref_pattern, mut_pattern, captured_pattern, identifier. */
static void rust_bind_pattern(RustLSPContext *ctx, TSNode pattern, const CBMType *type) {
    if (ts_node_is_null(pattern))
        return;
    const char *kind = ts_node_type(pattern);

    if (strcmp(kind, "identifier") == 0) {
        char *name = rust_node_text(ctx, pattern);
        if (name && strcmp(name, "_") != 0) {
            cbm_scope_bind(ctx->current_scope, name, type);
        }
        return;
    }
    if (strcmp(kind, "captured_pattern") == 0) {
        /* name @ subpattern */
        TSNode name_node = ts_node_child_by_field_name(pattern, "name", 4);
        if (!ts_node_is_null(name_node)) {
            char *name = rust_node_text(ctx, name_node);
            if (name && strcmp(name, "_") != 0) {
                cbm_scope_bind(ctx->current_scope, name, type);
            }
        }
        TSNode sub = ts_node_child_by_field_name(pattern, "pattern", 7);
        if (!ts_node_is_null(sub))
            rust_bind_pattern(ctx, sub, type);
        return;
    }
    if (strcmp(kind, "ref_pattern") == 0 || strcmp(kind, "mut_pattern") == 0 ||
        strcmp(kind, "reference_pattern") == 0) {
        if (ts_node_named_child_count(pattern) > 0) {
            rust_bind_pattern(ctx, ts_node_named_child(pattern, 0), type);
        }
        return;
    }
    if (strcmp(kind, "tuple_pattern") == 0) {
        const CBMType *base = type;
        while (base && base->kind == CBM_TYPE_REFERENCE)
            base = base->data.reference.elem;
        uint32_t nc = ts_node_named_child_count(pattern);
        for (uint32_t i = 0; i < nc; i++) {
            const CBMType *elem_t = cbm_type_unknown();
            if (base && base->kind == CBM_TYPE_TUPLE && (int)i < base->data.tuple.count) {
                elem_t = base->data.tuple.elems[i];
            }
            rust_bind_pattern(ctx, ts_node_named_child(pattern, i), elem_t);
        }
        return;
    }
    if (strcmp(kind, "tuple_struct_pattern") == 0) {
        /* Some(x), Ok(x), Err(e) — peel one Option/Result/template. */
        const CBMType *base = type;
        while (base && base->kind == CBM_TYPE_REFERENCE)
            base = base->data.reference.elem;
        const CBMType *inner = cbm_type_unknown();
        if (base && base->kind == CBM_TYPE_TEMPLATE && base->data.template_type.arg_count > 0) {
            inner = base->data.template_type.template_args[0];
        }
        uint32_t nc = ts_node_named_child_count(pattern);
        /* First named child is the path; subsequent are sub-patterns. */
        for (uint32_t i = 1; i < nc; i++) {
            rust_bind_pattern(ctx, ts_node_named_child(pattern, i), inner);
        }
        return;
    }
    if (strcmp(kind, "struct_pattern") == 0) {
        /* For each field_pattern, bind the local name to the field's type. */
        TSNode body = ts_node_child_by_field_name(pattern, "body", 4);
        TSNode iter = ts_node_is_null(body) ? pattern : body;
        const CBMType *base = type;
        while (base && base->kind == CBM_TYPE_REFERENCE)
            base = base->data.reference.elem;
        const char *type_qn = NULL;
        if (base && base->kind == CBM_TYPE_NAMED)
            type_qn = base->data.named.qualified_name;
        else if (base && base->kind == CBM_TYPE_TEMPLATE)
            type_qn = base->data.template_type.template_name;

        uint32_t nc = ts_node_named_child_count(iter);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode fp = ts_node_named_child(iter, i);
            const char *fk = ts_node_type(fp);
            if (strcmp(fk, "field_pattern") == 0) {
                TSNode name_node = ts_node_child_by_field_name(fp, "name", 4);
                TSNode pat_node = ts_node_child_by_field_name(fp, "pattern", 7);
                char *fname = rust_node_text(ctx, name_node);
                if (!fname)
                    continue;
                const CBMType *ft =
                    type_qn ? rust_lookup_field(ctx, type_qn, fname, 0) : cbm_type_unknown();
                if (!ft)
                    ft = cbm_type_unknown();
                if (!ts_node_is_null(pat_node)) {
                    rust_bind_pattern(ctx, pat_node, ft);
                } else {
                    cbm_scope_bind(ctx->current_scope, fname, ft);
                }
            } else if (strcmp(fk, "shorthand_field_identifier") == 0 ||
                       strcmp(fk, "identifier") == 0) {
                char *fname = rust_node_text(ctx, fp);
                if (fname && strcmp(fname, "_") != 0) {
                    const CBMType *ft =
                        type_qn ? rust_lookup_field(ctx, type_qn, fname, 0) : cbm_type_unknown();
                    cbm_scope_bind(ctx->current_scope, fname, ft ? ft : cbm_type_unknown());
                }
            }
        }
        return;
    }
    if (strcmp(kind, "or_pattern") == 0) {
        /* For an OR pattern we attempt to bind names from the first branch. */
        if (ts_node_named_child_count(pattern) > 0) {
            rust_bind_pattern(ctx, ts_node_named_child(pattern, 0), type);
        }
        return;
    }
    /* Other patterns we ignore for binding purposes. */
}

void rust_process_statement(RustLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return;
    const char *kind = ts_node_type(node);

    /* let_declaration: let pat: T = expr;
     *
     * Bidirectional inference: if the user wrote `let v: Vec<String> = …;`
     * we pass `Vec<String>` as the expected hint when synthesising the
     * RHS. That lets ambiguous calls like `Vec::new()` keep their full
     * template arguments through the chain. */
    if (strcmp(kind, "let_declaration") == 0) {
        TSNode pat = ts_node_child_by_field_name(node, "pattern", 7);
        TSNode tn = ts_node_child_by_field_name(node, "type", 4);
        TSNode val = ts_node_child_by_field_name(node, "value", 5);

        const CBMType *annotated = NULL;
        if (!ts_node_is_null(tn)) {
            annotated = rust_parse_type_node(ctx, tn);
        }
        const CBMType *let_type = annotated;
        if ((!let_type || cbm_type_is_unknown(let_type)) && !ts_node_is_null(val)) {
            /* Synthesis: evaluate the RHS with the (possibly NULL)
             * annotated type as a hint. */
            let_type = rust_eval_expr_typed(ctx, val, annotated);
        }
        if (!let_type)
            let_type = cbm_type_unknown();
        if (!ts_node_is_null(pat))
            rust_bind_pattern(ctx, pat, let_type);
        return;
    }

    /* const_item / static_item: const NAME: T = …; */
    if (strcmp(kind, "const_item") == 0 || strcmp(kind, "static_item") == 0) {
        TSNode name_node = ts_node_child_by_field_name(node, "name", 4);
        TSNode tn = ts_node_child_by_field_name(node, "type", 4);
        const CBMType *type =
            ts_node_is_null(tn) ? cbm_type_unknown() : rust_parse_type_node(ctx, tn);
        if (!ts_node_is_null(name_node)) {
            char *name = rust_node_text(ctx, name_node);
            if (name)
                cbm_scope_bind(ctx->current_scope, name, type);
        }
        return;
    }
}

/* ════════════════════════════════════════════════════════════════════
 * 10. Function & file walk
 * ════════════════════════════════════════════════════════════════════ */

/* Inject a synthetic CBMCall into result->calls so the downstream pipeline
 * (cbm_pipeline_find_lsp_resolution) can pair it with the resolved_call and
 * emit a CALLS edge. `callee_qn`'s last dot segment is used as the textual
 * callee_name, matching how the resolver's short-name comparison works. Only
 * used for calls the syntactic extractor cannot see (operator desugaring,
 * macro-hidden method calls). */
static void rust_inject_syn_call(RustLSPContext *ctx, const char *callee_qn, int start_line) {
    if (!ctx || !ctx->syn_calls || !callee_qn || !ctx->enclosing_func_qn || start_line <= 0)
        return;
    const char *dot = strrchr(callee_qn, '.');
    const char *short_name = dot ? dot + 1 : callee_qn;
    if (!short_name || !short_name[0])
        return;
    CBMCall call = {0};
    call.callee_name = cbm_arena_strdup(ctx->arena, short_name);
    call.enclosing_func_qn = ctx->enclosing_func_qn;
    call.start_line = start_line;
    if (!cbm_calls_push(ctx->syn_calls, ctx->arena, call)) {
        return;
    }
}

static void rust_emit_resolved_call(RustLSPContext *ctx, const char *callee_qn,
                                    const char *strategy, float confidence) {
    if (!ctx || !ctx->resolved_calls || !callee_qn || !ctx->enclosing_func_qn)
        return;
    CBMResolvedCall rc = {
        .caller_qn = ctx->enclosing_func_qn,
        .callee_qn = callee_qn,
        .strategy = strategy,
        .confidence = confidence,
        .reason = NULL,
    };
    if (!cbm_resolvedcall_push(ctx->resolved_calls, ctx->arena, rc)) {
        return;
    }
    if (ctx->inject_syn_calls > 0) {
        rust_inject_syn_call(ctx, callee_qn, ctx->macro_origin_line);
    }
}

static void rust_emit_unresolved_call(RustLSPContext *ctx, const char *expr_text,
                                      const char *reason) {
    if (!ctx || !ctx->resolved_calls || !ctx->enclosing_func_qn)
        return;
    CBMResolvedCall rc = {
        .caller_qn = ctx->enclosing_func_qn,
        .callee_qn = expr_text ? expr_text : "?",
        .strategy = "lsp_unresolved",
        .confidence = 0.0f,
        .reason = reason,
    };
    if (!cbm_resolvedcall_push(ctx->resolved_calls, ctx->arena, rc)) {
        return;
    }
}

/* Entry hook: classify a call_expression and emit the best edge we can. */
static void rust_resolve_call_expression(RustLSPContext *ctx, TSNode node) {
    TSNode func_node = ts_node_child_by_field_name(node, "function", 8);
    TSNode args_node = ts_node_child_by_field_name(node, "arguments", 9);
    if (ts_node_is_null(func_node))
        return;
    const char *fk = ts_node_type(func_node);

    /* Method call via field_expression. The grammar can also expose
     * `s.cast::<T>(x)` as a `generic_function` callee whose inner
     * `function` is a field_expression — peel that wrapper here. */
    if (strcmp(fk, "generic_function") == 0) {
        TSNode inner = ts_node_child_by_field_name(func_node, "function", 8);
        if (!ts_node_is_null(inner)) {
            func_node = inner;
            fk = ts_node_type(func_node);
        }
    }
    if (strcmp(fk, "field_expression") == 0) {
        TSNode value = ts_node_child_by_field_name(func_node, "value", 5);
        TSNode field = ts_node_child_by_field_name(func_node, "field", 5);
        if (ts_node_is_null(value) || ts_node_is_null(field))
            return;
        char *mname = rust_node_text(ctx, field);
        if (!mname)
            return;
        /* Strip turbofish from the method name in case the grammar
         * embedded it as part of the field token. */
        rust_strip_turbofish(mname);

        const CBMType *recv = rust_eval_expr_type(ctx, value);
        const CBMType *base = recv;
        while (base && (base->kind == CBM_TYPE_REFERENCE || base->kind == CBM_TYPE_POINTER)) {
            base = (base->kind == CBM_TYPE_REFERENCE) ? base->data.reference.elem
                                                      : base->data.pointer.elem;
        }

        const char *type_qn = NULL;
        if (base && base->kind == CBM_TYPE_NAMED)
            type_qn = base->data.named.qualified_name;
        else if (base && base->kind == CBM_TYPE_TEMPLATE)
            type_qn = base->data.template_type.template_name;
        else if (base && base->kind == CBM_TYPE_BUILTIN) {
            const char *nm = base->data.builtin.name;
            if (strcmp(nm, "str") == 0)
                type_qn = "core.str";
            else if (strcmp(nm, "String") == 0)
                type_qn = "alloc.string.String";
            else if (is_rust_primitive(nm)) {
                /* Primitive integer / float / char / bool / unit / never
                 * methods are registered under their primitive name. */
                type_qn = nm;
            }
        } else if (base && base->kind == CBM_TYPE_SLICE) {
            /* `&[T]` / `[T]` method dispatch. */
            type_qn = "core.slice";
        }

        if (type_qn) {
            int impl_count = 0;
            const CBMRegisteredFunc *m =
                rust_resolve_trait_method(ctx, type_qn, mname, &impl_count);
            if (m) {
                const char *strategy = "lsp_method_dispatch";
                float conf = CBM_RUST_CONF_METHOD;
                if (m->receiver_type && strcmp(m->receiver_type, type_qn) != 0) {
                    strategy = "lsp_trait_dispatch";
                    conf = (impl_count == 1) ? CBM_RUST_CONF_TRAIT_SOLE : CBM_RUST_CONF_TRAIT_AMB;
                } else if (rust_method_is_trait_impl(ctx, type_qn, mname)) {
                    // Inherently resolved, but the method comes from a trait impl
                    // (`impl Trait for Type`) → polymorphic trait dispatch.
                    strategy = "lsp_trait_dispatch";
                    conf = CBM_RUST_CONF_TRAIT_SOLE;
                }
                rust_emit_resolved_call(ctx, m->qualified_name, strategy, conf);
                (void)args_node;
                return;
            }

            /* Walk the Deref chain — `Box<T>::method` may live on `T`,
             * `Rc<RefCell<T>>::method` peels two levels, etc. We bound
             * the chain at 8 hops to mirror the rust-analyzer cap. */
            const CBMType *cur = base;
            for (int hop = 0; hop < 8; hop++) {
                const CBMType *next = rust_deref_step(ctx, cur);
                if (!next)
                    break;
                /* Unwrap reference layers introduced by deref. */
                while (next &&
                       (next->kind == CBM_TYPE_REFERENCE || next->kind == CBM_TYPE_POINTER)) {
                    next = (next->kind == CBM_TYPE_REFERENCE) ? next->data.reference.elem
                                                              : next->data.pointer.elem;
                }
                if (!next)
                    break;
                const char *next_qn = NULL;
                if (next->kind == CBM_TYPE_NAMED)
                    next_qn = next->data.named.qualified_name;
                else if (next->kind == CBM_TYPE_TEMPLATE)
                    next_qn = next->data.template_type.template_name;
                else if (next->kind == CBM_TYPE_BUILTIN) {
                    const char *nm = next->data.builtin.name;
                    if (strcmp(nm, "str") == 0)
                        next_qn = "core.str";
                    else if (strcmp(nm, "String") == 0)
                        next_qn = "alloc.string.String";
                }
                if (!next_qn)
                    break;
                int hop_impls = 0;
                const CBMRegisteredFunc *hm =
                    rust_resolve_trait_method(ctx, next_qn, mname, &hop_impls);
                if (hm) {
                    rust_emit_resolved_call(ctx, hm->qualified_name, "lsp_deref_dispatch",
                                            CBM_RUST_CONF_PROMOTED);
                    return;
                }
                cur = next;
            }

            /* Chalk-lite: receiver is typed as a NAMED with a name
             * that matches a current type-param bound. Resolve through
             * the bound trait. */
            {
                /* Just the local tail name. */
                const char *short_qn = type_qn;
                const char *dot = strrchr(type_qn, '.');
                if (dot)
                    short_qn = dot + 1;
                const char *bound = rust_lookup_type_param_bound(ctx, short_qn);
                if (bound) {
                    int bimpls = 0;
                    const CBMRegisteredFunc *bm =
                        rust_resolve_trait_method(ctx, bound, mname, &bimpls);
                    if (bm) {
                        rust_emit_resolved_call(ctx, bm->qualified_name, "lsp_bound_dispatch",
                                                CBM_RUST_CONF_TRAIT_AMB);
                        return;
                    }
                }
            }

            /* Prelude trait method best-effort. */
            if (is_prelude_trait_method(mname)) {
                rust_emit_resolved_call(ctx, cbm_arena_sprintf(ctx->arena, "%s.%s", type_qn, mname),
                                        "lsp_prelude_trait", CBM_RUST_CONF_TRAIT_AMB);
                return;
            }
            rust_emit_unresolved_call(ctx, cbm_arena_sprintf(ctx->arena, "%s.%s", type_qn, mname),
                                      "method_not_found");
            return;
        }

        /* Receiver type is unknown — record best-effort with the textual
         * receiver path so downstream can still see what we tried. */
        char *recv_text = rust_node_text(ctx, value);
        rust_emit_unresolved_call(
            ctx, cbm_arena_sprintf(ctx->arena, "%s.%s", recv_text ? recv_text : "?", mname),
            "unknown_receiver_type");
        return;
    }

    /* Direct identifier or scoped path call. */
    if (strcmp(fk, "identifier") == 0 || strcmp(fk, "scoped_identifier") == 0 ||
        strcmp(fk, "generic_function") == 0) {
        TSNode actual_func = func_node;
        if (strcmp(fk, "generic_function") == 0) {
            TSNode inner = ts_node_child_by_field_name(actual_func, "function", 8);
            if (!ts_node_is_null(inner))
                actual_func = inner;
        }
        char *path = rust_node_text(ctx, actual_func);
        if (!path)
            return;
        /* Strip ALL turbofish (`Vec::<i32>::new` → `Vec::new`). */
        rust_strip_turbofish(path);

        const char *qn = rust_resolve_path_expr(ctx, path);
        if (!qn)
            return;

        /* Try registered free function first. Also try module-prefixed
         * fallback so `Logger::new` (which resolves to "Logger.new")
         * still finds the project's `<module>.Logger.new`. */
        if (cbm_registry_lookup_func(ctx->registry, qn)) {
            rust_emit_resolved_call(ctx, qn, "lsp_direct", CBM_RUST_CONF_DIRECT);
            return;
        }
        if (ctx->module_qn && strstr(qn, ".") == NULL) {
            const char *full = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, qn);
            if (cbm_registry_lookup_func(ctx->registry, full)) {
                rust_emit_resolved_call(ctx, full, "lsp_direct", CBM_RUST_CONF_DIRECT);
                return;
            }
        }

        /* UFCS form: T::method or trait_qn::method. */
        const char *dot = strrchr(qn, '.');
        if (dot) {
            char *head = cbm_arena_strndup(ctx->arena, qn, (size_t)(dot - qn));
            const char *short_name = dot + 1;
            /* If `head` is a trait, `Trait::method` UFCS resolves to the sole
             * concrete impl (lsp_trait_ufcs), NEVER the trait's own abstract
             * method that the inherent lookup below would find. Resolve the trait
             * QN (head or module-qualified) via its is_interface flag — set at
             * type-registration time, so it is reliable even on an early pass
             * before impl links are wired. When the impl isn't known yet, emit
             * nothing: a partial-pass lsp_ufcs to the abstract method would
             * otherwise outrank (higher conf) the real trait_ufcs from the
             * complete pass and win the join. */
            const char *trait_qn = NULL;
            const CBMRegisteredType *head_t = cbm_registry_lookup_type(ctx->registry, head);
            if (head_t && head_t->is_interface) {
                trait_qn = head;
            } else if (ctx->module_qn) {
                const char *fh = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, head);
                const CBMRegisteredType *ft = cbm_registry_lookup_type(ctx->registry, fh);
                if (ft && ft->is_interface)
                    trait_qn = fh;
            }
            if (trait_qn) {
                int tn = 0;
                const CBMRegisteredFunc *ti_m =
                    rust_find_sole_trait_impl(ctx, trait_qn, short_name, &tn);
                if (tn >= 1) {
                    rust_emit_resolved_call(
                        ctx,
                        ti_m ? ti_m->qualified_name
                             : cbm_arena_sprintf(ctx->arena, "%s.%s", trait_qn, short_name),
                        tn == 1 ? "lsp_trait_ufcs" : "lsp_trait_ufcs_amb",
                        tn == 1 ? CBM_RUST_CONF_TRAIT_SOLE : CBM_RUST_CONF_TRAIT_AMB);
                }
                return;
            }
            const CBMRegisteredFunc *m = rust_lookup_method_depth(ctx, head, short_name, 0);
            if (!m && ctx->module_qn) {
                /* Fall back to module-qualified head: `Logger.new` →
                 * `<module>.Logger.new`. */
                const char *full_head =
                    cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, head);
                m = rust_lookup_method_depth(ctx, full_head, short_name, 0);
            }
            if (m) {
                rust_emit_resolved_call(ctx, m->qualified_name,
                                        strcmp(short_name, "new") == 0 ? "lsp_constructor"
                                                                       : "lsp_ufcs",
                                        CBM_RUST_CONF_UFCS);
                return;
            }
            /* Trait method through single-impl dispatch. */
            int impls = 0;
            const CBMRegisteredFunc *tm = rust_resolve_trait_method(ctx, head, short_name, &impls);
            if (!tm && ctx->module_qn) {
                const char *full_head =
                    cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, head);
                tm = rust_resolve_trait_method(ctx, full_head, short_name, &impls);
            }
            if (tm) {
                rust_emit_resolved_call(
                    ctx, tm->qualified_name, impls == 1 ? "lsp_trait_ufcs" : "lsp_trait_ufcs_amb",
                    impls == 1 ? CBM_RUST_CONF_TRAIT_SOLE : CBM_RUST_CONF_TRAIT_AMB);
                return;
            }
        }

        const char *tail = strrchr(path, ':');
        if (tail && tail > path && tail[-1] == ':') {
            tail += 1;
        } else {
            tail = path;
        }

        /* Cross-crate workspace-member resolution (#56): when the call
         * path's head is a declared Cargo workspace member (e.g.
         * `crate_a::helper` from inside crate_b) we cannot rely on the
         * caller-crate-scoped fallback below — that filters by the
         * CALLER's module prefix and would resolve to a same-named local
         * function instead. Route to the function defined inside the
         * MEMBER crate by matching the registered QN's `.<member>.`
         * path segment plus the call tail. Requires a parsed manifest
         * (threaded through pass_lsp_cross.c); NULL manifest skips this. */
        if (ctx->cargo_manifest && tail && *tail) {
            const char *head_sep = strstr(path, "::");
            if (head_sep && head_sep > path) {
                char *head = cbm_arena_strndup(ctx->arena, path, (size_t)(head_sep - path));
                const CBMCargoManifest *m = (const CBMCargoManifest *)ctx->cargo_manifest;
                if (head && cbm_cargo_find_member(m, head)) {
                    /* `.crate_a.` — the member directory appears as a dotted
                     * QN segment for every def inside that crate. */
                    char *needle = cbm_arena_sprintf(ctx->arena, ".%s.", head);
                    const CBMRegisteredFunc *mem_unique = NULL;
                    int mem_matches = 0;
                    /* Iterate only free funcs whose short_name == tail via the index;
                     * the receiver/short_name/needle re-checks below are unchanged. */
                    CBMFreeFuncIter ffit;
                    cbm_registry_free_funcs_by_short_name(ctx->registry, tail, &ffit);
                    for (int i; mem_matches < 2 && (i = cbm_free_func_iter_next(&ffit)) >= 0;) {
                        const CBMRegisteredFunc *f = &ctx->registry->funcs[i];
                        if (!f->short_name || !f->qualified_name)
                            continue;
                        if (f->receiver_type)
                            continue; /* free functions only */
                        if (strcmp(f->short_name, tail) != 0)
                            continue;
                        if (!strstr(f->qualified_name, needle))
                            continue; /* not defined in the member crate */
                        mem_matches++;
                        if (mem_matches == 1)
                            mem_unique = f;
                    }
                    if (mem_matches == 1 && mem_unique) {
                        rust_emit_resolved_call(ctx, mem_unique->qualified_name, "lsp_cross_crate",
                                                CBM_RUST_CONF_DIRECT);
                        return;
                    }
                }
            }
        }

        /* Global short-name fallback: scan the registry for a unique
         * function whose short_name matches the path's tail and whose
         * QN starts with the current crate prefix. This gives `mod
         * foo; use foo::bar; bar()` a chance to resolve when the
         * intermediate module wasn't tracked through an explicit
         * use-map entry. */
        if (tail && *tail && ctx->module_qn) {
            /* Crate prefix is the first dotted segment of module_qn after
             * the project name, but for simplicity we just match on
             * "starts with first dot-segment". */
            const char *first_dot = strchr(ctx->module_qn, '.');
            size_t crate_len =
                first_dot ? (size_t)(first_dot - ctx->module_qn) : strlen(ctx->module_qn);
            const CBMRegisteredFunc *unique = NULL;
            int matches = 0;
            /* Iterate only free funcs whose short_name == tail via the index; the
             * receiver/short_name/crate-prefix re-checks below are unchanged. */
            CBMFreeFuncIter ffit;
            cbm_registry_free_funcs_by_short_name(ctx->registry, tail, &ffit);
            for (int i; matches < 2 && (i = cbm_free_func_iter_next(&ffit)) >= 0;) {
                const CBMRegisteredFunc *f = &ctx->registry->funcs[i];
                if (!f->short_name || !f->qualified_name)
                    continue;
                if (f->receiver_type)
                    continue; /* free functions only */
                if (strcmp(f->short_name, tail) != 0)
                    continue;
                /* Crate-scoped: QN must start with the same prefix. */
                if (strncmp(f->qualified_name, ctx->module_qn, crate_len) != 0)
                    continue;
                matches++;
                if (matches == 1)
                    unique = f;
            }
            if (matches == 1 && unique) {
                rust_emit_resolved_call(ctx, unique->qualified_name, "lsp_short_name_unique",
                                        CBM_RUST_CONF_PROMOTED);
                return;
            }
        }

        /* Last-ditch: emit with the resolved path. */
        rust_emit_unresolved_call(ctx, qn, "function_not_in_registry");
        return;
    }
}

/* Walk every node in a function body, recording calls and refining scope
 * for control-flow constructs that bind variables. */
static void rust_resolve_calls_in_node(RustLSPContext *ctx, TSNode node) {
    if (!ctx || cbm_arena_failed(ctx->arena)) {
        return;
    }
    if (ctx->walk_depth >= ctx->walk_depth_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_ast_walk_depth", (size_t)ctx->walk_depth_limit);
        return;
    }
    ctx->walk_depth++;
    rust_resolve_calls_in_node_inner(ctx, node);
    ctx->walk_depth--;
}

static void rust_resolve_calls_in_node_inner(RustLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return;
    /* Pathological-input guard: bail out once we've spent too many
     * eval steps on this file. Prevents hangs on adversarial input. */
    if (ctx->eval_step_count >= ctx->eval_step_limit) {
        cbm_arena_mark_failed(ctx->arena, "CBM_LSP_ANALYSIS_LIMIT_EXCEEDED",
                              "rust_lsp_semantic_steps", (size_t)ctx->eval_step_limit);
        return;
    }
    ctx->eval_step_count++;
    const char *kind = ts_node_type(node);

    /* Bind variables introduced by this statement. */
    rust_process_statement(ctx, node);

    /* Resolve a call expression. */
    if (strcmp(kind, "call_expression") == 0) {
        rust_resolve_call_expression(ctx, node);
        /* Closure-parameter inference: when the call is a known
         * iterator-style method that takes a closure of `Item`, stash
         * the receiver's element type so the closure_expression child
         * binds its first param to it. We compute this here (after
         * the call edge is emitted) so the recursion picks it up. */
        TSNode fn = ts_node_child_by_field_name(node, "function", 8);
        if (!ts_node_is_null(fn) && strcmp(ts_node_type(fn), "field_expression") == 0) {
            TSNode val = ts_node_child_by_field_name(fn, "value", 5);
            TSNode fld = ts_node_child_by_field_name(fn, "field", 5);
            if (!ts_node_is_null(val) && !ts_node_is_null(fld)) {
                char *mname = rust_node_text(ctx, fld);
                static const char *item_methods[] = {
                    "map",    "filter",     "for_each",   "find",        "position", "any",
                    "all",    "take_while", "skip_while", "filter_map",  "inspect",  "max_by",
                    "min_by", "max_by_key", "min_by_key", "sort_by_key", NULL};
                bool is_item_method = false;
                if (mname) {
                    for (const char **mm = item_methods; *mm; mm++) {
                        if (strcmp(mname, *mm) == 0) {
                            is_item_method = true;
                            break;
                        }
                    }
                }
                if (is_item_method) {
                    const CBMType *recv = rust_eval_expr_type(ctx, val);
                    const CBMType *base = recv;
                    while (base &&
                           (base->kind == CBM_TYPE_REFERENCE || base->kind == CBM_TYPE_POINTER)) {
                        base = (base->kind == CBM_TYPE_REFERENCE) ? base->data.reference.elem
                                                                  : base->data.pointer.elem;
                    }
                    if (base && base->kind == CBM_TYPE_TEMPLATE &&
                        base->data.template_type.arg_count > 0) {
                        const char *tn = base->data.template_type.template_name;
                        if (tn && (strstr(tn, "Iterator") || strstr(tn, "Vec") ||
                                   strstr(tn, "VecDeque") || strstr(tn, "Option") ||
                                   strstr(tn, "Result") || strstr(tn, "HashSet") ||
                                   strstr(tn, "BTreeSet") || strstr(tn, "Slice"))) {
                            ctx->pending_closure_param_type =
                                base->data.template_type.template_args[0];
                        }
                    } else if (base && base->kind == CBM_TYPE_SLICE) {
                        ctx->pending_closure_param_type = base->data.slice.elem;
                    }
                }
            }
        }
        /* Continue recursion so calls inside arguments are also seen. */
    }

    /* Operator-overload desugaring: `a + b` calls <T as Add>::add when the
     * left operand is a user-defined type T with that operator method;
     * `a[i]` calls T::index. The tree-sitter-rust grammar models these as
     * binary_expression / index_expression rather than call_expression, so
     * lang_specs.c's call-type whitelist never sees them — we recover the
     * call edge here. Sound-only via rust_emit_operator_call (no edge unless
     * the operand type actually defines the method). */
    if (strcmp(kind, "binary_expression") == 0) {
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        if (!ts_node_is_null(left)) {
            for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
                TSNode c = ts_node_child(node, i);
                if (ts_node_is_named(c))
                    continue;
                char *op = rust_node_text(ctx, c);
                const char *method = rust_binop_trait_method(op);
                if (method) {
                    rust_emit_operator_call(ctx, rust_eval_expr_type(ctx, left), method, node);
                }
                break; /* operator is the sole anonymous child */
            }
        }
    } else if (strcmp(kind, "index_expression") == 0) {
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        if (ts_node_is_null(value) && ts_node_named_child_count(node) > 0) {
            value = ts_node_named_child(node, 0);
        }
        if (!ts_node_is_null(value)) {
            rust_emit_operator_call(ctx, rust_eval_expr_type(ctx, value), "index", node);
        }
    }

    /* Macro invocation: known standard macros evaluate their expression
     * arguments, while macro_rules!/procedural macros consume arbitrary token
     * trees and may discard, duplicate, or transform them.  Raw arguments are
     * therefore never walked for an unknown/user macro; only its exact local
     * expansion may produce semantic call edges. */
    if (strcmp(kind, "macro_invocation") == 0) {
        TSNode mname_node = ts_node_child_by_field_name(node, "macro", 5);
        if (!ts_node_is_null(mname_node)) {
            char *mname = rust_node_text(ctx, mname_node);
            if (mname) {
                /* For known std macros emit a synthetic call under their
                 * canonical paths so trace tools can see the dependency. */
                const char *path = NULL;
                if (strcmp(mname, "println") == 0 || strcmp(mname, "eprintln") == 0 ||
                    strcmp(mname, "print") == 0 || strcmp(mname, "eprint") == 0 ||
                    strcmp(mname, "format") == 0 || strcmp(mname, "write") == 0 ||
                    strcmp(mname, "writeln") == 0) {
                    path = cbm_arena_sprintf(ctx->arena, "std.macros.%s", mname);
                } else if (strcmp(mname, "vec") == 0) {
                    path = "alloc.vec.vec";
                } else if (strcmp(mname, "panic") == 0) {
                    path = "core.panicking.panic";
                } else if (strcmp(mname, "include") == 0) {
                    /* `include!` pulls another file in at compile time —
                     * we never see the included source. Emit a
                     * documentation edge so trace tools can flag it. */
                    path = "core.macros.include";
                } else if (strcmp(mname, "include_str") == 0 ||
                           strcmp(mname, "include_bytes") == 0) {
                    /* Equivalent for data inclusion. */
                    path = cbm_arena_sprintf(ctx->arena, "core.macros.%s", mname);
                } else if (strcmp(mname, "env") == 0 || strcmp(mname, "option_env") == 0) {
                    /* Compile-time env var read. Specifically: an
                     * `include!(concat!(env!("OUT_DIR"), …))` pattern
                     * indicates code generated by a build.rs that we
                     * cannot see. We surface the env! call so trace
                     * tools know to look for OUT_DIR. */
                    path = cbm_arena_sprintf(ctx->arena, "core.macros.%s", mname);
                } else if (strcmp(mname, "concat") == 0) {
                    path = "core.macros.concat";
                }
                if (path) {
                    if (rust_resolve_known_macro_args(ctx, mname, node)) {
                        rust_emit_resolved_call(ctx, path, "lsp_macro", CBM_RUST_CONF_MACRO_KNOWN);
                    }
                } else {
                    /* User-defined macro: try expanding via macro_rules!. */
                    rust_expand_user_macro(ctx, mname, node);
                }
            }
        }
        /* Do not descend into raw token trees.  Known built-ins were reparsed
         * once above; user macros were walked only after exact substitution. */
        return;
    }

    /* Push a fresh scope for blocks and constructs introducing new bindings. */
    bool push_scope =
        (strcmp(kind, "block") == 0 || strcmp(kind, "if_expression") == 0 ||
         strcmp(kind, "if_let_expression") == 0 || strcmp(kind, "while_expression") == 0 ||
         strcmp(kind, "while_let_expression") == 0 || strcmp(kind, "for_expression") == 0 ||
         strcmp(kind, "match_arm") == 0 || strcmp(kind, "closure_expression") == 0);

    CBMScope *saved = ctx->current_scope;
    if (push_scope) {
        ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);
    }

    /* if_let / while_let bind a pattern from the value's matched form.
     * Modern tree-sitter-rust parses `if let X = y { ... }` as
     * `if_expression` containing a `let_condition` child rather than as
     * the legacy `if_let_expression`. Same for `while let`. We handle
     * both shapes here. */
    if (strcmp(kind, "if_let_expression") == 0 || strcmp(kind, "while_let_expression") == 0) {
        TSNode pat = ts_node_child_by_field_name(node, "pattern", 7);
        TSNode val = ts_node_child_by_field_name(node, "value", 5);
        if (!ts_node_is_null(pat) && !ts_node_is_null(val)) {
            const CBMType *vt = rust_eval_expr_type(ctx, val);
            rust_bind_pattern(ctx, pat, vt);
        }
    }
    if (strcmp(kind, "if_expression") == 0 || strcmp(kind, "while_expression") == 0) {
        /* Look for a let_condition (or let_chain) anywhere in the
         * condition slot. */
        TSNode cond = ts_node_child_by_field_name(node, "condition", 9);
        if (!ts_node_is_null(cond)) {
            uint32_t nc2 = ts_node_named_child_count(cond);
            /* Walk one level down for let_condition / let_chain. */
            const char *ck = ts_node_type(cond);
            TSNode *targets = NULL;
            size_t tcount = 0;
            size_t target_capacity = 0;
            if (strcmp(ck, "let_condition") == 0) {
                if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&targets, 0,
                                                    &target_capacity, sizeof(*targets), 1,
                                                    "rust let condition targets")) {
                    return;
                }
                targets[tcount++] = cond;
            } else if (strcmp(ck, "let_chain") == 0) {
                for (uint32_t i = 0; i < nc2; i++) {
                    TSNode c2 = ts_node_named_child(cond, i);
                    if (strcmp(ts_node_type(c2), "let_condition") == 0) {
                        if (!cbm_lsp_semantic_array_reserve(ctx->arena, (void **)&targets, tcount,
                                                            &target_capacity, sizeof(*targets),
                                                            tcount + 1, "rust let chain targets")) {
                            return;
                        }
                        targets[tcount++] = c2;
                    }
                }
            }
            for (size_t t = 0; t < tcount; t++) {
                TSNode lc = targets[t];
                TSNode pat = ts_node_child_by_field_name(lc, "pattern", 7);
                TSNode val = ts_node_child_by_field_name(lc, "value", 5);
                if (!ts_node_is_null(pat) && !ts_node_is_null(val)) {
                    const CBMType *vt = rust_eval_expr_type(ctx, val);
                    rust_bind_pattern(ctx, pat, vt);
                }
            }
        }
    }

    /* for_expression: bind the loop variable from the iter's element type. */
    if (strcmp(kind, "for_expression") == 0) {
        TSNode pat = ts_node_child_by_field_name(node, "pattern", 7);
        TSNode val = ts_node_child_by_field_name(node, "value", 5);
        if (!ts_node_is_null(pat) && !ts_node_is_null(val)) {
            const CBMType *vt = rust_eval_expr_type(ctx, val);
            const CBMType *base = vt;
            while (base && base->kind == CBM_TYPE_REFERENCE)
                base = base->data.reference.elem;
            const CBMType *elem = cbm_type_unknown();
            if (base && base->kind == CBM_TYPE_SLICE) {
                elem = base->data.slice.elem;
            } else if (base && base->kind == CBM_TYPE_TEMPLATE) {
                const char *nm = base->data.template_type.template_name;
                if ((strstr(nm, "Vec") || strstr(nm, "VecDeque") || strstr(nm, "Iterator") ||
                     strstr(nm, "Range")) &&
                    base->data.template_type.arg_count > 0) {
                    elem = base->data.template_type.template_args[0];
                }
                if ((strstr(nm, "HashMap") || strstr(nm, "BTreeMap")) &&
                    base->data.template_type.arg_count > 1) {
                    /* Iter over (K, V) tuples. */
                    const CBMType *pair[2] = {base->data.template_type.template_args[0],
                                              base->data.template_type.template_args[1]};
                    elem = cbm_type_tuple(ctx->arena, pair, 2);
                }
            }
            rust_bind_pattern(ctx, pat, elem);
        }
    }

    /* match_expression: per-arm scope handled when we descend. */
    if (strcmp(kind, "match_arm") == 0) {
        /* The match value type is captured by the parent walker — best
         * effort: peek at the arm's pattern and let rust_bind_pattern do the
         * work using cbm_type_unknown() if we cannot derive it. */
    }

    /* closure_expression: bind closure parameters.
     *
     * Priority order for each param:
     *   1. Explicit type annotation (`|n: &i32|`) — use it directly.
     *   2. `ctx->pending_closure_param_type` for the FIRST param when the
     *      surrounding call resolver inferred one (`.map(|x| ...)` on
     *      Iterator<T>).
     *   3. Otherwise unknown.
     *
     * After binding, clear the pending type so it doesn't leak into a
     * sibling closure. */
    if (strcmp(kind, "closure_expression") == 0) {
        const CBMType *hint = ctx->pending_closure_param_type;
        ctx->pending_closure_param_type = NULL;
        TSNode params = ts_node_child_by_field_name(node, "parameters", 10);
        if (!ts_node_is_null(params)) {
            uint32_t pc = ts_node_named_child_count(params);
            for (uint32_t i = 0; i < pc; i++) {
                TSNode p = ts_node_named_child(params, i);
                /* For `parameter`-shaped nodes, peel off the type
                 * annotation if present; otherwise treat the whole node
                 * as the pattern. */
                TSNode pat = p;
                const CBMType *bound = (i == 0 && hint) ? hint : cbm_type_unknown();
                if (strcmp(ts_node_type(p), "parameter") == 0) {
                    TSNode tn = ts_node_child_by_field_name(p, "type", 4);
                    TSNode pn = ts_node_child_by_field_name(p, "pattern", 7);
                    if (!ts_node_is_null(pn))
                        pat = pn;
                    if (!ts_node_is_null(tn)) {
                        bound = rust_parse_type_node(ctx, tn);
                    }
                }
                rust_bind_pattern(ctx, pat, bound);
            }
        }
    }

    /* Recurse. */
    uint32_t nc = ts_node_child_count(node);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode c = ts_node_child(node, i);
        if (!ts_node_is_null(c)) {
            rust_resolve_calls_in_node(ctx, c);
        }
    }

    if (push_scope) {
        ctx->current_scope = saved;
    }
}

/* Process a single function: bind parameters / `self`, then walk body. */
static void rust_process_function(RustLSPContext *ctx, TSNode func_node, const char *parent_qn) {
    TSNode name_node = ts_node_child_by_field_name(func_node, "name", 4);
    if (ts_node_is_null(name_node))
        return;
    char *name = rust_node_text(ctx, name_node);
    if (!name || !name[0])
        return;

    const char *prefix = parent_qn ? parent_qn : ctx->module_qn;
    const char *saved_enclosing_func_qn = ctx->enclosing_func_qn;
    ctx->enclosing_func_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", prefix, name);

    CBMScope *saved = ctx->current_scope;
    ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);

    /* Chalk-lite: capture the active function's type-parameter bounds
     * and where-clause bounds into ctx so dispatch through generic
     * receivers can route via the bound trait. */
    int saved_bound_count = ctx->type_param_bound_count;
    TSNode tp_list = ts_node_child_by_field_name(func_node, "type_parameters", 15);
    if (!ts_node_is_null(tp_list)) {
        char *tp_text = rust_node_text(ctx, tp_list);
        if (tp_text)
            rust_collect_bounds_from_text(ctx, tp_text);
    }
    TSNode where_clause = ts_node_child_by_field_name(func_node, "where_clause", 12);
    if (!ts_node_is_null(where_clause)) {
        char *wt = rust_node_text(ctx, where_clause);
        if (wt)
            rust_collect_bounds_from_text(ctx, wt);
    }

    /* Bind self for impl/trait methods. */
    TSNode params = ts_node_child_by_field_name(func_node, "parameters", 10);
    if (!ts_node_is_null(params)) {
        uint32_t pc = ts_node_named_child_count(params);
        for (uint32_t i = 0; i < pc; i++) {
            TSNode p = ts_node_named_child(params, i);
            const char *pk = ts_node_type(p);
            if (strcmp(pk, "self_parameter") == 0) {
                if (ctx->self_type_qn) {
                    /* Determine if &self / &mut self / self by reference. */
                    char *text = rust_node_text(ctx, p);
                    const CBMType *self_t = cbm_type_named(ctx->arena, ctx->self_type_qn);
                    if (text && strchr(text, '&')) {
                        self_t = cbm_type_reference(ctx->arena, self_t);
                    }
                    cbm_scope_bind(ctx->current_scope, "self", self_t);
                }
                continue;
            }
            if (strcmp(pk, "parameter") == 0) {
                TSNode pat = ts_node_child_by_field_name(p, "pattern", 7);
                TSNode tn = ts_node_child_by_field_name(p, "type", 4);
                const CBMType *pt =
                    ts_node_is_null(tn) ? cbm_type_unknown() : rust_parse_type_node(ctx, tn);
                if (!ts_node_is_null(pat))
                    rust_bind_pattern(ctx, pat, pt);
            }
        }
    }

    /* Walk function body. */
    TSNode body = ts_node_child_by_field_name(func_node, "body", 4);
    if (!ts_node_is_null(body)) {
        rust_resolve_calls_in_node(ctx, body);
    }

    ctx->current_scope = saved;
    ctx->enclosing_func_qn = saved_enclosing_func_qn;
    /* Restore bound-env count so the caller's bounds are unaffected. */
    ctx->type_param_bound_count = saved_bound_count;
}

/* Walk an `impl_item`, processing each `function_item` inside its body
 * with the appropriate `self_type_qn` (and `self_trait_qn` for trait impls). */
/* Chalk-lite: record a `T: Trait` bound in the per-function bound
 * environment. The arrays grow by 8 to keep allocs cheap. */
static void rust_record_type_param_bound(RustLSPContext *ctx, const char *param_name,
                                         const char *trait_qn) {
    if (!ctx || !param_name || !trait_qn)
        return;
    /* Grow by 8s. */
    if (ctx->type_param_bound_count % 8 == 0) {
        int new_cap = ctx->type_param_bound_count + 8;
        void *narr = cbm_arena_alloc(ctx->arena, new_cap * sizeof(*ctx->type_param_bounds));
        if (!narr)
            return;
        if (ctx->type_param_bounds && ctx->type_param_bound_count > 0) {
            memcpy(narr, ctx->type_param_bounds,
                   ctx->type_param_bound_count * sizeof(*ctx->type_param_bounds));
        }
        ctx->type_param_bounds = narr;
    }
    ctx->type_param_bounds[ctx->type_param_bound_count].param_name =
        cbm_arena_strdup(ctx->arena, param_name);
    ctx->type_param_bounds[ctx->type_param_bound_count].trait_qn =
        cbm_arena_strdup(ctx->arena, trait_qn);
    ctx->type_param_bound_count++;
}

/* Look up the first trait bound for a given type-param name. Returns
 * NULL if `name` has no bound recorded. */
static const char *rust_lookup_type_param_bound(RustLSPContext *ctx, const char *name) {
    if (!ctx || !name)
        return NULL;
    for (int i = 0; i < ctx->type_param_bound_count; i++) {
        if (strcmp(ctx->type_param_bounds[i].param_name, name) == 0) {
            return ctx->type_param_bounds[i].trait_qn;
        }
    }
    return NULL;
}

/* Parse the impl/function's <T: Bound + Bound, U: Bound> + where clause
 * text into the per-context bound environment. We don't reason about
 * lifetimes; we record only trait bounds and associated-type bindings.
 *
 * Format we accept (simplified TOML-like grammar):
 *   `<T: Clone + Debug, U: Iterator<Item = V>>`
 *   `where T: Clone, U: Iterator<Item = V>`
 *
 * Multiple bounds are split on `+` (top-level), entries on `,`. */
static void rust_collect_bounds_from_text(RustLSPContext *ctx, const char *text) {
    if (!ctx || !text)
        return;
    /* Walk text, find segments separated by `,` at top depth. For each
     * segment, split on `:` to get (param, bound-list); split bounds on `+`
     * at top depth. Resolve each bound through the path resolver to its QN. */
    int len = (int)strlen(text);
    int from = 0;
    while (from < len) {
        /* Skip whitespace + leading 'where'/punct. */
        while (from < len && (text[from] == ' ' || text[from] == '\n' || text[from] == '<' ||
                              text[from] == ',' || text[from] == '>' || text[from] == 'w')) {
            if (text[from] == 'w' && from + 5 < len && strncmp(text + from, "where", 5) == 0) {
                from += 5;
            } else {
                from++;
            }
        }
        if (from >= len)
            break;

        /* Param name. */
        int name_start = from;
        if (text[from] == '\'') {
            /* Lifetime — skip. */
            from++;
            while (from < len && (isalnum((unsigned char)text[from]) || text[from] == '_'))
                from++;
            continue;
        }
        while (from < len && (isalnum((unsigned char)text[from]) || text[from] == '_'))
            from++;
        int name_end = from;
        if (name_end == name_start) {
            from++;
            continue;
        }
        char *pname =
            cbm_arena_strndup(ctx->arena, text + name_start, (size_t)(name_end - name_start));
        /* Look for `:`. */
        while (from < len && (text[from] == ' ' || text[from] == '\t'))
            from++;
        if (from >= len || text[from] != ':') {
            /* No bound; skip to next entry. */
            while (from < len && text[from] != ',' && text[from] != '>' && text[from] != '\n')
                from++;
            continue;
        }
        from++; /* consume `:` */

        /* Bound list: split on `+` at depth 0, terminated by `,` / `>` /
         * end of where clause. */
        int depth = 0;
        int bound_start = from;
        while (from < len) {
            char c = text[from];
            if (c == '<' || c == '(' || c == '[')
                depth++;
            else if (c == '>' || c == ')' || c == ']') {
                if (depth == 0)
                    break;
                depth--;
            } else if (depth == 0 && (c == '+' || c == ',' || c == '\n')) {
                /* End of one bound. */
                int b_end = from;
                /* Trim trailing whitespace. */
                while (b_end > bound_start && (text[b_end - 1] == ' ' || text[b_end - 1] == '\t')) {
                    b_end--;
                }
                /* Trim leading whitespace. */
                int b_start = bound_start;
                while (b_start < b_end && (text[b_start] == ' ' || text[b_start] == '\t')) {
                    b_start++;
                }
                if (b_end > b_start) {
                    char *btext =
                        cbm_arena_strndup(ctx->arena, text + b_start, (size_t)(b_end - b_start));
                    /* Strip any `<…>` associated-type suffix for the
                     * trait QN lookup — we keep the trait name only. */
                    char *langle = strchr(btext, '<');
                    if (langle)
                        *langle = '\0';
                    const char *qn = rust_resolve_path_expr(ctx, btext);
                    if (qn) {
                        rust_record_type_param_bound(ctx, pname, qn);
                    }
                }
                if (c == '+') {
                    from++;
                    bound_start = from;
                    continue;
                }
                /* End of entry. */
                break;
            }
            from++;
        }
        /* Advance past entry terminator. */
        if (from < len && (text[from] == ',' || text[from] == '\n'))
            from++;
    }
}

/* Helper: does `name` appear in the impl's `<T, U, ...>` type
 * parameter list? Used to detect blanket impls (impl<T: Trait> X for T). */
static bool rust_impl_has_type_param(RustLSPContext *ctx, TSNode impl_node, const char *name) {
    if (!name)
        return false;
    TSNode tp = ts_node_child_by_field_name(impl_node, "type_parameters", 15);
    if (ts_node_is_null(tp))
        return false;
    uint32_t nc = ts_node_named_child_count(tp);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode c = ts_node_named_child(tp, i);
        const char *ck = ts_node_type(c);
        if (strcmp(ck, "type_identifier") == 0 || strcmp(ck, "constrained_type_parameter") == 0) {
            char *nm = rust_node_text(ctx, c);
            if (!nm)
                continue;
            /* For constrained_type_parameter, the name is the
             * first identifier-y child. */
            if (strcmp(ck, "constrained_type_parameter") == 0) {
                TSNode lhs = ts_node_child_by_field_name(c, "left", 4);
                if (!ts_node_is_null(lhs))
                    nm = rust_node_text(ctx, lhs);
            }
            if (nm && strcmp(nm, name) == 0)
                return true;
        }
    }
    return false;
}

static void rust_process_impl(RustLSPContext *ctx, TSNode impl_node) {
    TSNode type_node = ts_node_child_by_field_name(impl_node, "type", 4);
    if (ts_node_is_null(type_node))
        return;
    char *type_text = rust_node_text(ctx, type_node);
    if (!type_text)
        return;

    /* Detect blanket impl: `impl<T: Trait> ForeignTrait for T { ... }`
     * where type_text is a name that appears in the impl's type
     * parameters. In that case the receiver isn't a concrete type — it's
     * any T satisfying the bound. We register the methods on the trait
     * QN itself so dispatch through T: Trait finds them. */
    TSNode trait_node = ts_node_child_by_field_name(impl_node, "trait", 5);
    bool is_blanket =
        !ts_node_is_null(trait_node) && rust_impl_has_type_param(ctx, impl_node, type_text);
    const char *effective_recv = NULL;

    if (is_blanket) {
        char *tt = rust_node_text(ctx, trait_node);
        if (tt)
            effective_recv = rust_resolve_path_expr(ctx, tt);
    } else {
        effective_recv = rust_resolve_path_expr(ctx, type_text);
    }
    if (!effective_recv)
        return;

    const char *saved_self = ctx->self_type_qn;
    const char *saved_trait = ctx->self_trait_qn;
    ctx->self_type_qn = effective_recv;
    ctx->self_trait_qn = NULL;

    if (!ts_node_is_null(trait_node) && !is_blanket) {
        char *tt = rust_node_text(ctx, trait_node);
        if (tt)
            ctx->self_trait_qn = rust_resolve_path_expr(ctx, tt);
    }

    TSNode body = ts_node_child_by_field_name(impl_node, "body", 4);
    if (!ts_node_is_null(body)) {
        uint32_t nc = ts_node_child_count(body);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode c = ts_node_child(body, i);
            if (ts_node_is_null(c) || !ts_node_is_named(c))
                continue;
            const char *ck = ts_node_type(c);
            if (strcmp(ck, "function_item") == 0) {
                rust_process_function(ctx, c, effective_recv);
            } else if (strcmp(ck, "macro_invocation") == 0) {
                TSNode macro_name = ts_node_child_by_field_name(c, "macro", 5);
                if (!ts_node_is_null(macro_name)) {
                    char *name = rust_node_text(ctx, macro_name);
                    if (name) {
                        rust_expand_user_macro(ctx, name, c);
                    }
                }
            }
            if (cbm_arena_failed(ctx->arena)) {
                break;
            }
        }
    }

    ctx->self_type_qn = saved_self;
    ctx->self_trait_qn = saved_trait;
}

void rust_lsp_process_file(RustLSPContext *ctx, TSNode root) {
    if (ts_node_is_null(root))
        return;

    /* Pass 0: collect macro_rules! definitions before walking bodies so
     * macro_invocation handlers can expand user-defined macros. */
    rust_collect_macro_rules(ctx, root);

    /* Record bare `mod foo;` declarations (file links). The pipeline
     * uses these to know which sibling files to include in cross-file
     * resolution. We just store them as Imports with a `mod:` prefix
     * so the pipeline can distinguish them from `use` imports.
     *
     * `mod foo { ... }` (inline module) is NOT recorded — the body is
     * already in this file. Only bare `mod foo;` declarations are. */
    {
        uint32_t rnc = ts_node_child_count(root);
        for (uint32_t i = 0; i < rnc; i++) {
            TSNode c = ts_node_child(root, i);
            if (ts_node_is_null(c))
                continue;
            if (strcmp(ts_node_type(c), "mod_item") != 0)
                continue;
            /* Inline mod has a `body` field; bare decl does not. */
            TSNode body = ts_node_child_by_field_name(c, "body", 4);
            if (!ts_node_is_null(body))
                continue; /* inline */
            TSNode mname = ts_node_child_by_field_name(c, "name", 4);
            if (ts_node_is_null(mname))
                continue;
            char *name = rust_node_text(ctx, mname);
            if (!name)
                continue;
            /* Surface as a synthetic CALLS edge from "<module>" to
             * the sibling module so the cross-file pass picks it up
             * via short-name fallback. We attribute it to the file's
             * synthetic module-scope caller. */
            const char *save_caller = ctx->enclosing_func_qn;
            ctx->enclosing_func_qn = ctx->module_qn;
            rust_emit_resolved_call(ctx,
                                    cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, name),
                                    "lsp_mod_decl", 0.70f);
            ctx->enclosing_func_qn = save_caller;
        }
    }

    /* Pass 1: bind module-level const/static so functions can see them. */
    uint32_t nc = ts_node_child_count(root);
    for (uint32_t i = 0; i < nc; i++) {
        TSNode c = ts_node_child(root, i);
        if (ts_node_is_null(c))
            continue;
        const char *ck = ts_node_type(c);
        if (strcmp(ck, "const_item") == 0 || strcmp(ck, "static_item") == 0) {
            rust_process_statement(ctx, c);
        }
    }

    /* Pass 2: walk every top-level item. */
    for (uint32_t i = 0; i < nc; i++) {
        TSNode c = ts_node_child(root, i);
        if (ts_node_is_null(c))
            continue;
        const char *ck = ts_node_type(c);
        if (strcmp(ck, "function_item") == 0) {
            rust_process_function(ctx, c, NULL);
        } else if (strcmp(ck, "impl_item") == 0) {
            rust_process_impl(ctx, c);
        } else if (strcmp(ck, "mod_item") == 0) {
            /* Inline module — recurse into its declaration_list. */
            TSNode body = ts_node_child_by_field_name(c, "body", 4);
            if (!ts_node_is_null(body)) {
                uint32_t mnc = ts_node_child_count(body);
                for (uint32_t j = 0; j < mnc; j++) {
                    TSNode mc = ts_node_child(body, j);
                    if (ts_node_is_null(mc))
                        continue;
                    const char *mck = ts_node_type(mc);
                    if (strcmp(mck, "function_item") == 0) {
                        rust_process_function(ctx, mc, NULL);
                    } else if (strcmp(mck, "impl_item") == 0) {
                        rust_process_impl(ctx, mc);
                    }
                }
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════
 * 11. Per-file entry: build registry + run
 * ════════════════════════════════════════════════════════════════════ */

/* Collect `use_declaration`s in the file and materialise our use map.
 * Tree-sitter-rust models the pattern as:
 *
 *   use_declaration → identifier | scoped_identifier | scoped_use_list |
 *                     use_list | use_as_clause | use_wildcard.
 *
 * We expand each of these into one or more (alias, full-path) entries. */
static void rust_collect_uses(RustLSPContext *ctx, TSNode root) {
    /* Recursive walker. */
    typedef struct stack_t {
        TSNode node;
        struct stack_t *prev;
    } stack_t;
    stack_t *top = (stack_t *)cbm_arena_alloc(ctx->arena, sizeof(stack_t));
    top->node = root;
    top->prev = NULL;
    while (top) {
        TSNode n = top->node;
        top = top->prev;
        if (ts_node_is_null(n))
            continue;
        const char *k = ts_node_type(n);
        if (strcmp(k, "use_declaration") == 0) {
            char *full = rust_node_text(ctx, n);
            if (full) {
                if (strncmp(full, "use ", 4) == 0)
                    full += 4;
                size_t len = strlen(full);
                if (len > 0 && full[len - 1] == ';')
                    full[len - 1] = '\0';
                /* Trim leading whitespace. */
                while (*full == ' ')
                    full++;
                /* Detect glob. */
                size_t flen = strlen(full);
                if (flen >= 3 && strcmp(full + flen - 3, "::*") == 0) {
                    char *mod = cbm_arena_strndup(ctx->arena, full, flen - 3);
                    rust_lsp_add_glob(ctx, convert_path_to_qn(ctx->arena, mod));
                } else if (flen >= 1 && full[flen - 1] == '}') {
                    /* Brace list: prefix::{a, b as c, d}. */
                    char *lbr = strchr(full, '{');
                    if (lbr) {
                        size_t prefix_len = (size_t)(lbr - full);
                        /* Strip trailing "::" from prefix. */
                        while (prefix_len >= 2 && full[prefix_len - 1] == ':' &&
                               full[prefix_len - 2] == ':') {
                            prefix_len -= 2;
                        }
                        char *prefix = cbm_arena_strndup(ctx->arena, full, prefix_len);
                        char *body = cbm_arena_strdup(ctx->arena, lbr + 1);
                        size_t blen = strlen(body);
                        if (blen > 0 && body[blen - 1] == '}')
                            body[blen - 1] = '\0';
                        char *save = NULL;
                        char *tok = strtok_r(body, ",", &save);
                        while (tok) {
                            while (*tok == ' ')
                                tok++;
                            char *eb = tok + strlen(tok) - 1;
                            while (eb > tok && *eb == ' ')
                                *eb-- = '\0';
                            if (*tok == '\0') {
                                tok = strtok_r(NULL, ",", &save);
                                continue;
                            }
                            /* `Read` or `Read as R`. */
                            char *asp = strstr(tok, " as ");
                            char *alias = NULL;
                            char *path_part = tok;
                            if (asp) {
                                *asp = '\0';
                                alias = asp + 4;
                                while (*alias == ' ')
                                    alias++;
                            } else {
                                alias = (char *)path_last_segment(tok);
                            }
                            char *full_path =
                                (strcmp(tok, "self") == 0)
                                    ? cbm_arena_strdup(ctx->arena, prefix)
                                    : cbm_arena_sprintf(ctx->arena, "%s::%s", prefix, path_part);
                            rust_lsp_add_use(ctx, alias, full_path);
                            tok = strtok_r(NULL, ",", &save);
                        }
                    }
                } else {
                    /* Single path; possibly followed by ` as X`. */
                    char *asp = strstr(full, " as ");
                    char *alias = NULL;
                    char *path_part = full;
                    if (asp) {
                        *asp = '\0';
                        alias = asp + 4;
                        while (*alias == ' ')
                            alias++;
                    } else {
                        alias = (char *)path_last_segment(full);
                    }
                    rust_lsp_add_use(ctx, alias, path_part);
                }
            }
        }
        /* Recurse into mod_item bodies so nested uses are captured too. */
        if (strcmp(k, "mod_item") == 0 || strcmp(k, "source_file") == 0 ||
            strcmp(k, "declaration_list") == 0) {
            uint32_t nc = ts_node_child_count(n);
            for (uint32_t i = 0; i < nc; i++) {
                TSNode c = ts_node_child(n, i);
                if (ts_node_is_null(c))
                    continue;
                stack_t *nx = (stack_t *)cbm_arena_alloc(ctx->arena, sizeof(stack_t));
                nx->node = c;
                nx->prev = top;
                top = nx;
            }
        }
    }
}

/* Build the registry from the per-file `result->defs`, `result->impl_traits`,
 * and a Rust prelude seed. */
static void rust_build_registry_from_defs(CBMArena *arena, CBMTypeRegistry *reg,
                                          CBMFileResult *result, const char *module_qn, TSNode root,
                                          const char *source) {

    cbm_registry_init(reg, arena);
    cbm_rust_stdlib_register(reg, arena);

    /* Phase A: register every Class/Type/Trait/Function/Method definition. */
    for (int i = 0; i < result->defs.count; i++) {
        CBMDefinition *d = &result->defs.items[i];
        if (!d->qualified_name || !d->name)
            continue;

        // Every type-like container (Class/Struct/Type/Interface/Trait/Enum).
        // Struct included so a Rust `struct Foo` (now labelled "Struct") registers
        // as a type and its `impl Foo` methods/fields resolve.
        if (cbm_label_is_type_like(d->label)) {
            CBMRegisteredType rt;
            memset(&rt, 0, sizeof(rt));
            rt.qualified_name = d->qualified_name;
            rt.short_name = d->name;
            rt.is_interface =
                (strcmp(d->label, "Interface") == 0 || strcmp(d->label, "Trait") == 0);
            cbm_registry_add_type(reg, rt);
        }

        if (d->label && (strcmp(d->label, "Function") == 0 || strcmp(d->label, "Method") == 0)) {
            CBMRegisteredFunc rf;
            memset(&rf, 0, sizeof(rf));
            rf.qualified_name = d->qualified_name;
            rf.short_name = d->name;
            rf.min_params = -1;

            /* Build FUNC sig from return_types / param_types. */
            const CBMType **ret_types = NULL;
            if (d->return_types) {
                int count = 0;
                while (d->return_types[count])
                    count++;
                if (count > 0) {
                    ret_types = (const CBMType **)cbm_arena_alloc(
                        arena, (count + 1) * sizeof(const CBMType *));
                    for (int j = 0; j < count; j++) {
                        ret_types[j] =
                            rust_parse_return_type_text(arena, d->return_types[j], module_qn);
                    }
                    ret_types[count] = NULL;
                }
            } else if (d->return_type && d->return_type[0]) {
                ret_types = (const CBMType **)cbm_arena_alloc(arena, 2 * sizeof(const CBMType *));
                ret_types[0] = rust_parse_return_type_text(arena, d->return_type, module_qn);
                ret_types[1] = NULL;
            }
            const CBMType **param_types = NULL;
            if (d->param_types) {
                int count = 0;
                while (d->param_types[count])
                    count++;
                if (count > 0) {
                    param_types = (const CBMType **)cbm_arena_alloc(
                        arena, (count + 1) * sizeof(const CBMType *));
                    for (int j = 0; j < count; j++) {
                        param_types[j] =
                            rust_parse_return_type_text(arena, d->param_types[j], module_qn);
                    }
                    param_types[count] = NULL;
                }
            }
            rf.signature = cbm_type_func(arena, d->param_names, param_types, ret_types);

            if (strcmp(d->label, "Method") == 0 && d->parent_class) {
                rf.receiver_type = d->parent_class;
                if (!cbm_registry_lookup_type(reg, rf.receiver_type)) {
                    CBMRegisteredType auto_t;
                    memset(&auto_t, 0, sizeof(auto_t));
                    auto_t.qualified_name = rf.receiver_type;
                    const char *dot = strrchr(rf.receiver_type, '.');
                    auto_t.short_name = dot ? cbm_arena_strdup(arena, dot + 1) : rf.receiver_type;
                    cbm_registry_add_type(reg, auto_t);
                }
            }

            cbm_registry_add_func(reg, rf);
        }
    }

    /* Phase B: walk the AST to extract struct fields + record `impl Trait
     * for Type` linkage as embedded types. */
    if (!ts_node_is_null(root)) {
        uint32_t nc = ts_node_child_count(root);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode top = ts_node_child(root, i);
            if (ts_node_is_null(top))
                continue;
            const char *tk = ts_node_type(top);

            if (strcmp(tk, "struct_item") == 0) {
                TSNode name_node = ts_node_child_by_field_name(top, "name", 4);
                TSNode body = ts_node_child_by_field_name(top, "body", 4);
                if (ts_node_is_null(name_node) || ts_node_is_null(body))
                    continue;
                char *tn = cbm_node_text(arena, name_node, source);
                if (!tn || !tn[0])
                    continue;
                const char *type_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, tn);

                /* Iterate field_declaration_list / ordered_field_declaration_list. */
                if (strcmp(ts_node_type(body), "field_declaration_list") == 0) {
                    uint32_t fc = ts_node_named_child_count(body);
                    const char **fld_names = NULL;
                    const CBMType **fld_types = NULL;
                    size_t fld_count = 0;
                    size_t fld_name_capacity = 0;
                    size_t fld_type_capacity = 0;
                    for (uint32_t j = 0; j < fc; j++) {
                        TSNode fd = ts_node_named_child(body, j);
                        if (strcmp(ts_node_type(fd), "field_declaration") != 0)
                            continue;
                        TSNode fn = ts_node_child_by_field_name(fd, "name", 4);
                        TSNode ft = ts_node_child_by_field_name(fd, "type", 4);
                        char *fname = cbm_node_text(arena, fn, source);
                        if (!fname)
                            continue;
                        /* Build a temporary context for parsing types. */
                        RustLSPContext tmp;
                        memset(&tmp, 0, sizeof(tmp));
                        tmp.arena = arena;
                        tmp.source = source;
                        tmp.source_len = (int)strlen(source);
                        tmp.registry = reg;
                        tmp.module_qn = module_qn;
                        const CBMType *ft_t = rust_parse_type_node(&tmp, ft);
                        if (!cbm_lsp_semantic_array_reserve(
                                arena, (void **)&fld_names, fld_count, &fld_name_capacity,
                                sizeof(*fld_names), fld_count + 2, "rust struct field names") ||
                            !cbm_lsp_semantic_array_reserve(
                                arena, (void **)&fld_types, fld_count, &fld_type_capacity,
                                sizeof(*fld_types), fld_count + 2, "rust struct field types")) {
                            return;
                        }
                        fld_names[fld_count] = fname;
                        fld_types[fld_count] = ft_t;
                        fld_count++;
                    }
                    if (fld_count > 0) {
                        for (int ti = 0; ti < reg->type_count; ti++) {
                            if (reg->types[ti].qualified_name &&
                                strcmp(reg->types[ti].qualified_name, type_qn) == 0) {
                                fld_names[fld_count] = NULL;
                                fld_types[fld_count] = NULL;
                                reg->types[ti].field_names = fld_names;
                                reg->types[ti].field_types = fld_types;
                                break;
                            }
                        }
                    }
                }
            }

            if (strcmp(tk, "trait_item") == 0) {
                TSNode name_node = ts_node_child_by_field_name(top, "name", 4);
                TSNode body = ts_node_child_by_field_name(top, "body", 4);
                if (ts_node_is_null(name_node))
                    continue;
                char *tn = cbm_node_text(arena, name_node, source);
                if (!tn || !tn[0])
                    continue;
                const char *trait_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, tn);

                /* Mark as interface and collect method names. */
                for (int ti = 0; ti < reg->type_count; ti++) {
                    if (!reg->types[ti].qualified_name)
                        continue;
                    if (strcmp(reg->types[ti].qualified_name, trait_qn) == 0) {
                        reg->types[ti].is_interface = true;
                        if (!ts_node_is_null(body)) {
                            const char **methods = NULL;
                            size_t mc = 0;
                            size_t method_capacity = 0;
                            uint32_t bc = ts_node_named_child_count(body);
                            for (uint32_t j = 0; j < bc; j++) {
                                TSNode item = ts_node_named_child(body, j);
                                const char *ik = ts_node_type(item);
                                if (strcmp(ik, "function_item") != 0 &&
                                    strcmp(ik, "function_signature_item") != 0)
                                    continue;
                                TSNode mn = ts_node_child_by_field_name(item, "name", 4);
                                if (ts_node_is_null(mn))
                                    continue;
                                char *mname = cbm_node_text(arena, mn, source);
                                if (mname) {
                                    if (!cbm_lsp_semantic_array_reserve(
                                            arena, (void **)&methods, mc, &method_capacity,
                                            sizeof(*methods), mc + 2, "rust trait method names")) {
                                        return;
                                    }
                                    methods[mc++] = mname;
                                }
                            }
                            if (mc > 0) {
                                methods[mc] = NULL;
                                reg->types[ti].method_names = methods;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    /* Phase B1: walk top-level free `function_item`s to harvest their
     * return types into the registry — `extract_defs` does not fill
     * `return_type` for Rust free functions either, so a let-binding
     * like `let v = pair();` would otherwise know nothing about pair's
     * return tuple. */
    if (!ts_node_is_null(root)) {
        RustLSPContext tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.arena = arena;
        tmp.source = source;
        tmp.source_len = (int)strlen(source);
        tmp.registry = reg;
        tmp.module_qn = module_qn;

        uint32_t rnc = ts_node_child_count(root);
        for (uint32_t i = 0; i < rnc; i++) {
            TSNode top = ts_node_child(root, i);
            if (ts_node_is_null(top) || strcmp(ts_node_type(top), "function_item") != 0)
                continue;
            TSNode mn = ts_node_child_by_field_name(top, "name", 4);
            TSNode rtn = ts_node_child_by_field_name(top, "return_type", 11);
            if (ts_node_is_null(mn) || ts_node_is_null(rtn))
                continue;
            char *fname = cbm_node_text(arena, mn, source);
            if (!fname)
                continue;
            const CBMType *ret = rust_parse_type_node(&tmp, rtn);
            const char *fn_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, fname);
            for (int k = 0; k < reg->func_count; k++) {
                CBMRegisteredFunc *rf = &reg->funcs[k];
                if (!rf->qualified_name)
                    continue;
                if (rf->receiver_type)
                    continue; /* free fns only */
                if (strcmp(rf->qualified_name, fn_qn) != 0)
                    continue;
                const CBMType **ret_arr =
                    (const CBMType **)cbm_arena_alloc(arena, 2 * sizeof(const CBMType *));
                ret_arr[0] = ret;
                ret_arr[1] = NULL;
                rf->signature = cbm_type_func(arena, NULL, NULL, ret_arr);
                break;
            }
        }
    }

    /* Phase A2: derive-macro synthesis.
     *
     * Real Rust code is saturated with `#[derive(Clone, Debug, …)]`.
     * Without expanding proc-macros we can still synthesize the trait
     * impl footprint that each well-known derive generates, so calls
     * like `x.clone()` / `format!("{:?}", x)` / `MyT::default()` on the
     * derived type actually resolve.
     *
     * We only synthesize the curated, high-frequency derives — anything
     * unknown is left alone (per the FOLLOWUP doc's "no false edge"
     * policy). Each synthesized impl:
     *   - registers a method (or static fn for `default`/`parse`) on
     *     the receiver type with the right short name and return type;
     *   - appends the trait's QN to the receiver's `embedded_types` so
     *     trait dispatch via `resolve_trait_method` walks it.
     */
    {
        /* Curated derive → (trait QN, [methods with sig sketch]) table. */
        struct DeriveMethod {
            const char *short_name;
            const char *return_type; /* QN or NULL for unknown */
            bool is_static;          /* no `self` (e.g. `default`, `parse`) */
        };
        struct DeriveImpl {
            const char *derive_name;
            const char *trait_qn;
            struct DeriveMethod methods[4]; /* NULL-terminated by empty short_name */
        };
        static const struct DeriveImpl derives[] = {
            {"Clone", "core.clone.Clone", {{"clone", NULL, false}, {NULL, NULL, false}}},
            {"Copy", "core.marker.Copy", {{NULL, NULL, false}}}, /* marker — no methods */
            {"Debug", "core.fmt.Debug", {{"fmt", NULL, false}, {NULL, NULL, false}}},
            {"Display", "core.fmt.Display", {{"fmt", NULL, false}, {NULL, NULL, false}}},
            {"Default", "core.default.Default", {{"default", NULL, true}, {NULL, NULL, false}}},
            {"PartialEq",
             "core.cmp.PartialEq",
             {{"eq", "bool", false}, {"ne", "bool", false}, {NULL, NULL, false}}},
            {"Eq", "core.cmp.Eq", {{NULL, NULL, false}}}, /* marker only */
            {"PartialOrd",
             "core.cmp.PartialOrd",
             {{"partial_cmp", NULL, false},
              {"lt", "bool", false},
              {"le", "bool", false},
              {NULL, NULL, false}}},
            {"Ord", "core.cmp.Ord", {{"cmp", NULL, false}, {NULL, NULL, false}}},
            {"Hash", "core.hash.Hash", {{"hash", "()", false}, {NULL, NULL, false}}},
            {"Send", "core.marker.Send", {{NULL, NULL, false}}},
            {"Sync", "core.marker.Sync", {{NULL, NULL, false}}},
            /* serde — extremely common. */
            {"Serialize", "serde.Serialize", {{"serialize", NULL, false}, {NULL, NULL, false}}},
            {"Deserialize",
             "serde.Deserialize",
             {{"deserialize", NULL, true}, {NULL, NULL, false}}},
            /* clap derive — synthesizes the Parser interface. */
            {"Parser",
             "clap.Parser",
             {{"parse", NULL, true},
              {"try_parse", NULL, true},
              {"parse_from", NULL, true},
              {"try_parse_from", NULL, true}}},
            {"Args", "clap.Args", {{NULL, NULL, false}}},
            {"Subcommand", "clap.Subcommand", {{NULL, NULL, false}}},
            {"ValueEnum", "clap.ValueEnum", {{NULL, NULL, false}}},
            /* thiserror — adds the Error impl. */
            {"Error", "core.error.Error", {{NULL, NULL, false}}},
        };
        const int derive_count = (int)(sizeof(derives) / sizeof(derives[0]));

        for (int i = 0; i < result->defs.count; i++) {
            CBMDefinition *d = &result->defs.items[i];
            if (!d->qualified_name || !d->name)
                continue;
            /* `#[derive(...)]` rides on type-like defs — most often a struct or
             * enum (now labelled "Struct"/"Enum"), also type aliases. Accept the
             * whole type-like set so a derive on a struct is not dropped. */
            if (!cbm_label_is_type_like(d->label))
                continue;
            if (!d->decorators)
                continue;

            /* Scan decorator strings for `#[derive(...)]`. */
            for (int di = 0; d->decorators[di]; di++) {
                const char *dec = d->decorators[di];
                const char *p = strstr(dec, "derive");
                if (!p)
                    continue;
                const char *lparen = strchr(p, '(');
                if (!lparen)
                    continue;
                const char *rparen = strchr(lparen, ')');
                if (!rparen)
                    continue;
                /* Now walk between the parens, splitting on comma. */
                const char *q = lparen + 1;
                while (q < rparen) {
                    while (q < rparen && (*q == ' ' || *q == ','))
                        q++;
                    /* Find the end of the identifier (may be qualified
                     * like `serde::Serialize`). We grab the trailing
                     * segment as the derive name. */
                    const char *tok_start = q;
                    while (q < rparen && *q != ',' && *q != ' ')
                        q++;
                    if (q == tok_start)
                        break;
                    /* Trailing-segment after the last `::`. */
                    const char *short_start = tok_start;
                    for (const char *r = tok_start; r < q - 1; r++) {
                        if (r[0] == ':' && r[1] == ':')
                            short_start = r + 2;
                    }
                    size_t name_len = (size_t)(q - short_start);
                    if (name_len == 0 || name_len > 64)
                        continue;
                    /* Look up in curated table. */
                    for (int di2 = 0; di2 < derive_count; di2++) {
                        const struct DeriveImpl *di_entry = &derives[di2];
                        size_t entry_len = strlen(di_entry->derive_name);
                        if (entry_len != name_len)
                            continue;
                        if (strncmp(di_entry->derive_name, short_start, name_len) != 0)
                            continue;

                        /* Found a matching curated derive. Register the
                         * trait QN as an embedded_type on the receiver
                         * AND synthesize the method entries. */
                        CBMRegisteredType *rt = NULL;
                        for (int ti = 0; ti < reg->type_count; ti++) {
                            if (reg->types[ti].qualified_name &&
                                strcmp(reg->types[ti].qualified_name, d->qualified_name) == 0) {
                                rt = &reg->types[ti];
                                break;
                            }
                        }
                        if (!rt)
                            break;

                        /* Append trait QN to embedded_types. */
                        int existing = 0;
                        if (rt->embedded_types) {
                            while (rt->embedded_types[existing])
                                existing++;
                        }
                        const char **new_arr = (const char **)cbm_arena_alloc(
                            arena, (existing + 2) * sizeof(const char *));
                        for (int k = 0; k < existing; k++) {
                            new_arr[k] = rt->embedded_types[k];
                        }
                        new_arr[existing] = di_entry->trait_qn;
                        new_arr[existing + 1] = NULL;
                        rt->embedded_types = new_arr;

                        /* Synthesize methods. Bound `mi < 4` BEFORE dereferencing
                         * methods[mi] so we never read methods[4] (OOB). */
                        for (int mi = 0; mi < 4 && di_entry->methods[mi].short_name; mi++) {
                            const struct DeriveMethod *dm = &di_entry->methods[mi];
                            CBMRegisteredFunc rf;
                            memset(&rf, 0, sizeof(rf));
                            rf.short_name = dm->short_name;
                            rf.qualified_name = cbm_arena_sprintf(arena, "%s.%s", d->qualified_name,
                                                                  dm->short_name);
                            /* Static methods (default/parse) have no
                             * receiver; method calls treat them as
                             * static path lookups via UFCS. */
                            rf.receiver_type = d->qualified_name;
                            rf.min_params = -1;
                            const CBMType *ret_t = cbm_type_unknown();
                            if (dm->return_type) {
                                if (strcmp(dm->return_type, "bool") == 0) {
                                    ret_t = cbm_type_builtin(arena, "bool");
                                } else if (strcmp(dm->return_type, "()") == 0) {
                                    ret_t = cbm_type_builtin(arena, "()");
                                }
                            } else if (dm->is_static) {
                                /* `default()`, `parse()` return Self. */
                                ret_t = cbm_type_named(arena, d->qualified_name);
                            }
                            const CBMType **ra = (const CBMType **)cbm_arena_alloc(
                                arena, 2 * sizeof(const CBMType *));
                            ra[0] = ret_t;
                            ra[1] = NULL;
                            rf.signature = cbm_type_func(arena, NULL, NULL, ra);
                            cbm_registry_add_func(reg, rf);
                        }
                        break;
                    }
                }
            }
        }
    }

    /* Phase B2: walk impl bodies to harvest each method's return type
     * from the AST. The unified `extract_defs` extractor does not fill
     * `return_type` for Rust impl methods, so without this pass our
     * registered functions have no return-type signature and chained
     * method calls (`File::open().read()`) break. */
    if (!ts_node_is_null(root)) {
        uint32_t rnc = ts_node_child_count(root);
        for (uint32_t i = 0; i < rnc; i++) {
            TSNode top = ts_node_child(root, i);
            if (ts_node_is_null(top) || strcmp(ts_node_type(top), "impl_item") != 0)
                continue;
            TSNode type_node = ts_node_child_by_field_name(top, "type", 4);
            TSNode body = ts_node_child_by_field_name(top, "body", 4);
            if (ts_node_is_null(type_node) || ts_node_is_null(body))
                continue;
            char *type_name = cbm_node_text(arena, type_node, source);
            if (!type_name || !type_name[0])
                continue;
            const char *type_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, type_name);

            RustLSPContext tmp;
            memset(&tmp, 0, sizeof(tmp));
            tmp.arena = arena;
            tmp.source = source;
            tmp.source_len = (int)strlen(source);
            tmp.registry = reg;
            tmp.module_qn = module_qn;
            tmp.self_type_qn = type_qn;

            uint32_t bnc = ts_node_child_count(body);
            for (uint32_t j = 0; j < bnc; j++) {
                TSNode item = ts_node_child(body, j);
                if (ts_node_is_null(item) || !ts_node_is_named(item))
                    continue;
                if (strcmp(ts_node_type(item), "function_item") != 0)
                    continue;
                TSNode mn = ts_node_child_by_field_name(item, "name", 4);
                TSNode rtn = ts_node_child_by_field_name(item, "return_type", 11);
                if (ts_node_is_null(mn) || ts_node_is_null(rtn))
                    continue;
                char *mname = cbm_node_text(arena, mn, source);
                if (!mname)
                    continue;
                const CBMType *ret = rust_parse_type_node(&tmp, rtn);
                /* Substitute Self -> receiver type so chains work. */
                if (ret && ret->kind == CBM_TYPE_NAMED &&
                    strcmp(ret->data.named.qualified_name, "Self") == 0) {
                    ret = cbm_type_named(arena, type_qn);
                }
                /* Patch the registered function's signature. */
                for (int k = 0; k < reg->func_count; k++) {
                    CBMRegisteredFunc *rf = &reg->funcs[k];
                    if (!rf->receiver_type || !rf->short_name)
                        continue;
                    if (strcmp(rf->receiver_type, type_qn) != 0)
                        continue;
                    if (strcmp(rf->short_name, mname) != 0)
                        continue;
                    const CBMType **ret_arr =
                        (const CBMType **)cbm_arena_alloc(arena, 2 * sizeof(const CBMType *));
                    ret_arr[0] = ret;
                    ret_arr[1] = NULL;
                    rf->signature = cbm_type_func(arena, NULL, NULL, ret_arr);
                    break;
                }
            }
        }
    }

    /* Phase C: encode `impl Trait for Type` as `embedded_types` on the
     * receiver type so trait dispatch can find them. */
    for (int i = 0; i < result->impl_traits.count; i++) {
        CBMImplTrait *it = &result->impl_traits.items[i];
        if (!it->struct_name || !it->trait_name)
            continue;
        const char *recv_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, it->struct_name);
        const char *trait_qn = strstr(it->trait_name, "::")
                                   ? convert_path_to_qn(arena, it->trait_name)
                                   : cbm_arena_sprintf(arena, "%s.%s", module_qn, it->trait_name);

        CBMRegisteredType *rt = NULL;
        for (int ti = 0; ti < reg->type_count; ti++) {
            if (reg->types[ti].qualified_name &&
                strcmp(reg->types[ti].qualified_name, recv_qn) == 0) {
                rt = &reg->types[ti];
                break;
            }
        }
        if (!rt) {
            CBMRegisteredType auto_t;
            memset(&auto_t, 0, sizeof(auto_t));
            auto_t.qualified_name = recv_qn;
            const char *dot = strrchr(recv_qn, '.');
            auto_t.short_name = dot ? dot + 1 : recv_qn;
            cbm_registry_add_type(reg, auto_t);
            rt = &reg->types[reg->type_count - 1];
        }
        /* Append trait_qn to embedded_types. */
        int existing = 0;
        if (rt->embedded_types) {
            while (rt->embedded_types[existing])
                existing++;
        }
        const char **new_arr =
            (const char **)cbm_arena_alloc(arena, (existing + 2) * sizeof(const char *));
        for (int j = 0; j < existing; j++)
            new_arr[j] = rt->embedded_types[j];
        new_arr[existing] = trait_qn;
        new_arr[existing + 1] = NULL;
        rt->embedded_types = new_arr;
    }
}

void cbm_run_rust_lsp_with_manifest(CBMArena *arena, CBMFileResult *result, const char *source,
                                    int source_len, TSNode root,
                                    const struct CBMCargoManifest *manifest) {
    if (!arena || !result || !source)
        return;
    const char *module_qn = result->module_qn ? result->module_qn : "rust";

    CBMTypeRegistry reg;
    rust_build_registry_from_defs(arena, &reg, result, module_qn, root, source);
    /* Finalize after all per-file adds so lookups during the walk
     * use the hash buckets. */
    cbm_registry_finalize(&reg);

    RustLSPContext ctx;
    rust_lsp_init(&ctx, arena, source, source_len, &reg, module_qn, &result->resolved_calls);
    ctx.cargo_manifest = manifest;
    /* Let the resolver inject synthetic syntactic calls for operator/macro
     * desugaring so those recovered calls reach the CALLS-edge pipeline. */
    ctx.syn_calls = &result->calls;

    rust_collect_uses(&ctx, root);
    /* Bridge any extracted CBMImports the unified extractor saw. */
    for (int i = 0; i < result->imports.count; i++) {
        CBMImport *imp = &result->imports.items[i];
        if (imp->local_name && imp->module_path) {
            rust_lsp_add_use(&ctx, imp->local_name, imp->module_path);
        }
    }

    rust_lsp_process_file(&ctx, root);

    /* Curated attribute proc-macro synthesis (Option B of the
     * follow-up plan). Runs after the main walk so the synthetic
     * edges are appended without affecting in-walk attribution. */
    cbm_rust_synth_proc_macro_edges(arena, result);
}

void cbm_run_rust_lsp(CBMArena *arena, CBMFileResult *result, const char *source, int source_len,
                      TSNode root) {
    cbm_run_rust_lsp_with_manifest(arena, result, source, source_len, root, NULL);
}

/* ════════════════════════════════════════════════════════════════════
 * 12. Cross-file + batch
 * ════════════════════════════════════════════════════════════════════ */

extern const TSLanguage *tree_sitter_rust(void);

/* Populate + finalize a Rust cross-file type registry from `defs`. Shared by the
 * per-file resolver (cbm_run_rust_lsp_cross_with_manifest) and the build-once shared
 * registry (cbm_rust_build_cross_registry) so both produce a byte-identical registry.
 * `module_qn` is ONLY the fallback used to qualify a def's return type when that def
 * carries no def_module_qn; pass NULL for the shared build (all_defs always carry
 * def_module_qn — verified: 0 NULL across the C + Rust kernel corpora). */
static void rust_populate_cross_registry(CBMTypeRegistry *reg, CBMArena *arena, CBMRustLSPDef *defs,
                                         int def_count, const char *module_qn) {
    cbm_registry_init(reg, arena);
    cbm_rust_stdlib_register(reg, arena);

    /* qn → (type index + 1), FIRST occurrence wins (mirrors the linear scans
     * this map replaces). Both in-loop registry probes below — the receiver
     * auto-registration check and the trait-linkage lookup — used to scan the
     * UNFINALIZED registry linearly (no buckets exist before finalize): the
     * checklist's lookup-in-registration-loop pattern. Invisible on small
     * per-file builds; on the shared all_defs build (~1.4M entries) those
     * scans were a constant ~63 s of the kernel run — and the sibling
     * null-filter files waited on the build once-guard for exactly that long,
     * which is why no resolution-side fix ever moved their wall time. Index,
     * not pointer, because reg->types reallocs as it grows. */
    CBMIdxMemo type_idx = {0};
    for (int ti = 0; ti < reg->type_count; ti++) {
        const char *qn = reg->types[ti].qualified_name;
        if (qn) {
            cbm_idxmemo_put_if_absent(&type_idx, arena, qn, ti);
        }
    }

    for (int i = 0; i < def_count; i++) {
        CBMRustLSPDef *d = &defs[i];
        if (!d->qualified_name || !d->short_name || !d->label)
            continue;
        const char *def_mod = d->def_module_qn ? d->def_module_qn : module_qn;

        // Every type-like container (Type/Class/Struct/Interface/Trait/Enum).
        // Struct included so Rust structs (now labelled "Struct") register here.
        if (cbm_label_is_type_like(d->label)) {
            CBMRegisteredType rt;
            memset(&rt, 0, sizeof(rt));
            rt.qualified_name = cbm_arena_strdup(arena, d->qualified_name);
            rt.short_name = cbm_arena_strdup(arena, d->short_name);
            rt.is_interface = d->is_interface || strcmp(d->label, "Trait") == 0 ||
                              strcmp(d->label, "Interface") == 0;
            cbm_registry_add_type(reg, rt);
            cbm_idxmemo_put_if_absent(&type_idx, arena, rt.qualified_name, reg->type_count - 1);
        }

        if (strcmp(d->label, "Function") == 0 || strcmp(d->label, "Method") == 0) {
            CBMRegisteredFunc rf;
            memset(&rf, 0, sizeof(rf));
            rf.qualified_name = cbm_arena_strdup(arena, d->qualified_name);
            rf.short_name = cbm_arena_strdup(arena, d->short_name);
            rf.min_params = -1;

            /* Build sig from return_types text. */
            const CBMType **ret_types = NULL;
            if (d->return_types && d->return_types[0]) {
                int count = 1;
                for (const char *p = d->return_types; *p; p++) {
                    if (*p == '|')
                        count++;
                }
                ret_types =
                    (const CBMType **)cbm_arena_alloc(arena, (count + 1) * sizeof(const CBMType *));
                int idx = 0;
                char *buf = cbm_arena_strdup(arena, d->return_types);
                char *start = buf;
                for (char *p = buf;; p++) {
                    if (*p == '|' || *p == '\0') {
                        char save = *p;
                        *p = '\0';
                        if (start[0]) {
                            ret_types[idx++] = rust_parse_return_type_text(arena, start, def_mod);
                        }
                        if (save == '\0')
                            break;
                        start = p + 1;
                    }
                }
                ret_types[idx] = NULL;
            }
            rf.signature = cbm_type_func(arena, NULL, NULL, ret_types);

            if (strcmp(d->label, "Method") == 0 && d->receiver_type && d->receiver_type[0]) {
                rf.receiver_type = cbm_arena_strdup(arena, d->receiver_type);
                if (cbm_idxmemo_get(&type_idx, rf.receiver_type) < 0) {
                    CBMRegisteredType auto_t;
                    memset(&auto_t, 0, sizeof(auto_t));
                    auto_t.qualified_name = rf.receiver_type;
                    const char *dot = strrchr(d->receiver_type, '.');
                    auto_t.short_name = dot ? cbm_arena_strdup(arena, dot + 1) : rf.receiver_type;
                    cbm_registry_add_type(reg, auto_t);
                    cbm_idxmemo_put_if_absent(&type_idx, arena, auto_t.qualified_name,
                                              reg->type_count - 1);
                }
            }

            cbm_registry_add_func(reg, rf);

            /* If trait_qn set: encode embedded_type linkage on receiver. */
            if (rf.receiver_type && d->trait_qn && d->trait_qn[0]) {
                CBMRegisteredType *rt = NULL;
                int32_t tix = cbm_idxmemo_get(&type_idx, rf.receiver_type);
                if (tix >= 0) {
                    rt = &reg->types[tix];
                }
                if (rt) {
                    int existing = 0;
                    if (rt->embedded_types)
                        while (rt->embedded_types[existing])
                            existing++;
                    const char **new_arr = (const char **)cbm_arena_alloc(
                        arena, (existing + 2) * sizeof(const char *));
                    for (int j = 0; j < existing; j++)
                        new_arr[j] = rt->embedded_types[j];
                    new_arr[existing] = cbm_arena_strdup(arena, d->trait_qn);
                    new_arr[existing + 1] = NULL;
                    rt->embedded_types = new_arr;
                }
            }
        }
    }

    /* Finalise the cross-file registry now that all defs are added.
     * (type_idx is arena-owned — freed with the registry's arena.) */
    cbm_registry_finalize(reg);
}

/* Resolve one Rust file against an ALREADY-built (per-file or shared) registry. */
static void rust_resolve_against_registry(CBMArena *arena, const char *source, int source_len,
                                          const char *module_qn, const CBMTypeRegistry *reg,
                                          const char **import_names, const char **import_qns,
                                          int import_count, TSNode root,
                                          const struct CBMCargoManifest *manifest,
                                          CBMResolvedCallArray *out, CBMFileResult *result) {
    RustLSPContext ctx;
    rust_lsp_init(&ctx, arena, source, source_len, reg, module_qn, out);
    ctx.cargo_manifest = manifest;
    rust_collect_uses(&ctx, root);
    for (int i = 0; i < import_count; i++) {
        if (import_names[i] && import_qns[i]) {
            rust_lsp_add_use(&ctx, import_names[i], import_qns[i]);
        }
    }
    rust_lsp_process_file(&ctx, root);
    if (result)
        cbm_rust_synth_proc_macro_edges(arena, result);
}

/* Tier-2: build the Rust cross registry ONCE from all project defs, sealed
 * read-only, and shared across every Rust file's resolve (mirrors C/py/cs/ts).
 * Converts the pipeline's CBMLSPDef into CBMRustLSPDef inline (same field copy as
 * pass_lsp_cross.c's pxc_lspdefs_to_rust, incl. trait_qn=NULL). module_qn=NULL is
 * byte-identical because all_defs always carry def_module_qn. */
CBMTypeRegistry *cbm_rust_build_cross_registry(CBMArena *arena, CBMLSPDef *defs, int def_count) {
    if (!arena)
        return NULL;
    CBMTypeRegistry *reg = (CBMTypeRegistry *)cbm_arena_alloc(arena, sizeof(*reg));
    if (!reg)
        return NULL;
    CBMRustLSPDef *rdefs = NULL;
    if (def_count > 0) {
        rdefs = (CBMRustLSPDef *)cbm_arena_alloc(arena, (size_t)def_count * sizeof(CBMRustLSPDef));
        if (!rdefs)
            return NULL;
        for (int i = 0; i < def_count; i++) {
            rdefs[i].qualified_name = defs[i].qualified_name;
            rdefs[i].short_name = defs[i].short_name;
            rdefs[i].label = defs[i].label;
            rdefs[i].receiver_type = defs[i].receiver_type;
            rdefs[i].def_module_qn = defs[i].def_module_qn;
            rdefs[i].return_types = defs[i].return_types;
            rdefs[i].embedded_types = defs[i].embedded_types;
            rdefs[i].field_defs = defs[i].field_defs;
            rdefs[i].method_names_str = defs[i].method_names_str;
            rdefs[i].trait_qn = NULL;
            rdefs[i].is_interface = defs[i].is_interface;
        }
    }
    rust_populate_cross_registry(reg, arena, rdefs, def_count, /*module_qn=*/NULL);
    reg->read_only = true; /* seal: shared Tier-2 registry is read-only during resolve */
    return reg;
}

/* Cross-file Rust resolve using a pre-built shared registry (Tier-2). Skips the
 * per-file registry build; just parse + resolve. Mirrors cbm_run_c_lsp_cross_with_registry. */
void cbm_run_rust_lsp_cross_with_registry(CBMArena *arena, const char *source, int source_len,
                                          const char *module_qn, const CBMTypeRegistry *reg,
                                          const char **import_names, const char **import_qns,
                                          int import_count, TSTree *cached_tree,
                                          const struct CBMCargoManifest *manifest,
                                          CBMResolvedCallArray *out, CBMFileResult *result) {
    if (!source || source_len <= 0 || !out || !reg)
        return;
    TSParser *parser = NULL;
    TSTree *tree = cached_tree;
    bool owns_tree = false;
    if (!tree) {
        parser = ts_parser_new();
        if (!parser)
            return;
        ts_parser_set_language(parser, tree_sitter_rust());
        tree = ts_parser_parse_string(parser, NULL, source, source_len);
        owns_tree = true;
        if (!tree) {
            ts_parser_delete(parser);
            return;
        }
    }
    TSNode root = ts_tree_root_node(tree);
    rust_resolve_against_registry(arena, source, source_len, module_qn, reg, import_names,
                                  import_qns, import_count, root, manifest, out, result);
    if (owns_tree) {
        ts_tree_delete(tree);
        if (parser)
            ts_parser_delete(parser);
    }
}

void cbm_run_rust_lsp_cross_with_manifest(CBMArena *arena, const char *source, int source_len,
                                          const char *module_qn, CBMRustLSPDef *defs, int def_count,
                                          const char **import_names, const char **import_qns,
                                          int import_count, TSTree *cached_tree,
                                          const struct CBMCargoManifest *manifest,
                                          CBMResolvedCallArray *out) {
    if (!source || source_len <= 0 || !out)
        return;

    TSParser *parser = NULL;
    TSTree *tree = cached_tree;
    bool owns_tree = false;
    if (!tree) {
        parser = ts_parser_new();
        if (!parser)
            return;
        ts_parser_set_language(parser, tree_sitter_rust());
        tree = ts_parser_parse_string(parser, NULL, source, source_len);
        owns_tree = true;
        if (!tree) {
            ts_parser_delete(parser);
            return;
        }
    }
    TSNode root = ts_tree_root_node(tree);

    /* Build registry from cross-file defs + stdlib (per-file). */
    CBMTypeRegistry reg;
    rust_populate_cross_registry(&reg, arena, defs, def_count, module_qn);

    RustLSPContext ctx;
    rust_lsp_init(&ctx, arena, source, source_len, &reg, module_qn, out);
    /* Workspace/dependency awareness for cross-CRATE path routing (#56).
     * Mirrors the single-file path (cbm_run_rust_lsp_with_manifest). NULL
     * when no Cargo.toml was parsed — in-crate resolution is unaffected. */
    ctx.cargo_manifest = manifest;
    rust_collect_uses(&ctx, root);
    for (int i = 0; i < import_count; i++) {
        if (import_names[i] && import_qns[i]) {
            rust_lsp_add_use(&ctx, import_names[i], import_qns[i]);
        }
    }
    rust_lsp_process_file(&ctx, root);

    if (owns_tree) {
        ts_tree_delete(tree);
        if (parser)
            ts_parser_delete(parser);
    }
}

/* Manifest-free entry point. Preserves the pre-existing signature used by
 * the unit tests (test_rust_lsp.c) and the batch wrapper — delegates to
 * the manifest-aware variant with a NULL manifest. */
void cbm_run_rust_lsp_cross(CBMArena *arena, const char *source, int source_len,
                            const char *module_qn, CBMRustLSPDef *defs, int def_count,
                            const char **import_names, const char **import_qns, int import_count,
                            TSTree *cached_tree, CBMResolvedCallArray *out) {
    cbm_run_rust_lsp_cross_with_manifest(arena, source, source_len, module_qn, defs, def_count,
                                         import_names, import_qns, import_count, cached_tree, NULL,
                                         out);
}

void cbm_batch_rust_lsp_cross(CBMArena *arena, CBMBatchRustLSPFile *files, int file_count,
                              CBMResolvedCallArray *out) {
    if (!files || file_count <= 0 || !out)
        return;

    for (int f = 0; f < file_count; f++) {
        CBMBatchRustLSPFile *file = &files[f];
        memset(&out[f], 0, sizeof(CBMResolvedCallArray));
        if (!file->source || file->source_len <= 0)
            continue;

        CBMArena file_arena;
        cbm_arena_init(&file_arena);

        CBMResolvedCallArray file_out;
        memset(&file_out, 0, sizeof(file_out));

        cbm_run_rust_lsp_cross(&file_arena, file->source, file->source_len, file->module_qn,
                               file->defs, file->def_count, file->import_names, file->import_qns,
                               file->import_count, file->cached_tree, &file_out);

        if (file_out.count > 0) {
            out[f].count = file_out.count;
            out[f].items =
                (CBMResolvedCall *)cbm_arena_alloc(arena, file_out.count * sizeof(CBMResolvedCall));
            for (int j = 0; j < file_out.count; j++) {
                CBMResolvedCall *src = &file_out.items[j];
                CBMResolvedCall *dst = &out[f].items[j];
                dst->caller_qn = src->caller_qn ? cbm_arena_strdup(arena, src->caller_qn) : NULL;
                dst->callee_qn = src->callee_qn ? cbm_arena_strdup(arena, src->callee_qn) : NULL;
                dst->strategy = src->strategy ? cbm_arena_strdup(arena, src->strategy) : NULL;
                dst->confidence = src->confidence;
                dst->reason = src->reason ? cbm_arena_strdup(arena, src->reason) : NULL;
                dst->preprocess_context_id =
                    src->preprocess_context_id
                        ? cbm_arena_strdup(arena, src->preprocess_context_id)
                        : NULL;
            }
        }

        cbm_arena_destroy(&file_arena);
    }
}
