/* rust_cargo.c — Hand-rolled TOML subset parser for Cargo.toml.
 *
 * Recognises only the shapes we need (per RUST_LSP_FOLLOWUP §A3):
 *   - `[section]`, `[a.b.c]`, `[workspace]`, `[dependencies]`
 *   - `key = "string"`, `key = 'string'`, `key = [...]`,
 *     `key = { ... }`
 *   - `members = ["a", "b/c"]`
 *
 * Everything else (numbers, dates, deep tables, comments past EOL) is
 * skipped without error.
 */

#include "rust_cargo.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Tiny tokenizer ──────────────────────────────────────────── */

static int skip_ws_and_comment(const char *s, int len, int from) {
    while (from < len) {
        char c = s[from];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            from++;
            continue;
        }
        if (c == '#') {
            while (from < len && s[from] != '\n')
                from++;
            continue;
        }
        break;
    }
    return from;
}

static bool is_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
           c == '-' || c == '.';
}

/* Parse a bare key (ident-like). Stores arena-allocated copy in *out. */
static int parse_key(CBMArena *a, const char *s, int len, int from, const char **out) {
    int start = from;
    if (from < len && s[from] == '"') {
        from++;
        start = from;
        while (from < len && s[from] != '"') {
            if (s[from] == '\\' && from + 1 < len)
                from += 2;
            else
                from++;
        }
        *out = cbm_arena_strndup(a, s + start, (size_t)(from - start));
        if (from < len && s[from] == '"')
            from++;
        return from;
    }
    while (from < len && is_ident_char(s[from]))
        from++;
    if (from > start) {
        *out = cbm_arena_strndup(a, s + start, (size_t)(from - start));
    }
    return from;
}

/* Parse a string literal (single or double quoted). */
static int parse_string(CBMArena *a, const char *s, int len, int from, const char **out) {
    if (from >= len)
        return from;
    char q = s[from];
    if (q != '"' && q != '\'')
        return from;
    from++;
    int start = from;
    while (from < len && s[from] != q) {
        if (s[from] == '\\' && from + 1 < len)
            from += 2;
        else
            from++;
    }
    *out = cbm_arena_strndup(a, s + start, (size_t)(from - start));
    if (from < len)
        from++;
    return from;
}

/* Skip a value (used for keys we don't care about). Handles strings,
 * arrays, inline tables, bare values. */
static int skip_value(const char *s, int len, int from) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len)
        return from;
    char c = s[from];
    if (c == '"' || c == '\'') {
        from++;
        while (from < len && s[from] != c) {
            if (s[from] == '\\' && from + 1 < len)
                from += 2;
            else
                from++;
        }
        if (from < len)
            from++;
        return from;
    }
    if (c == '[' || c == '{') {
        char open = c, close = (c == '[' ? ']' : '}');
        int depth = 1;
        from++;
        while (from < len && depth > 0) {
            char d = s[from];
            if (d == '"' || d == '\'') {
                from++;
                while (from < len && s[from] != d) {
                    if (s[from] == '\\' && from + 1 < len)
                        from += 2;
                    else
                        from++;
                }
                if (from < len)
                    from++;
                continue;
            }
            if (d == open)
                depth++;
            else if (d == close)
                depth--;
            from++;
        }
        return from;
    }
    /* Bare value: skip to end of line. */
    while (from < len && s[from] != '\n' && s[from] != '#')
        from++;
    return from;
}

/* Parse `[section.path]` header — returns the section name as a flat
 * dotted string, e.g. "dependencies" or "workspace.dependencies". */
static int parse_section(CBMArena *a, const char *s, int len, int from, const char **out,
                         bool *out_array_of_tables) {
    if (from >= len || s[from] != '[')
        return from;
    /* Skip leading `[` or `[[`. */
    bool array_of_tables = false;
    from++;
    if (from < len && s[from] == '[') {
        array_of_tables = true;
        from++;
    }
    int start = from;
    while (from < len && s[from] != ']')
        from++;
    *out = cbm_arena_strndup(a, s + start, (size_t)(from - start));
    /* Consume closing `]` (or `]]`). */
    if (from < len)
        from++;
    if (array_of_tables && from < len && s[from] == ']')
        from++;
    if (out_array_of_tables)
        *out_array_of_tables = array_of_tables;
    return from;
}

static int parse_bool(const char *s, int len, int from, bool *out, bool *parsed) {
    from = skip_ws_and_comment(s, len, from);
    if (from + 4 <= len && strncmp(s + from, "true", 4) == 0 &&
        (from + 4 == len || !is_ident_char(s[from + 4]))) {
        *out = true;
        *parsed = true;
        return from + 4;
    }
    if (from + 5 <= len && strncmp(s + from, "false", 5) == 0 &&
        (from + 5 == len || !is_ident_char(s[from + 5]))) {
        *out = false;
        *parsed = true;
        return from + 5;
    }
    *parsed = false;
    return skip_value(s, len, from);
}

/* For the `[dependencies]` / `[dev-dependencies]` / `[workspace.dependencies]`
 * sections, parse `key = value` lines until the next section. The value
 * may be a string (the version) or an inline table. We capture both
 * shapes — only the key (crate name) and optional `path = "..."` field
 * matter for us. */
static int parse_dep_entry(CBMArena *a, const char *s, int len, int from, CBMCargoManifest *out) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len || s[from] == '[')
        return from;
    const char *key = NULL;
    from = parse_key(a, s, len, from, &key);
    from = skip_ws_and_comment(s, len, from);
    if (from < len && s[from] == '=') {
        from++;
        from = skip_ws_and_comment(s, len, from);
    }
    const char *path_val = NULL;
    if (from < len && s[from] == '{') {
        /* Inline table — scan for `path = "..."`. */
        int depth = 1;
        from++;
        while (from < len && depth > 0) {
            from = skip_ws_and_comment(s, len, from);
            if (from >= len)
                break;
            char c = s[from];
            if (c == '}') {
                depth--;
                from++;
                continue;
            }
            if (c == ',') {
                from++;
                continue;
            }
            /* sub-key */
            const char *sub_key = NULL;
            from = parse_key(a, s, len, from, &sub_key);
            from = skip_ws_and_comment(s, len, from);
            if (from < len && s[from] == '=') {
                from++;
                from = skip_ws_and_comment(s, len, from);
            }
            if (sub_key && strcmp(sub_key, "path") == 0) {
                from = parse_string(a, s, len, from, &path_val);
            } else {
                from = skip_value(s, len, from);
            }
        }
    } else {
        from = skip_value(s, len, from);
    }
    if (key && out->dep_count < CBM_CARGO_MAX_DEPS) {
        out->deps[out->dep_count].name = key;
        out->deps[out->dep_count].path = path_val;
        out->dep_count++;
    }
    return from;
}

/* ── Section dispatcher ──────────────────────────────────────── */

static int parse_package_kv(CBMArena *a, const char *s, int len, int from, CBMCargoManifest *out) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len || s[from] == '[')
        return from;
    const char *key = NULL;
    from = parse_key(a, s, len, from, &key);
    from = skip_ws_and_comment(s, len, from);
    if (from < len && s[from] == '=') {
        from++;
        from = skip_ws_and_comment(s, len, from);
    }
    if (key && strcmp(key, "name") == 0) {
        from = parse_string(a, s, len, from, &out->package_name);
    } else if (key && strcmp(key, "version") == 0) {
        from = parse_string(a, s, len, from, &out->package_version);
    } else if (key && strcmp(key, "edition") == 0) {
        from = parse_string(a, s, len, from, &out->package_edition);
    } else if (key && strcmp(key, "edition.workspace") == 0) {
        int start = from;
        from = skip_value(s, len, from);
        int value_len = from - start;
        while (value_len > 0 && isspace((unsigned char)s[start + value_len - 1]))
            value_len--;
        out->package_edition_inherits_workspace =
            value_len == 4 && strncmp(s + start, "true", 4) == 0;
    } else if (key && strcmp(key, "workspace") == 0) {
        from = parse_string(a, s, len, from, &out->package_workspace);
    } else if (key && strcmp(key, "build") == 0) {
        out->package_build_declared = true;
        if (from < len && (s[from] == '"' || s[from] == '\'')) {
            from = parse_string(a, s, len, from, &out->package_build_path);
            out->package_build_enabled = out->package_build_path != NULL;
        } else {
            bool parsed = false;
            from = parse_bool(s, len, from, &out->package_build_enabled, &parsed);
            if (!parsed || out->package_build_enabled) {
                cbm_arena_mark_failed(a, "CBM_CARGO_BUILD_VALUE_INVALID",
                                      "parse_package_build", 0);
            }
        }
    } else if (key && (strcmp(key, "autolib") == 0 || strcmp(key, "autobins") == 0 ||
                       strcmp(key, "autoexamples") == 0 || strcmp(key, "autotests") == 0 ||
                       strcmp(key, "autobenches") == 0)) {
        bool *value = NULL;
        bool *declared = NULL;
        if (strcmp(key, "autolib") == 0) {
            value = &out->autolib;
            declared = &out->autolib_declared;
        } else if (strcmp(key, "autobins") == 0) {
            value = &out->autobins;
            declared = &out->autobins_declared;
        } else if (strcmp(key, "autoexamples") == 0) {
            value = &out->autoexamples;
            declared = &out->autoexamples_declared;
        } else if (strcmp(key, "autotests") == 0) {
            value = &out->autotests;
            declared = &out->autotests_declared;
        } else {
            value = &out->autobenches;
            declared = &out->autobenches_declared;
        }
        bool parsed = false;
        from = parse_bool(s, len, from, value, &parsed);
        if (!parsed) {
            cbm_arena_mark_failed(a, "CBM_CARGO_AUTO_TARGET_VALUE_INVALID",
                                  "parse_package_auto_target", 0);
        } else {
            *declared = true;
        }
    } else {
        from = skip_value(s, len, from);
    }
    return from;
}

static int parse_target_kv(CBMArena *a, const char *s, int len, int from,
                           CBMCargoTarget *target) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len || s[from] == '[')
        return from;
    const char *key = NULL;
    from = parse_key(a, s, len, from, &key);
    from = skip_ws_and_comment(s, len, from);
    if (from < len && s[from] == '=') {
        from++;
        from = skip_ws_and_comment(s, len, from);
    }
    if (key && strcmp(key, "name") == 0) {
        from = parse_string(a, s, len, from, &target->name);
    } else if (key && strcmp(key, "path") == 0) {
        from = parse_string(a, s, len, from, &target->path);
    } else {
        from = skip_value(s, len, from);
    }
    return from;
}

static bool cargo_target_kind(const char *section, bool array_of_tables,
                              CBMCargoTargetKind *out_kind) {
    if (!section || !out_kind)
        return false;
    if (!array_of_tables && strcmp(section, "lib") == 0) {
        *out_kind = CBM_CARGO_TARGET_LIB;
        return true;
    }
    if (!array_of_tables)
        return false;
    if (strcmp(section, "bin") == 0)
        *out_kind = CBM_CARGO_TARGET_BIN;
    else if (strcmp(section, "example") == 0)
        *out_kind = CBM_CARGO_TARGET_EXAMPLE;
    else if (strcmp(section, "test") == 0)
        *out_kind = CBM_CARGO_TARGET_TEST;
    else if (strcmp(section, "bench") == 0)
        *out_kind = CBM_CARGO_TARGET_BENCH;
    else
        return false;
    return true;
}

static int parse_workspace_package_kv(CBMArena *a, const char *s, int len, int from,
                                      CBMCargoManifest *out) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len || s[from] == '[')
        return from;
    const char *key = NULL;
    from = parse_key(a, s, len, from, &key);
    from = skip_ws_and_comment(s, len, from);
    if (from < len && s[from] == '=') {
        from++;
        from = skip_ws_and_comment(s, len, from);
    }
    if (key && strcmp(key, "edition") == 0) {
        from = parse_string(a, s, len, from, &out->workspace_package_edition);
    } else {
        from = skip_value(s, len, from);
    }
    return from;
}

static int parse_workspace_kv(CBMArena *a, const char *s, int len, int from,
                              CBMCargoManifest *out) {
    from = skip_ws_and_comment(s, len, from);
    if (from >= len || s[from] == '[')
        return from;
    out->is_workspace_root = true;
    const char *key = NULL;
    from = parse_key(a, s, len, from, &key);
    from = skip_ws_and_comment(s, len, from);
    if (from < len && s[from] == '=') {
        from++;
        from = skip_ws_and_comment(s, len, from);
    }
    if (key && strcmp(key, "members") == 0 && from < len && s[from] == '[') {
        from++;
        while (from < len && s[from] != ']') {
            from = skip_ws_and_comment(s, len, from);
            if (from < len && (s[from] == '"' || s[from] == '\'')) {
                const char *mem = NULL;
                from = parse_string(a, s, len, from, &mem);
                if (mem && out->member_count < CBM_CARGO_MAX_MEMBERS) {
                    /* Derive a member NAME from the path's last segment. */
                    const char *last = mem;
                    for (const char *p = mem; *p; p++) {
                        if (*p == '/')
                            last = p + 1;
                    }
                    out->members[out->member_count].member_name = last;
                    out->members[out->member_count].member_path = mem;
                    out->member_count++;
                }
            }
            from = skip_ws_and_comment(s, len, from);
            if (from < len && s[from] == ',')
                from++;
            from = skip_ws_and_comment(s, len, from);
        }
        if (from < len)
            from++; /* consume `]` */
    } else {
        from = skip_value(s, len, from);
    }
    return from;
}

void cbm_cargo_parse(CBMArena *arena, const char *src, int src_len, CBMCargoManifest *out) {
    if (!arena || !src || !out)
        return;
    memset(out, 0, sizeof(*out));
    out->package_build_enabled = true;
    out->autolib = true;
    out->autobins = true;
    out->autoexamples = true;
    out->autotests = true;
    out->autobenches = true;
    if (src_len <= 0)
        src_len = (int)strlen(src);

    int from = 0;
    /* Default: pre-header content treated as [package]. */
    const char *section = "package";
    int active_target = -1;

    while (from < src_len) {
        from = skip_ws_and_comment(src, src_len, from);
        if (from >= src_len)
            break;
        if (src[from] == '[') {
            const char *hdr = NULL;
            bool array_of_tables = false;
            from = parse_section(arena, src, src_len, from, &hdr, &array_of_tables);
            section = hdr ? hdr : "";
            active_target = -1;
            CBMCargoTargetKind kind;
            if (cargo_target_kind(section, array_of_tables, &kind)) {
                if (out->target_count >= CBM_CARGO_MAX_TARGETS) {
                    cbm_arena_mark_failed(arena, "CBM_CARGO_TARGET_LIMIT_EXCEEDED",
                                          "parse_cargo_target_table",
                                          (size_t)out->target_count + 1);
                    return;
                }
                active_target = out->target_count++;
                out->targets[active_target].kind = kind;
            }
            continue;
        }
        if (!section) {
            from = skip_value(src, src_len, from);
            continue;
        }
        if (active_target >= 0) {
            from = parse_target_kv(arena, src, src_len, from, &out->targets[active_target]);
        } else if (strcmp(section, "package") == 0) {
            from = parse_package_kv(arena, src, src_len, from, out);
        } else if (strcmp(section, "workspace") == 0) {
            from = parse_workspace_kv(arena, src, src_len, from, out);
        } else if (strcmp(section, "workspace.package") == 0) {
            from = parse_workspace_package_kv(arena, src, src_len, from, out);
        } else if (strcmp(section, "dependencies") == 0 ||
                   strcmp(section, "dev-dependencies") == 0 ||
                   strcmp(section, "build-dependencies") == 0 ||
                   strcmp(section, "workspace.dependencies") == 0) {
            from = parse_dep_entry(arena, src, src_len, from, out);
        } else {
            /* Section we don't care about — skip the line. */
            while (from < src_len && src[from] != '\n' && src[from] != '[') {
                from++;
            }
        }
    }
}

bool cbm_cargo_is_known_dep(const CBMCargoManifest *m, const char *head) {
    if (!m || !head)
        return false;
    for (int i = 0; i < m->dep_count; i++) {
        if (m->deps[i].name && strcmp(m->deps[i].name, head) == 0) {
            return true;
        }
    }
    for (int i = 0; i < m->member_count; i++) {
        if (m->members[i].member_name && strcmp(m->members[i].member_name, head) == 0) {
            return true;
        }
    }
    return false;
}

const CBMCargoMember *cbm_cargo_find_member(const CBMCargoManifest *m, const char *name) {
    if (!m || !name)
        return NULL;
    for (int i = 0; i < m->member_count; i++) {
        if (m->members[i].member_name && strcmp(m->members[i].member_name, name) == 0) {
            return &m->members[i];
        }
    }
    return NULL;
}

static bool cargo_path_prefix(const char *path, const char *prefix) {
    if (!path || !prefix || !prefix[0])
        return false;
    size_t i = 0;
    while (prefix[i]) {
        char left = path[i] == '\\' ? '/' : path[i];
        char right = prefix[i] == '\\' ? '/' : prefix[i];
        if (!path[i] || left != right)
            return false;
        i++;
    }
    return path[i] == '\0' || path[i] == '/' || path[i] == '\\';
}

static int cargo_string_ptr_compare(const void *left, const void *right) {
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;
    return strcmp(*a, *b);
}

bool cbm_cargo_is_crate_root(const CBMCargoManifest *m, const char *relative_path) {
    if (!m || !relative_path || !m->crate_roots || m->crate_root_count <= 0)
        return false;
    const char *key = relative_path;
    return bsearch(&key, m->crate_roots, (size_t)m->crate_root_count,
                   sizeof(m->crate_roots[0]), cargo_string_ptr_compare) != NULL;
}

const char *cbm_cargo_edition_for_path(const CBMCargoManifest *m, const char *relative_path) {
    if (!m)
        return NULL;
    const CBMCargoPackage *package = NULL;
    size_t package_len = 0;
    for (int i = 0; i < m->package_count; i++) {
        const CBMCargoPackage *candidate = &m->packages[i];
        size_t len = candidate->package_dir ? strlen(candidate->package_dir) : 0;
        if ((len > package_len || (!package && len == 0)) &&
            (len == 0 || cargo_path_prefix(relative_path, candidate->package_dir))) {
            package = candidate;
            package_len = len;
        }
    }
    if (package)
        return package->edition;
    const CBMCargoMember *selected = NULL;
    size_t selected_len = 0;
    for (int i = 0; i < m->member_count; i++) {
        const CBMCargoMember *member = &m->members[i];
        size_t len = member->member_path ? strlen(member->member_path) : 0;
        if (len > selected_len && cargo_path_prefix(relative_path, member->member_path)) {
            selected = member;
            selected_len = len;
        }
    }
    if (selected)
        return selected->edition;
    if (m->package_edition)
        return m->package_edition;
    if (m->package_name)
        return "2015"; /* Cargo's specified package default. */
    return NULL;
}
