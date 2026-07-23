/*
 * path_alias.c — Resolve build-tool path aliases.
 *
 * Builds a directory-scoped collection of alias maps from per-language
 * config files (currently tsconfig.json / jsconfig.json) so the import
 * resolver can turn "@/lib/auth"-style imports into repo-relative paths.
 *
 * Design notes:
 *   - Public types and functions are language-agnostic. Adding a Vite /
 *     Webpack / Python loader means writing a new load_*_file() helper
 *     and registering it in find_alias_files. The resolver, the
 *     collection, and the pipeline integration do not change.
 *   - Inputs come only from the immutable captured file set. No independent
 *     filesystem walk may observe a different repository revision.
 */

#include "pipeline/path_alias.h"

#include "pipeline/pipeline_internal.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/platform.h"

#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson/yyjson.h>

/* ── Helpers ───────────────────────────────────────────────────── */

/* Strip .ts/.tsx/.js/.jsx in place. Returns its argument. */
static char *strip_resolved_ext(char *path) {
    if (!path) {
        return path;
    }
    size_t len = strlen(path);
    if (len > 3 && path[len - 3] == '.' && (path[len - 2] == 't' || path[len - 2] == 'j') &&
        path[len - 1] == 's') {
        path[len - 3] = '\0';
        return path;
    }
    if (len > 4 && path[len - 4] == '.' && (path[len - 3] == 't' || path[len - 3] == 'j') &&
        path[len - 2] == 's' && path[len - 1] == 'x') {
        path[len - 4] = '\0';
    }
    return path;
}

/* Join dir_prefix with target, collapsing "." and ".." segments so aliases
 * that climb out of their tsconfig's directory (the common monorepo
 * pattern: a tsconfig at apps/web/tsconfig.json pointing an alias at a
 * wildcard target like "../../packages/shared/src/" + wildcard) resolve
 * to a real repo-relative path. Naive concatenation left literal ".."
 * components in the target, which never match a module's FQN since
 * cbm_pipeline_fqn_module tokenizes on '/' without collapsing them
 * (#730). A trailing '/' on target (the usual case right before a
 * wildcard) is preserved so the caller's later wildcard-substring
 * concat still lines up. Returns heap-allocated
 * repo-relative target. */
static char *resolve_target_relative(const char *dir_prefix, const char *target) {
    if (!target) {
        return NULL;
    }
    size_t dp_len = (dir_prefix && dir_prefix[0] != '\0') ? strlen(dir_prefix) : 0;
    size_t t_len = strlen(target);
    if (dp_len > SIZE_MAX - t_len - PAIR_LEN) {
        return NULL;
    }
    char *buf = malloc(dp_len + t_len + 2);
    if (!buf) {
        return NULL;
    }
    buf[0] = '\0';
    if (dp_len > 0) {
        memcpy(buf, dir_prefix, dp_len);
        buf[dp_len] = '\0';
    }

    bool trailing_slash = t_len > 0 && target[t_len - 1] == '/';

    const char *p = target;
    while (*p) {
        while (*p == '/') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *seg_start = p;
        while (*p && *p != '/') {
            p++;
        }
        size_t seg_len = (size_t)(p - seg_start);
        if (seg_len == 1 && seg_start[0] == '.') {
            continue;
        }
        if (seg_len == 2 && seg_start[0] == '.' && seg_start[1] == '.') {
            char *last = strrchr(buf, '/');
            if (last) {
                *last = '\0';
            } else if (buf[0] != '\0') {
                buf[0] = '\0';
            } else {
                free(buf);
                return NULL;
            }
            continue;
        }
        size_t cur = strlen(buf);
        if (cur > 0) {
            buf[cur++] = '/';
        }
        memcpy(buf + cur, seg_start, seg_len);
        buf[cur + seg_len] = '\0';
    }

    if (trailing_slash) {
        size_t cur = strlen(buf);
        buf[cur] = '/';
        buf[cur + 1] = '\0';
    }
    return buf;
}

/* qsort comparator: alias entries by alias_prefix length, descending. */
static int cmp_alias_entry_by_specificity(const void *a, const void *b) {
    const cbm_path_alias_t *ea = a;
    const cbm_path_alias_t *eb = b;
    size_t la = strlen(ea->alias_prefix);
    size_t lb = strlen(eb->alias_prefix);
    if (lb > la) {
        return 1;
    }
    if (lb < la) {
        return -1;
    }
    if (ea->priority < eb->priority) {
        return -1;
    }
    if (ea->priority > eb->priority) {
        return 1;
    }
    return strcmp(ea->alias_prefix, eb->alias_prefix);
}

/* qsort comparator: scopes by dir_prefix length, descending. */
static int cmp_scope_by_specificity(const void *a, const void *b) {
    const cbm_path_alias_scope_t *sa = a;
    const cbm_path_alias_scope_t *sb = b;
    size_t la = strlen(sa->dir_prefix);
    size_t lb = strlen(sb->dir_prefix);
    if (lb > la) {
        return 1;
    }
    if (lb < la) {
        return -1;
    }
    return 0;
}

/* ── tsconfig.json / jsconfig.json loader ──────────────────────── */

static void free_alias_map(cbm_path_alias_map_t *map) {
    if (!map) {
        return;
    }
    for (int i = 0; i < map->count; i++) {
        free(map->entries[i].alias_prefix);
        free(map->entries[i].alias_suffix);
        free(map->entries[i].target_prefix);
        free(map->entries[i].target_suffix);
    }
    free(map->entries);
    free(map->base_url);
    free(map);
}

static int alias_failure(const char *code, const char *operation, const char *path) {
    cbm_log_error("path_alias.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "message",
                  "the complete captured path-alias configuration could not be represented",
                  "remediation", "correct the configuration or free resources, then retry");
    return CBM_NOT_FOUND;
}

/* Parse one captured tsconfig/jsconfig. A valid file with no alias settings is
 * success with *out == NULL; every present malformed or unreadable file fails. */
static int load_tsconfig_file(const cbm_file_info_t *file, const char *dir_prefix,
                              cbm_path_alias_map_t **out) {
    *out = NULL;
    FILE *f = cbm_fopen(file->path, "rb");
    if (!f) {
        return alias_failure("CBM_PATH_ALIAS_OPEN_FAILED", "open", file->rel_path);
    }
    if (file->size < 0 || (uint64_t)file->size > SIZE_MAX - 1u) {
        fclose(f);
        return alias_failure("CBM_PATH_ALIAS_SIZE_INVALID", "validate_size", file->rel_path);
    }
    size_t len = (size_t)file->size;
    char *buf = malloc(len + 1u);
    if (!buf) {
        fclose(f);
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_source", file->rel_path);
    }
    size_t nread = len ? fread(buf, 1, len, f) : 0;
    bool read_ok = nread == len && ferror(f) == 0;
    if (fclose(f) != 0) {
        read_ok = false;
    }
    if (!read_ok) {
        free(buf);
        return alias_failure("CBM_PATH_ALIAS_READ_FAILED", "read", file->rel_path);
    }
    buf[nread] = '\0';

    yyjson_read_flag flg = YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS;
    yyjson_doc *doc = yyjson_read(buf, nread, flg);
    free(buf);
    if (!doc) {
        return alias_failure("CBM_PATH_ALIAS_JSON_INVALID", "parse_json", file->rel_path);
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_ROOT_INVALID", "validate_root", file->rel_path);
    }
    yyjson_val *compiler_opts = yyjson_obj_get(root, "compilerOptions");
    if (!compiler_opts) {
        yyjson_doc_free(doc);
        return 0;
    }
    if (!yyjson_is_obj(compiler_opts)) {
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_COMPILER_OPTIONS_INVALID", "validate_compiler_options",
                             file->rel_path);
    }
    yyjson_val *base_url_val = yyjson_obj_get(compiler_opts, "baseUrl");
    if (base_url_val && !yyjson_is_str(base_url_val)) {
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_BASE_URL_INVALID", "validate_base_url",
                             file->rel_path);
    }
    const char *base_url_str = base_url_val ? yyjson_get_str(base_url_val) : NULL;
    yyjson_val *paths_obj = yyjson_obj_get(compiler_opts, "paths");
    if (paths_obj && !yyjson_is_obj(paths_obj)) {
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_PATHS_INVALID", "validate_paths", file->rel_path);
    }
    if (!paths_obj && !base_url_str) {
        yyjson_doc_free(doc);
        return 0;
    }

    cbm_path_alias_map_t *map = calloc(1, sizeof(*map));
    if (!map) {
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_map", file->rel_path);
    }

    if (base_url_str && base_url_str[0] != '\0' && strcmp(base_url_str, ".") != 0) {
        map->base_url = resolve_target_relative(dir_prefix, base_url_str);
    } else if (base_url_str && strcmp(base_url_str, ".") == 0) {
        map->base_url = strdup(dir_prefix ? dir_prefix : "");
    }
    if (base_url_str && base_url_str[0] != '\0' && !map->base_url &&
        strcmp(base_url_str, ".") != 0) {
        free_alias_map(map);
        yyjson_doc_free(doc);
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "resolve_base_url", file->rel_path);
    }

    if (paths_obj && yyjson_is_obj(paths_obj)) {
        size_t capacity_size = 0;
        yyjson_val *count_key = NULL;
        yyjson_obj_iter count_iter = yyjson_obj_iter_with(paths_obj);
        while ((count_key = yyjson_obj_iter_next(&count_iter)) != NULL) {
            yyjson_val *targets = yyjson_obj_iter_get_val(count_key);
            const char *alias_pattern = yyjson_get_str(count_key);
            if (!alias_pattern || alias_pattern[0] == '\0' || !yyjson_is_arr(targets) ||
                yyjson_arr_size(targets) == 0) {
                free_alias_map(map);
                yyjson_doc_free(doc);
                return alias_failure("CBM_PATH_ALIAS_ENTRY_INVALID", "count_targets",
                                     file->rel_path);
            }
            if (strchr(alias_pattern, '*') && strchr(strchr(alias_pattern, '*') + SKIP_ONE, '*')) {
                free_alias_map(map);
                yyjson_doc_free(doc);
                return alias_failure("CBM_PATH_ALIAS_PATTERN_INVALID", "validate_pattern",
                                     file->rel_path);
            }
            size_t target_count = yyjson_arr_size(targets);
            if (target_count > SIZE_MAX - capacity_size) {
                free_alias_map(map);
                yyjson_doc_free(doc);
                return alias_failure("CBM_PATH_ALIAS_ENTRY_COUNT_OVERFLOW", "count_targets",
                                     file->rel_path);
            }
            for (size_t target_index = 0; target_index < target_count; target_index++) {
                const char *target = yyjson_get_str(yyjson_arr_get(targets, target_index));
                if (!target || target[0] == '\0' ||
                    (strchr(target, '*') && strchr(strchr(target, '*') + SKIP_ONE, '*'))) {
                    free_alias_map(map);
                    yyjson_doc_free(doc);
                    return alias_failure("CBM_PATH_ALIAS_TARGET_INVALID", "validate_targets",
                                         file->rel_path);
                }
            }
            capacity_size += target_count;
        }
        if (capacity_size > INT_MAX || capacity_size > SIZE_MAX / sizeof(cbm_path_alias_t)) {
            free_alias_map(map);
            yyjson_doc_free(doc);
            return alias_failure("CBM_PATH_ALIAS_ENTRY_COUNT_OVERFLOW", "count_paths",
                                 file->rel_path);
        }
        int capacity = (int)capacity_size;
        if (capacity > 0) {
            map->entries = calloc((size_t)capacity, sizeof(cbm_path_alias_t));
            if (!map->entries) {
                free_alias_map(map);
                yyjson_doc_free(doc);
                return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_entries",
                                     file->rel_path);
            }
            yyjson_val *key;
            yyjson_obj_iter iter = yyjson_obj_iter_with(paths_obj);
            while ((key = yyjson_obj_iter_next(&iter)) != NULL) {
                yyjson_val *val = yyjson_obj_iter_get_val(key);
                const char *alias_pattern = yyjson_get_str(key);
                size_t target_count = yyjson_arr_size(val);
                for (size_t target_index = 0; target_index < target_count; target_index++) {
                    const char *target_pattern = yyjson_get_str(yyjson_arr_get(val, target_index));
                    cbm_path_alias_t *entry = &map->entries[map->count];
                    entry->priority = (int)target_index;
                    const char *star = strchr(alias_pattern, '*');
                    if (star) {
                        entry->has_wildcard = true;
                        entry->alias_prefix =
                            cbm_strndup(alias_pattern, (size_t)(star - alias_pattern));
                        entry->alias_suffix = strdup(star + 1);
                    } else {
                        entry->has_wildcard = false;
                        entry->alias_prefix = strdup(alias_pattern);
                        entry->alias_suffix = strdup("");
                    }
                    const char *tstar = strchr(target_pattern, '*');
                    if (tstar) {
                        char *pre = cbm_strndup(target_pattern, (size_t)(tstar - target_pattern));
                        entry->target_prefix =
                            pre ? resolve_target_relative(dir_prefix, pre) : NULL;
                        free(pre);
                        entry->target_suffix = strdup(tstar + 1);
                    } else {
                        entry->target_prefix = resolve_target_relative(dir_prefix, target_pattern);
                        entry->target_suffix = strdup("");
                    }
                    if (!entry->alias_prefix || !entry->alias_suffix || !entry->target_prefix ||
                        !entry->target_suffix) {
                        map->count++;
                        free_alias_map(map);
                        yyjson_doc_free(doc);
                        return alias_failure("CBM_PATH_ALIAS_ENTRY_RESOLUTION_FAILED", "copy_entry",
                                             file->rel_path);
                    }
                    map->count++;
                }
            }
            qsort(map->entries, (size_t)map->count, sizeof(cbm_path_alias_t),
                  cmp_alias_entry_by_specificity);
        }
    }

    yyjson_doc_free(doc);
    if (map->count == 0 && !map->base_url) {
        free_alias_map(map);
        return 0;
    }
    *out = map;
    return 0;
}

/* ── Public API ────────────────────────────────────────────────── */

void cbm_path_alias_collection_free(cbm_path_alias_collection_t *coll) {
    if (!coll) {
        return;
    }
    for (int i = 0; i < coll->count; i++) {
        free(coll->scopes[i].dir_prefix);
        if (coll->scopes[i].map) {
            cbm_path_alias_map_t *map = coll->scopes[i].map;
            free_alias_map(map);
        }
    }
    free(coll->scopes);
    free(coll);
}

static bool alias_entry_matches(const cbm_path_alias_t *entry, const char *module_path,
                                size_t module_len, const char **wild_start, size_t *wild_len) {
    if (entry->has_wildcard) {
        size_t prefix_len = strlen(entry->alias_prefix);
        size_t suffix_len = strlen(entry->alias_suffix);
        if (module_len < prefix_len + suffix_len ||
            strncmp(module_path, entry->alias_prefix, prefix_len) != 0 ||
            (suffix_len > 0 &&
             strcmp(module_path + module_len - suffix_len, entry->alias_suffix) != 0)) {
            return false;
        }
        *wild_start = module_path + prefix_len;
        *wild_len = module_len - prefix_len - suffix_len;
        return true;
    }
    *wild_start = NULL;
    *wild_len = 0;
    return strcmp(module_path, entry->alias_prefix) == 0;
}

int cbm_path_alias_resolve_all(const cbm_path_alias_map_t *map, const char *module_path,
                               char ***out_targets, int *out_count) {
    if (!map || !module_path || !out_targets || !out_count) {
        return CBM_NOT_FOUND;
    }
    *out_targets = NULL;
    *out_count = 0;
    size_t mod_len = strlen(module_path);
    bool alias_matched = false;
    for (int i = 0; i < map->count; i++) {
        const cbm_path_alias_t *e = &map->entries[i];
        const char *wild_start = NULL;
        size_t wild_len = 0;
        if (!alias_entry_matches(e, module_path, mod_len, &wild_start, &wild_len)) {
            continue;
        }
        alias_matched = true;
        size_t tp_len = strlen(e->target_prefix);
        size_t ts_len = strlen(e->target_suffix);
        if (tp_len > SIZE_MAX - wild_len || tp_len + wild_len > SIZE_MAX - ts_len - SKIP_ONE) {
            goto fail;
        }
        char *result = malloc(tp_len + wild_len + ts_len + SKIP_ONE);
        if (!result) {
            goto fail;
        }
        memcpy(result, e->target_prefix, tp_len);
        if (wild_len > 0) {
            memcpy(result + tp_len, wild_start, wild_len);
        }
        memcpy(result + tp_len + wild_len, e->target_suffix, ts_len);
        result[tp_len + wild_len + ts_len] = '\0';
        result = strip_resolved_ext(result);
        if (*out_count == INT_MAX) {
            free(result);
            goto fail;
        }
        char **grown = realloc(*out_targets, (size_t)(*out_count + SKIP_ONE) * sizeof(char *));
        if (!grown) {
            free(result);
            goto fail;
        }
        *out_targets = grown;
        grown[(*out_count)++] = result;
    }

    /* baseUrl fallback. Apply only to non-relative imports that look
     * sub-path-ish (contain '/' but don't start with '.' or '@'); skips
     * obvious package names like "react" or "lodash". */
    if (!alias_matched && map->base_url && module_path[0] != '.' && module_path[0] != '@' &&
        strchr(module_path, '/') != NULL) {
        size_t bu_len = strlen(map->base_url);
        size_t separator = bu_len > 0 ? SKIP_ONE : 0;
        if (bu_len > SIZE_MAX - separator || bu_len + separator > SIZE_MAX - mod_len - SKIP_ONE) {
            goto fail;
        }
        size_t need = bu_len + separator + mod_len + SKIP_ONE;
        char *result = malloc(need);
        if (!result) {
            goto fail;
        }
        snprintf(result, need, "%s%s%s", map->base_url, separator ? "/" : "", module_path);
        char **grown = malloc(sizeof(char *));
        if (!grown) {
            free(result);
            goto fail;
        }
        grown[0] = strip_resolved_ext(result);
        *out_targets = grown;
        *out_count = SKIP_ONE;
    }
    return 0;

fail:
    for (int i = 0; i < *out_count; i++) {
        free((*out_targets)[i]);
    }
    free(*out_targets);
    *out_targets = NULL;
    *out_count = 0;
    return CBM_NOT_FOUND;
}

/* ── Captured config inventory ─────────────────────────────────── */

static const char *alias_basename(const char *rel_path) {
    const char *slash = strrchr(rel_path, '/');
    return slash ? slash + 1 : rel_path;
}

static size_t alias_dir_length(const char *rel_path) {
    const char *slash = strrchr(rel_path, '/');
    return slash ? (size_t)(slash - rel_path) : 0;
}

static int compare_config_files(const void *left, const void *right) {
    const cbm_file_info_t *const *a = left;
    const cbm_file_info_t *const *b = right;
    size_t a_len = alias_dir_length((*a)->rel_path);
    size_t b_len = alias_dir_length((*b)->rel_path);
    size_t shared = a_len < b_len ? a_len : b_len;
    int dir_cmp = memcmp((*a)->rel_path, (*b)->rel_path, shared);
    if (dir_cmp != 0) {
        return dir_cmp;
    }
    if (a_len != b_len) {
        return a_len < b_len ? -1 : 1;
    }
    /* tsconfig is authoritative when both files exist in one directory. */
    return strcmp(alias_basename((*b)->rel_path), alias_basename((*a)->rel_path));
}

int cbm_load_path_aliases_from_files(const cbm_file_info_t *files, int file_count,
                                     cbm_path_alias_collection_t **out) {
    if (!out || file_count < 0 || (file_count > 0 && !files)) {
        return alias_failure("CBM_PATH_ALIAS_ARGUMENT_INVALID", "validate_inventory", "");
    }
    *out = NULL;
    int candidate_count = 0;
    for (int i = 0; i < file_count; i++) {
        const char *name = alias_basename(files[i].rel_path);
        if (strcmp(name, "tsconfig.json") == 0 || strcmp(name, "jsconfig.json") == 0) {
            candidate_count++;
        }
    }
    if (candidate_count == 0) {
        return 0;
    }
    cbm_file_info_t const **candidates = malloc((size_t)candidate_count * sizeof(*candidates));
    if (!candidates) {
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_inventory", "");
    }
    int candidate_index = 0;
    for (int i = 0; i < file_count; i++) {
        const char *name = alias_basename(files[i].rel_path);
        if (strcmp(name, "tsconfig.json") == 0 || strcmp(name, "jsconfig.json") == 0) {
            candidates[candidate_index++] = &files[i];
        }
    }
    qsort(candidates, (size_t)candidate_count, sizeof(*candidates), compare_config_files);

    cbm_path_alias_collection_t *collection = calloc(1, sizeof(*collection));
    if (!collection) {
        free(candidates);
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_collection", "");
    }
    collection->scopes = calloc((size_t)candidate_count, sizeof(*collection->scopes));
    if (!collection->scopes) {
        free(candidates);
        free(collection);
        return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "allocate_scopes", "");
    }

    char *previous_dir = NULL;
    for (int i = 0; i < candidate_count; i++) {
        const cbm_file_info_t *file = candidates[i];
        size_t dir_len = alias_dir_length(file->rel_path);
        char *dir = cbm_strndup(file->rel_path, dir_len);
        if (!dir) {
            free(previous_dir);
            free(candidates);
            cbm_path_alias_collection_free(collection);
            return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "copy_scope", file->rel_path);
        }
        if (previous_dir && strcmp(previous_dir, dir) == 0) {
            free(dir);
            continue;
        }
        free(previous_dir);
        previous_dir = strdup(dir);
        if (!previous_dir) {
            free(dir);
            free(candidates);
            cbm_path_alias_collection_free(collection);
            return alias_failure("CBM_PATH_ALIAS_ALLOC_FAILED", "remember_scope", file->rel_path);
        }
        cbm_path_alias_map_t *map = NULL;
        if (load_tsconfig_file(file, dir, &map) != 0) {
            free(dir);
            free(previous_dir);
            free(candidates);
            cbm_path_alias_collection_free(collection);
            return CBM_NOT_FOUND;
        }
        if (!map) {
            free(dir);
            continue;
        }
        collection->scopes[collection->count].dir_prefix = dir;
        collection->scopes[collection->count].map = map;
        collection->count++;
    }
    free(previous_dir);
    free(candidates);
    if (collection->count == 0) {
        cbm_path_alias_collection_free(collection);
        return 0;
    }
    qsort(collection->scopes, (size_t)collection->count, sizeof(*collection->scopes),
          cmp_scope_by_specificity);
    *out = collection;
    return 0;
}

const cbm_path_alias_map_t *cbm_path_alias_find_for_file(const cbm_path_alias_collection_t *coll,
                                                         const char *rel_path) {
    if (!coll || !rel_path) {
        return NULL;
    }
    for (int i = 0; i < coll->count; i++) {
        const char *prefix = coll->scopes[i].dir_prefix;
        size_t plen = strlen(prefix);
        if (plen == 0) {
            return coll->scopes[i].map;
        }
        if (strncmp(rel_path, prefix, plen) == 0 &&
            (rel_path[plen] == '/' || rel_path[plen] == '\0')) {
            return coll->scopes[i].map;
        }
    }
    return NULL;
}
