/*
 * pass_compile_commands.c — immutable C-family build-context preparation.
 *
 * A filename is not a translation unit. This module binds each discovered
 * C/C++ source atom to every real compiler invocation that consumes it,
 * including headers and unity-build .c fragments through compiler dependency
 * records. The complete index is prepared before extraction workers start and
 * is read-only thereafter.
 */
#include "pipeline/pipeline_internal.h"

#include "foundation/sha256.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "yyjson/yyjson.h"
#ifdef ASTRO_SPAWN
#include "astro_spawn.h"
#endif

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *id;
    char **defines;
    int define_count;
    char **system_include_paths;
    int system_include_count;
    char *query_key;
} compile_baseline_t;

typedef struct {
    CBMPreprocessContext view;
    char *tu_rel_path;
    char *directory;
    char **owned_include_paths;
    int owned_include_count;
    char **owned_undefines;
    int owned_undefine_count;
    char **owned_forced_includes;
    int owned_forced_include_count;
    char **dependencies;
    int dependency_count;
} compile_context_owner_t;

typedef struct {
    char *rel_path;
    CBMPreprocessContextSet view;
    CBMPreprocessContext *items;
    size_t capacity;
} compile_context_set_owner_t;

struct cbm_compile_context_index {
    compile_baseline_t *baselines;
    int baseline_count;
    int baseline_capacity;
    compile_context_owner_t *contexts;
    int context_count;
    int context_capacity;
    compile_context_set_owner_t *sets;
    int set_count;
};

static int context_fail(cbm_pipeline_ctx_t *ctx, const char *code, const char *operation,
                        const char *path, size_t requested, const char *message,
                        const char *remediation) {
    cbm_log_error("compile_context.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "message", message, "remediation", remediation);
    cbm_pipeline_record_fatal_error(ctx ? ctx->pipeline : NULL, code, operation,
                                    "compile_context", path, requested, message, remediation);
    return CBM_NOT_FOUND;
}

static bool grow_array(void **items, int *capacity, int needed, size_t item_size) {
    if (needed <= *capacity) {
        return true;
    }
    int next = *capacity > 0 ? *capacity : 8;
    while (next < needed) {
        if (next > INT_MAX / 2) {
            return false;
        }
        next *= 2;
    }
    if ((size_t)next > SIZE_MAX / item_size) {
        return false;
    }
    void *replacement = realloc(*items, (size_t)next * item_size);
    if (!replacement) {
        return false;
    }
    memset((char *)replacement + (size_t)(*capacity) * item_size, 0,
           (size_t)(next - *capacity) * item_size);
    *items = replacement;
    *capacity = next;
    return true;
}

static char *normalize_slashes_dup(const char *value) {
    if (!value) {
        return NULL;
    }
    char *copy = strdup(value);
    if (!copy) {
        return NULL;
    }
    for (char *at = copy; *at; at++) {
        if (*at == '\\') {
            *at = '/';
        }
    }
    return copy;
}

static bool path_equal(const char *left, const char *right) {
    if (!left || !right) {
        return false;
    }
    while (*left && *right) {
        char a = *left == '\\' ? '/' : *left;
        char b = *right == '\\' ? '/' : *right;
#ifdef _WIN32
        a = (char)tolower((unsigned char)a);
        b = (char)tolower((unsigned char)b);
#endif
        if (a != b) {
            return false;
        }
        left++;
        right++;
    }
    while (*left == '/' || *left == '\\') {
        left++;
    }
    while (*right == '/' || *right == '\\') {
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static bool path_is_absolute(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    return path[0] == '/' || path[0] == '\\' ||
           (isalpha((unsigned char)path[0]) && path[1] == ':');
}

static char *join_path(const char *directory, const char *path) {
    if (!path) {
        return NULL;
    }
    if (path_is_absolute(path) || !directory || !directory[0]) {
        return normalize_slashes_dup(path);
    }
    size_t directory_len = strlen(directory);
    size_t path_len = strlen(path);
    if (directory_len > SIZE_MAX - path_len - 2) {
        return NULL;
    }
    char *joined = malloc(directory_len + path_len + 2);
    if (!joined) {
        return NULL;
    }
    memcpy(joined, directory, directory_len);
    joined[directory_len] = '/';
    memcpy(joined + directory_len + 1, path, path_len + 1);
    for (char *at = joined; *at; at++) {
        if (*at == '\\') {
            *at = '/';
        }
    }
    return joined;
}

static char **json_string_array(yyjson_val *value, int *out_count) {
    *out_count = 0;
    if (!value || !yyjson_is_arr(value)) {
        return NULL;
    }
    size_t count = yyjson_arr_size(value);
    if (count > (size_t)INT_MAX || count > SIZE_MAX / sizeof(char *) - 1) {
        return NULL;
    }
    char **items = calloc(count + 1, sizeof(char *));
    if (!items) {
        return NULL;
    }
    yyjson_arr_iter iterator;
    yyjson_arr_iter_init(value, &iterator);
    yyjson_val *item;
    int at = 0;
    while ((item = yyjson_arr_iter_next(&iterator))) {
        const char *text = yyjson_get_str(item);
        if (!text || !text[0]) {
            for (int i = 0; i < at; i++) {
                free(items[i]);
            }
            free(items);
            return NULL;
        }
        items[at] = strdup(text);
        if (!items[at]) {
            for (int i = 0; i < at; i++) {
                free(items[i]);
            }
            free(items);
            return NULL;
        }
        at++;
    }
    *out_count = at;
    return items;
}

static void free_string_array(char **items, int count) {
    if (!items) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
}

static compile_baseline_t *find_baseline(cbm_compile_context_index_t *index, const char *id) {
    if (!index || !id) {
        return NULL;
    }
    for (int i = 0; i < index->baseline_count; i++) {
        if (index->baselines[i].id && strcmp(index->baselines[i].id, id) == 0) {
            return &index->baselines[i];
        }
    }
    return NULL;
}

static int parse_embedded_baselines(cbm_pipeline_ctx_t *ctx,
                                    cbm_compile_context_index_t *index, yyjson_val *root) {
    yyjson_val *baselines = yyjson_obj_get(root, "baselines");
    if (!baselines || !yyjson_is_arr(baselines) || yyjson_arr_size(baselines) == 0) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_BASELINES_MISSING",
                            "parse_embedded_baselines", "", 0,
                            "the embedded build context has no compiler baselines",
                            "rebuild Astrolabe so cbm-sys captures compiler predefines and system "
                            "include roots");
    }
    yyjson_arr_iter iterator;
    yyjson_arr_iter_init(baselines, &iterator);
    yyjson_val *entry;
    while ((entry = yyjson_arr_iter_next(&iterator))) {
        const char *id = yyjson_get_str(yyjson_obj_get(entry, "id"));
        if (!id || !id[0] || find_baseline(index, id)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_BASELINE_ID_INVALID",
                                "parse_embedded_baselines", id, 0,
                                "a compiler baseline id is absent or duplicated",
                                "regenerate the artifact compilation-context manifest");
        }
        if (!grow_array((void **)&index->baselines, &index->baseline_capacity,
                        index->baseline_count + 1, sizeof(*index->baselines))) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "allocate_baseline", id, 0,
                                "the compiler baseline index could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
        compile_baseline_t *baseline = &index->baselines[index->baseline_count];
        baseline->id = strdup(id);
        baseline->defines = json_string_array(yyjson_obj_get(entry, "predefined_macros"),
                                              &baseline->define_count);
        baseline->system_include_paths =
            json_string_array(yyjson_obj_get(entry, "system_include_paths"),
                              &baseline->system_include_count);
        if (!baseline->id || !baseline->defines || baseline->define_count == 0 ||
            !baseline->system_include_paths || baseline->system_include_count == 0) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_BASELINE_INCOMPLETE",
                                "parse_embedded_baselines", id, 0,
                                "a compiler baseline lacks predefines or system include roots",
                                "rebuild with a working exact compiler baseline query");
        }
        index->baseline_count++;
    }
    return 0;
}

static bool append_owned_string(char ***items, int *count, const char *value) {
    if (!value || !value[0] || *count == INT_MAX ||
        (size_t)(*count + 2) > SIZE_MAX / sizeof(char *)) {
        return false;
    }
    char **replacement = realloc(*items, (size_t)(*count + 2) * sizeof(char *));
    if (!replacement) {
        return false;
    }
    *items = replacement;
    replacement[*count] = strdup(value);
    if (!replacement[*count]) {
        return false;
    }
    (*count)++;
    replacement[*count] = NULL;
    return true;
}

static bool append_resolved_path(char ***items, int *count, const char *directory,
                                 const char *path) {
    char *resolved = join_path(directory, path);
    if (!resolved) {
        return false;
    }
    bool ok = append_owned_string(items, count, resolved);
    free(resolved);
    return ok;
}

static const char *consume_option_value(char **arguments, int argument_count, int *index,
                                        const char *joined_prefix) {
    const char *argument = arguments[*index];
    size_t prefix_len = strlen(joined_prefix);
    if (strncmp(argument, joined_prefix, prefix_len) == 0 && argument[prefix_len]) {
        return argument + prefix_len;
    }
    if (strcmp(argument, joined_prefix) == 0 && *index + 1 < argument_count) {
        (*index)++;
        return arguments[*index];
    }
    return NULL;
}

static int configure_context_from_arguments(cbm_pipeline_ctx_t *ctx,
                                            compile_context_owner_t *owner,
                                            compile_baseline_t *baseline, char **arguments,
                                            int argument_count, bool cpp_mode) {
    owner->view.cpp_mode = cpp_mode;
    for (int i = 1; i < argument_count; i++) {
        const char *value = NULL;
        if (strncmp(arguments[i], "-std=", 5) == 0 && arguments[i][5]) {
            if (owner->view.standard) {
                return context_fail(ctx, "CBM_COMPILE_CONTEXT_STANDARD_CONTRADICTORY",
                                    "parse_compile_arguments", owner->tu_rel_path, 0,
                                    "one compiler invocation declares several language standards",
                                    "repair the exact compile command and regenerate its database");
            }
            owner->view.standard = strdup(arguments[i] + 5);
        } else if ((value = consume_option_value(arguments, argument_count, &i, "-I")) != NULL ||
                   (value = consume_option_value(arguments, argument_count, &i,
                                                 "-isystem")) != NULL ||
                   (value = consume_option_value(arguments, argument_count, &i,
                                                 "-iquote")) != NULL) {
            if (!append_resolved_path(&owner->owned_include_paths, &owner->owned_include_count,
                                      owner->directory, value)) {
                return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                    "append_include_path", owner->tu_rel_path, 0,
                                    "an ordered include root could not be retained",
                                    "free memory and retry the unchanged corpus");
            }
        } else if ((value = consume_option_value(arguments, argument_count, &i, "-U")) != NULL) {
            if (!append_owned_string(&owner->owned_undefines, &owner->owned_undefine_count,
                                     value)) {
                return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                    "append_undefine", owner->tu_rel_path, 0,
                                    "a compiler undefine could not be retained",
                                    "free memory and retry the unchanged corpus");
            }
        } else if ((value = consume_option_value(arguments, argument_count, &i,
                                                 "-include")) != NULL) {
            if (!append_resolved_path(&owner->owned_forced_includes,
                                      &owner->owned_forced_include_count, owner->directory,
                                      value)) {
                return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                    "append_forced_include", owner->tu_rel_path, 0,
                                    "a forced include could not be retained",
                                    "free memory and retry the unchanged corpus");
            }
        }
    }
    if (!owner->view.standard || !owner->view.standard[0]) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_STANDARD_MISSING",
                            "parse_compile_arguments", owner->tu_rel_path, 0,
                            "the compiler invocation has no explicit language standard",
                            "add an exact -std= flag to the build and regenerate "
                            "compile_commands.json");
    }
    for (int i = 0; i < baseline->system_include_count; i++) {
        if (!append_owned_string(&owner->owned_include_paths, &owner->owned_include_count,
                                 baseline->system_include_paths[i])) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "append_system_include", owner->tu_rel_path, 0,
                                "a compiler system include root could not be retained",
                                "free memory and retry the unchanged corpus");
        }
    }
    owner->view.defines = (const char **)baseline->defines;
    owner->view.include_paths = (const char **)owner->owned_include_paths;
    owner->view.undefines = (const char **)owner->owned_undefines;
    owner->view.forced_includes = (const char **)owner->owned_forced_includes;
    return 0;
}

static const cbm_file_info_t *find_source_file(const cbm_file_info_t *files, int file_count,
                                               const char *rel_path) {
    for (int i = 0; i < file_count; i++) {
        if (files[i].rel_path && strcmp(files[i].rel_path, rel_path) == 0) {
            return &files[i];
        }
    }
    return NULL;
}

static compile_context_set_owner_t *find_set(cbm_compile_context_index_t *index,
                                             const char *rel_path) {
    for (int i = 0; i < index->set_count; i++) {
        if (strcmp(index->sets[i].rel_path, rel_path) == 0) {
            return &index->sets[i];
        }
    }
    return NULL;
}

static int append_context_to_set(cbm_pipeline_ctx_t *ctx, compile_context_set_owner_t *set,
                                 const CBMPreprocessContext *context) {
    for (size_t i = 0; i < set->view.count; i++) {
        if (strcmp(set->items[i].context_id, context->context_id) == 0) {
            return 0;
        }
    }
    if (set->view.count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2 : 2;
        if (next < set->capacity || next > SIZE_MAX / sizeof(*set->items)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                                "append_file_context", set->rel_path, next,
                                "the number of real consumer contexts exceeds representation",
                                "reduce contradictory build variants or extend the representation");
        }
        CBMPreprocessContext *replacement =
            realloc(set->items, next * sizeof(*set->items));
        if (!replacement) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "append_file_context", set->rel_path, next,
                                "the file consumer-context set could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
        set->items = replacement;
        set->capacity = next;
        set->view.items = set->items;
    }
    set->items[set->view.count++] = *context;
    set->view.items = set->items;
    return 0;
}

static int materialize_context_sets(cbm_pipeline_ctx_t *ctx,
                                    cbm_compile_context_index_t *index,
                                    const cbm_file_info_t *source_files, int source_count) {
    if (source_count > 0) {
        index->sets = calloc((size_t)source_count, sizeof(*index->sets));
        if (!index->sets) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_file_sets",
                                "", (size_t)source_count,
                                "the per-file compilation-context index could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
    }
    index->set_count = source_count;
    for (int i = 0; i < source_count; i++) {
        index->sets[i].rel_path = strdup(source_files[i].rel_path);
        if (!index->sets[i].rel_path) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "copy_file_path",
                                source_files[i].rel_path, 0,
                                "a source path could not be retained in the context index",
                                "free memory and retry the unchanged corpus");
        }
    }
    for (int c = 0; c < index->context_count; c++) {
        compile_context_owner_t *context = &index->contexts[c];
        for (int d = 0; d < context->dependency_count; d++) {
            compile_context_set_owner_t *set = find_set(index, context->dependencies[d]);
            if (set && append_context_to_set(ctx, set, &context->view) != 0) {
                return CBM_NOT_FOUND;
            }
        }
    }
    int c_family_files = 0;
    int context_bindings = 0;
    for (int i = 0; i < source_count; i++) {
        CBMLanguage language = source_files[i].language;
        if (language != CBM_LANG_C && language != CBM_LANG_CPP && language != CBM_LANG_CUDA) {
            continue;
        }
        c_family_files++;
        if (source_files[i].size == 0) {
            continue;
        }
        if (index->sets[i].view.count == 0) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_FILE_UNBOUND",
                                "bind_file_consumer", source_files[i].rel_path, 0,
                                "a non-empty C-family source has no real consuming translation unit",
                                "emit this translation unit in compile_commands.json or include "
                                "the file from one captured compiler dependency closure");
        }
        if (index->sets[i].view.count > (size_t)(INT_MAX - context_bindings)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                                "count_context_bindings", source_files[i].rel_path,
                                index->sets[i].view.count,
                                "context binding telemetry exceeds integer representation",
                                "extend the telemetry representation before retrying");
        }
        context_bindings += (int)index->sets[i].view.count;
    }
    char files_text[32];
    char contexts_text[32];
    char bindings_text[32];
    snprintf(files_text, sizeof(files_text), "%d", c_family_files);
    snprintf(contexts_text, sizeof(contexts_text), "%d", index->context_count);
    snprintf(bindings_text, sizeof(bindings_text), "%d", context_bindings);
    cbm_log_info("compile_context.ready", "c_family_files", files_text, "translation_units",
                 contexts_text, "file_context_bindings", bindings_text, "cache", "immutable");
    return 0;
}

static int parse_embedded_commands(cbm_pipeline_ctx_t *ctx,
                                   cbm_compile_context_index_t *index, yyjson_val *root,
                                   const cbm_file_info_t *source_files, int source_count) {
    yyjson_val *commands = yyjson_obj_get(root, "commands");
    if (!commands || !yyjson_is_arr(commands) || yyjson_arr_size(commands) == 0) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMANDS_MISSING",
                            "parse_embedded_commands", "", 0,
                            "the embedded build context has no translation-unit commands",
                            "rebuild Astrolabe from the canonical native Makefile");
    }
    yyjson_arr_iter iterator;
    yyjson_arr_iter_init(commands, &iterator);
    yyjson_val *entry;
    while ((entry = yyjson_arr_iter_next(&iterator))) {
        const char *file = yyjson_get_str(yyjson_obj_get(entry, "file"));
        const char *directory = yyjson_get_str(yyjson_obj_get(entry, "directory"));
        const char *baseline_id = yyjson_get_str(yyjson_obj_get(entry, "baseline_id"));
        yyjson_val *arguments_value = yyjson_obj_get(entry, "arguments");
        yyjson_val *dependencies_value = yyjson_obj_get(entry, "dependencies");
        compile_baseline_t *baseline = find_baseline(index, baseline_id);
        if (!file || !file[0] || !directory || !directory[0] || !baseline ||
            !arguments_value || !dependencies_value) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMAND_INCOMPLETE",
                                "parse_embedded_commands", file, 0,
                                "a translation-unit command lacks file, directory, baseline, "
                                "arguments, or dependencies",
                                "regenerate the artifact compilation-context manifest");
        }
        int argument_count = 0;
        char **arguments = json_string_array(arguments_value, &argument_count);
        int dependency_count = 0;
        char **dependencies = json_string_array(dependencies_value, &dependency_count);
        if (!arguments || argument_count < 2 || !dependencies || dependency_count == 0) {
            free_string_array(arguments, argument_count);
            free_string_array(dependencies, dependency_count);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMAND_INCOMPLETE",
                                "parse_embedded_commands", file, 0,
                                "a translation-unit command has empty argv or dependency closure",
                                "regenerate the artifact compilation-context manifest");
        }
        if (!find_source_file(source_files, source_count, file)) {
            free_string_array(arguments, argument_count);
            free_string_array(dependencies, dependency_count);
            continue;
        }
        if (!grow_array((void **)&index->contexts, &index->context_capacity,
                        index->context_count + 1, sizeof(*index->contexts))) {
            free_string_array(arguments, argument_count);
            free_string_array(dependencies, dependency_count);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_context",
                                file, 0, "a translation-unit context could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
        compile_context_owner_t *owner = &index->contexts[index->context_count];
        owner->tu_rel_path = strdup(file);
        owner->directory = normalize_slashes_dup(directory);
        owner->dependencies = dependencies;
        owner->dependency_count = dependency_count;
        bool cpp_mode = strstr(file, ".cpp") != NULL || strstr(file, ".cc") != NULL ||
                        strstr(file, ".cxx") != NULL || strstr(file, ".cu") != NULL;
        if (!owner->tu_rel_path || !owner->directory ||
            configure_context_from_arguments(ctx, owner, baseline, arguments, argument_count,
                                             cpp_mode) != 0) {
            free_string_array(arguments, argument_count);
            return CBM_NOT_FOUND;
        }
        const cbm_file_info_t *translation_unit =
            find_source_file(source_files, source_count, owner->tu_rel_path);
        if (!translation_unit) {
            free_string_array(arguments, argument_count);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_TU_UNDISCOVERED",
                                "bind_translation_unit", file, 0,
                                "the captured compiler translation unit is absent from immutable "
                                "source discovery",
                                "repair discovery exclusions or regenerate the build context");
        }
        owner->view.entry_path = translation_unit->path;
        cbm_sha256_ctx hash;
        uint8_t digest[CBM_SHA256_DIGEST_LEN];
        char hex[CBM_SHA256_HEX_LEN + 1];
        cbm_sha256_init(&hash);
        cbm_sha256_update(&hash, owner->tu_rel_path, strlen(owner->tu_rel_path));
        cbm_sha256_update(&hash, "\0", 1);
        for (int i = 0; i < argument_count; i++) {
            cbm_sha256_update(&hash, arguments[i], strlen(arguments[i]));
            cbm_sha256_update(&hash, "\0", 1);
        }
        cbm_sha256_final(&hash, digest);
        for (int i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
            snprintf(hex + (i * 2), 3, "%02x", digest[i]);
        }
        owner->view.context_id = strdup(hex);
        free_string_array(arguments, argument_count);
        if (!owner->view.context_id) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "copy_context_id",
                                file, 0, "the context identity could not be retained",
                                "free memory and retry the unchanged corpus");
        }
        index->context_count++;
    }
    return materialize_context_sets(ctx, index, source_files, source_count);
}

static int parse_embedded_manifest(cbm_pipeline_ctx_t *ctx,
                                   cbm_compile_context_index_t *index,
                                   const uint8_t *bytes, size_t byte_count,
                                   const cbm_file_info_t *source_files, int source_count,
                                   bool *matched) {
    *matched = false;
    if (!bytes || byte_count == 0) {
        return 0;
    }
    yyjson_read_err error;
    yyjson_doc *document = yyjson_read_opts((char *)bytes, byte_count, 0, NULL, &error);
    if (!document) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_EMBEDDED_MALFORMED",
                            "parse_embedded_manifest", "", error.pos,
                            "the artifact compilation-context bytes are not valid JSON",
                            "rebuild the native artifact from the canonical source tree");
    }
    yyjson_val *root = yyjson_doc_get_root(document);
    const char *format = yyjson_get_str(yyjson_obj_get(root, "format"));
    const char *source_root = yyjson_get_str(yyjson_obj_get(root, "source_root"));
    if (!yyjson_is_obj(root) || !format ||
        strcmp(format, "astrolabe.compilation-context.v1") != 0 || !source_root) {
        yyjson_doc_free(document);
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_EMBEDDED_SCHEMA_INVALID",
                            "parse_embedded_manifest", "", 0,
                            "the artifact compilation-context schema is unsupported",
                            "rebuild the native artifact with the current cbm-sys build script");
    }
    if (!path_equal(source_root, ctx->repo_path)) {
        yyjson_doc_free(document);
        return 0;
    }
    *matched = true;
    int rc = parse_embedded_baselines(ctx, index, root);
    if (rc == 0) {
        rc = parse_embedded_commands(ctx, index, root, source_files, source_count);
    }
    yyjson_doc_free(document);
    return rc;
}

static bool has_c_family_source(const cbm_file_info_t *files, int count) {
    for (int i = 0; i < count; i++) {
        if (files[i].size > 0 && (files[i].language == CBM_LANG_C ||
                                  files[i].language == CBM_LANG_CPP ||
                                  files[i].language == CBM_LANG_CUDA)) {
            return true;
        }
    }
    return false;
}

int cbm_compile_context_index_prepare(cbm_pipeline_ctx_t *ctx,
                                      const cbm_file_info_t *source_files, int source_count,
                                      const uint8_t *embedded_bytes, size_t embedded_byte_count,
                                      cbm_compile_context_index_t **out_index) {
    if (!ctx || !source_files || source_count < 0 || !out_index) {
        return CBM_NOT_FOUND;
    }
    *out_index = NULL;
    cbm_compile_context_index_t *index = calloc(1, sizeof(*index));
    if (!index) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_index", "", 0,
                            "the immutable compilation-context index could not be allocated",
                            "free memory and retry the unchanged corpus");
    }
    if (!has_c_family_source(source_files, source_count)) {
        index->sets = calloc((size_t)(source_count > 0 ? source_count : 1), sizeof(*index->sets));
        if (!index->sets) {
            cbm_compile_context_index_free(index);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_empty_index",
                                "", (size_t)source_count,
                                "the empty C-family context index could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
        index->set_count = source_count;
        for (int i = 0; i < source_count; i++) {
            index->sets[i].rel_path = strdup(source_files[i].rel_path);
            if (!index->sets[i].rel_path) {
                cbm_compile_context_index_free(index);
                return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "copy_file_path",
                                    source_files[i].rel_path, 0,
                                    "a source path could not be retained",
                                    "free memory and retry the unchanged corpus");
            }
        }
        cbm_log_info("compile_context.ready", "c_family_files", "0", "translation_units", "0",
                     "file_context_bindings", "0", "cache", "immutable");
        *out_index = index;
        return 0;
    }

    bool embedded_matched = false;
    int rc = parse_embedded_manifest(ctx, index, embedded_bytes, embedded_byte_count,
                                     source_files, source_count, &embedded_matched);
    if (rc != 0) {
        cbm_compile_context_index_free(index);
        return rc;
    }
    if (!embedded_matched) {
        cbm_compile_context_index_free(index);
        return context_fail(
            ctx, "CBM_COMPILE_CONTEXT_DATABASE_REQUIRED", "select_context_authority",
            ctx->repo_path, 0,
            "this C-family repository has no matching immutable compilation context",
            "generate compile_commands.json at the repository root from the real build, ensure "
            "its compiler remains reachable, then retry the complete corpus");
    }
    *out_index = index;
    return 0;
}

const CBMPreprocessContextSet *cbm_compile_context_for_file(
    const cbm_compile_context_index_t *index, const char *rel_path) {
    if (!index || !rel_path) {
        return NULL;
    }
    for (int i = 0; i < index->set_count; i++) {
        if (index->sets[i].rel_path && strcmp(index->sets[i].rel_path, rel_path) == 0) {
            return &index->sets[i].view;
        }
    }
    return NULL;
}

void cbm_compile_context_index_free(cbm_compile_context_index_t *index) {
    if (!index) {
        return;
    }
    for (int i = 0; i < index->set_count; i++) {
        free(index->sets[i].rel_path);
        free(index->sets[i].items);
    }
    free(index->sets);
    for (int i = 0; i < index->context_count; i++) {
        compile_context_owner_t *context = &index->contexts[i];
        free((char *)context->view.context_id);
        free((char *)context->view.standard);
        free(context->tu_rel_path);
        free(context->directory);
        free_string_array(context->owned_include_paths, context->owned_include_count);
        free_string_array(context->owned_undefines, context->owned_undefine_count);
        free_string_array(context->owned_forced_includes, context->owned_forced_include_count);
        free_string_array(context->dependencies, context->dependency_count);
    }
    free(index->contexts);
    for (int i = 0; i < index->baseline_count; i++) {
        compile_baseline_t *baseline = &index->baselines[i];
        free(baseline->id);
        free(baseline->query_key);
        free_string_array(baseline->defines, baseline->define_count);
        free_string_array(baseline->system_include_paths, baseline->system_include_count);
    }
    free(index->baselines);
    free(index);
}
