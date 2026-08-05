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
#include "pipeline/lsp_resolve.h"

#include "foundation/sha256.h"
#include "foundation/constants.h"
#include "foundation/compat_fs.h"
#include "foundation/log.h"
#include "yyjson/yyjson.h"
#ifdef ASTRO_SPAWN
#include "astro_spawn.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PREPROCESS_STDERR_LIMIT = 65536 };

static bool compiler_ambiguous_fragment_filename(const char *filename) {
    if (!filename || !filename[0]) {
        return false;
    }
    const char *extension = strrchr(filename, '.');
    /* `.inc` is registry-declared as BitBake and is also a conventional
     * generated C/C++ include fragment. Only an exact compiler dependency
     * edge may refine it; filename, directory, and content never do so. */
    return extension && strcmp(extension, ".inc") == 0;
}

typedef struct {
    char *text;
    size_t text_bytes;
    uint32_t *line_targets;
    uint32_t *line_source_lines;
    size_t line_count;
    size_t mapped_lines;
    size_t workspace_local_compiler_markers;
    size_t working_directory_markers;
} compiler_expansion_t;

#define PREPROCESS_TARGET_NONE UINT32_MAX
#define PREPROCESS_TARGET_IGNORED (UINT32_MAX - 1U)

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
    char **preprocess_arguments;
    int preprocess_argument_count;
    char **owned_include_paths;
    int owned_include_count;
    char **owned_undefines;
    int owned_undefine_count;
    char **owned_forced_includes;
    int owned_forced_include_count;
    char **compiler_system_roots;
    int compiler_system_root_count;
    char **dependencies;
    int dependency_count;
} compile_context_owner_t;

typedef struct {
    char *rel_path;
    int source_index;
    CBMLanguage declared_language;
    bool compiler_language_applied;
    bool has_c_owner;
    bool has_cpp_owner;
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
    int compiler_baseline_queries;
    int compiler_baseline_reuses;
    int captured_command_count;
    bool compiler_capture_telemetry_present;
    bool authority_absent;
    char *source_date_epoch;
    char *source_date_epoch_revision;
    char *source_date_epoch_repository_root;
    CBMHashTable *contexts_by_id;
    CBMHashTable *sets_by_rel_path;
};

static bool context_dependency_contains(const compile_context_owner_t *context,
                                        const char *rel_path);

static int context_fail(cbm_pipeline_ctx_t *ctx, const char *code, const char *operation,
                        const char *path, size_t requested, const char *message,
                        const char *remediation) {
    cbm_log_error("compile_context.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "message", message, "remediation", remediation);
    cbm_pipeline_record_fatal_error(ctx ? ctx->pipeline : NULL, code, operation,
                                    "compile_context", path, requested, message, remediation);
    return CBM_NOT_FOUND;
}

static int preprocess_fail(cbm_pipeline_ctx_t *ctx, const char *code,
                           const char *operation, const char *path, size_t requested,
                           const char *message, const char *remediation) {
    cbm_log_error("compiler_preprocess.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "message", message, "remediation", remediation);
    cbm_pipeline_record_fatal_error(ctx ? ctx->pipeline : NULL, code, operation,
                                    "compiler_preprocess", path, requested, message,
                                    remediation);
    return CBM_NOT_FOUND;
}

static int preprocess_linemarker_fail(cbm_pipeline_ctx_t *ctx,
                                      const compile_context_owner_t *owner,
                                      const char *code, const char *operation,
                                      const char *filename, const char *canonical,
                                      const char *message, const char *remediation) {
    const char *translation_unit = owner && owner->tu_rel_path ? owner->tu_rel_path : "";
    cbm_log_error("compiler_preprocess.failed", "code", code, "operation", operation,
                  "path", translation_unit, "marker_filename", filename ? filename : "",
                  "marker_canonical", canonical ? canonical : "", "source_root",
                  ctx && ctx->source_root ? ctx->source_root : "", "repository_root",
                  ctx && ctx->repo_path ? ctx->repo_path : "", "message", message,
                  "remediation", remediation);
    cbm_pipeline_record_fatal_error(ctx ? ctx->pipeline : NULL, code, operation,
                                    "compiler_preprocess", translation_unit,
                                    filename ? strlen(filename) : 0, message, remediation);
    return CBM_NOT_FOUND;
}

static bool source_date_epoch_is_canonical(const char *value) {
    if (!value || !value[0] || (value[0] == '0' && value[1])) {
        return false;
    }
    for (const unsigned char *at = (const unsigned char *)value; *at; at++) {
        if (!isdigit(*at)) {
            return false;
        }
    }
    errno = 0;
    char *end = NULL;
    (void)strtoull(value, &end, 10);
    return errno == 0 && end && *end == '\0';
}

static bool source_revision_is_canonical(const char *value) {
    size_t length = value ? strlen(value) : 0;
    if (length != 40 && length != 64) {
        return false;
    }
    for (const unsigned char *at = (const unsigned char *)value; *at; at++) {
        if (!isxdigit(*at)) {
            return false;
        }
    }
    return true;
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

static bool path_char_equal(char left, char right) {
    left = left == '\\' ? '/' : left;
    right = right == '\\' ? '/' : right;
#ifdef _WIN32
    left = (char)tolower((unsigned char)left);
    right = (char)tolower((unsigned char)right);
#endif
    return left == right;
}

static const char *path_relative_within(const char *root, const char *path) {
    if (!root || !root[0] || !path || !path[0]) {
        return NULL;
    }
    const char *root_at = root;
    const char *path_at = path;
    while (*root_at && *path_at && path_char_equal(*root_at, *path_at)) {
        root_at++;
        path_at++;
    }
    while (*root_at == '/' || *root_at == '\\') {
        root_at++;
    }
    if (*root_at != '\0') {
        return NULL;
    }
    if (*path_at && *path_at != '/' && *path_at != '\\') {
        return NULL;
    }
    while (*path_at == '/' || *path_at == '\\') {
        path_at++;
    }
    return path_at;
}

static char *canonical_normalized_path(const char *directory, const char *path) {
    char *joined = join_path(directory, path);
    if (!joined) {
        return NULL;
    }
    char *canonical = cbm_canonicalize_existing_path(joined);
    free(joined);
    if (!canonical) {
        return NULL;
    }
    char *normalized = normalize_slashes_dup(canonical);
    free(canonical);
    return normalized;
}

static char *snapshot_path_for_original(cbm_pipeline_ctx_t *ctx, const char *directory,
                                        const char *path) {
    char *canonical = canonical_normalized_path(directory, path);
    if (!canonical) {
        return NULL;
    }
    const char *relative = path_relative_within(ctx->repo_path, canonical);
    if (!relative) {
        return canonical;
    }
    char *snapshot = join_path(ctx->source_root, relative);
    free(canonical);
    return snapshot;
}

static bool option_consumes_path(const char *argument) {
    return argument &&
           (strcmp(argument, "-I") == 0 || strcmp(argument, "-isystem") == 0 ||
            strcmp(argument, "-iquote") == 0 || strcmp(argument, "-idirafter") == 0 ||
            strcmp(argument, "-include") == 0 || strcmp(argument, "-imacros") == 0 ||
            strcmp(argument, "-isysroot") == 0 || strcmp(argument, "--sysroot") == 0 ||
            strcmp(argument, "-B") == 0);
}

static size_t joined_path_option_prefix(const char *argument) {
    static const char *const prefixes[] = {"--sysroot=", "-idirafter", "-isystem", "-iquote",
                                           "-include",   "-imacros",   "-isysroot", "-I",
                                           "-B",         NULL};
    if (!argument) {
        return 0;
    }
    for (int i = 0; prefixes[i]; i++) {
        size_t length = strlen(prefixes[i]);
        if (strncmp(argument, prefixes[i], length) == 0 && argument[length]) {
            return length;
        }
    }
    return 0;
}

static char *rewrite_path_argument(cbm_pipeline_ctx_t *ctx,
                                   const compile_context_owner_t *owner,
                                   const char *argument) {
    char *rewritten = snapshot_path_for_original(ctx, owner->directory, argument);
    return rewritten ? rewritten : strdup(argument);
}

static char *rewrite_joined_path_argument(cbm_pipeline_ctx_t *ctx,
                                          const compile_context_owner_t *owner,
                                          const char *argument, size_t prefix_length) {
    char *path = rewrite_path_argument(ctx, owner, argument + prefix_length);
    if (!path || prefix_length > SIZE_MAX - strlen(path) - 1) {
        free(path);
        return NULL;
    }
    size_t path_length = strlen(path);
    char *rewritten = malloc(prefix_length + path_length + 1);
    if (rewritten) {
        memcpy(rewritten, argument, prefix_length);
        memcpy(rewritten + prefix_length, path, path_length + 1);
    }
    free(path);
    return rewritten;
}

static void free_preprocess_argv(char **argv, int count) {
    if (!argv) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(argv[i]);
    }
    free(argv);
}

static int build_preprocess_argv(cbm_pipeline_ctx_t *ctx,
                                 const compile_context_owner_t *owner,
                                 char ***out_argv, int *out_count,
                                 char **out_working_directory) {
    *out_argv = NULL;
    *out_count = 0;
    *out_working_directory = NULL;
    if (!ctx || !ctx->repo_path || !ctx->source_root || !owner ||
        !owner->preprocess_arguments || owner->preprocess_argument_count < 1 ||
        !owner->view.entry_path || !owner->view.entry_path[0]) {
        return CBM_NOT_FOUND;
    }
    if (owner->preprocess_argument_count > INT_MAX - 4 ||
        (size_t)(owner->preprocess_argument_count + 4) > SIZE_MAX / sizeof(char *)) {
        return CBM_NOT_FOUND;
    }
    char **argv = calloc((size_t)owner->preprocess_argument_count + 4, sizeof(*argv));
    if (!argv) {
        return CBM_NOT_FOUND;
    }
    int count = 0;
    for (int i = 0; i < owner->preprocess_argument_count; i++) {
        const char *argument = owner->preprocess_arguments[i];
        char *copy = NULL;
        if (i > 0 && option_consumes_path(owner->preprocess_arguments[i - 1])) {
            copy = rewrite_path_argument(ctx, owner, argument);
        } else {
            size_t prefix = joined_path_option_prefix(argument);
            copy = prefix > 0 ? rewrite_joined_path_argument(ctx, owner, argument, prefix)
                              : strdup(argument);
        }
        if (!copy) {
            free_preprocess_argv(argv, count);
            return CBM_NOT_FOUND;
        }
        argv[count++] = copy;
    }
    size_t mapping_length = strlen(ctx->source_root) + strlen(ctx->repo_path) + 21;
    char *macro_mapping = malloc(mapping_length);
    if (!macro_mapping) {
        free_preprocess_argv(argv, count);
        return CBM_NOT_FOUND;
    }
    snprintf(macro_mapping, mapping_length, "-fmacro-prefix-map=%s=%s", ctx->source_root,
             ctx->repo_path);
    argv[count++] = macro_mapping;
    argv[count++] = strdup("-E");
    argv[count++] = strdup(owner->view.entry_path);
    if (!argv[count - 2] || !argv[count - 1]) {
        free_preprocess_argv(argv, count);
        return CBM_NOT_FOUND;
    }
    argv[count] = NULL;

    const char *relative_directory = path_relative_within(ctx->repo_path, owner->directory);
    char *working_directory = relative_directory
                                  ? join_path(ctx->source_root, relative_directory)
                                  : strdup(owner->directory);
    if (!working_directory) {
        free_preprocess_argv(argv, count);
        return CBM_NOT_FOUND;
    }
    *out_argv = argv;
    *out_count = count;
    *out_working_directory = working_directory;
    return 0;
}

static bool compiler_windows_path_length(const char *path, size_t *characters) {
    if (!path || !characters) {
        return false;
    }
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (length <= 0) {
        return false;
    }
    *characters = (size_t)(length - 1);
    return true;
}

static char *relative_parent_path(const char *relative_path) {
    if (!relative_path) {
        return NULL;
    }
    const char *slash = strrchr(relative_path, '/');
    const char *backslash = strrchr(relative_path, '\\');
    const char *separator = slash;
    if (backslash && (!separator || backslash > separator)) {
        separator = backslash;
    }
    size_t length = separator ? (size_t)(separator - relative_path) : 0;
    char *parent = malloc(length + 1);
    if (!parent) {
        return NULL;
    }
    memcpy(parent, relative_path, length);
    parent[length] = '\0';
    return parent;
}

/* Resolve only lexical repository-relative components. The returned path is
 * used for dependency identity; the compiler-facing spelling remains untouched. */
static char *normalize_relative_include(const char *including_relative_path,
                                        const char *include_request,
                                        bool *escaped_repository_root) {
    if (escaped_repository_root) {
        *escaped_repository_root = false;
    }
    if (!including_relative_path || !include_request || !include_request[0] ||
        path_is_absolute(include_request)) {
        return NULL;
    }
    char *parent = relative_parent_path(including_relative_path);
    char *joined = parent ? join_path(parent, include_request) : NULL;
    free(parent);
    if (!joined) {
        return NULL;
    }

    size_t joined_length = strlen(joined);
    char *normalized = malloc(joined_length + 1);
    if (!normalized) {
        free(joined);
        return NULL;
    }
    size_t output_length = 0;
    const char *at = joined;
    while (*at) {
        while (*at == '/' || *at == '\\') {
            at++;
        }
        const char *segment = at;
        while (*at && *at != '/' && *at != '\\') {
            at++;
        }
        size_t segment_length = (size_t)(at - segment);
        if (segment_length == 0 || (segment_length == 1 && segment[0] == '.')) {
            continue;
        }
        if (segment_length == 2 && segment[0] == '.' && segment[1] == '.') {
            if (output_length == 0) {
                if (escaped_repository_root) {
                    *escaped_repository_root = true;
                }
                free(normalized);
                free(joined);
                return NULL;
            }
            while (output_length > 0 && normalized[output_length - 1] != '/') {
                output_length--;
            }
            if (output_length > 0) {
                output_length--;
            }
            continue;
        }
        if (output_length > 0) {
            normalized[output_length++] = '/';
        }
        memcpy(normalized + output_length, segment, segment_length);
        output_length += segment_length;
    }
    normalized[output_length] = '\0';
    free(joined);
    return normalized;
}

static char *raw_snapshot_include_path(cbm_pipeline_ctx_t *ctx, const char *including_relative_path,
                                       const char *include_request) {
    char *parent = relative_parent_path(including_relative_path);
    char *snapshot_parent = parent && parent[0] ? join_path(ctx->source_root, parent)
                                                : (parent ? strdup(ctx->source_root) : NULL);
    char *raw_path = snapshot_parent ? join_path(snapshot_parent, include_request) : NULL;
    free(snapshot_parent);
    free(parent);
    return raw_path;
}

static const char *context_dependency_match(const compile_context_owner_t *context,
                                            const char *relative_path) {
    if (!context || !relative_path) {
        return NULL;
    }
    if (context_dependency_contains(context, relative_path)) {
        return relative_path;
    }
#ifdef _WIN32
    /* Captured paths retain source spelling, but Windows identity is case-insensitive.
     * Pay for the linear probe only on the exceptional case-mismatch path. */
    for (int i = 0; i < context->dependency_count; i++) {
        if (path_equal(context->dependencies[i], relative_path)) {
            return context->dependencies[i];
        }
    }
#endif
    return NULL;
}

static int validate_compiler_snapshot_path_budget(cbm_pipeline_ctx_t *ctx,
                                                  const compile_context_owner_t *owner,
                                                  const cbm_compile_context_index_t *index,
                                                  const cbm_file_info_t *source_files,
                                                  int source_count,
                                                  CBMFileResult *const *result_cache) {
    const char *relative_directory =
        path_relative_within(ctx ? ctx->repo_path : NULL, owner ? owner->directory : NULL);
    if (!ctx || !ctx->source_root || !owner || !relative_directory || !index || !source_files ||
        source_count < 0 || (source_count > 0 && !result_cache)) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_WORKING_DIRECTORY_UNPROJECTABLE", "validate_compiler_path_budget",
            owner && owner->tu_rel_path ? owner->tu_rel_path : "", 0,
            "the captured compiler working directory cannot be projected into the immutable "
            "snapshot",
            "preserve the compilation-context manifest and repair its repository-root binding");
    }

    char *longest_path = join_path(ctx->source_root, relative_directory);
    if (!longest_path) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_PATH_BUDGET_ALLOC_FAILED", "validate_compiler_path_budget",
            owner->tu_rel_path, 0, "the compiler snapshot path budget could not be represented",
            "free memory and preserve the unchanged source generation for diagnosis");
    }
    size_t longest_characters = 0;
    if (!compiler_windows_path_length(longest_path, &longest_characters)) {
        int failure =
            preprocess_fail(ctx, "CBM_PREPROCESS_PATH_ENCODING_INVALID",
                            "validate_compiler_path_budget", longest_path, strlen(longest_path),
                            "the projected compiler working directory is not valid UTF-8",
                            "repair the captured compiler directory encoding before indexing");
        free(longest_path);
        return failure;
    }
    size_t longest_bytes = strlen(longest_path);
    const char *longest_kind = "working_directory";
    char *longest_normalized_target = NULL;
    const char *longest_including_source = NULL;
    const char *longest_include_request = NULL;

    for (int i = 0; i < owner->dependency_count; i++) {
        const char *dependency = owner->dependencies[i];
        char *projected = join_path(ctx->source_root, dependency);
        if (!projected) {
            free(longest_normalized_target);
            free(longest_path);
            return preprocess_fail(
                ctx, "CBM_PREPROCESS_PATH_BUDGET_ALLOC_FAILED", "validate_compiler_path_budget",
                dependency, (size_t)i,
                "one compiler dependency path could not be projected into the immutable snapshot",
                "free memory and preserve the unchanged source generation for diagnosis");
        }
        size_t projected_characters = 0;
        if (!compiler_windows_path_length(projected, &projected_characters)) {
            int failure =
                preprocess_fail(ctx, "CBM_PREPROCESS_PATH_ENCODING_INVALID",
                                "validate_compiler_path_budget", projected, strlen(projected),
                                "one projected compiler dependency path is not valid UTF-8",
                                "repair the captured dependency path encoding before indexing");
            free(projected);
            free(longest_normalized_target);
            free(longest_path);
            return failure;
        }
        size_t projected_bytes = strlen(projected);
        if (projected_characters > longest_characters) {
            free(longest_path);
            free(longest_normalized_target);
            longest_path = projected;
            longest_normalized_target = NULL;
            longest_bytes = projected_bytes;
            longest_characters = projected_characters;
            longest_kind = "repository_dependency";
            longest_including_source = NULL;
            longest_include_request = NULL;
        } else {
            free(projected);
        }
    }

    /* GCC searches a quoted include relative to the including file before it
     * normalizes `..`. MinGW hands that literal spelling to MAX_PATH-bound Win32
     * APIs, so measuring only the normalized dependency can undercount the real
     * compiler lookup. Inspect only this context's dependency closure and retain
     * the literal spelling for admission. */
    for (int dependency_index = 0; dependency_index < owner->dependency_count; dependency_index++) {
        compile_context_set_owner_t *set = (compile_context_set_owner_t *)cbm_ht_get(
            index->sets_by_rel_path, owner->dependencies[dependency_index]);
        if (!set) {
            continue;
        }
        if (set->source_index < 0 || set->source_index >= source_count) {
            free(longest_normalized_target);
            free(longest_path);
            return preprocess_fail(
                ctx, "CBM_PREPROCESS_TARGET_INDEX_INVALID", "measure_exact_include_paths",
                set->rel_path, (size_t)(set->source_index < 0 ? 0 : set->source_index),
                "a compiler dependency has no bounded immutable source index",
                "preserve the generation and repair compilation-context materialization");
        }
        const cbm_file_info_t *source_file = &source_files[set->source_index];
        CBMFileResult *result = result_cache[set->source_index];
        if (!result || result->has_error) {
            continue;
        }
        if (!result->exact_quoted_includes_captured || result->exact_quoted_include_count < 0 ||
            (result->exact_quoted_include_count > 0 && !result->exact_quoted_includes)) {
            free(longest_normalized_target);
            free(longest_path);
            return preprocess_fail(
                ctx, "CBM_PREPROCESS_EXACT_INCLUDE_CAPTURE_MISSING",
                "validate_exact_include_capture", source_file->rel_path,
                (size_t)(result->exact_quoted_include_count < 0
                             ? 0
                             : result->exact_quoted_include_count),
                "a C-family compiler dependency has no complete parse-time quoted-include "
                "witness",
                "preserve the generation and repair exact-include capture before parser-tree "
                "retirement");
        }
        for (int request_index = 0; request_index < result->exact_quoted_include_count;
             request_index++) {
            const char *include_request = result->exact_quoted_includes[request_index];
            if (!include_request || !include_request[0] || path_is_absolute(include_request)) {
                continue;
            }
            bool escaped_repository_root = false;
            char *normalized_target = normalize_relative_include(
                source_file->rel_path, include_request, &escaped_repository_root);
            if (!normalized_target) {
                if (escaped_repository_root) {
                    continue;
                }
                free(longest_normalized_target);
                free(longest_path);
                return preprocess_fail(
                    ctx, "CBM_PREPROCESS_EXACT_INCLUDE_NORMALIZE_FAILED",
                    "normalize_exact_include_path", source_file->rel_path, strlen(include_request),
                    "an exact quoted include could not be normalized for path admission",
                    "preserve the source generation and repair exact-include extraction");
            }
            const char *dependency_target = context_dependency_match(owner, normalized_target);
            if (!dependency_target) {
                free(normalized_target);
                continue;
            }

            char *raw_lookup =
                raw_snapshot_include_path(ctx, source_file->rel_path, include_request);
            if (!raw_lookup) {
                free(normalized_target);
                free(longest_normalized_target);
                free(longest_path);
                return preprocess_fail(
                    ctx, "CBM_PREPROCESS_PATH_BUDGET_ALLOC_FAILED", "measure_exact_include_paths",
                    source_file->rel_path, strlen(include_request),
                    "an exact quoted-include lookup path could not be represented",
                    "free memory and preserve the unchanged source generation for diagnosis");
            }
            size_t raw_lookup_characters = 0;
            if (!compiler_windows_path_length(raw_lookup, &raw_lookup_characters)) {
                int failure =
                    preprocess_fail(ctx, "CBM_PREPROCESS_PATH_ENCODING_INVALID",
                                    "measure_exact_include_paths", raw_lookup, strlen(raw_lookup),
                                    "an exact quoted-include lookup path is not valid UTF-8",
                                    "repair the quoted include encoding before indexing");
                free(raw_lookup);
                free(normalized_target);
                free(longest_normalized_target);
                free(longest_path);
                return failure;
            }
            if (raw_lookup_characters > longest_characters) {
                free(longest_path);
                free(longest_normalized_target);
                longest_path = raw_lookup;
                longest_normalized_target = normalized_target;
                longest_bytes = strlen(raw_lookup);
                longest_characters = raw_lookup_characters;
                longest_kind = "exact_quoted_include_lookup";
                longest_including_source = source_file->rel_path;
                longest_include_request = include_request;
            } else {
                free(raw_lookup);
                free(normalized_target);
            }
            (void)dependency_target;
        }
    }

    char length_text[32];
    char bytes_text[32];
    char limit_text[32];
    snprintf(length_text, sizeof(length_text), "%zu", longest_characters);
    snprintf(bytes_text, sizeof(bytes_text), "%zu", longest_bytes);
    snprintf(limit_text, sizeof(limit_text), "%d", MAX_PATH - 1);
    cbm_log_info("compiler_preprocess.path_budget", "translation_unit", owner->tu_rel_path,
                 "context_id", owner->view.context_id, "longest_kind", longest_kind, "longest_path",
                 longest_path, "longest_path_characters", length_text, "longest_path_utf8_bytes",
                 bytes_text, "maximum_path_characters", limit_text, "including_source",
                 longest_including_source ? longest_including_source : "", "include_request",
                 longest_include_request ? longest_include_request : "", "normalized_target",
                 longest_normalized_target ? longest_normalized_target : "", "compiler",
                 "pinned_mingw_gcc");
    if (longest_characters >= MAX_PATH) {
        cbm_log_error("compiler_preprocess.path_budget_exceeded", "translation_unit",
                      owner->tu_rel_path, "context_id", owner->view.context_id, "longest_kind",
                      longest_kind, "literal_lookup", longest_path, "including_source",
                      longest_including_source ? longest_including_source : "", "include_request",
                      longest_include_request ? longest_include_request : "", "normalized_target",
                      longest_normalized_target ? longest_normalized_target : "",
                      "maximum_path_characters", limit_text);
        int failure = preprocess_fail(
            ctx, "CBM_PREPROCESS_SNAPSHOT_PATH_TOO_LONG", "validate_compiler_path_budget",
            longest_path, longest_characters,
            "a literal compiler lookup exceeds the pinned MinGW preprocessor path limit",
            "select a shorter project store root through CBM_CACHE_DIR; Astrolabe never reads "
            "live source or mutates host long-path policy");
        free(longest_normalized_target);
        free(longest_path);
        return failure;
    }
    free(longest_normalized_target);
    free(longest_path);
    return 0;
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

static bool paths_overlap(const char *left, const char *right) {
    return path_relative_within(left, right) != NULL ||
           path_relative_within(right, left) != NULL;
}

static bool retained_path_contains(char **items, int count, const char *path) {
    for (int i = 0; i < count; i++) {
        if (path_equal(items[i], path)) {
            return true;
        }
    }
    return false;
}

static int retain_compiler_system_roots(cbm_pipeline_ctx_t *ctx,
                                        compile_context_owner_t *owner,
                                        const compile_baseline_t *baseline) {
    for (int baseline_index = 0; baseline_index < baseline->system_include_count;
         baseline_index++) {
        const char *declared = baseline->system_include_paths[baseline_index];
        char *canonical = canonical_normalized_path(owner->directory, declared);
        if (!canonical) {
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_SYSTEM_INCLUDE_UNRESOLVED",
                "canonicalize_system_include_root", declared, 0,
                "an exact compiler-reported include root cannot be resolved",
                "restore the captured compiler installation and regenerate its build context");
        }
        bool command_source_root = false;
        for (int include_index = 0; include_index < owner->owned_include_count;
             include_index++) {
            char *include_root = canonical_normalized_path(
                owner->directory, owner->owned_include_paths[include_index]);
            if (include_root && paths_overlap(include_root, canonical)) {
                command_source_root = true;
            }
            free(include_root);
            if (command_source_root) {
                break;
            }
        }
        if (!command_source_root &&
            !retained_path_contains(owner->compiler_system_roots,
                                    owner->compiler_system_root_count, canonical) &&
            !append_owned_string(&owner->compiler_system_roots,
                                 &owner->compiler_system_root_count, canonical)) {
            free(canonical);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "retain_compiler_system_root", declared, 0,
                                "an exact compiler-owned include root could not be retained",
                                "free memory and retry the unchanged corpus");
        }
        free(canonical);
    }
    return 0;
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
                                            int argument_count, const char *language) {
    if (!language || (strcmp(language, "c") != 0 && strcmp(language, "c++") != 0)) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_LANGUAGE_INVALID",
                            "parse_compile_arguments", owner->tu_rel_path, 0,
                            "one compiler invocation has no exact C/C++ language fact",
                            "regenerate the compilation context with the current Astrolabe artifact");
    }
    owner->view.cpp_mode = strcmp(language, "c++") == 0;
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
    bool standard_is_cpp = strstr(owner->view.standard, "++") != NULL;
    if (standard_is_cpp != owner->view.cpp_mode) {
        return context_fail(
            ctx, "CBM_COMPILE_CONTEXT_LANGUAGE_STANDARD_CONTRADICTORY",
            "parse_compile_arguments", owner->tu_rel_path, 0,
            "the exact translation-unit language contradicts its declared compiler standard",
            "repair the real compiler argv and regenerate the compilation context");
    }
    if (retain_compiler_system_roots(ctx, owner, baseline) != 0) {
        return CBM_NOT_FOUND;
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
    if (index && index->sets_by_rel_path && rel_path) {
        return (compile_context_set_owner_t *)cbm_ht_get(index->sets_by_rel_path, rel_path);
    }
    for (int i = 0; i < index->set_count; i++) {
        if (strcmp(index->sets[i].rel_path, rel_path) == 0) {
            return &index->sets[i];
        }
    }
    return NULL;
}

static int compare_string_ptrs(const void *left, const void *right) {
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;
    return strcmp(*a, *b);
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
                                    cbm_file_info_t *source_files, int source_count) {
    if (index->compiler_capture_telemetry_present &&
        (index->compiler_baseline_queries < index->baseline_count ||
         index->compiler_baseline_queries > index->captured_command_count ||
         index->compiler_baseline_reuses > index->captured_command_count ||
         (int64_t)index->compiler_baseline_queries +
                 (int64_t)index->compiler_baseline_reuses !=
             (int64_t)index->captured_command_count)) {
        return context_fail(
            ctx, "CBM_COMPILE_CONTEXT_CAPTURE_TELEMETRY_INCONSISTENT",
            "validate_capture_telemetry", ctx->repo_path, 0,
            "compiler baseline query/reuse telemetry contradicts the captured commands",
            "preserve the compilation database and regenerate the immutable context");
    }
    int candidate_files = 0;
    for (int i = 0; i < source_count; i++) {
        CBMLanguage language = source_files[i].language;
        if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA ||
            compiler_ambiguous_fragment_filename(source_files[i].rel_path)) {
            candidate_files++;
        }
    }
    if (candidate_files > 0) {
        index->sets = calloc((size_t)candidate_files, sizeof(*index->sets));
        if (!index->sets) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_file_sets",
                                "", (size_t)candidate_files,
                                "the per-file compilation-context index could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
    }
    index->set_count = candidate_files;
    if (candidate_files > (int)((UINT32_MAX - 16U) / 2U)) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                            "index_file_contexts", ctx->repo_path, (size_t)candidate_files,
                            "the source count exceeds the context hash representation",
                            "reduce the corpus generation or extend the context index");
    }
    index->sets_by_rel_path = cbm_ht_create((uint32_t)candidate_files * 2U + 16U);
    if (!index->sets_by_rel_path) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "index_file_contexts",
                            ctx->repo_path, (size_t)candidate_files,
                            "the immutable file-to-context hash index could not be allocated",
                            "free memory and retry the unchanged corpus");
    }
    int set_index = 0;
    for (int i = 0; i < source_count; i++) {
        CBMLanguage language = source_files[i].language;
        if (language != CBM_LANG_C && language != CBM_LANG_CPP && language != CBM_LANG_CUDA &&
            !compiler_ambiguous_fragment_filename(source_files[i].rel_path)) {
            continue;
        }
        compile_context_set_owner_t *set = &index->sets[set_index++];
        set->rel_path = strdup(source_files[i].rel_path);
        set->source_index = i;
        set->declared_language = language;
        if (!set->rel_path ||
            !cbm_ht_set_checked(index->sets_by_rel_path, set->rel_path, set, NULL)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "copy_file_path",
                                source_files[i].rel_path, 0,
                                "a source path could not be retained in the context index",
                                "free memory and retry the unchanged corpus");
        }
    }
    if (index->context_count > 0) {
        if (index->context_count > (int)((UINT32_MAX - 16U) / 2U)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                                "index_context_identities", ctx->repo_path,
                                (size_t)index->context_count,
                                "the translation-unit count exceeds the context hash representation",
                                "reduce the corpus generation or extend the context index");
        }
        index->contexts_by_id =
            cbm_ht_create((uint32_t)index->context_count * 2U + 16U);
        if (!index->contexts_by_id) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "index_context_identities", ctx->repo_path,
                                (size_t)index->context_count,
                                "the immutable context-identity hash index could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
    }
    for (int c = 0; c < index->context_count; c++) {
        compile_context_owner_t *context = &index->contexts[c];
        compile_context_owner_t *existing = (compile_context_owner_t *)cbm_ht_get(
            index->contexts_by_id, context->view.context_id);
        if (!existing &&
            !cbm_ht_set_checked(index->contexts_by_id, context->view.context_id, context, NULL)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                                "index_context_identity", context->tu_rel_path, 0,
                                "a context identity could not be indexed",
                                "free memory and retry the unchanged corpus");
        }
        if (context->dependency_count > 1) {
            qsort(context->dependencies, (size_t)context->dependency_count,
                  sizeof(*context->dependencies), compare_string_ptrs);
        }
        for (int d = 0; d < context->dependency_count; d++) {
            compile_context_set_owner_t *set = find_set(index, context->dependencies[d]);
            if (set && append_context_to_set(ctx, set, &context->view) != 0) {
                return CBM_NOT_FOUND;
            }
        }
    }
    int compiler_refined_fragments = 0;
    for (int i = 0; i < index->set_count; i++) {
        compile_context_set_owner_t *set = &index->sets[i];
        for (size_t c = 0; c < set->view.count; c++) {
            if (set->view.items[c].cpp_mode) {
                set->has_cpp_owner = true;
            } else {
                set->has_c_owner = true;
            }
        }
        if (!compiler_ambiguous_fragment_filename(set->rel_path) ||
            set->view.count == 0) {
            continue;
        }
        if (set->source_index < 0 || set->source_index >= source_count ||
            (!set->has_c_owner && !set->has_cpp_owner)) {
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_LANGUAGE_OWNERSHIP_INVALID",
                "resolve_ambiguous_fragment_language", set->rel_path, set->view.count,
                "an ambiguous compiler dependency has no complete C/C++ owner classification",
                "preserve the manifest and regenerate its exact language ownership facts");
        }
        source_files[set->source_index].language =
            set->has_cpp_owner ? CBM_LANG_CPP : CBM_LANG_C;
        set->compiler_language_applied = true;
        compiler_refined_fragments++;
    }
    int c_family_files = 0;
    for (int i = 0; i < source_count; i++) {
        CBMLanguage language = source_files[i].language;
        if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA) {
            c_family_files++;
        }
    }
    int bound_files = 0;
    int configuration_absent_files = 0;
    int empty_files = 0;
    int context_bindings = 0;
    for (int i = 0; i < source_count; i++) {
        CBMLanguage language = source_files[i].language;
        if (language != CBM_LANG_C && language != CBM_LANG_CPP && language != CBM_LANG_CUDA) {
            continue;
        }
        compile_context_set_owner_t *set = find_set(index, source_files[i].rel_path);
        if (!set) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_FILE_STATE_MISSING",
                                "classify_file_context", source_files[i].rel_path, 0,
                                "a discovered C-family source has no explicit context-state row",
                                "preserve the generation and rebuild its complete context index");
        }
        if (source_files[i].size == 0) {
            empty_files++;
            continue;
        }
        if (set->view.count == 0) {
            configuration_absent_files++;
            continue;
        }
        if (!set->view.items) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_FILE_STATE_INVALID",
                                "classify_file_context", source_files[i].rel_path,
                                set->view.count,
                                "a bound C-family source has no retained compiler contexts",
                                "preserve the generation and rebuild its complete context index");
        }
        bound_files++;
        if (set->view.count > (size_t)(INT_MAX - context_bindings)) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                                "count_context_bindings", source_files[i].rel_path,
                                set->view.count,
                                "context binding telemetry exceeds integer representation",
                                "extend the telemetry representation before retrying");
        }
        context_bindings += (int)set->view.count;
    }
    char files_text[32];
    char bound_text[32];
    char absent_text[32];
    char empty_text[32];
    char contexts_text[32];
    char bindings_text[32];
    char reuse_text[32];
    char baseline_queries_text[32];
    char baseline_reuses_text[32];
    char refined_text[32];
    snprintf(files_text, sizeof(files_text), "%d", c_family_files);
    snprintf(bound_text, sizeof(bound_text), "%d", bound_files);
    snprintf(absent_text, sizeof(absent_text), "%d", configuration_absent_files);
    snprintf(empty_text, sizeof(empty_text), "%d", empty_files);
    snprintf(contexts_text, sizeof(contexts_text), "%d", index->context_count);
    snprintf(bindings_text, sizeof(bindings_text), "%d", context_bindings);
    snprintf(reuse_text, sizeof(reuse_text), "%d",
             context_bindings > index->context_count
                 ? context_bindings - index->context_count
                 : 0);
    snprintf(baseline_queries_text, sizeof(baseline_queries_text), "%d",
             index->compiler_baseline_queries);
    snprintf(baseline_reuses_text, sizeof(baseline_reuses_text), "%d",
             index->compiler_baseline_reuses);
    snprintf(refined_text, sizeof(refined_text), "%d", compiler_refined_fragments);
    cbm_log_info("compile_context.ready", "c_family_files", files_text, "translation_units",
                 contexts_text, "bound_files", bound_text, "configuration_absent_files",
                 absent_text, "empty_files", empty_text, "file_context_bindings",
                 bindings_text, "authority", index->authority_absent ? "absent" : "exact_commands",
                 "cache_builds", "1", "context_reuses", reuse_text, "compiler_baseline_queries",
                 baseline_queries_text, "compiler_baseline_reuses", baseline_reuses_text,
                 "source_date_epoch",
                 index->source_date_epoch ? index->source_date_epoch : "not_applicable",
                 "source_date_epoch_provenance",
                 index->source_date_epoch ? "git_head_commit" : "not_applicable",
                 "source_date_epoch_revision",
                 index->source_date_epoch_revision ? index->source_date_epoch_revision
                                                   : "not_applicable",
                 "cache", "generation_owned_immutable", "entry_source_cache", "source_slab",
                 "entry_source_disk_reads", "0", "file_context_lookup", "hash_o1",
                 "context_identity_lookup", "hash_o1", "dependency_membership",
                 "sorted_binary_search", "compiler_refined_fragments", refined_text);
    return 0;
}

static int parse_embedded_commands(cbm_pipeline_ctx_t *ctx,
                                   cbm_compile_context_index_t *index, yyjson_val *root,
                                   cbm_file_info_t *source_files, int source_count) {
    yyjson_val *commands = yyjson_obj_get(root, "commands");
    if (!commands || !yyjson_is_arr(commands) || yyjson_arr_size(commands) == 0) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMANDS_MISSING",
                            "parse_embedded_commands", "", 0,
                            "the embedded build context has no translation-unit commands",
                            "rebuild Astrolabe from the canonical native Makefile");
    }
    if (yyjson_arr_size(commands) > INT_MAX) {
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_CAPACITY_OVERFLOW",
                            "count_captured_commands", "", yyjson_arr_size(commands),
                            "captured command count exceeds integer representation",
                            "reduce the compilation database or extend representation");
    }
    index->captured_command_count = (int)yyjson_arr_size(commands);
    yyjson_arr_iter iterator;
    yyjson_arr_iter_init(commands, &iterator);
    yyjson_val *entry;
    while ((entry = yyjson_arr_iter_next(&iterator))) {
        const char *file = yyjson_get_str(yyjson_obj_get(entry, "file"));
        const char *language = yyjson_get_str(yyjson_obj_get(entry, "language"));
        const char *directory = yyjson_get_str(yyjson_obj_get(entry, "directory"));
        const char *baseline_id = yyjson_get_str(yyjson_obj_get(entry, "baseline_id"));
        yyjson_val *arguments_value = yyjson_obj_get(entry, "arguments");
        yyjson_val *preprocess_arguments_value =
            yyjson_obj_get(entry, "preprocess_arguments");
        yyjson_val *dependencies_value = yyjson_obj_get(entry, "dependencies");
        compile_baseline_t *baseline = find_baseline(index, baseline_id);
        if (!file || !file[0] || !language || !language[0] || !directory || !directory[0] || !baseline ||
            !arguments_value || !preprocess_arguments_value || !dependencies_value) {
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMAND_INCOMPLETE",
                                "parse_embedded_commands", file, 0,
                                "a translation-unit command lacks file, language, directory, baseline, "
                                "arguments, preprocess_arguments, or dependencies",
                                "regenerate the artifact compilation-context manifest");
        }
        int argument_count = 0;
        char **arguments = json_string_array(arguments_value, &argument_count);
        int preprocess_argument_count = 0;
        char **preprocess_arguments =
            json_string_array(preprocess_arguments_value, &preprocess_argument_count);
        int dependency_count = 0;
        char **dependencies = json_string_array(dependencies_value, &dependency_count);
        if (!arguments || argument_count < 2 || !preprocess_arguments ||
            preprocess_argument_count < 1 || !dependencies || dependency_count == 0) {
            free_string_array(arguments, argument_count);
            free_string_array(preprocess_arguments, preprocess_argument_count);
            free_string_array(dependencies, dependency_count);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_COMMAND_INCOMPLETE",
                                "parse_embedded_commands", file, 0,
                                "a translation-unit command has empty argv or dependency closure",
                                "regenerate the artifact compilation-context manifest");
        }
        if (!find_source_file(source_files, source_count, file)) {
            free_string_array(arguments, argument_count);
            free_string_array(preprocess_arguments, preprocess_argument_count);
            free_string_array(dependencies, dependency_count);
            continue;
        }
        if (!grow_array((void **)&index->contexts, &index->context_capacity,
                        index->context_count + 1, sizeof(*index->contexts))) {
            free_string_array(arguments, argument_count);
            free_string_array(preprocess_arguments, preprocess_argument_count);
            free_string_array(dependencies, dependency_count);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED", "allocate_context",
                                file, 0, "a translation-unit context could not be allocated",
                                "free memory and retry the unchanged corpus");
        }
        compile_context_owner_t *owner = &index->contexts[index->context_count];
        /* Publish ownership immediately so every later fail-closed return is
         * reclaimed by cbm_compile_context_index_free(). */
        index->context_count++;
        owner->tu_rel_path = strdup(file);
        owner->directory = normalize_slashes_dup(directory);
        owner->preprocess_arguments = preprocess_arguments;
        owner->preprocess_argument_count = preprocess_argument_count;
        owner->dependencies = dependencies;
        owner->dependency_count = dependency_count;
        if (!owner->tu_rel_path || !owner->directory ||
            configure_context_from_arguments(ctx, owner, baseline, arguments, argument_count,
                                             language) != 0) {
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
        ptrdiff_t translation_unit_index = translation_unit - source_files;
        if (translation_unit_index < 0 || translation_unit_index >= source_count) {
            free_string_array(arguments, argument_count);
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_TU_SOURCE_INVALID", "bind_translation_unit_source",
                file, 0,
                "the consuming translation unit has no stable immutable source-slab index",
                "preserve the source-slab diagnostic and retry the complete unchanged corpus");
        }
        size_t entry_source_len = 0;
        const uint8_t *entry_source =
            cbm_source_slab_get(ctx->source_slab, (int)translation_unit_index,
                                &entry_source_len);
        if (!entry_source || entry_source_len > (size_t)INT_MAX ||
            entry_source_len != (size_t)translation_unit->size) {
            free_string_array(arguments, argument_count);
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_TU_SOURCE_INVALID", "bind_translation_unit_source",
                file, entry_source_len,
                "the consuming translation unit is absent or inconsistent in the immutable source slab",
                "preserve the source-slab diagnostic and retry the complete unchanged corpus");
        }
        owner->view.entry_path = translation_unit->path;
        owner->view.entry_source = (const char *)entry_source;
        owner->view.entry_source_len = (int)entry_source_len;
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
        cbm_sha256_update(&hash, "SOURCE_DATE_EPOCH", strlen("SOURCE_DATE_EPOCH"));
        cbm_sha256_update(&hash, "\0", 1);
        cbm_sha256_update(&hash, index->source_date_epoch,
                          strlen(index->source_date_epoch));
        cbm_sha256_update(&hash, "\0", 1);
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
    }
    return materialize_context_sets(ctx, index, source_files, source_count);
}

static int parse_embedded_manifest(cbm_pipeline_ctx_t *ctx,
                                   cbm_compile_context_index_t *index,
                                   const uint8_t *bytes, size_t byte_count,
                                   cbm_file_info_t *source_files, int source_count,
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
    const char *authority = yyjson_get_str(yyjson_obj_get(root, "authority"));
    if (authority) {
        if (strcmp(authority, "absent") != 0) {
            yyjson_doc_free(document);
            return context_fail(ctx, "CBM_COMPILE_CONTEXT_AUTHORITY_INVALID",
                                "select_context_authority", ctx->repo_path, 0,
                                "the compilation-context authority marker is unsupported",
                                "regenerate the immutable repository compilation context");
        }
        yyjson_val *baselines = yyjson_obj_get(root, "baselines");
        yyjson_val *commands = yyjson_obj_get(root, "commands");
        if (!yyjson_is_arr(baselines) || !yyjson_is_arr(commands) ||
            yyjson_arr_size(baselines) != 0 || yyjson_arr_size(commands) != 0 ||
            yyjson_obj_get(root, "capture") != NULL ||
            yyjson_obj_get(root, "source_date_epoch") != NULL) {
            yyjson_doc_free(document);
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_ABSENCE_CONTRADICTORY",
                "select_context_authority", ctx->repo_path, 0,
                "an absent compilation-context authority carries compiler state",
                "preserve the contradictory manifest and regenerate it from one repository state");
        }
        index->authority_absent = true;
        int rc = materialize_context_sets(ctx, index, source_files, source_count);
        yyjson_doc_free(document);
        return rc;
    }
    yyjson_val *source_date_epoch = yyjson_obj_get(root, "source_date_epoch");
    const char *epoch_value = yyjson_get_str(
        source_date_epoch ? yyjson_obj_get(source_date_epoch, "value") : NULL);
    const char *epoch_provenance = yyjson_get_str(
        source_date_epoch ? yyjson_obj_get(source_date_epoch, "provenance") : NULL);
    const char *epoch_revision = yyjson_get_str(
        source_date_epoch ? yyjson_obj_get(source_date_epoch, "revision") : NULL);
    const char *epoch_repository_root = yyjson_get_str(
        source_date_epoch ? yyjson_obj_get(source_date_epoch, "repository_root") : NULL);
    if (!yyjson_is_obj(source_date_epoch) ||
        !source_date_epoch_is_canonical(epoch_value) ||
        !source_revision_is_canonical(epoch_revision) || !epoch_provenance ||
        strcmp(epoch_provenance, "git_head_commit") != 0 || !epoch_repository_root ||
        !epoch_repository_root[0]) {
        yyjson_doc_free(document);
        return context_fail(
            ctx, "CBM_COMPILE_CONTEXT_SOURCE_EPOCH_INVALID", "parse_source_date_epoch",
            ctx->repo_path, 0,
            "the active compilation context has invalid Git source-date provenance",
            "regenerate the immutable context from the exact committed Git repository");
    }
    char *canonical_epoch_root = canonical_normalized_path(NULL, epoch_repository_root);
    if (!canonical_epoch_root ||
        !path_relative_within(canonical_epoch_root, ctx->repo_path)) {
        free(canonical_epoch_root);
        yyjson_doc_free(document);
        return context_fail(
            ctx, "CBM_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_MISMATCH",
            "bind_source_date_epoch_repository", epoch_repository_root, 0,
            "the indexed root is not within the source-date Git repository root",
            "discard the mismatched context and regenerate it for the exact repository");
    }
    index->source_date_epoch = strdup(epoch_value);
    index->source_date_epoch_revision = strdup(epoch_revision);
    index->source_date_epoch_repository_root = canonical_epoch_root;
    if (!index->source_date_epoch || !index->source_date_epoch_revision) {
        yyjson_doc_free(document);
        return context_fail(ctx, "CBM_COMPILE_CONTEXT_ALLOC_FAILED",
                            "retain_source_date_epoch", ctx->repo_path, 0,
                            "the exact source-date provenance could not be retained",
                            "free memory and retry the unchanged corpus");
    }
    yyjson_val *capture = yyjson_obj_get(root, "capture");
    if (capture) {
        if (!yyjson_is_obj(capture)) {
            yyjson_doc_free(document);
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_CAPTURE_TELEMETRY_INVALID",
                "parse_capture_telemetry", ctx->repo_path, 0,
                "compilation-context capture telemetry is not an object",
                "regenerate the immutable compilation context with this Astrolabe artifact");
        }
        yyjson_val *queries = yyjson_obj_get(capture, "baseline_queries");
        yyjson_val *reuses = yyjson_obj_get(capture, "baseline_reuses");
        if (!yyjson_is_uint(queries) || !yyjson_is_uint(reuses) ||
            yyjson_get_uint(queries) == 0 || yyjson_get_uint(queries) > INT_MAX ||
            yyjson_get_uint(reuses) > INT_MAX) {
            yyjson_doc_free(document);
            return context_fail(
                ctx, "CBM_COMPILE_CONTEXT_CAPTURE_TELEMETRY_INVALID",
                "parse_capture_telemetry", ctx->repo_path, 0,
                "compilation-context capture telemetry is missing or exceeds representation",
                "regenerate the immutable compilation context with this Astrolabe artifact");
        }
        index->compiler_baseline_queries = (int)yyjson_get_uint(queries);
        index->compiler_baseline_reuses = (int)yyjson_get_uint(reuses);
        index->compiler_capture_telemetry_present = true;
    }
    int rc = parse_embedded_baselines(ctx, index, root);
    if (rc == 0 && !capture) {
        index->compiler_baseline_queries = index->baseline_count;
    }
    if (rc == 0) {
        rc = parse_embedded_commands(ctx, index, root, source_files, source_count);
    }
    yyjson_doc_free(document);
    return rc;
}

static bool has_c_family_file(const cbm_file_info_t *files, int count) {
    for (int i = 0; i < count; i++) {
        if (files[i].language == CBM_LANG_C || files[i].language == CBM_LANG_CPP ||
            files[i].language == CBM_LANG_CUDA) {
            return true;
        }
    }
    return false;
}

static bool has_compiler_ambiguous_file(const cbm_file_info_t *files, int count) {
    for (int i = 0; i < count; i++) {
        if (compiler_ambiguous_fragment_filename(files[i].rel_path)) {
            return true;
        }
    }
    return false;
}

int cbm_compile_context_index_prepare(cbm_pipeline_ctx_t *ctx,
                                      cbm_file_info_t *source_files, int source_count,
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
    bool has_c_family = has_c_family_file(source_files, source_count);
    bool has_ambiguous_fragment = has_compiler_ambiguous_file(source_files, source_count);
    if (!has_c_family && (!has_ambiguous_fragment || !embedded_bytes || embedded_byte_count == 0)) {
        cbm_log_info("compile_context.ready", "c_family_files", "0", "translation_units", "0",
                     "bound_files", "0", "configuration_absent_files", "0", "empty_files", "0",
                     "file_context_bindings", "0", "authority", "not_applicable", "cache_builds",
                     "1", "context_reuses", "0", "compiler_baseline_queries", "0",
                     "compiler_baseline_reuses", "0", "cache", "generation_owned_immutable",
                     "entry_source_cache", "source_slab", "entry_source_disk_reads", "0",
                     "file_context_lookup", "not_applicable", "context_identity_lookup",
                     "not_applicable", "dependency_membership", "not_applicable");
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
    compile_context_set_owner_t *set = index->sets_by_rel_path
                                           ? (compile_context_set_owner_t *)cbm_ht_get(
                                                 index->sets_by_rel_path, rel_path)
                                           : NULL;
    return set ? &set->view : NULL;
}

bool cbm_compile_context_language_metadata(
    const cbm_compile_context_index_t *index, const char *rel_path,
    cbm_compile_context_language_metadata_t *out) {
    if (!index || !rel_path || !out) {
        return false;
    }
    compile_context_set_owner_t *set = index->sets_by_rel_path
                                           ? (compile_context_set_owner_t *)cbm_ht_get(
                                                 index->sets_by_rel_path, rel_path)
                                           : NULL;
    if (!set) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->declared_language = set->declared_language;
    out->owners = &set->view;
    out->ambiguous_fragment = compiler_ambiguous_fragment_filename(rel_path);
    out->compiler_language_applied = set->compiler_language_applied;
    out->provenance = set->compiler_language_applied ? "exact_compiler_dependency"
                                                     : "declared_extension";
    if (set->has_c_owner && set->has_cpp_owner) {
        out->effective_family = "c/c++";
    } else if (set->has_cpp_owner) {
        out->effective_family = "c++";
    } else if (set->has_c_owner) {
        out->effective_family = "c";
    } else {
        out->effective_family = cbm_language_name(set->declared_language);
    }
    return true;
}

static const compile_context_owner_t *find_context_by_id(
    const cbm_compile_context_index_t *index, const char *context_id) {
    return index && index->contexts_by_id && context_id
               ? (const compile_context_owner_t *)cbm_ht_get(index->contexts_by_id, context_id)
               : NULL;
}

bool cbm_compile_context_id_exists(const cbm_compile_context_index_t *index,
                                   const char *context_id) {
    return find_context_by_id(index, context_id) != NULL;
}

cbm_compile_context_file_state_t cbm_compile_context_file_state(
    const cbm_compile_context_index_t *index, const char *rel_path, CBMLanguage language,
    int64_t source_size, size_t *context_count) {
    if (context_count) {
        *context_count = 0;
    }
    if (language != CBM_LANG_C && language != CBM_LANG_CPP && language != CBM_LANG_CUDA) {
        return CBM_COMPILE_CONTEXT_NOT_APPLICABLE;
    }
    compile_context_set_owner_t *set = index && index->sets_by_rel_path && rel_path
                                           ? (compile_context_set_owner_t *)cbm_ht_get(
                                                 index->sets_by_rel_path, rel_path)
                                           : NULL;
    if (!set || source_size < 0) {
        return CBM_COMPILE_CONTEXT_STATE_INVALID;
    }
    if (source_size == 0) {
        return CBM_COMPILE_CONTEXT_EMPTY_SOURCE;
    }
    if (context_count) {
        *context_count = set->view.count;
    }
    if (set->view.count == 0) {
        return CBM_COMPILE_CONTEXT_CONFIGURATION_ABSENT;
    }
    return set->view.items ? CBM_COMPILE_CONTEXT_BOUND : CBM_COMPILE_CONTEXT_STATE_INVALID;
}

const char *cbm_compile_context_authority(
    const cbm_compile_context_index_t *index, int c_family_file_count) {
    if (c_family_file_count == 0) {
        return "not_applicable";
    }
    return index && index->authority_absent ? "absent" : "exact_commands";
}

const char *cbm_compile_context_absence_reason(
    const cbm_compile_context_index_t *index) {
    return index && index->authority_absent ? "compile_database_absent"
                                            : "not_in_active_build_closure";
}

static bool context_dependency_contains(const compile_context_owner_t *context,
                                        const char *rel_path) {
    if (!context || !rel_path || context->dependency_count <= 0) {
        return false;
    }
    char *key = (char *)rel_path;
    return bsearch(&key, context->dependencies, (size_t)context->dependency_count,
                   sizeof(*context->dependencies), compare_string_ptrs) != NULL;
}

static bool context_compiler_system_contains(const compile_context_owner_t *context,
                                             const char *canonical) {
    if (!context || !canonical) {
        return false;
    }
    for (int i = 0; i < context->compiler_system_root_count; i++) {
        if (path_relative_within(context->compiler_system_roots[i], canonical)) {
            return true;
        }
    }
    return false;
}

static void sha256_hex(const void *bytes, size_t byte_count,
                       char out[CBM_SHA256_HEX_LEN + 1]) {
    cbm_sha256_ctx hash;
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_init(&hash);
    cbm_sha256_update(&hash, bytes, byte_count);
    cbm_sha256_final(&hash, digest);
    for (int i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        snprintf(out + (i * 2), 3, "%02x", digest[i]);
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
}

static bool parse_decimal_u32(const char *text, size_t length, size_t *position,
                              uint32_t *value) {
    size_t at = *position;
    if (at >= length || !isdigit((unsigned char)text[at])) {
        return false;
    }
    uint32_t parsed = 0;
    while (at < length && isdigit((unsigned char)text[at])) {
        uint32_t digit = (uint32_t)(text[at] - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
        at++;
    }
    *position = at;
    *value = parsed;
    return true;
}

static bool parse_compiler_linemarker(const char *line, size_t length,
                                      uint32_t *source_line, char **filename,
                                      bool *is_marker) {
    *filename = NULL;
    *is_marker = false;
    size_t at = 0;
    if (length == 0 || line[at] != '#') {
        return true;
    }
    at++;
    while (at < length && (line[at] == ' ' || line[at] == '\t')) {
        at++;
    }
    if (at >= length || !isdigit((unsigned char)line[at])) {
        return true; /* an ordinary directive such as #pragma */
    }
    *is_marker = true;
    if (!parse_decimal_u32(line, length, &at, source_line)) {
        return false;
    }
    while (at < length && (line[at] == ' ' || line[at] == '\t')) {
        at++;
    }
    if (at >= length || line[at++] != '"') {
        return false;
    }
    char *decoded = malloc(length - at + 1);
    if (!decoded) {
        return false;
    }
    size_t written = 0;
    bool closed = false;
    while (at < length) {
        char byte = line[at++];
        if (byte == '"') {
            closed = true;
            break;
        }
        if (byte == '\\') {
            if (at >= length || (line[at] != '\\' && line[at] != '"')) {
                free(decoded);
                return false;
            }
            byte = line[at++];
        }
        decoded[written++] = byte;
    }
    if (!closed || written == 0) {
        free(decoded);
        return false;
    }
    decoded[written] = '\0';
    while (at < length) {
        if (line[at] == ' ' || line[at] == '\t' || isdigit((unsigned char)line[at])) {
            at++;
            continue;
        }
        free(decoded);
        return false;
    }
    *filename = decoded;
    return true;
}

static bool is_exact_working_directory_marker(const char *working_directory,
                                              const char *filename,
                                              uint32_t source_line,
                                              size_t output_line_index) {
    /* GCC's -fworking-directory emits exactly this synthetic second
     * linemarker (cwd followed by "//"); -g enables it implicitly. It is
     * compiler metadata, not a dependency. Validate every documented field
     * before excluding it from repository-source mapping. */
    if (!working_directory || !filename || source_line != 1U || output_line_index != 1U) {
        return false;
    }
    size_t filename_length = strlen(filename);
    if (filename_length <= 2U || filename[filename_length - 2U] != '/' ||
        filename[filename_length - 1U] != '/') {
        return false;
    }
    size_t marker_directory_length = filename_length - 2U;
    size_t working_directory_length = strlen(working_directory);
    while (marker_directory_length > 0U &&
           (filename[marker_directory_length - 1U] == '/' ||
            filename[marker_directory_length - 1U] == '\\')) {
        marker_directory_length--;
    }
    while (working_directory_length > 0U &&
           (working_directory[working_directory_length - 1U] == '/' ||
            working_directory[working_directory_length - 1U] == '\\')) {
        working_directory_length--;
    }
    if (marker_directory_length != working_directory_length) {
        return false;
    }
    for (size_t i = 0; i < marker_directory_length; i++) {
        if (!path_char_equal(filename[i], working_directory[i])) {
            return false;
        }
    }
    return true;
}

static int marker_target(cbm_pipeline_ctx_t *ctx, cbm_compile_context_index_t *index,
                          const compile_context_owner_t *owner,
                          const char *working_directory, const char *filename,
                          uint32_t source_line, size_t output_line_index,
                          const uint32_t *target_by_source_index, uint32_t *target_out,
                          bool *mapped_target,
                          bool *workspace_local_compiler_marker,
                          bool *working_directory_marker) {
    *target_out = PREPROCESS_TARGET_NONE;
    *mapped_target = false;
    *workspace_local_compiler_marker = false;
    *working_directory_marker = false;
    size_t filename_length = strlen(filename);
    if (filename_length >= 2 && filename[0] == '<' &&
        filename[filename_length - 1] == '>') {
        return 0;
    }
    if (is_exact_working_directory_marker(working_directory, filename, source_line,
                                          output_line_index)) {
        *working_directory_marker = true;
        return 0;
    }
    char *canonical = canonical_normalized_path(working_directory, filename);
    if (!canonical) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_LINEMARKER_PATH_UNRESOLVED",
            "canonicalize_compiler_linemarker", owner->tu_rel_path, filename_length,
            "the compiler emitted a source filename that cannot be resolved",
            "preserve the compiler output and repair the exact working-directory/path inputs");
    }
    const char *relative = path_relative_within(ctx->source_root, canonical);
    if (relative) {
        compile_context_set_owner_t *set = find_set(index, relative);
        if (!context_dependency_contains(owner, relative)) {
            int failure = preprocess_linemarker_fail(
                ctx, owner, "CBM_PREPROCESS_DEPENDENCY_DRIFT", "map_compiler_linemarker",
                filename, canonical,
                "the compiler expansion names a repository source outside its captured dependency closure",
                "regenerate the compilation context and retry the unchanged source generation");
            free(canonical);
            return failure;
        }
        if (set) {
            uint32_t target = target_by_source_index[set->source_index];
            if (target == PREPROCESS_TARGET_IGNORED) {
                free(canonical);
                return 0;
            }
            if (target == PREPROCESS_TARGET_NONE) {
                free(canonical);
                return preprocess_fail(
                    ctx, "CBM_PREPROCESS_TARGET_MISSING", "map_compiler_linemarker",
                    relative, 0,
                    "a compiler-emitted C-family dependency has no prepared extraction target",
                    "repair the source/result cache handoff and retry the complete corpus");
            }
            *target_out = target;
            *mapped_target = true;
        }
        free(canonical);
        return 0;
    }
    const char *live_relative = path_relative_within(ctx->repo_path, canonical);
    if (live_relative) {
        if (!context_dependency_contains(owner, live_relative) &&
            !find_set(index, live_relative) &&
            context_compiler_system_contains(owner, canonical)) {
            *workspace_local_compiler_marker = true;
            free(canonical);
            return 0;
        }
        int failure = preprocess_linemarker_fail(
            ctx, owner, "CBM_PREPROCESS_LIVE_SOURCE_ESCAPE", "map_compiler_linemarker",
            filename, canonical,
            "the compiler read live repository bytes instead of the immutable source snapshot",
            "rewrite every repository-local compiler path to the captured generation and retry");
        free(canonical);
        return failure;
    }
    free(canonical);
    return 0; /* compiler/toolchain headers are context, not repository atoms */
}

static void compiler_expansion_destroy(compiler_expansion_t *expansion) {
    if (!expansion) {
        return;
    }
    free(expansion->text);
    free(expansion->line_targets);
    free(expansion->line_source_lines);
    memset(expansion, 0, sizeof(*expansion));
}

static int map_compiler_expansion(cbm_pipeline_ctx_t *ctx,
                                  cbm_compile_context_index_t *index,
                                  const compile_context_owner_t *owner,
                                  const char *working_directory,
                                  const uint32_t *target_by_source_index,
                                  char *text, size_t text_bytes,
                                  compiler_expansion_t *out) {
    memset(out, 0, sizeof(*out));
    if (!text || text_bytes == 0 || memchr(text, '\0', text_bytes) != NULL) {
        free(text);
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_OUTPUT_INVALID", "map_compiler_output", owner->tu_rel_path,
            text_bytes,
            "the exact compiler emitted empty or embedded-NUL preprocessing output",
            "inspect the captured compiler stdout and repair the compiler/source inputs");
    }
    size_t line_count = 1;
    for (size_t i = 0; i < text_bytes; i++) {
        if (text[i] == '\n') {
            if (line_count == SIZE_MAX) {
                free(text);
                return preprocess_fail(
                    ctx, "CBM_PREPROCESS_LINE_COUNT_OVERFLOW", "count_compiler_output_lines",
                    owner->tu_rel_path, text_bytes,
                    "compiler output line count exceeds addressable representation",
                    "reduce the translation unit or extend the source-map representation");
            }
            line_count++;
        }
    }
    if (line_count > SIZE_MAX / sizeof(uint32_t)) {
        free(text);
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_SOURCE_MAP_OVERFLOW", "allocate_compiler_source_map",
            owner->tu_rel_path, line_count,
            "compiler output source-map allocation exceeds addressable representation",
            "reduce the translation unit or extend the source-map representation");
    }
    uint32_t *targets = malloc(line_count * sizeof(*targets));
    uint32_t *source_lines = malloc(line_count * sizeof(*source_lines));
    if (!targets || !source_lines) {
        free(text);
        free(targets);
        free(source_lines);
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_SOURCE_MAP_ALLOC_FAILED", "allocate_compiler_source_map",
            owner->tu_rel_path, line_count * sizeof(uint32_t) * 2,
            "the exact compiler source map could not be allocated",
            "free memory or reduce concurrent repository workload, then retry");
    }

    uint32_t current_target = PREPROCESS_TARGET_NONE;
    uint32_t logical_line = 0;
    size_t mapped_lines = 0;
    size_t workspace_local_compiler_markers = 0;
    size_t working_directory_markers = 0;
    size_t line_index = 0;
    size_t canonical_bytes = 0;
    size_t start = 0;
    for (;;) {
        size_t end = start;
        while (end < text_bytes && text[end] != '\n') {
            end++;
        }
        size_t content_end = end;
        if (content_end > start && text[content_end - 1] == '\r') {
            content_end--;
        }
        uint32_t marker_line = 0;
        char *marker_file = NULL;
        bool marker = false;
        if (!parse_compiler_linemarker(text + start, content_end - start, &marker_line,
                                       &marker_file, &marker)) {
            free(marker_file);
            free(text);
            free(targets);
            free(source_lines);
            return preprocess_fail(
                ctx, "CBM_PREPROCESS_LINEMARKER_MALFORMED", "parse_compiler_linemarker",
                owner->tu_rel_path, line_index + 1,
                "the compiler emitted a malformed or unsupported line-control record",
                "preserve stdout and use a compiler with documented GCC-compatible linemarkers");
        }
        if (marker) {
            bool mapped_target = false;
            bool workspace_local_compiler_marker = false;
            bool working_directory_marker = false;
            int mapping = marker_target(
                ctx, index, owner, working_directory, marker_file, marker_line, line_index,
                target_by_source_index, &current_target, &mapped_target,
                &workspace_local_compiler_marker, &working_directory_marker);
            free(marker_file);
            if (mapping != 0) {
                free(text);
                free(targets);
                free(source_lines);
                return mapping;
            }
            logical_line = marker_line;
            if (workspace_local_compiler_marker) {
                workspace_local_compiler_markers++;
            }
            if (working_directory_marker) {
                working_directory_markers++;
            }
            targets[line_index] = PREPROCESS_TARGET_NONE;
            source_lines[line_index] = PREPROCESS_TARGET_NONE;
            (void)mapped_target;
        } else {
            targets[line_index] = current_target;
            source_lines[line_index] =
                current_target == PREPROCESS_TARGET_NONE ? PREPROCESS_TARGET_NONE : logical_line;
            if (current_target != PREPROCESS_TARGET_NONE) {
                if (logical_line == 0) {
                    free(text);
                    free(targets);
                    free(source_lines);
                    return preprocess_fail(
                        ctx, "CBM_PREPROCESS_SOURCE_LINE_INVALID", "map_compiler_output",
                        owner->tu_rel_path, line_index + 1,
                        "repository code follows a zero-valued compiler source line",
                        "preserve stdout and repair the compiler's line-control output");
                }
                mapped_lines++;
            }
            if (logical_line < UINT32_MAX) {
                logical_line++;
            } else if (current_target != PREPROCESS_TARGET_NONE) {
                free(text);
                free(targets);
                free(source_lines);
                return preprocess_fail(
                    ctx, "CBM_PREPROCESS_SOURCE_LINE_OVERFLOW", "map_compiler_output",
                    owner->tu_rel_path, line_index + 1,
                    "repository source-line mapping overflowed 32-bit representation",
                    "reduce the translation unit or extend source-line representation");
            }
            size_t content_bytes = content_end - start;
            if (content_bytes > 0) {
                memmove(text + canonical_bytes, text + start, content_bytes);
                canonical_bytes += content_bytes;
            }
        }
        if (end < text_bytes) {
            text[canonical_bytes++] = '\n';
        }
        line_index++;
        if (end == text_bytes) {
            break;
        }
        start = end + 1;
    }
    if (line_index != line_count || mapped_lines == 0) {
        free(text);
        free(targets);
        free(source_lines);
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_SOURCE_MAP_EMPTY", "map_compiler_output", owner->tu_rel_path,
            mapped_lines,
            "the compiler expansion maps no code line to its captured repository dependency closure",
            "inspect the exact compiler stdout, cwd, and immutable snapshot path mapping");
    }
    if (canonical_bytes == 0) {
        free(text);
        free(targets);
        free(source_lines);
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_CANONICAL_OUTPUT_EMPTY", "canonicalize_compiler_output",
            owner->tu_rel_path, text_bytes,
            "validated compiler output contains no canonical source bytes",
            "inspect the compiler expansion and repair the exact source/context inputs");
    }
    if (canonical_bytes < text_bytes) {
        text[canonical_bytes] = '\0';
    }
    out->text = text;
    out->text_bytes = canonical_bytes;
    out->line_targets = targets;
    out->line_source_lines = source_lines;
    out->line_count = line_count;
    out->mapped_lines = mapped_lines;
    out->workspace_local_compiler_markers = workspace_local_compiler_markers;
    out->working_directory_markers = working_directory_markers;
    return 0;
}

#ifdef ASTRO_SPAWN
static char *hex_encode_bytes(const char *bytes, size_t byte_count) {
    static const char hex[] = "0123456789abcdef";
    if ((!bytes && byte_count > 0) || byte_count > (SIZE_MAX - 1U) / 2U) {
        return NULL;
    }
    char *encoded = malloc(byte_count * 2U + 1U);
    if (!encoded) {
        return NULL;
    }
    for (size_t i = 0; i < byte_count; i++) {
        unsigned char byte = (unsigned char)bytes[i];
        encoded[i * 2U] = hex[byte >> 4U];
        encoded[i * 2U + 1U] = hex[byte & 0x0fU];
    }
    encoded[byte_count * 2U] = '\0';
    return encoded;
}

static void log_failed_compiler_invocation(const compile_context_owner_t *owner,
                                           char *const *argv, int argc,
                                           const char *working_directory) {
    cbm_sha256_ctx argv_hash;
    cbm_sha256_init(&argv_hash);
    for (int i = 0; i < argc; i++) {
        const char *argument = argv && argv[i] ? argv[i] : "";
        cbm_sha256_update(&argv_hash, argument, strlen(argument));
        cbm_sha256_update(&argv_hash, "\0", 1);
    }
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    char digest_hex[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_final(&argv_hash, digest);
    for (int i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        snprintf(digest_hex + i * 2, 3, "%02x", digest[i]);
    }
    digest_hex[CBM_SHA256_HEX_LEN] = '\0';

    char argc_text[32];
    char working_bytes_text[32];
    snprintf(argc_text, sizeof(argc_text), "%d", argc);
    snprintf(working_bytes_text, sizeof(working_bytes_text), "%zu",
             working_directory ? strlen(working_directory) : 0U);
    cbm_log_error(
        "compiler_preprocess.failed_invocation", "translation_unit",
        owner && owner->tu_rel_path ? owner->tu_rel_path : "", "context_id",
        owner && owner->view.context_id ? owner->view.context_id : "", "working_directory",
        working_directory ? working_directory : "", "working_directory_bytes",
        working_bytes_text, "argv_count", argc_text, "argv_encoding",
        "ordered_utf8_nul_delimited", "argv_sha256", digest_hex);
    for (int i = 0; i < argc; i++) {
        char index_text[32];
        snprintf(index_text, sizeof(index_text), "%d", i);
        cbm_log_error(
            "compiler_preprocess.failed_argument", "translation_unit",
            owner && owner->tu_rel_path ? owner->tu_rel_path : "", "context_id",
            owner && owner->view.context_id ? owner->view.context_id : "", "argument_index",
            index_text, "argument", argv && argv[i] ? argv[i] : "");
    }
}

static int compiler_spawn_fail(cbm_pipeline_ctx_t *ctx,
                               const compile_context_owner_t *owner,
                               const cbm_spawn_error_t *error,
                               const cbm_spawn_bounded_capture_t *stderr_capture,
                               const char *stdout_data, size_t stdout_bytes,
                               char *const *argv, int argc,
                               const char *working_directory) {
    char spawn_code[32];
    char exit_code[32];
    char os_error[32];
    char stdout_size[32];
    char stderr_size[32];
    char stderr_total[32];
    char stdout_hash[CBM_SHA256_HEX_LEN + 1];
    char stderr_hash[CBM_SHA256_HEX_LEN + 1];
    snprintf(spawn_code, sizeof(spawn_code), "%d", error ? (int)error->code : -1);
    snprintf(exit_code, sizeof(exit_code), "%d", error ? error->exit_code : -1);
    snprintf(os_error, sizeof(os_error), "%lu", error ? error->os_error : 0UL);
    snprintf(stdout_size, sizeof(stdout_size), "%zu", stdout_bytes);
    snprintf(stderr_size, sizeof(stderr_size), "%zu",
             stderr_capture ? stderr_capture->len : 0U);
    snprintf(stderr_total, sizeof(stderr_total), "%llu",
             (unsigned long long)(stderr_capture ? stderr_capture->total_len : 0U));
    sha256_hex(stdout_data ? stdout_data : "", stdout_bytes, stdout_hash);
    sha256_hex(stderr_capture && stderr_capture->data ? stderr_capture->data : "",
               stderr_capture ? stderr_capture->len : 0U, stderr_hash);
    log_failed_compiler_invocation(owner, argv, argc, working_directory);
    char *stderr_hex =
        hex_encode_bytes(stderr_capture ? stderr_capture->data : NULL,
                         stderr_capture ? stderr_capture->len : 0U);
    if (!stderr_hex) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_DIAGNOSTIC_ALLOC_FAILED", "retain_compiler_stderr",
            owner ? owner->tu_rel_path : "", stderr_capture ? stderr_capture->len : 0U,
            "the exact compiler failed and its bounded diagnostic could not be retained",
            "free memory, preserve the unchanged source generation, and retry");
    }
    cbm_log_error(
        "compiler_preprocess.compiler_failed", "code", "CBM_PREPROCESS_COMPILER_FAILED",
        "translation_unit", owner && owner->tu_rel_path ? owner->tu_rel_path : "", "context_id",
        owner && owner->view.context_id ? owner->view.context_id : "", "spawn_code", spawn_code,
        "spawn_code_name", error && error->code_name ? error->code_name : "", "exit_code",
        exit_code, "os_error", os_error, "stdout_bytes", stdout_size, "stdout_sha256",
        stdout_hash, "stderr_encoding", "hex", "stderr_hex", stderr_hex,
        "stderr_retained_bytes", stderr_size, "stderr_total_bytes", stderr_total,
        "stderr_truncated", stderr_capture && stderr_capture->truncated ? "true" : "false",
        "stderr_sha256", stderr_hash, "message",
        error && error->message ? error->message : "the exact compiler preprocessing step failed",
        "remediation",
        error && error->remediation
            ? error->remediation
            : "inspect the exact compiler diagnostic and repair the captured build inputs");
    free(stderr_hex);
    return preprocess_fail(
        ctx, "CBM_PREPROCESS_COMPILER_FAILED", "spawn_exact_compiler_preprocessor",
        owner ? owner->tu_rel_path : "", stdout_bytes,
        "the compiler-authoritative translation-unit expansion did not complete",
        "inspect compiler_preprocess.compiler_failed and repair the exact compiler context");
}
#endif

int cbm_compile_context_extract_calls(cbm_pipeline_ctx_t *ctx, cbm_compile_context_index_t *index,
                                      const cbm_file_info_t *source_files, int source_count,
                                      CBMFileResult **result_cache) {
    if (!ctx || !index || !source_files || source_count < 0 ||
        (source_count > 0 && !result_cache)) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_HANDOFF_INVALID", "admit_compiler_preprocess", "", 0,
            "the compiler-preprocess phase received an incomplete immutable extraction handoff",
            "preserve the generation and repair the context/source/result ownership boundary");
    }
    if (index->authority_absent || index->context_count == 0) {
        cbm_log_info("compiler_preprocess.ready", "compiler_invocations", "0", "syntax_trees", "0",
                     "target_projections", "0", "expanded_bytes", "0", "mapped_lines", "0",
                     "workspace_local_compiler_markers", "0", "peak_expansion_bytes", "0",
                     "authority", index->authority_absent ? "absent" : "not_applicable", "cache",
                     "one_compiler_expansion_per_context", "canonicalization",
                     "validated_linemarkers_to_empty_lines", "date_time_macros", "not_applicable",
                     "timestamp_macro_input", "not_applicable", "source_date_epoch",
                     "not_applicable", "fallback", "none");
        return 0;
    }
#ifndef ASTRO_SPAWN
    return preprocess_fail(
        ctx, "CBM_PREPROCESS_SPAWN_UNAVAILABLE", "spawn_exact_compiler_preprocessor",
        ctx->repo_path, (size_t)index->context_count,
        "this build cannot execute the compiler-authoritative preprocessing phase",
        "build the native Astrolabe artifact with its shell-free spawn authority enabled");
#else
    if ((size_t)source_count > SIZE_MAX / sizeof(uint32_t) ||
        (size_t)index->set_count > SIZE_MAX / sizeof(char *) ||
        (size_t)index->set_count > SIZE_MAX / sizeof(CBMFileResult *)) {
        return preprocess_fail(
            ctx, "CBM_PREPROCESS_TARGET_CAPACITY_OVERFLOW", "allocate_projection_index",
            ctx->repo_path, (size_t)source_count,
            "the compiler-preprocess target index exceeds addressable representation",
            "reduce the corpus generation or extend the target-index representation");
    }
    uint32_t *target_by_source_index =
        source_count > 0 ? malloc((size_t)source_count * sizeof(*target_by_source_index)) : NULL;
    const char **target_rel_paths =
        index->set_count > 0 ? malloc((size_t)index->set_count * sizeof(*target_rel_paths)) : NULL;
    CBMFileResult **target_results =
        index->set_count > 0 ? malloc((size_t)index->set_count * sizeof(*target_results)) : NULL;
    bool *touched = source_count > 0 ? calloc((size_t)source_count, sizeof(*touched)) : NULL;
    if ((source_count > 0 && (!target_by_source_index || !touched)) ||
        (index->set_count > 0 && (!target_rel_paths || !target_results))) {
        free(target_by_source_index);
        free(target_rel_paths);
        free(target_results);
        free(touched);
        return preprocess_fail(ctx, "CBM_PREPROCESS_TARGET_ALLOC_FAILED",
                               "allocate_projection_index", ctx->repo_path, (size_t)source_count,
                               "the compiler-preprocess target index could not be allocated",
                               "free memory or reduce concurrent repository workload, then retry");
    }

    cbm_sha256_ctx expansion_set_hash;
    cbm_sha256_init(&expansion_set_hash);
    uint64_t expanded_bytes_total = 0;
    uint64_t compiler_stdout_bytes_total = 0;
    uint64_t mapped_lines_total = 0;
    uint64_t workspace_local_compiler_markers_total = 0;
    uint64_t working_directory_markers_total = 0;
    uint64_t target_projections = 0;
    size_t peak_expansion_bytes = 0;
    size_t peak_compiler_stdout_bytes = 0;
    int status = 0;
    for (int context_index = 0; context_index < index->context_count && status == 0;
         context_index++) {
        if (cbm_pipeline_check_cancel(ctx)) {
            status = preprocess_fail(
                ctx, "CBM_PREPROCESS_CANCELLED", "spawn_exact_compiler_preprocessor",
                ctx->repo_path, (size_t)context_index,
                "the indexing request was cancelled before all translation units were expanded",
                "retry the complete unchanged corpus when the request can run to completion");
            break;
        }
        const compile_context_owner_t *owner = &index->contexts[context_index];
        if (validate_compiler_snapshot_path_budget(ctx, owner, index, source_files, source_count,
                                                   result_cache) != 0) {
            status = CBM_NOT_FOUND;
            break;
        }
        for (int i = 0; i < source_count; i++) {
            target_by_source_index[i] = PREPROCESS_TARGET_NONE;
        }
        size_t target_count = 0;
        for (int set_index = 0; set_index < index->set_count; set_index++) {
            const compile_context_set_owner_t *set = &index->sets[set_index];
            if (!context_dependency_contains(owner, set->rel_path)) {
                continue;
            }
            if (set->source_index < 0 || set->source_index >= source_count) {
                status = preprocess_fail(
                    ctx, "CBM_PREPROCESS_TARGET_INDEX_INVALID", "prepare_projection_targets",
                    set->rel_path, (size_t)(set->source_index < 0 ? 0 : set->source_index),
                    "a compiler dependency has no bounded immutable source index",
                    "preserve the generation and repair compilation-context materialization");
                break;
            }
            if (source_files[set->source_index].size == 0) {
                target_by_source_index[set->source_index] = PREPROCESS_TARGET_IGNORED;
                continue;
            }
            CBMFileResult *result = result_cache[set->source_index];
            if (!result || result->has_error || !result->module_qn || !result->module_qn[0]) {
                status = preprocess_fail(
                    ctx, "CBM_PREPROCESS_TARGET_RESULT_INVALID", "prepare_projection_targets",
                    set->rel_path, (size_t)set->source_index,
                    "a non-empty compiler dependency has no complete extracted source result",
                    "inspect parallel extraction and repair the exact result-cache handoff");
                break;
            }
            if (target_count >= (size_t)UINT32_MAX) {
                status = preprocess_fail(
                    ctx, "CBM_PREPROCESS_TARGET_CAPACITY_OVERFLOW", "prepare_projection_targets",
                    owner->tu_rel_path, target_count,
                    "one translation unit has too many repository projection targets",
                    "split the translation unit or extend the source-map representation");
                break;
            }
            target_by_source_index[set->source_index] = (uint32_t)target_count;
            target_rel_paths[target_count] = set->rel_path;
            target_results[target_count] = result;
            touched[set->source_index] = true;
            target_count++;
        }
        if (status != 0) {
            break;
        }
        if (target_count == 0) {
            status = preprocess_fail(
                ctx, "CBM_PREPROCESS_TARGETS_EMPTY", "prepare_projection_targets",
                owner->tu_rel_path, 0,
                "a captured non-empty translation unit has no repository extraction target",
                "repair discovery/context dependency alignment and retry the complete corpus");
            break;
        }

        char **argv = NULL;
        int argc = 0;
        char *working_directory = NULL;
        if (build_preprocess_argv(ctx, owner, &argv, &argc, &working_directory) != 0) {
            status = preprocess_fail(
                ctx, "CBM_PREPROCESS_ARGV_BUILD_FAILED", "build_exact_compiler_argv",
                owner->tu_rel_path, (size_t)owner->preprocess_argument_count,
                "the exact compiler argument vector could not be projected to the immutable "
                "snapshot",
                "preserve the manifest and repair path/action argument classification");
            break;
        }
        char *output = NULL;
        size_t output_bytes = 0;
        cbm_spawn_error_t spawn_error = {0};
        cbm_spawn_bounded_capture_t stderr_capture = {0};
        int spawn_status = cbm_spawn_capture_with_stderr_cwd_source_epoch(
            (const char *const *)argv, working_directory, index->source_date_epoch, &output,
            &output_bytes, PREPROCESS_STDERR_LIMIT, &stderr_capture, &spawn_error);
        if (spawn_status != 0) {
            status = compiler_spawn_fail(ctx, owner, &spawn_error, &stderr_capture, output,
                                         output_bytes, argv, argc, working_directory);
            free(output);
            free(stderr_capture.data);
            free_preprocess_argv(argv, argc);
            free(working_directory);
            break;
        }
        size_t compiler_stdout_bytes = output_bytes;
        uint64_t stderr_total_bytes = stderr_capture.total_len;
        bool stderr_truncated = stderr_capture.truncated;
        free(stderr_capture.data);

        compiler_expansion_t expansion = {0};
        status = map_compiler_expansion(ctx, index, owner, working_directory,
                                        target_by_source_index, output, output_bytes, &expansion);
        if (status == 0) {
            char expansion_hash[CBM_SHA256_HEX_LEN + 1];
            char bytes_text[32];
            char stdout_bytes_text[32];
            char targets_text[32];
            char stderr_text[32];
            char workspace_local_compiler_markers_text[32];
            char working_directory_markers_text[32];
            sha256_hex(expansion.text, expansion.text_bytes, expansion_hash);
            snprintf(bytes_text, sizeof(bytes_text), "%zu", expansion.text_bytes);
            snprintf(stdout_bytes_text, sizeof(stdout_bytes_text), "%zu", compiler_stdout_bytes);
            snprintf(targets_text, sizeof(targets_text), "%zu", target_count);
            snprintf(stderr_text, sizeof(stderr_text), "%llu",
                     (unsigned long long)stderr_total_bytes);
            snprintf(workspace_local_compiler_markers_text,
                     sizeof(workspace_local_compiler_markers_text), "%zu",
                     expansion.workspace_local_compiler_markers);
            snprintf(working_directory_markers_text, sizeof(working_directory_markers_text), "%zu",
                     expansion.working_directory_markers);
            cbm_sha256_update(&expansion_set_hash, owner->view.context_id,
                              strlen(owner->view.context_id));
            cbm_sha256_update(&expansion_set_hash, "\0", 1);
            cbm_sha256_update(&expansion_set_hash, expansion.text, expansion.text_bytes);
            cbm_log_info("compiler_preprocess.context", "translation_unit", owner->tu_rel_path,
                         "context_id", owner->view.context_id, "compiler_stdout_bytes",
                         stdout_bytes_text, "expanded_bytes", bytes_text, "expanded_sha256",
                         expansion_hash, "projection_targets", targets_text, "stderr_total_bytes",
                         stderr_text, "stderr_truncated", stderr_truncated ? "true" : "false",
                         "canonicalization", "validated_linemarkers_to_empty_lines",
                         "workspace_local_compiler_markers", workspace_local_compiler_markers_text,
                         "working_directory_markers", working_directory_markers_text,
                         "source_date_epoch", index->source_date_epoch,
                         "source_date_epoch_provenance", "git_head_commit",
                         "source_date_epoch_revision", index->source_date_epoch_revision,
                         "timestamp_macro_input", "immutable_snapshot_last_write_time");
            char *diagnostic = NULL;
            status = cbm_extract_preprocessed_translation_unit(
                expansion.text, expansion.text_bytes, owner->view.cpp_mode, owner->view.context_id,
                expansion.line_targets, expansion.line_source_lines, expansion.line_count,
                ctx->project_name, target_rel_paths, target_results, target_count, &diagnostic);
            if (status != 0) {
                status = preprocess_fail(
                    ctx, "CBM_PREPROCESS_PROJECTION_FAILED", "extract_compiler_expansion",
                    owner->tu_rel_path, expansion.text_bytes,
                    diagnostic ? diagnostic : "the exact compiler expansion could not be projected",
                    "preserve the mapped expansion diagnostic, repair the cause, and retry");
            }
            free(diagnostic);
            if (status == 0) {
                expanded_bytes_total += expansion.text_bytes;
                compiler_stdout_bytes_total += compiler_stdout_bytes;
                mapped_lines_total += expansion.mapped_lines;
                workspace_local_compiler_markers_total +=
                    expansion.workspace_local_compiler_markers;
                working_directory_markers_total += expansion.working_directory_markers;
                target_projections += target_count;
                if (expansion.text_bytes > peak_expansion_bytes) {
                    peak_expansion_bytes = expansion.text_bytes;
                }
                if (compiler_stdout_bytes > peak_compiler_stdout_bytes) {
                    peak_compiler_stdout_bytes = compiler_stdout_bytes;
                }
            }
        }
        compiler_expansion_destroy(&expansion);
        free_preprocess_argv(argv, argc);
        free(working_directory);
    }

    if (status == 0) {
        for (int source_index = 0; source_index < source_count; source_index++) {
            if (!touched[source_index]) {
                continue;
            }
            CBMFileResult *result = result_cache[source_index];
            cbm_finalize_compiler_context_calls(result);
            if (!result || result->has_error || !cbm_file_result_compact_arrays(result)) {
                status = preprocess_fail(
                    ctx, "CBM_PREPROCESS_RESULT_FINALIZE_FAILED", "finalize_contextual_calls",
                    source_files[source_index].rel_path, (size_t)source_index,
                    "compiler-derived call facts could not be finalized into exact retained arrays",
                    "inspect the file-result diagnostic, free memory, and retry the complete "
                    "corpus");
                break;
            }
        }
    }
    if (status == 0) {
        uint8_t digest[CBM_SHA256_DIGEST_LEN];
        char set_hash[CBM_SHA256_HEX_LEN + 1];
        char contexts_text[32];
        char projections_text[32];
        char total_bytes_text[32];
        char total_stdout_bytes_text[32];
        char mapped_text[32];
        char workspace_local_compiler_markers_text[32];
        char working_directory_markers_text[32];
        char peak_text[32];
        char peak_stdout_text[32];
        cbm_sha256_final(&expansion_set_hash, digest);
        for (int i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
            snprintf(set_hash + i * 2, 3, "%02x", digest[i]);
        }
        set_hash[CBM_SHA256_HEX_LEN] = '\0';
        snprintf(contexts_text, sizeof(contexts_text), "%d", index->context_count);
        snprintf(projections_text, sizeof(projections_text), "%llu",
                 (unsigned long long)target_projections);
        snprintf(total_bytes_text, sizeof(total_bytes_text), "%llu",
                 (unsigned long long)expanded_bytes_total);
        snprintf(total_stdout_bytes_text, sizeof(total_stdout_bytes_text), "%llu",
                 (unsigned long long)compiler_stdout_bytes_total);
        snprintf(mapped_text, sizeof(mapped_text), "%llu", (unsigned long long)mapped_lines_total);
        snprintf(workspace_local_compiler_markers_text,
                 sizeof(workspace_local_compiler_markers_text), "%llu",
                 (unsigned long long)workspace_local_compiler_markers_total);
        snprintf(working_directory_markers_text, sizeof(working_directory_markers_text), "%llu",
                 (unsigned long long)working_directory_markers_total);
        snprintf(peak_text, sizeof(peak_text), "%zu", peak_expansion_bytes);
        snprintf(peak_stdout_text, sizeof(peak_stdout_text), "%zu", peak_compiler_stdout_bytes);
        cbm_log_info(
            "compiler_preprocess.ready", "compiler_invocations", contexts_text, "syntax_trees",
            contexts_text, "target_projections", projections_text, "expanded_bytes",
            total_bytes_text, "compiler_stdout_bytes", total_stdout_bytes_text, "mapped_lines",
            mapped_text, "workspace_local_compiler_markers", workspace_local_compiler_markers_text,
            "working_directory_markers", working_directory_markers_text, "peak_expansion_bytes",
            peak_text, "peak_compiler_stdout_bytes", peak_stdout_text, "expansion_set_sha256",
            set_hash, "cache", "one_compiler_expansion_per_context", "canonicalization",
            "validated_linemarkers_to_empty_lines", "date_time_macros", "git_source_date_epoch",
            "timestamp_macro_input", "immutable_snapshot_last_write_time", "source_date_epoch",
            index->source_date_epoch, "source_date_epoch_revision",
            index->source_date_epoch_revision, "fallback", "none");
    }
    free(target_by_source_index);
    free(target_rel_paths);
    free(target_results);
    free(touched);
    return status;
#endif
}

int cbm_compile_context_target_visible(const cbm_compile_context_index_t *index,
                                       const char *context_id, const char *target_rel_path) {
    const compile_context_owner_t *context = find_context_by_id(index, context_id);
    if (!context) {
        return CBM_NOT_FOUND;
    }
    return context_dependency_contains(context, target_rel_path) ? SKIP_ONE : 0;
}

static size_t normalize_context_qn(char *out, size_t capacity, const char *value) {
    size_t written = 0;
    if (!out || capacity == 0 || !value) {
        return 0;
    }
    for (const char *at = value; *at && written + 1 < capacity;) {
        if (at[0] == ':' && at[1] == ':') {
            out[written++] = '.';
            at += 2;
        } else {
            out[written++] = *at++;
        }
    }
    out[written] = '\0';
    return written;
}

static bool context_qn_has_tail(const char *qualified_name, const char *tail) {
    size_t qn_len = qualified_name ? strlen(qualified_name) : 0;
    size_t tail_len = tail ? strlen(tail) : 0;
    if (tail_len == 0 || qn_len < tail_len) {
        return false;
    }
    const char *start = qualified_name + qn_len - tail_len;
    return strcmp(start, tail) == 0 && (start == qualified_name || start[-1] == '.');
}

static cbm_resolution_t select_visible_context_target(
    const cbm_compile_context_index_t *index, const cbm_registry_t *registry,
    const cbm_gbuf_t *gbuf, const char *context_id, const char *reference_name,
    const char *required_tail, const char *strategy) {
    cbm_resolution_t result = {0};
    const char *leaf = cbm_pipeline_call_callee_leaf(reference_name);
    const char **candidates = NULL;
    int candidate_count = 0;
    if (!leaf || !leaf[0] ||
        cbm_registry_find_by_name(registry, leaf, &candidates, &candidate_count) != 0) {
        result.strategy = "compiler_scope_target_missing";
        return result;
    }
    const char *match = NULL;
    int matches = 0;
    for (int i = 0; i < candidate_count; i++) {
        const char *candidate = candidates[i];
        if (required_tail && !context_qn_has_tail(candidate, required_tail)) {
            continue;
        }
        const cbm_gbuf_node_t *node = cbm_gbuf_find_by_qn_domain(
            gbuf, candidate, CBM_REF_DOMAIN_CALLABLE, "compile_context.call_target");
        if (!node || !node->file_path ||
            cbm_compile_context_target_visible(index, context_id, node->file_path) != SKIP_ONE) {
            continue;
        }
        match = node->qualified_name;
        matches++;
        if (matches > SKIP_ONE) {
            break;
        }
    }
    result.candidate_count = matches;
    if (matches == SKIP_ONE) {
        result.qualified_name = match;
        result.strategy = strategy;
        result.confidence = required_tail ? 0.99 : 0.98;
    } else if (matches > SKIP_ONE) {
        result.strategy = "ambiguous_compiler_scope";
    } else {
        result.strategy = "compiler_scope_target_missing";
    }
    return result;
}

cbm_resolution_t cbm_compile_context_resolve_call(
    const cbm_compile_context_index_t *index, const cbm_registry_t *registry,
    const cbm_gbuf_t *gbuf, const char *context_id, const char *reference_name,
    const char *preferred_qn, const char *focus_module_qn, bool qualified_reference) {
    cbm_resolution_t missing = {0};
    if (!find_context_by_id(index, context_id)) {
        missing.strategy = "compiler_context_missing";
        return missing;
    }

    char normalized[CBM_SZ_512];
    if (preferred_qn && preferred_qn[0]) {
        size_t preferred_len = normalize_context_qn(normalized, sizeof(normalized), preferred_qn);
        const char *tail = normalized;
        size_t module_len = focus_module_qn ? strlen(focus_module_qn) : 0;
        if (module_len > 0 && preferred_len > module_len &&
            strncmp(normalized, focus_module_qn, module_len) == 0 &&
            normalized[module_len] == '.') {
            tail = normalized + module_len + 1;
        }
        cbm_resolution_t typed = select_visible_context_target(
            index, registry, gbuf, context_id, reference_name, tail, "compiler_scope_lsp");
        if (typed.qualified_name ||
            (typed.strategy && strcmp(typed.strategy, "ambiguous_compiler_scope") == 0)) {
            return typed;
        }
    }

    if (qualified_reference) {
        normalize_context_qn(normalized, sizeof(normalized), reference_name);
        cbm_resolution_t qualified = select_visible_context_target(
            index, registry, gbuf, context_id, reference_name, normalized,
            "compiler_scope_qualified");
        if (qualified.qualified_name ||
            (qualified.strategy && strcmp(qualified.strategy, "ambiguous_compiler_scope") == 0)) {
            return qualified;
        }
    }

    return select_visible_context_target(index, registry, gbuf, context_id, reference_name, NULL,
                                         "compiler_scope");
}

void cbm_compile_context_index_free(cbm_compile_context_index_t *index) {
    if (!index) {
        return;
    }
    cbm_ht_free(index->contexts_by_id);
    cbm_ht_free(index->sets_by_rel_path);
    free(index->source_date_epoch);
    free(index->source_date_epoch_revision);
    free(index->source_date_epoch_repository_root);
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
        free_string_array(context->preprocess_arguments,
                          context->preprocess_argument_count);
        free_string_array(context->owned_include_paths, context->owned_include_count);
        free_string_array(context->owned_undefines, context->owned_undefine_count);
        free_string_array(context->owned_forced_includes, context->owned_forced_include_count);
        free_string_array(context->compiler_system_roots,
                          context->compiler_system_root_count);
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
