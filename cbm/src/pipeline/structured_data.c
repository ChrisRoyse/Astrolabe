#include "pipeline/structured_data.h"

#include "astro_spawn.h"
#include "foundation/constants.h"
#include "foundation/log.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    STRUCT_ATTR_SEEN_ASTROLABE = 1,
    STRUCT_ATTR_SEEN_GENERATED = 2,
    STRUCT_ATTR_SEEN_DETECTABLE = 4,
    /* CreateProcessW is limited to 32,767 UTF-16 command-line characters.
     * Counting every UTF-8 path byte twice plus quoting beneath 30,000 leaves
     * deterministic room for the fixed git/check-attr arguments. */
    STRUCT_ATTR_COMMAND_UNITS = 30000,
    STRUCT_ATTR_FIXED_ARGC = 10,
};

static int structured_fail(const char *code, const char *operation, const char *path,
                           const char *message, const char *remediation) {
    cbm_log_error("structured_data.classification_failed", "code", code, "operation", operation,
                  "path", path ? path : "", "message", message, "remediation", remediation);
    return CBM_NOT_FOUND;
}

static bool is_json_source(const cbm_file_info_t *file) {
    return file && !file->auxiliary && file->language == CBM_LANG_JSON && file->rel_path;
}

static bool is_attributes_input(const cbm_file_info_t *file) {
    if (!file || !file->interpretation_input || !file->rel_path) {
        return false;
    }
    const char *basename = strrchr(file->rel_path, '/');
    basename = basename ? basename + SKIP_ONE : file->rel_path;
    return strcmp(basename, ".gitattributes") == 0;
}

static int find_file(const cbm_file_info_t *files, int file_count, const char *rel_path) {
    for (int i = 0; i < file_count; i++) {
        if (files[i].rel_path && strcmp(files[i].rel_path, rel_path) == 0) {
            return i;
        }
    }
    return CBM_NOT_FOUND;
}

static bool attr_value_is(const char *value, const char *left, const char *right) {
    return strcmp(value, left) == 0 || strcmp(value, right) == 0;
}

static bool set_classification(cbm_file_info_t *file, uint8_t rank, const char *classification,
                               const char *attribute, const char *value) {
    if (rank < file->structured_classification_rank) {
        return true;
    }
    int class_len = snprintf(file->structured_classification,
                             sizeof(file->structured_classification), "%s", classification);
    int provenance_len = snprintf(file->structured_classification_provenance,
                                  sizeof(file->structured_classification_provenance),
                                  "repository:.gitattributes:%s=%s", attribute, value);
    if (class_len <= 0 || (size_t)class_len >= sizeof(file->structured_classification) ||
        provenance_len <= 0 ||
        (size_t)provenance_len >= sizeof(file->structured_classification_provenance)) {
        return false;
    }
    file->structured_classification_rank = rank;
    return true;
}

static int consume_attribute(cbm_file_info_t *file, const char *attribute, const char *value) {
    if (strcmp(attribute, "astrolabe-structured") == 0) {
        if (strcmp(value, "unspecified") == 0 || strcmp(value, "unset") == 0) {
            return 0;
        }
        if (strcmp(value, "code") != 0 && strcmp(value, "config") != 0 &&
            strcmp(value, "data") != 0 && strcmp(value, "generated") != 0) {
            return structured_fail(
                "CBM_STRUCTURED_ATTRIBUTE_VALUE_INVALID", "parse_astrolabe_structured",
                file->rel_path, "astrolabe-structured has an unsupported value",
                "set it to code, config, data, or generated and retry");
        }
        return set_classification(file, 3, value, attribute, value)
                   ? 0
                   : structured_fail("CBM_STRUCTURED_ATTRIBUTE_BUFFER_EXCEEDED",
                                     "persist_astrolabe_structured", file->rel_path,
                                     "the exact repository attribute exceeded its metadata buffer",
                                     "shorten the attribute value and retry");
    }
    if (strcmp(attribute, "linguist-generated") == 0) {
        if (!attr_value_is(value, "set", "true")) {
            return 0;
        }
        return set_classification(file, 2, "generated", attribute, value)
                   ? 0
                   : structured_fail("CBM_STRUCTURED_ATTRIBUTE_BUFFER_EXCEEDED",
                                     "persist_linguist_generated", file->rel_path,
                                     "the exact repository attribute exceeded its metadata buffer",
                                     "shorten the attribute value and retry");
    }
    if (strcmp(attribute, "linguist-detectable") == 0) {
        if (!attr_value_is(value, "unset", "false")) {
            return 0;
        }
        return set_classification(file, 1, "data", attribute, value)
                   ? 0
                   : structured_fail("CBM_STRUCTURED_ATTRIBUTE_BUFFER_EXCEEDED",
                                     "persist_linguist_detectable", file->rel_path,
                                     "the exact repository attribute exceeded its metadata buffer",
                                     "shorten the attribute value and retry");
    }
    return structured_fail("CBM_STRUCTURED_ATTRIBUTE_NAME_UNEXPECTED", "parse_check_attr",
                           file->rel_path, "git returned an undeclared classification attribute",
                           "inspect the exact git check-attr output and retry");
}

static char *next_nul_field(char *data, size_t len, size_t *position) {
    if (*position >= len) {
        return NULL;
    }
    char *field = data + *position;
    void *terminator = memchr(field, '\0', len - *position);
    if (!terminator) {
        return NULL;
    }
    *position = (size_t)((char *)terminator - data) + SKIP_ONE;
    return field;
}

static int classify_batch(const char *repo_path, const char *snapshot_root, cbm_file_info_t *files,
                          int file_count, int *indices, int index_count, uint8_t *seen) {
    char worktree_arg[CBM_SZ_8K];
    int worktree_len = snprintf(worktree_arg, sizeof(worktree_arg), "--work-tree=%s", snapshot_root);
    if (worktree_len <= 0 || (size_t)worktree_len >= sizeof(worktree_arg)) {
        return structured_fail("CBM_STRUCTURED_WORKTREE_PATH_EXCEEDED", "build_check_attr_argv",
                               snapshot_root, "the immutable snapshot path cannot fit git argv",
                               "shorten the workspace path and retry");
    }
    size_t argv_count = (size_t)STRUCT_ATTR_FIXED_ARGC + (size_t)index_count + SKIP_ONE;
    const char **argv = calloc(argv_count, sizeof(*argv));
    if (!argv) {
        return structured_fail("CBM_STRUCTURED_ATTRIBUTE_ARGV_ALLOC_FAILED", "allocate_check_attr_argv",
                               snapshot_root, "git attribute argv allocation failed",
                               "free memory and retry");
    }
    int at = 0;
    argv[at++] = "git";
    argv[at++] = "-C";
    argv[at++] = repo_path;
    argv[at++] = worktree_arg;
    argv[at++] = "check-attr";
    argv[at++] = "-z";
    argv[at++] = "astrolabe-structured";
    argv[at++] = "linguist-generated";
    argv[at++] = "linguist-detectable";
    argv[at++] = "--";
    for (int i = 0; i < index_count; i++) {
        argv[at++] = files[indices[i]].rel_path;
    }
    argv[at] = NULL;

    char *output = NULL;
    size_t output_len = 0;
    cbm_spawn_error_t error = {0};
    int spawn_rc = cbm_spawn_capture(argv, &output, &output_len, &error);
    free(argv);
    if (spawn_rc != 0) {
        char native[CBM_SZ_64];
        snprintf(native, sizeof(native), "spawn_code=%d,exit=%d,os_error=%lu", spawn_rc,
                 error.exit_code, error.os_error);
        free(output);
        return structured_fail("CBM_STRUCTURED_ATTRIBUTE_QUERY_FAILED", "git_check_attr",
                               snapshot_root, native,
                               "restore the Git repository and captured .gitattributes, then retry");
    }

    size_t position = 0;
    while (position < output_len) {
        char *path = next_nul_field(output, output_len, &position);
        char *attribute = next_nul_field(output, output_len, &position);
        char *value = next_nul_field(output, output_len, &position);
        if (!path || !attribute || !value) {
            free(output);
            return structured_fail("CBM_STRUCTURED_ATTRIBUTE_OUTPUT_TRUNCATED", "parse_check_attr",
                                   snapshot_root, "git check-attr returned a partial NUL record",
                                   "inspect Git output integrity and retry");
        }
        int file_index = find_file(files, file_count, path);
        if (file_index < 0 || !is_json_source(&files[file_index])) {
            free(output);
            return structured_fail("CBM_STRUCTURED_ATTRIBUTE_PATH_UNKNOWN", "parse_check_attr", path,
                                   "git returned an unrequested structured-data path",
                                   "inspect snapshot path normalization and retry");
        }
        uint8_t bit = 0;
        if (strcmp(attribute, "astrolabe-structured") == 0) {
            bit = STRUCT_ATTR_SEEN_ASTROLABE;
        } else if (strcmp(attribute, "linguist-generated") == 0) {
            bit = STRUCT_ATTR_SEEN_GENERATED;
        } else if (strcmp(attribute, "linguist-detectable") == 0) {
            bit = STRUCT_ATTR_SEEN_DETECTABLE;
        }
        if (bit == 0 || (seen[file_index] & bit) != 0) {
            free(output);
            return structured_fail("CBM_STRUCTURED_ATTRIBUTE_OUTPUT_DUPLICATE", "parse_check_attr",
                                   path, "git returned a duplicate or unknown attribute record",
                                   "inspect the exact check-attr protocol output and retry");
        }
        seen[file_index] |= bit;
        if (consume_attribute(&files[file_index], attribute, value) != 0) {
            free(output);
            return CBM_NOT_FOUND;
        }
    }
    free(output);
    return 0;
}

int cbm_structured_classify_files(const char *repo_path, const char *snapshot_root,
                                  cbm_file_info_t *files, int file_count) {
    if (!repo_path || !snapshot_root || !files || file_count < 0) {
        return structured_fail("CBM_STRUCTURED_CLASSIFICATION_INPUT_INVALID", "classify_files",
                               snapshot_root, "structured-data classification input is invalid",
                               "supply the exact repository, snapshot, and discovered files");
    }
    int json_count = 0;
    int attributes_count = 0;
    for (int i = 0; i < file_count; i++) {
        json_count += is_json_source(&files[i]) ? SKIP_ONE : 0;
        attributes_count += is_attributes_input(&files[i]) ? SKIP_ONE : 0;
    }
    if (json_count == 0 || attributes_count == 0) {
        return 0;
    }

    int *batch = malloc((size_t)json_count * sizeof(*batch));
    uint8_t *seen = calloc((size_t)file_count, sizeof(*seen));
    if (!batch || !seen) {
        free(batch);
        free(seen);
        return structured_fail("CBM_STRUCTURED_CLASSIFICATION_ALLOC_FAILED", "allocate_batches",
                               snapshot_root, "structured-data classification state allocation failed",
                               "free memory and retry");
    }

    size_t repo_len = strlen(repo_path);
    size_t snapshot_len = strlen(snapshot_root);
    if (repo_len > (SIZE_MAX - snapshot_len - CBM_SZ_512) / PAIR_LEN) {
        free(batch);
        free(seen);
        return structured_fail("CBM_STRUCTURED_ATTRIBUTE_BASE_ARGV_OVERFLOW",
                               "size_check_attr_argv", snapshot_root,
                               "the repository and snapshot paths exceed the argv size domain",
                               "shorten the workspace paths and retry");
    }
    size_t fixed_units = (repo_len + snapshot_len) * PAIR_LEN + CBM_SZ_512;
    if (fixed_units >= STRUCT_ATTR_COMMAND_UNITS) {
        free(batch);
        free(seen);
        return structured_fail("CBM_STRUCTURED_ATTRIBUTE_BASE_ARGV_EXCEEDED",
                               "size_check_attr_argv", snapshot_root,
                               "the repository and snapshot paths cannot fit the native Git command",
                               "shorten the workspace paths and retry");
    }
    int batch_count = 0;
    size_t command_units = fixed_units;
    int classified = 0;
    int rc = 0;
    for (int i = 0; i <= file_count; i++) {
        bool at_end = i == file_count;
        if (!at_end && !is_json_source(&files[i])) {
            continue;
        }
        size_t units = 0;
        if (!at_end) {
            size_t path_len = strlen(files[i].rel_path);
            if (path_len > (SIZE_MAX - 3) / PAIR_LEN) {
                rc = structured_fail("CBM_STRUCTURED_ATTRIBUTE_PATH_OVERFLOW",
                                     "size_check_attr_argv", files[i].rel_path,
                                     "a structured-data path exceeds the argv size domain",
                                     "shorten the repository-relative path and retry");
                break;
            }
            units = path_len * PAIR_LEN + 3;
            if (units >= STRUCT_ATTR_COMMAND_UNITS) {
                rc = structured_fail("CBM_STRUCTURED_ATTRIBUTE_PATH_EXCEEDED",
                                     "size_check_attr_argv", files[i].rel_path,
                                     "one structured-data path cannot fit the native Git command",
                                     "shorten the repository-relative path and retry");
                break;
            }
        }
        if ((at_end || command_units + units >= STRUCT_ATTR_COMMAND_UNITS) && batch_count > 0) {
            rc = classify_batch(repo_path, snapshot_root, files, file_count, batch, batch_count, seen);
            if (rc != 0) {
                break;
            }
            classified += batch_count;
            batch_count = 0;
            command_units = fixed_units;
        }
        if (!at_end) {
            batch[batch_count++] = i;
            command_units += units;
        }
    }

    if (rc == 0 && classified != json_count) {
        rc = structured_fail("CBM_STRUCTURED_ATTRIBUTE_COVERAGE_INCOMPLETE", "verify_check_attr",
                             snapshot_root, "not every JSON source received an attribute result",
                             "inspect Git attribute batching and retry");
    }
    if (rc == 0) {
        const uint8_t expected = STRUCT_ATTR_SEEN_ASTROLABE | STRUCT_ATTR_SEEN_GENERATED |
                                 STRUCT_ATTR_SEEN_DETECTABLE;
        for (int i = 0; i < file_count; i++) {
            if (is_json_source(&files[i]) && seen[i] != expected) {
                rc = structured_fail("CBM_STRUCTURED_ATTRIBUTE_COVERAGE_INCOMPLETE",
                                     "verify_check_attr", files[i].rel_path,
                                     "one JSON source lacks a complete attribute result",
                                     "inspect Git check-attr output and retry");
                break;
            }
        }
    }
    free(batch);
    free(seen);
    return rc;
}
