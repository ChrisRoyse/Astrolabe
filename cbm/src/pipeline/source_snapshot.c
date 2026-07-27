#include "pipeline/source_snapshot.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/sha256.h"
#include "foundation/hash_table.h"
#include "foundation/win_utf8.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

enum { SNAPSHOT_DIR_PERMS = 0755 };

typedef struct {
    FILE_ID_INFO id;
    FILE_BASIC_INFO basic;
    FILE_STANDARD_INFO standard;
} snapshot_identity_t;

static void snapshot_log_failure(const char *code, const char *operation, const char *path,
                                 unsigned long native_error) {
    char error_buf[32];
    snprintf(error_buf, sizeof(error_buf), "%lu", native_error);
    cbm_log_error("source_snapshot.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "native_error", error_buf, "message",
                  "the immutable source snapshot could not be completed", "remediation",
                  "stabilize source access, free workspace disk space, and retry indexing");
}

static char *snapshot_join(const char *left, const char *right) {
    if (!left || !right) {
        return NULL;
    }
    size_t a = strlen(left);
    size_t b = strlen(right);
    bool sep = a > 0 && left[a - 1] != '/' && left[a - 1] != '\\';
    if (a > SIZE_MAX - b - (sep ? 2u : 1u)) {
        return NULL;
    }
    size_t n = a + b + (sep ? 1u : 0u);
    char *out = malloc(n + 1u);
    if (!out) {
        return NULL;
    }
    memcpy(out, left, a);
    size_t pos = a;
    if (sep) {
        out[pos++] = '/';
    }
    memcpy(out + pos, right, b);
    out[n] = '\0';
    return out;
}

static bool snapshot_get_identity(HANDLE handle, snapshot_identity_t *identity) {
    return GetFileInformationByHandleEx(handle, FileIdInfo, &identity->id, sizeof(identity->id)) &&
           GetFileInformationByHandleEx(handle, FileBasicInfo, &identity->basic,
                                        sizeof(identity->basic)) &&
           GetFileInformationByHandleEx(handle, FileStandardInfo, &identity->standard,
                                        sizeof(identity->standard));
}

static bool snapshot_identity_equal(const snapshot_identity_t *a, const snapshot_identity_t *b) {
    return a->id.VolumeSerialNumber == b->id.VolumeSerialNumber &&
           memcmp(a->id.FileId.Identifier, b->id.FileId.Identifier,
                  sizeof(a->id.FileId.Identifier)) == 0 &&
           a->standard.EndOfFile.QuadPart == b->standard.EndOfFile.QuadPart &&
           a->basic.LastWriteTime.QuadPart == b->basic.LastWriteTime.QuadPart &&
           a->basic.ChangeTime.QuadPart == b->basic.ChangeTime.QuadPart && !a->standard.Directory &&
           !b->standard.Directory && !a->standard.DeletePending && !b->standard.DeletePending;
}

static void digest_to_hex(const uint8_t digest[CBM_SHA256_DIGEST_LEN],
                          char out[CBM_SHA256_HEX_LEN + 1]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 15];
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
}

static int64_t filetime_to_unix_ns(LONGLONG ticks);

static bool hash_handle(HANDLE handle, uint8_t digest[CBM_SHA256_DIGEST_LEN], uint64_t *byte_count,
                        DWORD *native_error) {
    LARGE_INTEGER zero = {.QuadPart = 0};
    if (!SetFilePointerEx(handle, zero, NULL, FILE_BEGIN)) {
        *native_error = GetLastError();
        return false;
    }
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    uint8_t buffer[CBM_SZ_64K];
    uint64_t total = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(handle, buffer, sizeof(buffer), &got, NULL)) {
            *native_error = GetLastError();
            return false;
        }
        if (got == 0) {
            break;
        }
        if (UINT64_MAX - total < got) {
            *native_error = ERROR_ARITHMETIC_OVERFLOW;
            return false;
        }
        total += got;
        cbm_sha256_update(&hash, buffer, got);
    }
    cbm_sha256_final(&hash, digest);
    *byte_count = total;
    return true;
}

typedef enum {
    SNAPSHOT_LIVE_MATCH = 0,
    SNAPSHOT_LIVE_CHANGED = 1,
    SNAPSHOT_LIVE_ERROR = 2,
} snapshot_live_match_t;

static bool snapshot_is_lower_sha256(const char *value) {
    if (!value || strlen(value) != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static snapshot_live_match_t snapshot_hash_live_match(const cbm_file_info_t *file,
                                                      const cbm_file_hash_t *expected,
                                                      cbm_file_info_t *verified) {
    wchar_t *wide_source = cbm_utf8_to_wide_path(file->path);
    if (!wide_source) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_PATH_ENCODING_FAILED", "widen_live_path",
                             file->path, GetLastError());
        return SNAPSHOT_LIVE_ERROR;
    }
    HANDLE source = CreateFileW(
        wide_source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide_source);
    if (source == INVALID_HANDLE_VALUE) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_OPEN_FAILED", "open_live_source", file->path,
                             GetLastError());
        return SNAPSHOT_LIVE_ERROR;
    }

    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    snapshot_identity_t before = {0};
    if (!GetFileInformationByHandleEx(source, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !snapshot_get_identity(source, &before)) {
        DWORD error = GetLastError();
        CloseHandle(source);
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_IDENTITY_FAILED", "inspect_live_source",
                             file->path, error ? error : ERROR_FILE_INVALID);
        return SNAPSHOT_LIVE_ERROR;
    }
    if (before.standard.EndOfFile.QuadPart < 0 ||
        before.standard.EndOfFile.QuadPart != file->size ||
        before.standard.EndOfFile.QuadPart != expected->size) {
        CloseHandle(source);
        return SNAPSHOT_LIVE_CHANGED;
    }

    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    uint64_t bytes = 0;
    DWORD error = ERROR_SUCCESS;
    bool hashed = hash_handle(source, digest, &bytes, &error);
    snapshot_identity_t after = {0};
    bool inspected_after = snapshot_get_identity(source, &after);
    if (!CloseHandle(source) && hashed && inspected_after) {
        error = GetLastError();
        hashed = false;
    }
    if (!hashed || !inspected_after) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_READ_FAILED", "hash_live_source", file->path,
                             error ? error : GetLastError());
        return SNAPSHOT_LIVE_ERROR;
    }
    if (!snapshot_identity_equal(&before, &after) ||
        bytes != (uint64_t)before.standard.EndOfFile.QuadPart) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_MUTATED", "verify_live_source_identity",
                             file->path, ERROR_FILE_INVALID);
        return SNAPSHOT_LIVE_ERROR;
    }

    char sha256[CBM_SHA256_HEX_LEN + 1];
    digest_to_hex(digest, sha256);
    if (strcmp(sha256, expected->sha256) != 0) {
        return SNAPSHOT_LIVE_CHANGED;
    }

    *verified = *file;
    verified->live_path = file->path;
    verified->size = (int64_t)bytes;
    verified->mtime_ns = filetime_to_unix_ns(before.basic.LastWriteTime.QuadPart);
    verified->source_volume_serial = before.id.VolumeSerialNumber;
    memcpy(verified->source_file_id, before.id.FileId.Identifier, sizeof(verified->source_file_id));
    verified->source_change_time_100ns = before.basic.ChangeTime.QuadPart;
    memcpy(verified->sha256, sha256, sizeof(verified->sha256));
    return SNAPSHOT_LIVE_MATCH;
}

static bool copy_and_hash(HANDLE source, HANDLE destination, uint8_t digest[CBM_SHA256_DIGEST_LEN],
                          uint64_t *byte_count, DWORD *native_error) {
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    uint8_t buffer[CBM_SZ_64K];
    uint64_t total = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(source, buffer, sizeof(buffer), &got, NULL)) {
            *native_error = GetLastError();
            return false;
        }
        if (got == 0) {
            break;
        }
        DWORD offset = 0;
        while (offset < got) {
            DWORD written = 0;
            if (!WriteFile(destination, buffer + offset, got - offset, &written, NULL) ||
                written == 0) {
                *native_error = GetLastError();
                return false;
            }
            offset += written;
        }
        if (UINT64_MAX - total < got) {
            *native_error = ERROR_ARITHMETIC_OVERFLOW;
            return false;
        }
        total += got;
        cbm_sha256_update(&hash, buffer, got);
    }
    cbm_sha256_final(&hash, digest);
    *byte_count = total;
    return true;
}

static int64_t filetime_to_unix_ns(LONGLONG ticks) {
    const LONGLONG epoch_delta = 116444736000000000LL;
    if (ticks < epoch_delta || ticks - epoch_delta > INT64_MAX / 100LL) {
        return 0;
    }
    return (int64_t)((ticks - epoch_delta) * 100LL);
}

static int snapshot_capture_one(const char *snapshot_root, cbm_file_info_t *file) {
    const char *source_path = file->path;
    char *destination_path = snapshot_join(snapshot_root, file->rel_path);
    if (!destination_path) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_ALLOC_FAILED", "build_destination",
                             file->rel_path, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }

    char *parent = strdup(destination_path);
    if (!parent) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_ALLOC_FAILED", "copy_parent_path",
                             file->rel_path, ERROR_NOT_ENOUGH_MEMORY);
        free(destination_path);
        return CBM_NOT_FOUND;
    }
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        if (!cbm_mkdir_p(parent, SNAPSHOT_DIR_PERMS)) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DIRECTORY_CREATE_FAILED", "create_parent",
                                 parent, (unsigned long)errno);
            free(parent);
            free(destination_path);
            return CBM_NOT_FOUND;
        }
    }
    free(parent);

    wchar_t *wide_source = cbm_utf8_to_wide_path(source_path);
    wchar_t *wide_destination = cbm_utf8_to_wide_path(destination_path);
    if (!wide_source || !wide_destination) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_ENCODING_FAILED", "widen_path", source_path,
                             GetLastError());
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    HANDLE source = CreateFileW(
        wide_source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (source == INVALID_HANDLE_VALUE) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_SOURCE_OPEN_FAILED", "open_source", source_path,
                             GetLastError());
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    snapshot_identity_t before = {0};
    if (!GetFileInformationByHandleEx(source, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !snapshot_get_identity(source, &before)) {
        DWORD error = GetLastError();
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_SOURCE_IDENTITY_FAILED", "inspect_source",
                             source_path, error);
        CloseHandle(source);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }
    if (before.standard.EndOfFile.QuadPart < 0 ||
        before.standard.EndOfFile.QuadPart != file->size) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DISCOVERY_DRIFT", "compare_discovered_size",
                             source_path, ERROR_FILE_INVALID);
        CloseHandle(source);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    HANDLE destination = CreateFileW(wide_destination, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                     CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (destination == INVALID_HANDLE_VALUE) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DESTINATION_CREATE_FAILED", "create_snapshot",
                             destination_path, GetLastError());
        CloseHandle(source);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    uint8_t captured_digest[CBM_SHA256_DIGEST_LEN];
    uint64_t captured_bytes = 0;
    DWORD error = ERROR_SUCCESS;
    /* The retained source handle was opened with FILE_SHARE_READ only. Windows
     * refuses that open when an existing writer/delete handle conflicts and
     * refuses every new writer/delete open until this handle closes. The
     * before/after FILE_ID + size + last-write/change-time comparison therefore
     * proves that the single copy-and-hash read observed one stable source
     * generation; replaying every source byte through the same protected handle
     * added no independent evidence.
     *
     * The destination is transaction-ephemeral and is consumed only after it is
     * closed and independently reopened, byte-counted, and SHA-256 verified
     * below. It is not a crash-durable publication, so forcing each file to
     * persistent media with FlushFileBuffers added thousands of synchronous disk
     * barriers without strengthening the readback or publication contract. */
    bool ok = copy_and_hash(source, destination, captured_digest, &captured_bytes, &error);
    if (!ok) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_COPY_FAILED", "copy_source", source_path,
                             error ? error : GetLastError());
        CloseHandle(destination);
        CloseHandle(source);
        DeleteFileW(wide_destination);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    snapshot_identity_t after = {0};
    if (!snapshot_get_identity(source, &after)) {
        error = GetLastError();
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_SOURCE_IDENTITY_FAILED",
                             "inspect_source_after_copy", source_path, error);
        CloseHandle(destination);
        CloseHandle(source);
        DeleteFileW(wide_destination);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }
    CloseHandle(destination);
    CloseHandle(source);

    if (!snapshot_identity_equal(&before, &after) ||
        captured_bytes != (uint64_t)before.standard.EndOfFile.QuadPart) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_SOURCE_MUTATED", "capture_identity", source_path,
                             error ? error : ERROR_FILE_INVALID);
        DeleteFileW(wide_destination);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    HANDLE readback =
        CreateFileW(wide_destination, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    uint8_t readback_digest[CBM_SHA256_DIGEST_LEN];
    uint64_t readback_bytes = 0;
    if (readback == INVALID_HANDLE_VALUE ||
        !hash_handle(readback, readback_digest, &readback_bytes, &error) ||
        readback_bytes != captured_bytes ||
        memcmp(readback_digest, captured_digest, sizeof(captured_digest)) != 0) {
        if (readback != INVALID_HANDLE_VALUE) {
            CloseHandle(readback);
        }
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_READBACK_MISMATCH", "readback_snapshot",
                             destination_path, error ? error : GetLastError());
        DeleteFileW(wide_destination);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }
    CloseHandle(readback);
    if (!SetFileAttributesW(wide_destination, FILE_ATTRIBUTE_READONLY)) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_IMMUTABILITY_FAILED", "set_readonly",
                             destination_path, GetLastError());
        DeleteFileW(wide_destination);
        free(wide_source);
        free(wide_destination);
        free(destination_path);
        return CBM_NOT_FOUND;
    }

    file->live_path = file->path;
    file->path = destination_path;
    file->size = (int64_t)captured_bytes;
    file->mtime_ns = filetime_to_unix_ns(before.basic.LastWriteTime.QuadPart);
    file->source_volume_serial = before.id.VolumeSerialNumber;
    memcpy(file->source_file_id, before.id.FileId.Identifier, sizeof(file->source_file_id));
    file->source_change_time_100ns = before.basic.ChangeTime.QuadPart;
    digest_to_hex(captured_digest, file->sha256);

    free(wide_source);
    free(wide_destination);
    return 0;
}

static int compare_rel_paths(const void *left, const void *right) {
    const cbm_file_info_t *const *a = left;
    const cbm_file_info_t *const *b = right;
    return strcmp((*a)->rel_path, (*b)->rel_path);
}

static bool snapshot_current_identity_matches(const cbm_file_info_t *file) {
    wchar_t *wide = cbm_utf8_to_wide_path(file->live_path);
    if (!wide) {
        return false;
    }
    HANDLE handle = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    snapshot_identity_t identity = {0};
    bool ok = snapshot_get_identity(handle, &identity) &&
              identity.id.VolumeSerialNumber == file->source_volume_serial &&
              memcmp(identity.id.FileId.Identifier, file->source_file_id,
                     sizeof(file->source_file_id)) == 0 &&
              identity.standard.EndOfFile.QuadPart == file->size &&
              filetime_to_unix_ns(identity.basic.LastWriteTime.QuadPart) == file->mtime_ns &&
              identity.basic.ChangeTime.QuadPart == file->source_change_time_100ns;
    CloseHandle(handle);
    return ok;
}

static int snapshot_verify_namespace(const char *repo_path, const cbm_discover_opts_t *opts,
                                     cbm_file_info_t *captured, int captured_count) {
    cbm_file_info_t *observed = NULL;
    int observed_count = 0;
    char **excluded = NULL;
    int excluded_count = 0;
    if (cbm_discover_ex(repo_path, opts, &observed, &observed_count, &excluded, &excluded_count) !=
        0) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_NAMESPACE_READ_FAILED", "rediscover_namespace",
                             repo_path, cbm_fs_last_error());
        return CBM_NOT_FOUND;
    }
    cbm_file_info_t **a = calloc((size_t)(captured_count > 0 ? captured_count : 1), sizeof(*a));
    cbm_file_info_t **b = calloc((size_t)(observed_count > 0 ? observed_count : 1), sizeof(*b));
    if (!a || !b) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_NAMESPACE_ALLOC_FAILED", "sort_namespace",
                             repo_path, ERROR_NOT_ENOUGH_MEMORY);
        free(a);
        free(b);
        cbm_discover_free(observed, observed_count);
        cbm_discover_free_excluded(excluded, excluded_count);
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < captured_count; i++) {
        a[i] = &captured[i];
    }
    for (int i = 0; i < observed_count; i++) {
        b[i] = &observed[i];
    }
    qsort(a, (size_t)captured_count, sizeof(*a), compare_rel_paths);
    qsort(b, (size_t)observed_count, sizeof(*b), compare_rel_paths);
    bool match = captured_count == observed_count;
    const char *mismatch = repo_path;
    for (int i = 0; match && i < captured_count; i++) {
        if (strcmp(a[i]->rel_path, b[i]->rel_path) != 0 || a[i]->language != b[i]->language ||
            a[i]->auxiliary != b[i]->auxiliary ||
            a[i]->interpretation_input != b[i]->interpretation_input ||
            !snapshot_current_identity_matches(a[i])) {
            match = false;
            mismatch = a[i]->live_path;
        }
    }
    free(a);
    free(b);
    cbm_discover_free(observed, observed_count);
    cbm_discover_free_excluded(excluded, excluded_count);
    if (!match) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_NAMESPACE_DRIFT", "compare_namespace", mismatch,
                             ERROR_FILE_INVALID);
        return CBM_NOT_FOUND;
    }
    return 0;
}

int cbm_source_snapshot_verify_unchanged(const char *repo_path, const cbm_discover_opts_t *opts,
                                         cbm_file_info_t *files, int file_count,
                                         const cbm_file_hash_t *stored, int stored_count,
                                         bool *out_unchanged) {
    if (!repo_path || !opts || file_count < 0 || stored_count < 0 || (file_count > 0 && !files) ||
        (stored_count > 0 && !stored) || !out_unchanged) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_INVALID_ARGUMENT", "validate_unchanged",
                             repo_path, ERROR_INVALID_PARAMETER);
        return CBM_NOT_FOUND;
    }
    *out_unchanged = false;
    if (file_count != stored_count) {
        return 0;
    }

    CBMHashTable *by_path = cbm_ht_create(stored_count > 0 ? (size_t)stored_count * 2u : CBM_SZ_64);
    if (!by_path) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_INDEX_ALLOC_FAILED", "allocate_hash_index",
                             repo_path, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < stored_count; i++) {
        if (!stored[i].rel_path || stored[i].rel_path[0] == '\0' ||
            !snapshot_is_lower_sha256(stored[i].sha256) || stored[i].size < 0 ||
            !cbm_ht_set_checked(by_path, stored[i].rel_path, (void *)&stored[i], NULL)) {
            snapshot_log_failure("CBM_SOURCE_UNCHANGED_HASH_ROW_INVALID", "index_persisted_hashes",
                                 stored[i].rel_path ? stored[i].rel_path : repo_path,
                                 ERROR_INVALID_DATA);
            cbm_ht_free(by_path);
            return CBM_NOT_FOUND;
        }
    }

    for (int i = 0; i < file_count; i++) {
        const cbm_file_hash_t *expected = cbm_ht_get(by_path, files[i].rel_path);
        if (!expected || files[i].size != expected->size) {
            cbm_ht_free(by_path);
            return 0;
        }
    }

    cbm_file_info_t *verified =
        calloc((size_t)(file_count > 0 ? file_count : 1), sizeof(*verified));
    if (!verified) {
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_IDENTITY_ALLOC_FAILED",
                             "allocate_identity_readback", repo_path, ERROR_NOT_ENOUGH_MEMORY);
        cbm_ht_free(by_path);
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        const cbm_file_hash_t *expected = cbm_ht_get(by_path, files[i].rel_path);
        snapshot_live_match_t match = snapshot_hash_live_match(&files[i], expected, &verified[i]);
        if (match != SNAPSHOT_LIVE_MATCH) {
            free(verified);
            cbm_ht_free(by_path);
            return match == SNAPSHOT_LIVE_CHANGED ? 0 : CBM_NOT_FOUND;
        }
    }
    cbm_ht_free(by_path);

    if (snapshot_verify_namespace(repo_path, opts, verified, file_count) != 0) {
        free(verified);
        return CBM_NOT_FOUND;
    }
    free(verified);
    *out_unchanged = true;
    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%d", file_count);
    cbm_log_info("source_snapshot.unchanged", "files", count_buf, "source_copy_started", "false");
    return 0;
}

static int snapshot_remove_tree(const char *path) {
    cbm_dir_t *dir = cbm_opendir(path);
    if (!dir) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_CLEANUP_OPEN_FAILED", "open_cleanup_root", path,
                             cbm_fs_last_error());
        return CBM_NOT_FOUND;
    }
    int rc = 0;
    cbm_dirent_t *entry = NULL;
    while ((entry = cbm_readdir(dir)) != NULL) {
        char *child = snapshot_join(path, entry->name);
        if (!child) {
            rc = CBM_NOT_FOUND;
            break;
        }
        if (entry->is_dir) {
            if (snapshot_remove_tree(child) != 0) {
                rc = CBM_NOT_FOUND;
            }
        } else {
            wchar_t *wide = cbm_utf8_to_wide_path(child);
            if (!wide || !SetFileAttributesW(wide, FILE_ATTRIBUTE_NORMAL) || !DeleteFileW(wide)) {
                snapshot_log_failure("CBM_SOURCE_SNAPSHOT_CLEANUP_FILE_FAILED", "delete_snapshot",
                                     child, GetLastError());
                rc = CBM_NOT_FOUND;
            }
            free(wide);
        }
        free(child);
        if (rc != 0) {
            break;
        }
    }
    unsigned long read_error = cbm_dir_error(dir);
    cbm_closedir(dir);
    if (read_error != 0) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_CLEANUP_READ_FAILED", "read_cleanup_root", path,
                             read_error);
        rc = CBM_NOT_FOUND;
    }
    if (rc == 0 && cbm_rmdir(path) != 0) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_CLEANUP_DIRECTORY_FAILED", "remove_directory",
                             path, (unsigned long)errno);
        rc = CBM_NOT_FOUND;
    }
    return rc;
}

int cbm_source_snapshot_capture(const char *repo_path, const cbm_discover_opts_t *opts,
                                cbm_file_info_t *files, int file_count,
                                cbm_source_snapshot_t *snapshot) {
    if (!repo_path || !opts || file_count < 0 || (file_count > 0 && !files) || !snapshot ||
        snapshot->root) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_INVALID_ARGUMENT", "validate_capture", repo_path,
                             ERROR_INVALID_PARAMETER);
        return CBM_NOT_FOUND;
    }
    const char *temp = cbm_tmpdir();
    size_t temp_len = strlen(temp);
    const size_t suffix_capacity = 96;
    if (temp_len > SIZE_MAX - suffix_capacity) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_OVERFLOW", "build_snapshot_root", temp,
                             ERROR_ARITHMETIC_OVERFLOW);
        return CBM_NOT_FOUND;
    }
    char *root = malloc(temp_len + suffix_capacity);
    if (!root) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_ROOT_ALLOC_FAILED", "allocate_snapshot_root",
                             temp, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }
    static volatile LONG sequence;
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONG generation = InterlockedIncrement(&sequence);
    int root_len =
        snprintf(root, temp_len + suffix_capacity, "%s/cbm-source-snapshot-%lu-%016llx-%ld", temp,
                 (unsigned long)GetCurrentProcessId(), (unsigned long long)counter.QuadPart,
                 (long)generation);
    wchar_t *wide_root = root_len > 0 && (size_t)root_len < temp_len + suffix_capacity
                             ? cbm_utf8_to_wide_path(root)
                             : NULL;
    if (!wide_root || !CreateDirectoryW(wide_root, NULL)) {
        DWORD error = GetLastError();
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_ROOT_CREATE_FAILED", "create_snapshot_root", root,
                             error);
        free(wide_root);
        free(root);
        return CBM_NOT_FOUND;
    }
    free(wide_root);
    snapshot->root = root;

    for (int i = 0; i < file_count; i++) {
        if (snapshot_capture_one(root, &files[i]) != 0) {
            (void)cbm_source_snapshot_destroy(snapshot);
            return CBM_NOT_FOUND;
        }
    }
    if (snapshot_verify_namespace(repo_path, opts, files, file_count) != 0) {
        (void)cbm_source_snapshot_destroy(snapshot);
        return CBM_NOT_FOUND;
    }
    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%d", file_count);
    cbm_log_info("source_snapshot.complete", "root", root, "files", count_buf);
    return 0;
}

int cbm_source_snapshot_destroy(cbm_source_snapshot_t *snapshot) {
    if (!snapshot || !snapshot->root) {
        return 0;
    }
    int rc = snapshot_remove_tree(snapshot->root);
    if (rc == 0) {
        free(snapshot->root);
        snapshot->root = NULL;
    }
    return rc;
}

#else
#error "Calyx codebase snapshot capture is currently implemented for the native Windows target"
#endif
