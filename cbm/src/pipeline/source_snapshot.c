#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#endif

#include "pipeline/source_snapshot.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/limits.h"
#include "foundation/mem.h"
#include "foundation/sha256.h"
#include "foundation/hash_table.h"
#include "foundation/platform.h"
#include "foundation/win_utf8.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* Scheduler-only live availability measurement. It intentionally remains off
 * the public CBM/Rust FFI surface. */
size_t cbm_mem_available(void);

enum {
    SNAPSHOT_INDEX_ORIGIN = -1,
    SNAPSHOT_INDEX_STEP = 1,
    SNAPSHOT_MIN_WORKERS = 1,
};

typedef struct {
    FILE_ID_INFO id;
    FILE_BASIC_INFO basic;
    FILE_STANDARD_INFO standard;
} snapshot_identity_t;

typedef struct {
    cbm_file_info_t *file;
    char *destination_path;
    wchar_t *wide_source;
    wchar_t *wide_destination;
    snapshot_identity_t source_identity;
    uint64_t byte_count;
    char sha256[CBM_SHA256_HEX_LEN + 1];
    const char *failure_code;
    const char *failure_operation;
    const char *failure_path;
    DWORD native_error;
    bool source_changed;
    const char *source_change_kind;
    bool expected_size_available;
    int64_t expected_size;
    bool observed_size_available;
    int64_t observed_size;
    bool expected_identity_available;
    snapshot_identity_t expected_identity;
    bool observed_identity_available;
    snapshot_identity_t observed_identity;
    bool complete;
} snapshot_capture_result_t;

typedef struct {
    char *path;
    wchar_t *wide_path;
    size_t depth;
} snapshot_directory_t;

typedef struct {
    bool match;
    const char *failure_code;
    const char *failure_operation;
    DWORD native_error;
    bool source_changed;
    const char *source_change_kind;
    bool observed_identity_available;
    snapshot_identity_t observed_identity;
} snapshot_identity_probe_result_t;

typedef enum {
    SNAPSHOT_DISPATCH_CAPTURE = 1,
    SNAPSHOT_DISPATCH_IDENTITY = 2,
} snapshot_dispatch_operation_t;

typedef struct {
    PTP_POOL pool;
    TP_CALLBACK_ENVIRON environment;
    PTP_WORK work;
    bool environment_initialized;
    int worker_count;
    volatile LONG next_index;
    int item_count;
    snapshot_dispatch_operation_t operation;
    snapshot_capture_result_t *capture_results;
    cbm_file_info_t **identity_files;
    const wchar_t **identity_wide_paths;
    snapshot_identity_probe_result_t *identity_results;
} snapshot_dispatcher_t;

static int64_t filetime_to_unix_ns(LONGLONG ticks);

static void snapshot_log_failure(const char *code, const char *operation, const char *path,
                                 unsigned long native_error) {
    char error_buf[32];
    snprintf(error_buf, sizeof(error_buf), "%lu", native_error);
    cbm_log_error("source_snapshot.failed", "code", code, "operation", operation, "path",
                  path ? path : "", "native_error_kind", "win32", "native_error", error_buf,
                  "message",
                  "the immutable source snapshot could not be completed", "remediation",
                  "stabilize source access, free workspace disk space, and retry indexing");
}

static const char *snapshot_bool_text(bool value) {
    return value ? "true" : "false";
}

static void snapshot_i64_text(int64_t value, char *out, size_t out_size) {
    snprintf(out, out_size, "%lld", (long long)value);
}

static void snapshot_u64_text(uint64_t value, char *out, size_t out_size) {
    snprintf(out, out_size, "%llu", (unsigned long long)value);
}

static void snapshot_file_id_hex(const uint8_t *file_id, char out[33]) {
    static const char digits[] = "0123456789abcdef";
    if (!file_id) {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < 16; i++) {
        out[i * 2] = digits[file_id[i] >> 4];
        out[i * 2 + 1] = digits[file_id[i] & 15];
    }
    out[32] = '\0';
}

static void snapshot_append_mismatch(char *out, size_t out_size, const char *field) {
    if (!out || out_size == 0 || !field || field[0] == '\0') {
        return;
    }
    size_t used = strlen(out);
    if (used >= out_size - 1) {
        return;
    }
    if (used > 0) {
        out[used++] = ',';
        out[used] = '\0';
        if (used >= out_size - 1) {
            return;
        }
    }
    snprintf(out + used, out_size - used, "%s", field);
}

static void snapshot_describe_file_identity_mismatch(const cbm_file_info_t *expected,
                                                     const snapshot_identity_t *observed,
                                                     char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (!expected || !observed) {
        snapshot_append_mismatch(out, out_size, "identity_unavailable");
        return;
    }
    if (observed->id.VolumeSerialNumber != expected->source_volume_serial) {
        snapshot_append_mismatch(out, out_size, "volume_serial");
    }
    if (memcmp(observed->id.FileId.Identifier, expected->source_file_id,
               sizeof(expected->source_file_id)) != 0) {
        snapshot_append_mismatch(out, out_size, "file_id");
    }
    if (observed->standard.EndOfFile.QuadPart != expected->size) {
        snapshot_append_mismatch(out, out_size, "stream_size");
    }
    if (filetime_to_unix_ns(observed->basic.LastWriteTime.QuadPart) != expected->mtime_ns) {
        snapshot_append_mismatch(out, out_size, "last_write_time");
    }
    if (observed->basic.ChangeTime.QuadPart != expected->source_change_time_100ns) {
        snapshot_append_mismatch(out, out_size, "change_time");
    }
    if (observed->standard.Directory) {
        snapshot_append_mismatch(out, out_size, "became_directory");
    }
    if (observed->standard.DeletePending) {
        snapshot_append_mismatch(out, out_size, "delete_pending");
    }
    if (out[0] == '\0') {
        snapshot_append_mismatch(out, out_size, "unspecified_identity_drift");
    }
}

static void snapshot_describe_identity_pair_mismatch(const snapshot_identity_t *expected,
                                                     const snapshot_identity_t *observed,
                                                     uint64_t observed_hash_bytes,
                                                     bool hash_bytes_available, char *out,
                                                     size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (!expected || !observed) {
        snapshot_append_mismatch(out, out_size, "identity_unavailable");
        return;
    }
    if (observed->id.VolumeSerialNumber != expected->id.VolumeSerialNumber) {
        snapshot_append_mismatch(out, out_size, "volume_serial");
    }
    if (memcmp(observed->id.FileId.Identifier, expected->id.FileId.Identifier,
               sizeof(expected->id.FileId.Identifier)) != 0) {
        snapshot_append_mismatch(out, out_size, "file_id");
    }
    if (observed->standard.EndOfFile.QuadPart != expected->standard.EndOfFile.QuadPart) {
        snapshot_append_mismatch(out, out_size, "stream_size");
    }
    if (observed->basic.LastWriteTime.QuadPart != expected->basic.LastWriteTime.QuadPart) {
        snapshot_append_mismatch(out, out_size, "last_write_time");
    }
    if (observed->basic.ChangeTime.QuadPart != expected->basic.ChangeTime.QuadPart) {
        snapshot_append_mismatch(out, out_size, "change_time");
    }
    if (observed->standard.Directory != expected->standard.Directory) {
        snapshot_append_mismatch(out, out_size, "directory");
    }
    if (observed->standard.DeletePending != expected->standard.DeletePending) {
        snapshot_append_mismatch(out, out_size, "delete_pending");
    }
    if (hash_bytes_available &&
        observed_hash_bytes != (uint64_t)expected->standard.EndOfFile.QuadPart) {
        snapshot_append_mismatch(out, out_size, "bytes_read");
    }
    if (out[0] == '\0') {
        snapshot_append_mismatch(out, out_size, "unspecified_identity_drift");
    }
}

static void snapshot_log_source_changed_basic(const char *code, const char *operation,
                                              const char *path, const char *source_change_kind) {
    cbm_log_error("source_snapshot.source_changed", "code", code, "operation", operation, "path",
                  path ? path : "", "diagnostic_kind", "source_change", "source_change_kind",
                  source_change_kind ? source_change_kind : "unspecified", "native_error_kind",
                  "none", "native_error", "0", "publication_started", "false", "message",
                  "the source tree changed while Astrolabe was proving a consistent snapshot",
                  "remediation",
                  "preserve the failed run evidence, wait for the source tree to stabilize, and "
                  "retry indexing without publishing a mixed-generation graph");
}

static void snapshot_log_source_changed_size(const char *code, const char *operation,
                                             const char *path, const char *source_change_kind,
                                             int64_t expected_size, int64_t observed_size) {
    char expected_size_text[32];
    char observed_size_text[32];
    snapshot_i64_text(expected_size, expected_size_text, sizeof(expected_size_text));
    snapshot_i64_text(observed_size, observed_size_text, sizeof(observed_size_text));
    cbm_log_error("source_snapshot.source_changed", "code", code, "operation", operation, "path",
                  path ? path : "", "diagnostic_kind", "source_change", "source_change_kind",
                  source_change_kind ? source_change_kind : "stream_size_changed",
                  "expected_size", expected_size_text, "observed_size", observed_size_text,
                  "native_error_kind", "none", "native_error", "0", "publication_started",
                  "false", "message",
                  "the source stream size changed while Astrolabe was proving a consistent "
                  "snapshot",
                  "remediation",
                  "preserve the failed run evidence, wait for the source tree to stabilize, and "
                  "retry indexing without publishing a mixed-generation graph");
}

static void snapshot_log_source_changed_file_identity(const char *code, const char *operation,
                                                      const char *path,
                                                      const char *source_change_kind,
                                                      const cbm_file_info_t *expected,
                                                      const snapshot_identity_t *observed) {
    char expected_volume[32];
    char observed_volume[32];
    char expected_file_id[33];
    char observed_file_id[33];
    char expected_size[32];
    char observed_size[32];
    char expected_mtime[32];
    char observed_mtime[32];
    char expected_change_time[32];
    char observed_change_time[32];
    char mismatch_fields[256];
    snapshot_u64_text(expected ? expected->source_volume_serial : 0, expected_volume,
                      sizeof(expected_volume));
    snapshot_u64_text(observed ? observed->id.VolumeSerialNumber : 0, observed_volume,
                      sizeof(observed_volume));
    snapshot_file_id_hex(expected ? expected->source_file_id : NULL, expected_file_id);
    snapshot_file_id_hex(observed ? observed->id.FileId.Identifier : NULL, observed_file_id);
    snapshot_i64_text(expected ? expected->size : 0, expected_size, sizeof(expected_size));
    snapshot_i64_text(observed ? observed->standard.EndOfFile.QuadPart : 0, observed_size,
                      sizeof(observed_size));
    snapshot_i64_text(expected ? expected->mtime_ns : 0, expected_mtime, sizeof(expected_mtime));
    snapshot_i64_text(observed ? filetime_to_unix_ns(observed->basic.LastWriteTime.QuadPart) : 0,
                      observed_mtime, sizeof(observed_mtime));
    snapshot_i64_text(expected ? expected->source_change_time_100ns : 0, expected_change_time,
                      sizeof(expected_change_time));
    snapshot_i64_text(observed ? observed->basic.ChangeTime.QuadPart : 0, observed_change_time,
                      sizeof(observed_change_time));
    snapshot_describe_file_identity_mismatch(expected, observed, mismatch_fields,
                                             sizeof(mismatch_fields));
    cbm_log_error(
        "source_snapshot.source_changed", "code", code, "operation", operation, "path",
        path ? path : "", "diagnostic_kind", "source_change", "source_change_kind",
        source_change_kind ? source_change_kind : "file_identity_changed", "mismatch_fields",
        mismatch_fields, "expected_volume_serial", expected_volume, "observed_volume_serial",
        observed_volume, "expected_file_id", expected_file_id, "observed_file_id",
        observed_file_id, "expected_size", expected_size, "observed_size", observed_size,
        "expected_mtime_ns", expected_mtime, "observed_mtime_ns", observed_mtime,
        "expected_change_time_100ns", expected_change_time, "observed_change_time_100ns",
        observed_change_time, "observed_directory",
        observed ? snapshot_bool_text(observed->standard.Directory) : "", "observed_delete_pending",
        observed ? snapshot_bool_text(observed->standard.DeletePending) : "",
        "native_error_kind", "none", "native_error", "0", "publication_started", "false",
        "message",
        "the source file identity changed while Astrolabe was proving a consistent snapshot",
        "remediation",
        "preserve the failed run evidence, wait for the source tree to stabilize, and retry "
        "indexing without publishing a mixed-generation graph");
}

static void snapshot_log_source_changed_identity_pair(const char *code, const char *operation,
                                                      const char *path,
                                                      const char *source_change_kind,
                                                      const snapshot_identity_t *expected,
                                                      const snapshot_identity_t *observed,
                                                      uint64_t observed_hash_bytes,
                                                      bool hash_bytes_available) {
    char expected_volume[32];
    char observed_volume[32];
    char expected_file_id[33];
    char observed_file_id[33];
    char expected_size[32];
    char observed_size[32];
    char expected_mtime[32];
    char observed_mtime[32];
    char expected_change_time[32];
    char observed_change_time[32];
    char observed_hash_bytes_text[32];
    char mismatch_fields[256];
    snapshot_u64_text(expected ? expected->id.VolumeSerialNumber : 0, expected_volume,
                      sizeof(expected_volume));
    snapshot_u64_text(observed ? observed->id.VolumeSerialNumber : 0, observed_volume,
                      sizeof(observed_volume));
    snapshot_file_id_hex(expected ? expected->id.FileId.Identifier : NULL, expected_file_id);
    snapshot_file_id_hex(observed ? observed->id.FileId.Identifier : NULL, observed_file_id);
    snapshot_i64_text(expected ? expected->standard.EndOfFile.QuadPart : 0, expected_size,
                      sizeof(expected_size));
    snapshot_i64_text(observed ? observed->standard.EndOfFile.QuadPart : 0, observed_size,
                      sizeof(observed_size));
    snapshot_i64_text(expected ? filetime_to_unix_ns(expected->basic.LastWriteTime.QuadPart) : 0,
                      expected_mtime, sizeof(expected_mtime));
    snapshot_i64_text(observed ? filetime_to_unix_ns(observed->basic.LastWriteTime.QuadPart) : 0,
                      observed_mtime, sizeof(observed_mtime));
    snapshot_i64_text(expected ? expected->basic.ChangeTime.QuadPart : 0, expected_change_time,
                      sizeof(expected_change_time));
    snapshot_i64_text(observed ? observed->basic.ChangeTime.QuadPart : 0, observed_change_time,
                      sizeof(observed_change_time));
    snapshot_u64_text(observed_hash_bytes, observed_hash_bytes_text,
                      sizeof(observed_hash_bytes_text));
    snapshot_describe_identity_pair_mismatch(expected, observed, observed_hash_bytes,
                                             hash_bytes_available, mismatch_fields,
                                             sizeof(mismatch_fields));
    cbm_log_error(
        "source_snapshot.source_changed", "code", code, "operation", operation, "path",
        path ? path : "", "diagnostic_kind", "source_change", "source_change_kind",
        source_change_kind ? source_change_kind : "file_identity_changed", "mismatch_fields",
        mismatch_fields, "expected_volume_serial", expected_volume, "observed_volume_serial",
        observed_volume, "expected_file_id", expected_file_id, "observed_file_id",
        observed_file_id, "expected_size", expected_size, "observed_size", observed_size,
        "expected_mtime_ns", expected_mtime, "observed_mtime_ns", observed_mtime,
        "expected_change_time_100ns", expected_change_time, "observed_change_time_100ns",
        observed_change_time, "observed_hash_bytes",
        hash_bytes_available ? observed_hash_bytes_text : "", "observed_directory",
        observed ? snapshot_bool_text(observed->standard.Directory) : "", "observed_delete_pending",
        observed ? snapshot_bool_text(observed->standard.DeletePending) : "",
        "native_error_kind", "none", "native_error", "0", "publication_started", "false",
        "message",
        "the source file identity changed while Astrolabe was proving a consistent snapshot",
        "remediation",
        "preserve the failed run evidence, wait for the source tree to stabilize, and retry "
        "indexing without publishing a mixed-generation graph");
}

static void snapshot_log_source_changed_namespace(const char *operation, const char *path,
                                                  const char *source_change_kind,
                                                  int captured_count, int observed_count,
                                                  const cbm_file_info_t *expected,
                                                  const cbm_file_info_t *observed) {
    char captured_count_text[32];
    char observed_count_text[32];
    char expected_language[32] = "";
    char observed_language[32] = "";
    snapshot_i64_text(captured_count, captured_count_text, sizeof(captured_count_text));
    snapshot_i64_text(observed_count, observed_count_text, sizeof(observed_count_text));
    if (expected) {
        snprintf(expected_language, sizeof(expected_language), "%d", (int)expected->language);
    }
    if (observed) {
        snprintf(observed_language, sizeof(observed_language), "%d", (int)observed->language);
    }
    cbm_log_error(
        "source_snapshot.source_changed", "code", "CBM_SOURCE_SNAPSHOT_NAMESPACE_DRIFT",
        "operation", operation, "path", path ? path : "", "diagnostic_kind", "source_change",
        "source_change_kind", source_change_kind ? source_change_kind : "namespace_changed",
        "captured_count", captured_count_text, "observed_count", observed_count_text,
        "expected_rel_path", expected ? expected->rel_path : "", "observed_rel_path",
        observed ? observed->rel_path : "", "expected_language", expected_language,
        "observed_language", observed_language, "expected_auxiliary",
        expected ? snapshot_bool_text(expected->auxiliary) : "", "observed_auxiliary",
        observed ? snapshot_bool_text(observed->auxiliary) : "",
        "expected_interpretation_input",
        expected ? snapshot_bool_text(expected->interpretation_input) : "",
        "observed_interpretation_input",
        observed ? snapshot_bool_text(observed->interpretation_input) : "", "native_error_kind",
        "none", "native_error", "0", "publication_started", "false", "message",
        "the source namespace changed while Astrolabe was proving a consistent snapshot",
        "remediation",
        "preserve the failed run evidence, wait for the source tree to stabilize, and retry "
        "indexing without publishing a mixed-generation graph");
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
    if (!GetFileInformationByHandleEx(source, FileAttributeTagInfo, &tag, sizeof(tag))) {
        DWORD error = GetLastError();
        CloseHandle(source);
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_IDENTITY_FAILED", "inspect_live_source",
                             file->path, error);
        return SNAPSHOT_LIVE_ERROR;
    }
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(source);
        snapshot_log_source_changed_basic("CBM_SOURCE_UNCHANGED_MUTATED",
                                          "inspect_live_source", file->path,
                                          "live_source_became_reparse_point");
        return SNAPSHOT_LIVE_ERROR;
    }
    if (!snapshot_get_identity(source, &before)) {
        DWORD error = GetLastError();
        CloseHandle(source);
        snapshot_log_failure("CBM_SOURCE_UNCHANGED_IDENTITY_FAILED", "inspect_live_source",
                             file->path, error);
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
        snapshot_log_source_changed_identity_pair(
            "CBM_SOURCE_UNCHANGED_MUTATED", "verify_live_source_identity", file->path,
            "live_source_changed_during_hash", &before, &after, bytes, true);
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

static void snapshot_capture_fail(snapshot_capture_result_t *result, const char *code,
                                  const char *operation, const char *path, DWORD native_error) {
    if (!result->failure_code) {
        result->failure_code = code;
        result->failure_operation = operation;
        result->failure_path = path;
        result->native_error = native_error != ERROR_SUCCESS ? native_error : ERROR_GEN_FAILURE;
    }
}

static void snapshot_capture_fail_source_changed_basic(snapshot_capture_result_t *result,
                                                       const char *code, const char *operation,
                                                       const char *path,
                                                       const char *source_change_kind) {
    if (!result->failure_code) {
        result->failure_code = code;
        result->failure_operation = operation;
        result->failure_path = path;
        result->native_error = ERROR_SUCCESS;
        result->source_changed = true;
        result->source_change_kind = source_change_kind;
    }
}

static void snapshot_capture_fail_source_changed_size(snapshot_capture_result_t *result,
                                                      const char *code, const char *operation,
                                                      const char *path,
                                                      const char *source_change_kind,
                                                      int64_t expected_size,
                                                      int64_t observed_size) {
    snapshot_capture_fail_source_changed_basic(result, code, operation, path, source_change_kind);
    if (result->source_changed) {
        result->expected_size_available = true;
        result->expected_size = expected_size;
        result->observed_size_available = true;
        result->observed_size = observed_size;
    }
}

static void snapshot_capture_fail_source_changed_identity(snapshot_capture_result_t *result,
                                                          const char *code,
                                                          const char *operation, const char *path,
                                                          const char *source_change_kind,
                                                          const snapshot_identity_t *expected,
                                                          const snapshot_identity_t *observed,
                                                          uint64_t observed_hash_bytes,
                                                          bool hash_bytes_available) {
    snapshot_capture_fail_source_changed_basic(result, code, operation, path, source_change_kind);
    if (result->source_changed) {
        if (expected) {
            result->expected_identity_available = true;
            result->expected_identity = *expected;
        }
        if (observed) {
            result->observed_identity_available = true;
            result->observed_identity = *observed;
        }
        if (hash_bytes_available) {
            result->observed_size_available = true;
            result->observed_size = (int64_t)observed_hash_bytes;
        }
    }
}

static void snapshot_capture_prepared(snapshot_capture_result_t *result) {
    cbm_file_info_t *file = result->file;
    HANDLE source = INVALID_HANDLE_VALUE;
    HANDLE destination = INVALID_HANDLE_VALUE;
    HANDLE readback = INVALID_HANDLE_VALUE;
    snapshot_identity_t before = {0};
    snapshot_identity_t after = {0};
    uint8_t captured_digest[CBM_SHA256_DIGEST_LEN] = {0};
    uint8_t readback_digest[CBM_SHA256_DIGEST_LEN] = {0};
    uint64_t captured_bytes = 0;
    uint64_t readback_bytes = 0;
    DWORD error = ERROR_SUCCESS;

    source = CreateFileW(
        result->wide_source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (source == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            snapshot_capture_fail_source_changed_basic(
                result, "CBM_SOURCE_SNAPSHOT_DISCOVERY_DRIFT", "open_source", file->path,
                "source_removed_after_discovery");
        } else {
            snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_OPEN_FAILED", "open_source",
                                  file->path, error);
        }
        goto cleanup;
    }

    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    if (!GetFileInformationByHandleEx(source, FileAttributeTagInfo, &tag, sizeof(tag))) {
        error = GetLastError();
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_IDENTITY_FAILED",
                              "inspect_source", file->path, error);
        goto cleanup;
    }
    if ((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        snapshot_capture_fail_source_changed_basic(
            result, "CBM_SOURCE_SNAPSHOT_DISCOVERY_DRIFT", "inspect_source", file->path,
            "source_became_reparse_point_after_discovery");
        goto cleanup;
    }
    if (!snapshot_get_identity(source, &before)) {
        error = GetLastError();
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_IDENTITY_FAILED",
                              "inspect_source", file->path, error);
        goto cleanup;
    }
    if (before.standard.EndOfFile.QuadPart < 0 ||
        before.standard.EndOfFile.QuadPart != file->size) {
        snapshot_capture_fail_source_changed_size(
            result, "CBM_SOURCE_SNAPSHOT_DISCOVERY_DRIFT", "compare_discovered_size", file->path,
            "discovered_size_changed_before_capture", file->size,
            before.standard.EndOfFile.QuadPart);
        goto cleanup;
    }

    destination = CreateFileW(result->wide_destination, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (destination == INVALID_HANDLE_VALUE) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_DESTINATION_CREATE_FAILED",
                              "create_snapshot", result->destination_path, GetLastError());
        goto cleanup;
    }

    /* The retained source handle was opened with FILE_SHARE_READ only. Windows
     * refuses that open when an existing writer/delete handle conflicts and
     * refuses every new writer/delete open until this handle closes. The
     * before/after FILE_ID + size + last-write/change-time comparison therefore
     * proves that this copy-and-hash read observed one stable source generation.
     *
     * The destination remains transaction-ephemeral. It is closed and
     * independently reopened, byte-counted, and SHA-256 verified below. This
     * second read is deliberately retained as the physical snapshot proof. */
    if (!copy_and_hash(source, destination, captured_digest, &captured_bytes, &error)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_COPY_FAILED", "copy_source", file->path,
                              error);
        goto cleanup;
    }
    FILETIME source_last_write = {
        .dwLowDateTime = before.basic.LastWriteTime.LowPart,
        .dwHighDateTime = (DWORD)before.basic.LastWriteTime.HighPart,
    };
    if (!SetFileTime(destination, NULL, NULL, &source_last_write)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_TIMESTAMP_COPY_FAILED",
                              "copy_source_last_write_time", result->destination_path,
                              GetLastError());
        goto cleanup;
    }
    if (!snapshot_get_identity(source, &after)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_IDENTITY_FAILED",
                              "inspect_source_after_copy", file->path, GetLastError());
        goto cleanup;
    }
    if (!CloseHandle(destination)) {
        error = GetLastError();
        destination = INVALID_HANDLE_VALUE;
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_DESTINATION_CLOSE_FAILED",
                              "close_snapshot_after_copy", result->destination_path, error);
        goto cleanup;
    }
    destination = INVALID_HANDLE_VALUE;
    if (!CloseHandle(source)) {
        error = GetLastError();
        source = INVALID_HANDLE_VALUE;
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_CLOSE_FAILED",
                              "close_source_after_copy", file->path, error);
        goto cleanup;
    }
    source = INVALID_HANDLE_VALUE;

    if (!snapshot_identity_equal(&before, &after) ||
        captured_bytes != (uint64_t)before.standard.EndOfFile.QuadPart) {
        snapshot_capture_fail_source_changed_identity(
            result, "CBM_SOURCE_SNAPSHOT_SOURCE_MUTATED", "capture_identity", file->path,
            "source_changed_during_capture", &before, &after, captured_bytes, true);
        goto cleanup;
    }

    readback = CreateFileW(result->wide_destination, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (readback == INVALID_HANDLE_VALUE) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_READBACK_OPEN_FAILED",
                              "open_snapshot_readback", result->destination_path, GetLastError());
        goto cleanup;
    }
    if (!hash_handle(readback, readback_digest, &readback_bytes, &error)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_READBACK_FAILED", "hash_snapshot",
                              result->destination_path, error);
        goto cleanup;
    }
    FILE_BASIC_INFO snapshot_basic = {0};
    if (!GetFileInformationByHandleEx(readback, FileBasicInfo, &snapshot_basic,
                                      sizeof(snapshot_basic))) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_TIMESTAMP_READBACK_FAILED",
                              "read_snapshot_last_write_time", result->destination_path,
                              GetLastError());
        goto cleanup;
    }
    if (snapshot_basic.LastWriteTime.QuadPart != before.basic.LastWriteTime.QuadPart) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_TIMESTAMP_READBACK_MISMATCH",
                              "compare_snapshot_last_write_time", result->destination_path,
                              ERROR_FILE_CORRUPT);
        goto cleanup;
    }
    if (readback_bytes != captured_bytes ||
        memcmp(readback_digest, captured_digest, sizeof(captured_digest)) != 0) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_READBACK_MISMATCH",
                              "compare_snapshot_readback", result->destination_path,
                              ERROR_FILE_CORRUPT);
        goto cleanup;
    }
    if (!CloseHandle(readback)) {
        error = GetLastError();
        readback = INVALID_HANDLE_VALUE;
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_READBACK_CLOSE_FAILED",
                              "close_snapshot_readback", result->destination_path, error);
        goto cleanup;
    }
    readback = INVALID_HANDLE_VALUE;
    if (!SetFileAttributesW(result->wide_destination, FILE_ATTRIBUTE_READONLY)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_IMMUTABILITY_FAILED", "set_readonly",
                              result->destination_path, GetLastError());
        goto cleanup;
    }

    result->source_identity = before;
    result->byte_count = captured_bytes;
    digest_to_hex(captured_digest, result->sha256);
    result->complete = true;

cleanup:
    if (readback != INVALID_HANDLE_VALUE && !CloseHandle(readback)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_READBACK_CLOSE_FAILED",
                              "close_snapshot_readback", result->destination_path, GetLastError());
    }
    if (destination != INVALID_HANDLE_VALUE && !CloseHandle(destination)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_DESTINATION_CLOSE_FAILED",
                              "close_snapshot_after_failure", result->destination_path,
                              GetLastError());
    }
    if (source != INVALID_HANDLE_VALUE && !CloseHandle(source)) {
        snapshot_capture_fail(result, "CBM_SOURCE_SNAPSHOT_SOURCE_CLOSE_FAILED",
                              "close_source_after_failure", file->path, GetLastError());
    }
}

static void snapshot_normalize_wide_separators(wchar_t *path) {
    for (wchar_t *cursor = path; cursor && *cursor; cursor++) {
        if (*cursor == L'/') {
            *cursor = L'\\';
        }
    }
}

static bool snapshot_rel_path_valid(const char *path) {
    if (!path || path[0] == '\0' || path[0] == '/' || path[0] == '\\') {
        return false;
    }
    const char *component = path;
    for (const char *cursor = path;; cursor++) {
        if (*cursor == ':') {
            return false;
        }
        if (*cursor == '/' || *cursor == '\\' || *cursor == '\0') {
            size_t length = (size_t)(cursor - component);
            if (length == 0 || (length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' && component[1] == '.')) {
                return false;
            }
            if (*cursor == '\0') {
                return true;
            }
            component = cursor + 1;
        }
    }
}

static int snapshot_compare_wide_paths(const wchar_t *left, const wchar_t *right) {
    int result = CompareStringOrdinal(left, -1, right, -1, TRUE);
    if (result == CSTR_LESS_THAN) {
        return -1;
    }
    if (result == CSTR_GREATER_THAN) {
        return 1;
    }
    if (result == CSTR_EQUAL) {
        return 0;
    }
    return wcscmp(left, right);
}

static int snapshot_compare_capture_destinations(const void *left, const void *right) {
    const snapshot_capture_result_t *const *a = left;
    const snapshot_capture_result_t *const *b = right;
    return snapshot_compare_wide_paths((*a)->wide_destination, (*b)->wide_destination);
}

static int snapshot_compare_directories(const void *left, const void *right) {
    const snapshot_directory_t *a = left;
    const snapshot_directory_t *b = right;
    if (a->depth < b->depth) {
        return -1;
    }
    if (a->depth > b->depth) {
        return 1;
    }
    return snapshot_compare_wide_paths(a->wide_path, b->wide_path);
}

static void snapshot_directories_free(snapshot_directory_t *directories, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(directories[i].path);
        free(directories[i].wide_path);
    }
    free(directories);
}

static void snapshot_capture_results_free(snapshot_capture_result_t *results, int count) {
    if (!results) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(results[i].destination_path);
        free(results[i].wide_source);
        free(results[i].wide_destination);
    }
    free(results);
}

static bool snapshot_directory_append(snapshot_directory_t **directories, size_t *count,
                                      size_t *capacity, const char *path, size_t path_length,
                                      size_t depth) {
    if (*count == *capacity) {
        size_t next = *capacity == 0 ? CBM_SZ_64 : *capacity * 2u;
        if (next < *capacity || next > SIZE_MAX / sizeof(**directories)) {
            SetLastError(ERROR_ARITHMETIC_OVERFLOW);
            return false;
        }
        snapshot_directory_t *grown = realloc(*directories, next * sizeof(**directories));
        if (!grown) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return false;
        }
        *directories = grown;
        *capacity = next;
    }
    char *copy = malloc(path_length + 1u);
    if (!copy) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    memcpy(copy, path, path_length);
    copy[path_length] = '\0';
    DWORD error = ERROR_SUCCESS;
    wchar_t *wide = cbm_utf8_to_wide_path_checked(copy, &error);
    if (!wide) {
        free(copy);
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    snapshot_normalize_wide_separators(wide);
    (*directories)[*count] = (snapshot_directory_t){
        .path = copy,
        .wide_path = wide,
        .depth = depth,
    };
    (*count)++;
    return true;
}

static bool snapshot_destination_exists(snapshot_capture_result_t **ordered, int count,
                                        const wchar_t *path) {
    int low = 0;
    int high = count;
    while (low < high) {
        int middle = low + (high - low) / 2;
        int comparison = snapshot_compare_wide_paths(ordered[middle]->wide_destination, path);
        if (comparison < 0) {
            low = middle + 1;
        } else if (comparison > 0) {
            high = middle;
        } else {
            return true;
        }
    }
    return false;
}

static int snapshot_prepare_capture_plan(const char *root, cbm_file_info_t *files, int file_count,
                                         snapshot_capture_result_t **results_out) {
    snapshot_capture_result_t *results =
        calloc((size_t)(file_count > 0 ? file_count : 1), sizeof(*results));
    snapshot_capture_result_t **ordered =
        calloc((size_t)(file_count > 0 ? file_count : 1), sizeof(*ordered));
    snapshot_directory_t *directories = NULL;
    size_t directory_count = 0;
    size_t directory_capacity = 0;
    if (!results || !ordered) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PLAN_ALLOC_FAILED", "allocate_capture_plan", root,
                             ERROR_NOT_ENOUGH_MEMORY);
        free(results);
        free(ordered);
        return CBM_NOT_FOUND;
    }

    size_t root_length = strlen(root);
    for (int i = 0; i < file_count; i++) {
        if (!snapshot_rel_path_valid(files[i].rel_path)) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_RELATIVE_PATH_INVALID",
                                 "validate_relative_path", files[i].rel_path, ERROR_INVALID_NAME);
            goto fail;
        }
        results[i].file = &files[i];
        results[i].destination_path = snapshot_join(root, files[i].rel_path);
        if (!results[i].destination_path) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_ALLOC_FAILED", "build_destination",
                                 files[i].rel_path, ERROR_NOT_ENOUGH_MEMORY);
            goto fail;
        }
        for (char *cursor = results[i].destination_path; *cursor; cursor++) {
            if (*cursor == '\\') {
                *cursor = '/';
            }
        }

        DWORD source_error = ERROR_SUCCESS;
        DWORD destination_error = ERROR_SUCCESS;
        results[i].wide_source = cbm_utf8_to_wide_path_checked(files[i].path, &source_error);
        results[i].wide_destination =
            cbm_utf8_to_wide_path_checked(results[i].destination_path, &destination_error);
        if (!results[i].wide_source || !results[i].wide_destination) {
            DWORD error = !results[i].wide_source ? source_error : destination_error;
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_ENCODING_FAILED", "prepare_wide_paths",
                                 files[i].path,
                                 error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION);
            goto fail;
        }
        snapshot_normalize_wide_separators(results[i].wide_source);
        snapshot_normalize_wide_separators(results[i].wide_destination);
        ordered[i] = &results[i];

        size_t depth = 0;
        for (const char *cursor = results[i].destination_path + root_length + 1u; *cursor;
             cursor++) {
            if (*cursor != '/') {
                continue;
            }
            depth++;
            size_t prefix_length = (size_t)(cursor - results[i].destination_path);
            if (!snapshot_directory_append(&directories, &directory_count, &directory_capacity,
                                           results[i].destination_path, prefix_length, depth)) {
                snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DIRECTORY_PLAN_ALLOC_FAILED",
                                     "prepare_unique_ancestors", results[i].destination_path,
                                     GetLastError());
                goto fail;
            }
        }
    }

    if (file_count > 1) {
        qsort(ordered, (size_t)file_count, sizeof(*ordered), snapshot_compare_capture_destinations);
    }
    for (int i = 1; i < file_count; i++) {
        if (snapshot_compare_wide_paths(ordered[i - 1]->wide_destination,
                                        ordered[i]->wide_destination) == 0) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DESTINATION_COLLISION",
                                 "validate_destination_uniqueness", ordered[i]->destination_path,
                                 ERROR_ALREADY_EXISTS);
            goto fail;
        }
    }

    if (directory_count > 1) {
        qsort(directories, directory_count, sizeof(*directories), snapshot_compare_directories);
    }
    size_t unique_count = 0;
    for (size_t i = 0; i < directory_count; i++) {
        if (unique_count > 0 && snapshot_compare_wide_paths(directories[unique_count - 1].wide_path,
                                                            directories[i].wide_path) == 0) {
            free(directories[i].path);
            free(directories[i].wide_path);
            continue;
        }
        if (unique_count != i) {
            directories[unique_count] = directories[i];
        }
        unique_count++;
    }
    directory_count = unique_count;

    for (size_t i = 0; i < directory_count; i++) {
        if (snapshot_destination_exists(ordered, file_count, directories[i].wide_path)) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_FILE_DIRECTORY_COLLISION",
                                 "validate_destination_topology", directories[i].path,
                                 ERROR_ALREADY_EXISTS);
            goto fail;
        }
        if (!CreateDirectoryW(directories[i].wide_path, NULL)) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_DIRECTORY_CREATE_FAILED",
                                 "create_unique_ancestor", directories[i].path, GetLastError());
            goto fail;
        }
    }

    snapshot_directories_free(directories, directory_count);
    free(ordered);
    *results_out = results;
    return 0;

fail:
    snapshot_directories_free(directories, directory_count);
    free(ordered);
    snapshot_capture_results_free(results, file_count);
    return CBM_NOT_FOUND;
}

static int compare_rel_paths(const void *left, const void *right) {
    const cbm_file_info_t *const *a = left;
    const cbm_file_info_t *const *b = right;
    return strcmp((*a)->rel_path, (*b)->rel_path);
}

static void snapshot_probe_current_identity(const cbm_file_info_t *file, const wchar_t *wide_path,
                                            snapshot_identity_probe_result_t *result) {
    HANDLE handle = CreateFileW(wide_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        result->failure_code = "CBM_SOURCE_SNAPSHOT_NAMESPACE_IDENTITY_OPEN_FAILED";
        result->failure_operation = "open_live_identity";
        result->native_error = GetLastError();
        return;
    }
    snapshot_identity_t identity = {0};
    if (!snapshot_get_identity(handle, &identity)) {
        result->failure_code = "CBM_SOURCE_SNAPSHOT_NAMESPACE_IDENTITY_READ_FAILED";
        result->failure_operation = "read_live_identity";
        result->native_error = GetLastError();
    } else {
        result->match =
            identity.id.VolumeSerialNumber == file->source_volume_serial &&
            memcmp(identity.id.FileId.Identifier, file->source_file_id,
                   sizeof(file->source_file_id)) == 0 &&
            identity.standard.EndOfFile.QuadPart == file->size &&
            filetime_to_unix_ns(identity.basic.LastWriteTime.QuadPart) == file->mtime_ns &&
            identity.basic.ChangeTime.QuadPart == file->source_change_time_100ns &&
            !identity.standard.Directory && !identity.standard.DeletePending;
        if (!result->match) {
            result->failure_code = "CBM_SOURCE_SNAPSHOT_NAMESPACE_DRIFT";
            result->failure_operation = "compare_live_identity";
            result->native_error = ERROR_SUCCESS;
            result->source_changed = true;
            result->source_change_kind = "live_identity_changed_after_capture";
            result->observed_identity_available = true;
            result->observed_identity = identity;
        }
    }
    if (!CloseHandle(handle) && !result->failure_code) {
        result->failure_code = "CBM_SOURCE_SNAPSHOT_NAMESPACE_IDENTITY_CLOSE_FAILED";
        result->failure_operation = "close_live_identity";
        result->native_error = GetLastError();
        result->match = false;
    }
}

static VOID CALLBACK snapshot_dispatch_callback(PTP_CALLBACK_INSTANCE instance, PVOID context,
                                                PTP_WORK work) {
    (void)instance;
    (void)work;
    snapshot_dispatcher_t *dispatcher = context;
    for (;;) {
        LONG index = InterlockedIncrement(&dispatcher->next_index);
        if (index < 0 || index >= dispatcher->item_count) {
            break;
        }
        if (dispatcher->operation == SNAPSHOT_DISPATCH_CAPTURE) {
            snapshot_capture_prepared(&dispatcher->capture_results[index]);
        } else if (dispatcher->operation == SNAPSHOT_DISPATCH_IDENTITY) {
            snapshot_probe_current_identity(dispatcher->identity_files[index],
                                            dispatcher->identity_wide_paths[index],
                                            &dispatcher->identity_results[index]);
        }
    }
}

static void snapshot_dispatcher_close(snapshot_dispatcher_t *dispatcher) {
    if (!dispatcher) {
        return;
    }
    if (dispatcher->work) {
        CloseThreadpoolWork(dispatcher->work);
        dispatcher->work = NULL;
    }
    if (dispatcher->environment_initialized) {
        DestroyThreadpoolEnvironment(&dispatcher->environment);
        dispatcher->environment_initialized = false;
    }
    if (dispatcher->pool) {
        CloseThreadpool(dispatcher->pool);
        dispatcher->pool = NULL;
    }
}

static int snapshot_dispatcher_init(snapshot_dispatcher_t *dispatcher, int item_count,
                                    const char *path) {
    memset(dispatcher, 0, sizeof(*dispatcher));
    if (item_count == 0) {
        return 0;
    }
    int workers = cbm_default_worker_count(true);
    if (workers < SNAPSHOT_MIN_WORKERS) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_WORKER_COUNT_INVALID", "admit_worker_count", path,
                             ERROR_INVALID_DATA);
        return CBM_NOT_FOUND;
    }
    if (workers > item_count) {
        workers = item_count;
    }

    dispatcher->pool = CreateThreadpool(NULL);
    if (!dispatcher->pool) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_THREADPOOL_CREATE_FAILED", "create_threadpool",
                             path, GetLastError());
        return CBM_NOT_FOUND;
    }
    SetThreadpoolThreadMaximum(dispatcher->pool, (DWORD)workers);
    if (!SetThreadpoolThreadMinimum(dispatcher->pool, (DWORD)workers)) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_THREADPOOL_ADMISSION_FAILED",
                             "set_threadpool_minimum", path, GetLastError());
        snapshot_dispatcher_close(dispatcher);
        return CBM_NOT_FOUND;
    }
    InitializeThreadpoolEnvironment(&dispatcher->environment);
    dispatcher->environment_initialized = true;
    SetThreadpoolCallbackPool(&dispatcher->environment, dispatcher->pool);
    dispatcher->work =
        CreateThreadpoolWork(snapshot_dispatch_callback, dispatcher, &dispatcher->environment);
    if (!dispatcher->work) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_WORK_CREATE_FAILED", "create_threadpool_work",
                             path, GetLastError());
        snapshot_dispatcher_close(dispatcher);
        return CBM_NOT_FOUND;
    }
    dispatcher->worker_count = workers;
    return 0;
}

static void snapshot_dispatch_capture(snapshot_dispatcher_t *dispatcher,
                                      snapshot_capture_result_t *results, int count) {
    if (count == 0) {
        return;
    }
    dispatcher->operation = SNAPSHOT_DISPATCH_CAPTURE;
    dispatcher->capture_results = results;
    dispatcher->identity_files = NULL;
    dispatcher->identity_wide_paths = NULL;
    dispatcher->identity_results = NULL;
    dispatcher->item_count = count;
    InterlockedExchange(&dispatcher->next_index, SNAPSHOT_INDEX_ORIGIN);
    for (int i = 0; i < dispatcher->worker_count; i++) {
        SubmitThreadpoolWork(dispatcher->work);
    }
    WaitForThreadpoolWorkCallbacks(dispatcher->work, FALSE);
}

static void snapshot_dispatch_identity(snapshot_dispatcher_t *dispatcher, cbm_file_info_t **files,
                                       const wchar_t **wide_paths,
                                       snapshot_identity_probe_result_t *results, int count) {
    if (count == 0) {
        return;
    }
    dispatcher->operation = SNAPSHOT_DISPATCH_IDENTITY;
    dispatcher->capture_results = NULL;
    dispatcher->identity_files = files;
    dispatcher->identity_wide_paths = wide_paths;
    dispatcher->identity_results = results;
    dispatcher->item_count = count;
    InterlockedExchange(&dispatcher->next_index, SNAPSHOT_INDEX_ORIGIN);
    for (int i = 0; i < dispatcher->worker_count; i++) {
        SubmitThreadpoolWork(dispatcher->work);
    }
    WaitForThreadpoolWorkCallbacks(dispatcher->work, FALSE);
}

static int snapshot_verify_namespace(const char *repo_path, const cbm_discover_opts_t *opts,
                                     cbm_file_info_t *captured, int captured_count,
                                     snapshot_dispatcher_t *dispatcher,
                                     snapshot_capture_result_t *capture_plan) {
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
    bool match = true;
    const char *mismatch_path = repo_path;
    const char *source_change_kind = "namespace_changed";
    const cbm_file_info_t *expected_diff = NULL;
    const cbm_file_info_t *observed_diff = NULL;
    int captured_index = 0;
    int observed_index = 0;
    while (captured_index < captured_count || observed_index < observed_count) {
        if (captured_index >= captured_count) {
            match = false;
            source_change_kind = "namespace_entry_added";
            observed_diff = b[observed_index];
            mismatch_path = observed_diff->path;
            break;
        }
        if (observed_index >= observed_count) {
            match = false;
            source_change_kind = "namespace_entry_removed";
            expected_diff = a[captured_index];
            mismatch_path = expected_diff->live_path ? expected_diff->live_path : expected_diff->path;
            break;
        }
        int path_cmp = strcmp(a[captured_index]->rel_path, b[observed_index]->rel_path);
        if (path_cmp < 0) {
            match = false;
            source_change_kind = "namespace_entry_removed";
            expected_diff = a[captured_index];
            mismatch_path = expected_diff->live_path ? expected_diff->live_path : expected_diff->path;
            break;
        }
        if (path_cmp > 0) {
            match = false;
            source_change_kind = "namespace_entry_added";
            observed_diff = b[observed_index];
            mismatch_path = observed_diff->path;
            break;
        }
        if (a[captured_index]->language != b[observed_index]->language ||
            a[captured_index]->auxiliary != b[observed_index]->auxiliary ||
            a[captured_index]->interpretation_input != b[observed_index]->interpretation_input) {
            match = false;
            source_change_kind = "namespace_metadata_changed";
            expected_diff = a[captured_index];
            observed_diff = b[observed_index];
            mismatch_path = expected_diff->live_path ? expected_diff->live_path : expected_diff->path;
            break;
        }
        captured_index++;
        observed_index++;
    }
    if (!match) {
        snapshot_log_source_changed_namespace("compare_namespace", mismatch_path,
                                              source_change_kind, captured_count, observed_count,
                                              expected_diff, observed_diff);
        free(a);
        free(b);
        cbm_discover_free(observed, observed_count);
        cbm_discover_free_excluded(excluded, excluded_count);
        return CBM_NOT_FOUND;
    }
    free(a);
    free(b);
    cbm_discover_free(observed, observed_count);
    cbm_discover_free_excluded(excluded, excluded_count);

    snapshot_identity_probe_result_t *identity_results =
        calloc((size_t)(captured_count > 0 ? captured_count : 1), sizeof(*identity_results));
    if (!identity_results) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_NAMESPACE_ALLOC_FAILED",
                             "allocate_identity_results", repo_path, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }
    if (dispatcher) {
        const wchar_t **wide_paths =
            calloc((size_t)(captured_count > 0 ? captured_count : 1), sizeof(*wide_paths));
        cbm_file_info_t **identity_files =
            calloc((size_t)(captured_count > 0 ? captured_count : 1), sizeof(*identity_files));
        if (!capture_plan || !wide_paths || !identity_files) {
            snapshot_log_failure("CBM_SOURCE_SNAPSHOT_NAMESPACE_ALLOC_FAILED",
                                 "prepare_identity_dispatch", repo_path, ERROR_NOT_ENOUGH_MEMORY);
            free(wide_paths);
            free(identity_files);
            free(identity_results);
            return CBM_NOT_FOUND;
        }
        for (int i = 0; i < captured_count; i++) {
            identity_files[i] = &captured[i];
            wide_paths[i] = capture_plan[i].wide_source;
        }
        snapshot_dispatch_identity(dispatcher, identity_files, wide_paths, identity_results,
                                   captured_count);
        free(wide_paths);
        free(identity_files);
    } else {
        for (int i = 0; i < captured_count; i++) {
            DWORD error = ERROR_SUCCESS;
            wchar_t *wide = cbm_utf8_to_wide_path_checked(captured[i].live_path, &error);
            if (!wide) {
                identity_results[i].failure_code =
                    "CBM_SOURCE_SNAPSHOT_NAMESPACE_IDENTITY_PATH_FAILED";
                identity_results[i].failure_operation = "widen_live_identity_path";
                identity_results[i].native_error =
                    error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION;
                continue;
            }
            snapshot_normalize_wide_separators(wide);
            snapshot_probe_current_identity(&captured[i], wide, &identity_results[i]);
            free(wide);
        }
    }
    for (int i = 0; i < captured_count; i++) {
        if (!identity_results[i].match) {
            const char *code = identity_results[i].failure_code
                                   ? identity_results[i].failure_code
                                   : "CBM_SOURCE_SNAPSHOT_NAMESPACE_DRIFT";
            const char *operation = identity_results[i].failure_operation
                                        ? identity_results[i].failure_operation
                                        : "compare_live_identity";
            if (identity_results[i].source_changed) {
                if (identity_results[i].observed_identity_available) {
                    snapshot_log_source_changed_file_identity(
                        code, operation, captured[i].live_path,
                        identity_results[i].source_change_kind, &captured[i],
                        &identity_results[i].observed_identity);
                } else {
                    snapshot_log_source_changed_basic(
                        code, operation, captured[i].live_path,
                        identity_results[i].source_change_kind
                            ? identity_results[i].source_change_kind
                            : "live_identity_changed_after_capture");
                }
            } else {
                snapshot_log_failure(
                    code, operation, captured[i].live_path,
                    identity_results[i].native_error != ERROR_SUCCESS
                        ? identity_results[i].native_error
                        : ERROR_GEN_FAILURE);
            }
            free(identity_results);
            return CBM_NOT_FOUND;
        }
    }
    free(identity_results);
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

    if (snapshot_verify_namespace(repo_path, opts, verified, file_count, NULL, NULL) != 0) {
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

int cbm_source_snapshot_capture(const char *repo_path, const char *store_path,
                                const cbm_discover_opts_t *opts, cbm_file_info_t *files,
                                int file_count, cbm_source_snapshot_t *snapshot) {
    if (!repo_path || !store_path || !store_path[0] || !opts || file_count < 0 ||
        (file_count > 0 && !files) || !snapshot || snapshot->root) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_INVALID_ARGUMENT", "validate_capture", repo_path,
                             ERROR_INVALID_PARAMETER);
        return CBM_NOT_FOUND;
    }
    char *store_directory = strdup(store_path);
    if (!store_directory) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_STORE_ALLOC_FAILED", "copy_snapshot_store",
                             store_path, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }
    for (char *cursor = store_directory; *cursor; cursor++) {
        if (*cursor == '\\') {
            *cursor = '/';
        }
    }
    char *last_separator = strrchr(store_directory, '/');
    if (!last_separator) {
        free(store_directory);
        store_directory = strdup(".");
    } else if (last_separator == store_directory + 2 && store_directory[1] == ':') {
        last_separator[1] = '\0';
    } else if (last_separator == store_directory) {
        last_separator[1] = '\0';
    } else {
        *last_separator = '\0';
    }
    if (!store_directory) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_STORE_ALLOC_FAILED", "derive_snapshot_store",
                             store_path, ERROR_NOT_ENOUGH_MEMORY);
        return CBM_NOT_FOUND;
    }
    char *snapshot_base = cbm_real_path_final(store_directory);
    if (!snapshot_base || !cbm_is_dir(snapshot_base)) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_STORE_INVALID", "open_snapshot_store",
                             store_directory, GetLastError());
        free(store_directory);
        free(snapshot_base);
        return CBM_NOT_FOUND;
    }
    free(store_directory);
    size_t base_len = strlen(snapshot_base);
    const size_t suffix_capacity = 96;
    if (base_len > SIZE_MAX - suffix_capacity) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_PATH_OVERFLOW", "build_snapshot_root",
                             snapshot_base, ERROR_ARITHMETIC_OVERFLOW);
        free(snapshot_base);
        return CBM_NOT_FOUND;
    }
    char *root = malloc(base_len + suffix_capacity);
    if (!root) {
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_ROOT_ALLOC_FAILED", "allocate_snapshot_root",
                             snapshot_base, ERROR_NOT_ENOUGH_MEMORY);
        free(snapshot_base);
        return CBM_NOT_FOUND;
    }
    static volatile LONG sequence;
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONG generation = InterlockedIncrement(&sequence);
    int root_len = snprintf(root, base_len + suffix_capacity,
                            "%s/.cbm-source-%lx-%016llx-%lx", snapshot_base,
                            (unsigned long)GetCurrentProcessId(),
                            (unsigned long long)counter.QuadPart, (unsigned long)generation);
    wchar_t *wide_root = root_len > 0 && (size_t)root_len < base_len + suffix_capacity
                             ? cbm_utf8_to_wide_path(root)
                             : NULL;
    if (!wide_root || !CreateDirectoryW(wide_root, NULL)) {
        DWORD error = GetLastError();
        snapshot_log_failure("CBM_SOURCE_SNAPSHOT_ROOT_CREATE_FAILED", "create_snapshot_root", root,
                             error);
        free(wide_root);
        free(root);
        free(snapshot_base);
        return CBM_NOT_FOUND;
    }
    free(wide_root);
    char root_length[32];
    char store_length[32];
    snprintf(root_length, sizeof(root_length), "%d", root_len);
    snprintf(store_length, sizeof(store_length), "%zu", base_len);
    cbm_log_info("source_snapshot.root_ready", "ownership", "configured_project_store",
                 "store_path", store_path, "store_directory", snapshot_base,
                 "store_directory_bytes", store_length, "root", root, "root_path_bytes",
                 root_length, "ambient_temp_used", "false");
    free(snapshot_base);
    snapshot->root = root;

    snapshot_dispatcher_t dispatcher = {0};
    if (snapshot_dispatcher_init(&dispatcher, file_count, root) != 0) {
        return CBM_NOT_FOUND;
    }
    snapshot_capture_result_t *results = NULL;
    if (snapshot_prepare_capture_plan(root, files, file_count, &results) != 0) {
        snapshot_dispatcher_close(&dispatcher);
        return CBM_NOT_FOUND;
    }

    snapshot_dispatch_capture(&dispatcher, results, file_count);
    for (int i = 0; i < file_count; i++) {
        if (!results[i].complete || results[i].failure_code) {
            const char *code = results[i].failure_code ? results[i].failure_code
                                                       : "CBM_SOURCE_SNAPSHOT_CAPTURE_INCOMPLETE";
            const char *operation =
                results[i].failure_operation ? results[i].failure_operation : "capture_worker";
            const char *path = results[i].failure_path ? results[i].failure_path : files[i].path;
            if (results[i].source_changed) {
                if (results[i].expected_identity_available &&
                    results[i].observed_identity_available) {
                    snapshot_log_source_changed_identity_pair(
                        code, operation, path, results[i].source_change_kind,
                        &results[i].expected_identity, &results[i].observed_identity,
                        results[i].observed_size_available ? (uint64_t)results[i].observed_size : 0,
                        results[i].observed_size_available);
                } else if (results[i].expected_size_available &&
                           results[i].observed_size_available) {
                    snapshot_log_source_changed_size(code, operation, path,
                                                     results[i].source_change_kind,
                                                     results[i].expected_size,
                                                     results[i].observed_size);
                } else {
                    snapshot_log_source_changed_basic(code, operation, path,
                                                      results[i].source_change_kind);
                }
            } else {
                snapshot_log_failure(code, operation, path,
                                     results[i].native_error != ERROR_SUCCESS
                                         ? results[i].native_error
                                         : ERROR_GEN_FAILURE);
            }
            snapshot_capture_results_free(results, file_count);
            snapshot_dispatcher_close(&dispatcher);
            return CBM_NOT_FOUND;
        }
    }

    /* Publish the staged records only after every independent file transaction
     * completed. No worker mutates discovery state, so failure cannot expose a
     * partially captured file array to later passes. */
    for (int i = 0; i < file_count; i++) {
        files[i].live_path = files[i].path;
        files[i].path = results[i].destination_path;
        results[i].destination_path = NULL;
        files[i].size = (int64_t)results[i].byte_count;
        files[i].mtime_ns =
            filetime_to_unix_ns(results[i].source_identity.basic.LastWriteTime.QuadPart);
        files[i].source_volume_serial = results[i].source_identity.id.VolumeSerialNumber;
        memcpy(files[i].source_file_id, results[i].source_identity.id.FileId.Identifier,
               sizeof(files[i].source_file_id));
        files[i].source_change_time_100ns = results[i].source_identity.basic.ChangeTime.QuadPart;
        memcpy(files[i].sha256, results[i].sha256, sizeof(files[i].sha256));
    }
    if (snapshot_verify_namespace(repo_path, opts, files, file_count, &dispatcher, results) != 0) {
        snapshot_capture_results_free(results, file_count);
        snapshot_dispatcher_close(&dispatcher);
        return CBM_NOT_FOUND;
    }
    int worker_count = dispatcher.worker_count;
    snapshot_capture_results_free(results, file_count);
    snapshot_dispatcher_close(&dispatcher);
    char count_buf[32];
    char worker_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%d", file_count);
    snprintf(worker_buf, sizeof(worker_buf), "%d", worker_count);
    cbm_log_info("source_snapshot.complete", "root", root, "files", count_buf, "workers",
                 worker_buf, "last_write_time", "copied_and_read_back_per_file");
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

static void source_slab_log_failure(const char *code, const char *operation, const char *path,
                                    size_t requested, size_t process_headroom,
                                    size_t machine_available, const char *message,
                                    const char *remediation) {
    char requested_text[32];
    char process_text[32];
    char machine_text[32];
    snprintf(requested_text, sizeof(requested_text), "%zu", requested);
    snprintf(process_text, sizeof(process_text), "%zu", process_headroom);
    snprintf(machine_text, sizeof(machine_text), "%zu", machine_available);
    cbm_log_error("source_slab.refused", "code", code, "operation", operation, "path",
                  path ? path : "", "requested_bytes", requested_text,
                  "process_headroom_bytes", process_text, "machine_available_bytes",
                  machine_text, "message", message, "remediation", remediation);
}

static void source_slab_hash_frame_u64(cbm_sha256_ctx *hash, uint64_t value) {
    uint8_t frame[8];
    for (int i = 7; i >= 0; i--) {
        frame[i] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
    cbm_sha256_update(hash, frame, sizeof(frame));
}

static void source_slab_digest_hex(const uint8_t digest[CBM_SHA256_DIGEST_LEN],
                                   char out[CBM_SHA256_HEX_LEN + 1]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
}

void cbm_source_slab_destroy(cbm_source_slab_t *slab) {
    if (!slab) {
        return;
    }
    free(slab->bytes);
    free(slab->offsets);
    free(slab->lengths);
    memset(slab, 0, sizeof(*slab));
}

int cbm_source_slab_build(const cbm_file_info_t *files, int file_count,
                          cbm_source_slab_t *slab) {
    if (!slab || file_count <= 0 || !files || slab->bytes || slab->offsets || slab->lengths ||
        slab->file_count != 0) {
        source_slab_log_failure(
            "CBM_SOURCE_SLAB_INVALID_ARGUMENT", "validate", "", 0, 0, 0,
            "the immutable source slab request is incomplete or already initialized",
            "supply one non-empty captured source view and one empty destination slab");
        return CBM_NOT_FOUND;
    }
    if ((size_t)file_count > SIZE_MAX / sizeof(size_t)) {
        source_slab_log_failure(
            "CBM_SOURCE_SLAB_INDEX_OVERFLOW", "measure_index", "", SIZE_MAX, 0, 0,
            "the source count exceeds the addressable slab index",
            "reduce the corpus to an addressable source count and retry the complete generation");
        return CBM_NOT_FOUND;
    }

    size_t source_bytes = 0;
    size_t storage_bytes = 0;
    long max_file_bytes = cbm_max_file_bytes();
    for (int i = 0; i < file_count; i++) {
        if (!files[i].path || !files[i].rel_path || files[i].size < 0 ||
            (uint64_t)files[i].size > (uint64_t)INT_MAX ||
            (max_file_bytes > 0 && files[i].size > max_file_bytes)) {
            source_slab_log_failure(
                "CBM_SOURCE_SLAB_FILE_INVALID", "measure_file", files[i].path, 0, 0, 0,
                "one captured source cannot be represented by the authoritative parser contract",
                "inspect the captured size/path and configured maximum, then retry unchanged");
            return CBM_NOT_FOUND;
        }
        size_t length = (size_t)files[i].size;
        if (source_bytes > SIZE_MAX - length || storage_bytes > SIZE_MAX - length - 1) {
            source_slab_log_failure(
                "CBM_SOURCE_SLAB_BYTES_OVERFLOW", "measure_file", files[i].path, SIZE_MAX, 0, 0,
                "the complete captured source corpus exceeds addressable memory",
                "split the corpus into an addressable project boundary and retry");
            return CBM_NOT_FOUND;
        }
        source_bytes += length;
        storage_bytes += length + 1;
    }

    size_t index_bytes = (size_t)file_count * sizeof(size_t);
    if (storage_bytes > SIZE_MAX - index_bytes || storage_bytes + index_bytes > SIZE_MAX - index_bytes) {
        source_slab_log_failure(
            "CBM_SOURCE_SLAB_ALLOCATION_OVERFLOW", "measure_allocation", "", SIZE_MAX, 0, 0,
            "the source slab and its exact index exceed addressable memory",
            "split the corpus into an addressable project boundary and retry");
        return CBM_NOT_FOUND;
    }
    size_t allocated_bytes = storage_bytes + (index_bytes * 2);
    size_t budget = cbm_mem_budget();
    size_t rss = cbm_mem_rss();
    size_t machine_available = cbm_mem_available();
    size_t process_headroom = budget > rss ? budget - rss : 0;
    if (budget == 0 || machine_available == 0 || allocated_bytes > process_headroom ||
        allocated_bytes > machine_available) {
        source_slab_log_failure(
            "CBM_SOURCE_SLAB_MEMORY_ADMISSION_REFUSED", "admit_allocation", "",
            allocated_bytes, process_headroom, machine_available,
            "the complete immutable source slab cannot be admitted within live memory",
            "close competing memory-intensive work or increase the declared process budget, then "
            "retry the complete unchanged corpus");
        return CBM_NOT_FOUND;
    }

    cbm_source_slab_t candidate = {0};
    candidate.bytes = malloc(storage_bytes);
    candidate.offsets = malloc(index_bytes);
    candidate.lengths = malloc(index_bytes);
    if (!candidate.bytes || !candidate.offsets || !candidate.lengths) {
        source_slab_log_failure(
            "CBM_SOURCE_SLAB_ALLOC_FAILED", "allocate", "", allocated_bytes, process_headroom,
            machine_available, "the admitted immutable source slab allocation failed",
            "free memory and retry the complete unchanged corpus");
        cbm_source_slab_destroy(&candidate);
        return CBM_NOT_FOUND;
    }

    cbm_sha256_ctx corpus_hash;
    cbm_sha256_init(&corpus_hash);
    size_t cursor = 0;
    for (int i = 0; i < file_count; i++) {
        size_t length = (size_t)files[i].size;
        candidate.offsets[i] = cursor;
        candidate.lengths[i] = length;
        FILE *stream = cbm_fopen(files[i].path, "rb");
        if (!stream) {
            source_slab_log_failure(
                "CBM_SOURCE_SLAB_OPEN_FAILED", "read_captured_file", files[i].path, length,
                process_headroom, machine_available,
                "one immutable captured source file could not be opened",
                "preserve the snapshot diagnostic, restore readable captured bytes, and retry");
            cbm_source_slab_destroy(&candidate);
            return CBM_NOT_FOUND;
        }
        size_t read_bytes = length > 0 ? fread(candidate.bytes + cursor, 1, length, stream) : 0;
        int extra = fgetc(stream);
        bool read_failed = read_bytes != length || extra != EOF || ferror(stream) != 0;
        (void)fclose(stream);
        if (read_failed) {
            source_slab_log_failure(
                "CBM_SOURCE_SLAB_READ_FAILED", "read_captured_file", files[i].path, length,
                process_headroom, machine_available,
                "one immutable captured source file changed length or became unreadable",
                "preserve the snapshot diagnostic and retry only from a complete stable capture");
            cbm_source_slab_destroy(&candidate);
            return CBM_NOT_FOUND;
        }
        candidate.bytes[cursor + length] = 0;

        char observed_sha256[CBM_SHA256_HEX_LEN + 1];
        cbm_sha256_hex(candidate.bytes + cursor, length, observed_sha256);
        if (files[i].sha256[0] == '\0' || strcmp(files[i].sha256, observed_sha256) != 0) {
            source_slab_log_failure(
                "CBM_SOURCE_SLAB_HASH_MISMATCH", "verify_captured_file", files[i].path, length,
                process_headroom, machine_available,
                "one source slab entry does not match its immutable snapshot hash",
                "preserve the snapshot and refuse publication until the captured bytes are stable");
            cbm_source_slab_destroy(&candidate);
            return CBM_NOT_FOUND;
        }

        size_t path_len = strlen(files[i].rel_path);
        source_slab_hash_frame_u64(&corpus_hash, (uint64_t)path_len);
        cbm_sha256_update(&corpus_hash, files[i].rel_path, path_len);
        source_slab_hash_frame_u64(&corpus_hash, (uint64_t)length);
        cbm_sha256_update(&corpus_hash, candidate.bytes + cursor, length);
        cursor += length + 1;
    }

    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&corpus_hash, digest);
    source_slab_digest_hex(digest, candidate.sha256);
    candidate.source_bytes = source_bytes;
    candidate.storage_bytes = storage_bytes;
    candidate.allocated_bytes = allocated_bytes;
    candidate.file_count = file_count;
    *slab = candidate;

    char files_text[32];
    char source_text[32];
    char allocated_text[32];
    snprintf(files_text, sizeof(files_text), "%d", file_count);
    snprintf(source_text, sizeof(source_text), "%zu", source_bytes);
    snprintf(allocated_text, sizeof(allocated_text), "%zu", allocated_bytes);
    cbm_log_info("source_slab.complete", "files", files_text, "source_bytes", source_text,
                 "allocated_bytes", allocated_text, "sha256", slab->sha256);
    return 0;
}

const uint8_t *cbm_source_slab_get(const cbm_source_slab_t *slab, int file_index,
                                   size_t *out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!slab || !slab->bytes || !slab->offsets || !slab->lengths || file_index < 0 ||
        file_index >= slab->file_count) {
        return NULL;
    }
    size_t offset = slab->offsets[file_index];
    size_t length = slab->lengths[file_index];
    if (offset > slab->storage_bytes || length > slab->storage_bytes - offset ||
        offset + length >= slab->storage_bytes || slab->bytes[offset + length] != 0) {
        return NULL;
    }
    if (out_len) {
        *out_len = length;
    }
    return slab->bytes + offset;
}

#else
#error "Calyx codebase snapshot capture is currently implemented for the native Windows target"
#endif
