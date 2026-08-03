/*
 * artifact.c — Persistent artifact export/import for team sharing.
 *
 * Export: strip indexes → VACUUM INTO temp → zstd compress → write .zst + metadata
 * Import: decompress → write to cache → open (auto-creates indexes) → integrity check
 */
#include "foundation/constants.h"
#include "foundation/schema_version.h"

enum {
    ART_DIR_PERMS = 0755,
    ART_ZSTD_FAST = 3,
    ART_ZSTD_BEST = 9,
    ART_RATIO_SCALE = 10, /* multiply ratio by 10 for integer logging */
    ART_NUL = 1,          /* NUL terminator byte */
};
#define ART_BYTES_PER_MB ((size_t)1024 * 1024)

/* Generous ceiling on an imported artifact's decompressed size. Real indexes
 * (a full Linux-kernel DB is ~14 GB) fit comfortably; a frame that declares
 * more than this is rejected before any allocation so a crafted content size
 * can neither trigger a runaway allocation nor be used to desync the decoder
 * capacity from the destination buffer. */
#define ART_MAX_DECOMPRESSED_BYTES ((size_t)64 * 1024 * ART_BYTES_PER_MB)

#ifdef ASTRO_SPAWN
#include "astro_spawn.h"
#endif
#include "pipeline/artifact.h"
#include "store/store.h"
#include "foundation/platform.h"
#include "foundation/compat_fs.h"
#include "foundation/compat.h"
#include "foundation/log.h"
#include "foundation/sha256.h"
#include "foundation/str_util.h" /* cbm_validate_shell_arg — git shell-out hardening */

#include "zstd_store.h"

#include <sqlite3.h>
#include <yyjson/yyjson.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#include "foundation/win_utf8.h" /* cbm_utf8_to_wide_path — #415 long-path-safe atomic swap */
#endif

/* ── Helpers ──────────────────────────────────────────────────────── */

/* Thread-local rotating buffers for small int→string conversions (logging).
 * Rotating allows multiple itoa_buf() calls in a single log statement. */
enum { ART_RING = 4, ART_RING_MASK = 3 };
static _Thread_local char g_export_error[CBM_SZ_512];

static const char *itoa_buf(int v) {
    static _Thread_local char bufs[ART_RING][CBM_SZ_32];
    static _Thread_local int idx = 0;
    int i = idx;
    idx = (idx + ART_NUL) & ART_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", v);
    return bufs[i];
}

const char *cbm_artifact_export_last_error(void) {
    return g_export_error[0] ? g_export_error : NULL;
}

static void clear_export_error(void) {
    g_export_error[0] = '\0';
}

static int artifact_export_fail(const char *stage, const char *path, const char *err, int err_no) {
    const char *safe_stage = stage ? stage : "unknown";
    const char *safe_err = err ? err : "unknown";

    if (path && err_no != 0) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s errno=%d path=%s", safe_stage,
                 safe_err, err_no, path);
    } else if (path) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s path=%s", safe_stage, safe_err,
                 path);
    } else if (err_no != 0) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s errno=%d", safe_stage, safe_err,
                 err_no);
    } else {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s", safe_stage, safe_err);
    }

    if (path && err_no != 0) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "errno",
                      itoa_buf(err_no), "path", path);
    } else if (path) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "path", path);
    } else if (err_no != 0) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "errno",
                      itoa_buf(err_no));
    } else {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err);
    }
    return CBM_NOT_FOUND;
}

static bool artifact_import_result_init(cbm_artifact_import_result_t *result,
                                        const char *destination_db_path) {
    memset(result, 0, sizeof(*result));
    result->abi_version = CBM_ARTIFACT_IMPORT_ABI_VERSION;
    result->struct_size = sizeof(*result);
    result->status = CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION;
    result->destination_probe = CBM_PATH_PROBE_ERROR;
    int wrote = snprintf(result->destination_db_path, sizeof(result->destination_db_path), "%s",
                         destination_db_path ? destination_db_path : "");
    if (wrote < 0 || (size_t)wrote >= sizeof(result->destination_db_path)) {
        result->destination_db_path[0] = '\0';
#ifdef _WIN32
        result->destination_probe_native_error = ERROR_BUFFER_OVERFLOW;
#else
        result->destination_probe_native_error = ENAMETOOLONG;
#endif
        snprintf(result->operation, sizeof(result->operation), "%s", "import.destination_path");
        snprintf(result->detail, sizeof(result->detail), "%s",
                 "destination database path exceeds the result-bearing ABI capacity");
        return false;
    }
    return true;
}

static cbm_artifact_import_status_t artifact_import_fail(
    cbm_artifact_import_result_t *result, cbm_artifact_import_status_t status,
    const char *operation, const char *detail) {
    result->status = status;
    snprintf(result->operation, sizeof(result->operation), "%s",
             operation ? operation : "unknown");
    snprintf(result->detail, sizeof(result->detail), "%s", detail ? detail : "unknown");
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe =
        cbm_path_probe(result->destination_db_path, &probe_error);
    result->destination_probe = probe;
    result->destination_probe_native_error = (uint32_t)probe_error;
    if (!g_export_error[0]) {
        artifact_export_fail(operation, result->destination_db_path, detail, 0);
    }
    return result->status;
}

typedef struct {
    const char *err;
    int err_no;
} artifact_file_error_t;

static void file_error_clear(artifact_file_error_t *out) {
    if (out) {
        out->err = NULL;
        out->err_no = 0;
    }
}

static void file_error_set(artifact_file_error_t *out, const char *err, int err_no) {
    if (out) {
        out->err = err;
        out->err_no = err_no;
    }
}

/* Build path: <repo>/.codebase-memory/<name> into caller-owned buf. */
static bool artifact_path(char *buf, size_t bufsz, const char *repo_path, const char *name) {
    int n = snprintf(buf, bufsz, "%s/%s/%s", repo_path, CBM_ARTIFACT_DIR, name);
    return n >= 0 && (size_t)n < bufsz;
}

/* Read entire file into malloc'd buffer. Sets *out_len. Returns NULL on error. */
static char *read_file_alloc(const char *path, size_t *out_len) {
    FILE *fp = cbm_fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz <= 0) {
        (void)fclose(fp);
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)sz);
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    size_t rd = fread(buf, ART_NUL, (size_t)sz, fp);
    (void)fclose(fp);
    if ((long)rd != sz) {
        free(buf);
        return NULL;
    }
    *out_len = (size_t)sz;
    return buf;
}

#ifdef _WIN32
static void artifact_close_handle_or_abort(HANDLE *handle, const char *stage, const char *path);

static FILE_RENAME_INFO *artifact_rename_info_create(const wchar_t *destination,
                                                     BOOL replace_if_exists,
                                                     DWORD *out_bytes, DWORD *out_error) {
    *out_bytes = 0;
    *out_error = ERROR_SUCCESS;
    if (!destination) {
        *out_error = ERROR_INVALID_PARAMETER;
        return NULL;
    }

    size_t destination_chars = wcslen(destination);
    const size_t name_offset = offsetof(FILE_RENAME_INFO, FileName);
    const size_t alignment = sizeof(void *);
    const size_t fixed_bytes = name_offset + sizeof(wchar_t) + (alignment - 1U);
    if (fixed_bytes > UINT32_MAX ||
        destination_chars > (UINT32_MAX - fixed_bytes) / sizeof(wchar_t)) {
        *out_error = ERROR_BUFFER_OVERFLOW;
        return NULL;
    }

    size_t destination_bytes = destination_chars * sizeof(wchar_t);
    size_t raw_bytes = name_offset + destination_bytes + sizeof(wchar_t);
    size_t buffer_bytes = ((raw_bytes + alignment - 1U) / alignment) * alignment;
    FILE_RENAME_INFO *rename_info = calloc(1, buffer_bytes);
    if (!rename_info) {
        *out_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    rename_info->ReplaceIfExists = replace_if_exists;
    rename_info->RootDirectory = NULL;
    rename_info->FileNameLength = (DWORD)destination_bytes;
    memcpy(rename_info->FileName, destination, destination_bytes);
    *out_bytes = (DWORD)buffer_bytes;
    return rename_info;
}

static bool artifact_remove_file_exact(const char *path, artifact_file_error_t *out_err,
                                       const char *failure) {
    unsigned long before_error = 0;
    cbm_path_probe_result_t before = cbm_path_probe(path, &before_error);
    if (before == CBM_PATH_PROBE_ABSENT) {
        return true;
    }
    if (before == CBM_PATH_PROBE_ERROR) {
        file_error_set(out_err, failure, (int)before_error);
        return false;
    }
    errno = 0;
    if (cbm_unlink(path) != 0) {
        file_error_set(out_err, failure, errno);
        return false;
    }
    unsigned long after_error = 0;
    cbm_path_probe_result_t after = cbm_path_probe(path, &after_error);
    if (after != CBM_PATH_PROBE_ABSENT) {
        file_error_set(out_err, failure,
                       after == CBM_PATH_PROBE_ERROR ? (int)after_error : ERROR_FILE_EXISTS);
        return false;
    }
    return true;
}
#endif

/* Write buffer to file atomically (write to tmp, rename). Returns 0 on success. */
static int write_file_atomic(const char *path, const char *data, size_t len,
                             artifact_file_error_t *out_err) {
    file_error_clear(out_err);

    char tmp[CBM_SZ_4K];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        file_error_set(out_err, "path_too_long", 0);
        return CBM_NOT_FOUND;
    }

#ifdef _WIN32
    DWORD tmp_error = ERROR_SUCCESS;
    DWORD destination_error = ERROR_SUCCESS;
    wchar_t *wide_tmp = cbm_utf8_to_wide_path_checked(tmp, &tmp_error);
    wchar_t *wide_destination = cbm_utf8_to_wide_path_checked(path, &destination_error);
    if (!wide_tmp || !wide_destination) {
        free(wide_tmp);
        free(wide_destination);
        file_error_set(out_err, "path_utf16_conversion_failed",
                       (int)(tmp_error ? tmp_error : destination_error));
        return CBM_NOT_FOUND;
    }
    HANDLE output = CreateFileW(wide_tmp, GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL,
                                CREATE_NEW,
                                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(wide_tmp);
        free(wide_destination);
        file_error_set(out_err, "create_exclusive_temp", (int)error);
        return CBM_NOT_FOUND;
    }

    bool wrote_all = true;
    DWORD write_error = ERROR_SUCCESS;
    size_t offset = 0;
    while (offset < len) {
        size_t remaining = len - offset;
        DWORD requested =
            remaining > (size_t)(64 * 1024) ? (DWORD)(64 * 1024) : (DWORD)remaining;
        DWORD written = 0;
        if (!WriteFile(output, data + offset, requested, &written, NULL) || written == 0) {
            write_error = GetLastError();
            if (write_error == ERROR_SUCCESS) {
                write_error = ERROR_WRITE_FAULT;
            }
            wrote_all = false;
            break;
        }
        offset += written;
    }
    if (wrote_all && !FlushFileBuffers(output)) {
        write_error = GetLastError();
        wrote_all = false;
    }

    BY_HANDLE_FILE_INFORMATION before = {0};
    if (wrote_all &&
        (!GetFileInformationByHandle(output, &before) ||
         (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
             0 ||
         ((uint64_t)before.nFileSizeHigh << 32 | before.nFileSizeLow) != (uint64_t)len)) {
        write_error = GetLastError();
        if (write_error == ERROR_SUCCESS) {
            write_error = ERROR_CRC;
        }
        wrote_all = false;
    }
    if (!wrote_all) {
        artifact_close_handle_or_abort(&output, "atomic_write_temp_close", tmp);
        free(wide_tmp);
        free(wide_destination);
        if (!artifact_remove_file_exact(tmp, out_err, "write_temp_cleanup_failed")) {
            return CBM_NOT_FOUND;
        }
        file_error_set(out_err, "write_or_flush_temp", (int)write_error);
        return CBM_NOT_FOUND;
    }

    DWORD rename_bytes = 0;
    DWORD rename_record_error = ERROR_SUCCESS;
    FILE_RENAME_INFO *rename_info =
        artifact_rename_info_create(wide_destination, TRUE, &rename_bytes,
                                    &rename_record_error);
    if (!rename_info) {
        artifact_close_handle_or_abort(&output, "atomic_write_temp_close", tmp);
        free(wide_tmp);
        free(wide_destination);
        const char *cleanup_failure = rename_record_error == ERROR_BUFFER_OVERFLOW
                                          ? "rename_record_cleanup_failed"
                                          : "rename_allocate_cleanup_failed";
        if (!artifact_remove_file_exact(tmp, out_err, cleanup_failure)) {
            return CBM_NOT_FOUND;
        }
        file_error_set(out_err,
                       rename_record_error == ERROR_BUFFER_OVERFLOW
                           ? "rename_record_too_large"
                           : "rename_record_allocation_failed",
                       (int)rename_record_error);
        return CBM_NOT_FOUND;
    }
    free(wide_tmp);
    free(wide_destination);

    bool renamed =
        SetFileInformationByHandle(output, FileRenameInfo, rename_info, rename_bytes) != 0;
    DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
    free(rename_info);
    if (!renamed) {
        artifact_close_handle_or_abort(&output, "atomic_write_temp_close", tmp);
        if (!artifact_remove_file_exact(tmp, out_err, "rename_temp_cleanup_failed")) {
            return CBM_NOT_FOUND;
        }
        file_error_set(out_err, "rename_temp", (int)rename_error);
        return CBM_NOT_FOUND;
    }

    BY_HANDLE_FILE_INFORMATION after = {0};
    unsigned long source_probe_error = 0;
    unsigned long destination_probe_error = 0;
    cbm_path_probe_result_t source_probe = cbm_path_probe(tmp, &source_probe_error);
    cbm_path_probe_result_t destination_probe =
        cbm_path_probe(path, &destination_probe_error);
    bool identity_stable = GetFileInformationByHandle(output, &after) &&
                           before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                           before.nFileIndexHigh == after.nFileIndexHigh &&
                           before.nFileIndexLow == after.nFileIndexLow &&
                           before.nFileSizeHigh == after.nFileSizeHigh &&
                           before.nFileSizeLow == after.nFileSizeLow;
    artifact_close_handle_or_abort(&output, "atomic_write_destination_close", path);
    if (!identity_stable || source_probe != CBM_PATH_PROBE_ABSENT ||
        destination_probe != CBM_PATH_PROBE_PRESENT) {
        DWORD error = source_probe == CBM_PATH_PROBE_ERROR
                          ? (DWORD)source_probe_error
                          : destination_probe == CBM_PATH_PROBE_ERROR
                                ? (DWORD)destination_probe_error
                                : ERROR_CRC;
        file_error_set(out_err, "rename_readback_failed", (int)error);
        return CBM_NOT_FOUND;
    }
    return 0;
#else
    /* #415: cbm_fopen widens + adds "\\?\" so a temp artifact under a deep cache
     * dir is writable instead of failing at MAX_PATH. */
    FILE *fp = cbm_fopen(tmp, "wb");
    if (!fp) {
        file_error_set(out_err, "open_temp", errno);
        return CBM_NOT_FOUND;
    }

    size_t wr = fwrite(data, ART_NUL, len, fp);
    if (wr != len) {
        int saved_errno = ferror(fp) ? errno : 0;
        (void)fclose(fp);
        cbm_unlink(tmp);
        file_error_set(out_err, "write_temp", saved_errno);
        return CBM_NOT_FOUND;
    }

    if (fclose(fp) != 0) {
        int saved_errno = errno;
        cbm_unlink(tmp);
        file_error_set(out_err, "close_temp", saved_errno);
        return CBM_NOT_FOUND;
    }

    if (rename(tmp, path) != 0) {
        int saved_errno = errno;
        cbm_unlink(tmp);
        file_error_set(out_err, "rename_temp", saved_errno);
        return CBM_NOT_FOUND;
    }
    return 0;
#endif
}

#ifdef ASTRO_SPAWN
/* See artifact.h. Defence in depth (#227): the git callers below no longer use a
 * shell at all — git is spawned with an explicit argv — so this validator is not
 * what makes interpolation safe; there is no interpolation left to make safe. It
 * still refuses a repo path carrying shell metacharacters (cbm_validate_shell_arg,
 * plus the cmd.exe expansion characters % ! ^ on Windows) instead of silently
 * accepting one. A path may legitimately contain spaces: argv needs no quoting. */
#else
#ifdef _WIN32
#define ARTIFACT_NULL_DEV "NUL"
#else
#define ARTIFACT_NULL_DEV "/dev/null"
#endif

/* See artifact.h. Mirrors git_context.c's git_validate_repo_path (the best-hardened
 * git shell-out): cbm_validate_shell_arg rejects quote / backslash / substitution
 * metacharacters, and on Windows we also reject the cmd.exe expansion metacharacters
 * % ! ^. Callers then use DOUBLE quotes (honored by both POSIX sh and cmd.exe, unlike
 * single quotes on cmd.exe), so a repo path may legitimately contain spaces. */
#endif
bool cbm_artifact_repo_path_is_shell_safe(const char *repo_path) {
    if (!cbm_validate_shell_arg(repo_path)) {
        return false;
    }
#ifdef _WIN32
    for (const char *p = repo_path; *p; p++) {
        if (*p == '%' || *p == '!' || *p == '^') {
            return false;
        }
    }
#endif
    return true;
}

/* Get current git HEAD hash. buf must be >= CBM_SZ_64. Returns false on error. */
static bool git_head_hash(const char *repo_path, char *buf, size_t bufsz) {
#ifdef ASTRO_SPAWN
    if (bufsz == 0) {
#else
    char cmd[CBM_SZ_1K];
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        buf[0] = '\0';
        return false;
    }
    int n =
        snprintf(cmd, sizeof(cmd), "git -C \"%s\" rev-parse HEAD 2>" ARTIFACT_NULL_DEV, repo_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        buf[0] = '\0'; /* truncated command → don't run a malformed shell string (parity with
                          git_context.c) */
        return false;
    }
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        buf[0] = '\0';
#endif
        return false;
    }
    buf[0] = '\0';
#ifdef ASTRO_SPAWN
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return false;
    }

    /* Shell-free spawn (#227): git receives this argv verbatim. There is no
     * command string to compose (so nothing can be truncated into a malformed
     * shell line), no quoting to get right, and no `2>NUL` / `2>/dev/null`
     * suffix — cbm_spawn_capture binds the child's stderr to the null device. */
    const char *const argv[] = {"git", "-C", repo_path, "rev-parse", "HEAD", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0) {
        /* A non-zero git status just means "no HEAD here"; anything else is a
         * real degradation and is labelled rather than swallowed. */
        if (err.code != CBM_SPAWN_E_EXIT) {
            cbm_log_warn("artifact.git_head.spawn_failed", "code", err.code_name, "message",
                         err.message, "remediation", err.remediation);
#else
    if (fgets(buf, (int)bufsz, fp)) {
        /* Strip trailing newline */
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - ART_NUL] == '\n' || buf[len - ART_NUL] == '\r')) {
            buf[--len] = '\0';
#endif
        }
#ifdef ASTRO_SPAWN
        free(data);
        return false;
#endif
    }
#ifdef ASTRO_SPAWN

    size_t line = 0;
    while (line < len && data[line] != '\n' && data[line] != '\r') {
        line++;
    }
    if (line >= bufsz) {
        line = bufsz - ART_NUL;
    }
    memcpy(buf, data, line);
    buf[line] = '\0';
    free(data);
#else
    (void)cbm_pclose(fp);
#endif
    return buf[0] != '\0';
}

/* Generate ISO 8601 timestamp into buf. */
static void iso_timestamp(char *buf, size_t bufsz) {
    time_t now = time(NULL);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    (void)strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ── Metadata read/write ─────────────────────────────────────────── */

static const char *CBM_ARTIFACT_FORMAT = "cbm.graph-artifact.v2";

typedef struct {
    int schema_version;
    int nodes;
    int edges;
    size_t original_size;
    size_t compressed_size;
    char project[CBM_SZ_1K];
    char compressed_sha256[CBM_SHA256_HEX_LEN + 1];
    char database_sha256[CBM_SHA256_HEX_LEN + 1];
} artifact_metadata_t;

static bool artifact_sha256_is_exact(const char *value) {
    if (!value || strlen(value) != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool read_artifact_metadata(const char *repo_path, artifact_metadata_t *metadata) {
    memset(metadata, 0, sizeof(*metadata));
    char meta_path[CBM_SZ_4K];
    if (!artifact_path(meta_path, sizeof(meta_path), repo_path, CBM_ARTIFACT_META)) {
        return false;
    }

    size_t len = 0;
    char *json = read_file_alloc(meta_path, &len);
    if (!json) {
        return false;
    }

    yyjson_doc *doc = yyjson_read(json, len, 0);
    free(json);
    if (!doc) {
        return false;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *format = yyjson_obj_get(root, "artifact_format");
    yyjson_val *schema = yyjson_obj_get(root, "schema_version");
    yyjson_val *project = yyjson_obj_get(root, "project");
    yyjson_val *nodes = yyjson_obj_get(root, "nodes");
    yyjson_val *edges = yyjson_obj_get(root, "edges");
    yyjson_val *original_size = yyjson_obj_get(root, "original_size");
    yyjson_val *compressed_size = yyjson_obj_get(root, "compressed_size");
    yyjson_val *compressed_sha256 = yyjson_obj_get(root, "graph_db_zst_sha256");
    yyjson_val *database_sha256 = yyjson_obj_get(root, "graph_db_sha256");
    const char *format_text = format ? yyjson_get_str(format) : NULL;
    const char *project_text = project ? yyjson_get_str(project) : NULL;
    const char *compressed_hash = compressed_sha256 ? yyjson_get_str(compressed_sha256) : NULL;
    const char *database_hash = database_sha256 ? yyjson_get_str(database_sha256) : NULL;
    uint64_t original = original_size ? yyjson_get_uint(original_size) : 0;
    uint64_t compressed = compressed_size ? yyjson_get_uint(compressed_size) : 0;
    uint64_t node_count = nodes ? yyjson_get_uint(nodes) : UINT64_MAX;
    uint64_t edge_count = edges ? yyjson_get_uint(edges) : UINT64_MAX;
    uint64_t schema_version = schema ? yyjson_get_uint(schema) : UINT64_MAX;
    bool valid = yyjson_is_obj(root) && yyjson_is_uint(schema) && yyjson_is_uint(nodes) &&
                 yyjson_is_uint(edges) && yyjson_is_uint(original_size) &&
                 yyjson_is_uint(compressed_size) && format_text &&
                 strcmp(format_text, CBM_ARTIFACT_FORMAT) == 0 &&
                 schema_version == (uint64_t)CBM_GRAPH_SCHEMA_VERSION && project_text &&
                 cbm_validate_project_name(project_text) &&
                 strlen(project_text) < sizeof(metadata->project) && node_count <= INT_MAX &&
                 edge_count <= INT_MAX &&
                 original > 0 && original <= SIZE_MAX && compressed > 0 &&
                 compressed <= SIZE_MAX && artifact_sha256_is_exact(compressed_hash) &&
                 artifact_sha256_is_exact(database_hash);
    if (valid) {
        metadata->schema_version = (int)schema_version;
        metadata->nodes = (int)node_count;
        metadata->edges = (int)edge_count;
        metadata->original_size = (size_t)original;
        metadata->compressed_size = (size_t)compressed;
        snprintf(metadata->project, sizeof(metadata->project), "%s", project_text);
        snprintf(metadata->compressed_sha256, sizeof(metadata->compressed_sha256), "%s",
                 compressed_hash);
        snprintf(metadata->database_sha256, sizeof(metadata->database_sha256), "%s",
                 database_hash);
    }
    yyjson_doc_free(doc);
    return valid;
}

/* Write artifact.json metadata. */
static int write_metadata(const char *repo_path, const char *project_name, int nodes, int edges,
                           size_t original_size, size_t compressed_size, int compression_level,
                           const char *compressed_sha256, const char *database_sha256) {
    char commit[CBM_SZ_64] = "";
    git_head_hash(repo_path, commit, sizeof(commit));

    char ts[CBM_SZ_64];
    iso_timestamp(ts, sizeof(ts));

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return artifact_export_fail("write_metadata", NULL, "json_document_allocation_failed",
                                    0);
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    if (!root) {
        yyjson_mut_doc_free(doc);
        return artifact_export_fail("write_metadata", NULL, "json_root_allocation_failed", 0);
    }
    yyjson_mut_doc_set_root(doc, root);

    bool metadata_complete =
        yyjson_mut_obj_add_str(doc, root, "artifact_format", CBM_ARTIFACT_FORMAT) &&
        yyjson_mut_obj_add_int(doc, root, "schema_version", CBM_GRAPH_SCHEMA_VERSION) &&
        yyjson_mut_obj_add_str(doc, root, "commit", commit) &&
        yyjson_mut_obj_add_str(doc, root, "indexed_at", ts) &&
        yyjson_mut_obj_add_str(doc, root, "project", project_name) &&
        yyjson_mut_obj_add_int(doc, root, "nodes", nodes) &&
        yyjson_mut_obj_add_int(doc, root, "edges", edges) &&
        yyjson_mut_obj_add_uint(doc, root, "original_size", (uint64_t)original_size) &&
        yyjson_mut_obj_add_uint(doc, root, "compressed_size", (uint64_t)compressed_size) &&
        yyjson_mut_obj_add_int(doc, root, "compression_level", compression_level) &&
        yyjson_mut_obj_add_str(doc, root, "graph_db_zst_sha256", compressed_sha256) &&
        yyjson_mut_obj_add_str(doc, root, "graph_db_sha256", database_sha256);
    if (!metadata_complete) {
        yyjson_mut_doc_free(doc);
        return artifact_export_fail("write_metadata", NULL, "json_field_allocation_failed", 0);
    }

    size_t json_len = 0;
    char *json = yyjson_mut_write(doc, YYJSON_WRITE_PRETTY, &json_len);
    yyjson_mut_doc_free(doc);
    if (!json) {
        return artifact_export_fail("write_metadata", NULL, "json_encode", 0);
    }

    char meta_path[CBM_SZ_4K];
    if (!artifact_path(meta_path, sizeof(meta_path), repo_path, CBM_ARTIFACT_META)) {
        free(json);
        return artifact_export_fail("write_metadata", repo_path, "path_too_long", 0);
    }
    artifact_file_error_t ioerr;
    int rc = write_file_atomic(meta_path, json, json_len, &ioerr);
    free(json);
    if (rc != 0) {
        return artifact_export_fail("write_metadata", meta_path, ioerr.err, ioerr.err_no);
    }
    return rc;
}

/* ── .gitattributes setup ────────────────────────────────────────── */

static void ensure_gitattributes(const char *repo_path) {
    char ga_path[CBM_SZ_4K];
    artifact_path(ga_path, sizeof(ga_path), repo_path, ".gitattributes");

    /* Atomic create-only-if-absent: O_EXCL closes the TOCTOU window
     * between checking existence and writing. If the file exists, open
     * fails with EEXIST and we leave it untouched. */
    int fd = open(ga_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno != EEXIST) {
            cbm_log_warn("artifact.gitattributes.open path=%s err=%s", ga_path, strerror(errno));
        }
        /* fall through to merge driver setup either way */
    } else {
        FILE *fp = fdopen(fd, "w");
        if (fp) {
            (void)fputs("# Auto-generated by codebase-memory-mcp\n"
                        "# Prevent merge conflicts on compressed artifact\n" CBM_ARTIFACT_FILENAME
                        " merge=ours binary\n",
                        fp);
            (void)fclose(fp);
        } else {
            (void)close(fd);
        }
    }

    /* Best-effort: configure merge driver */
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return;
    }
#ifdef ASTRO_SPAWN

    /* Shell-free spawn (#227). */
    const char *const argv[] = {"git",  "-C", repo_path, "config", "merge.ours.driver",
                                "true", NULL};
    char *data = NULL;
    size_t len = 0;
    cbm_spawn_error_t err;
    if (cbm_spawn_capture(argv, &data, &len, &err) != 0 && err.code != CBM_SPAWN_E_EXIT) {
        cbm_log_warn("artifact.merge_driver.spawn_failed", "code", err.code_name, "message",
                     err.message, "remediation", err.remediation);
#else
    char cmd[CBM_SZ_1K];
    int n = snprintf(cmd, sizeof(cmd),
                     "git -C \"%s\" config merge.ours.driver true 2>" ARTIFACT_NULL_DEV, repo_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return; /* truncated command → skip (parity with git_context.c) */
#endif
    }
#ifdef ASTRO_SPAWN
    free(data);
#else
    FILE *p = cbm_popen(cmd, "r");
    if (p) {
        (void)cbm_pclose(p);
    }
#endif
}

/* ── Index stripping ─────────────────────────────────────────────── */

/* SQL to drop all user-created indexes (not autoindexes, not FTS5). */
static const char *DROP_INDEXES_SQL = "DROP INDEX IF EXISTS idx_nodes_label;"
                                      "DROP INDEX IF EXISTS idx_nodes_name;"
                                      "DROP INDEX IF EXISTS idx_nodes_file;"
                                      "DROP INDEX IF EXISTS idx_edges_source;"
                                      "DROP INDEX IF EXISTS idx_edges_target;"
                                      "DROP INDEX IF EXISTS idx_edges_type;"
                                      "DROP INDEX IF EXISTS idx_edges_target_type;"
                                      "DROP INDEX IF EXISTS idx_edges_source_type;"
                                      "DROP INDEX IF EXISTS idx_edges_url_path;";

/* ── Export helpers ───────────────────────────────────────────────── */

static bool artifact_close_snapshot_store(cbm_store_t **store, const char *path) {
    cbm_store_close_result_t close_result;
    cbm_store_close_status_t close_status = cbm_store_close(store, &close_result);
    if (close_status == CBM_STORE_CLOSE_OK && close_result.connection_destroyed && !*store) {
        return true;
    }
    artifact_export_fail("snapshot_close", path, "exact_physical_close_failed", 0);
    if (!close_result.connection_destroyed || *store) {
        /* No API above artifact export can retain this scratch-store owner.
         * Terminate instead of returning while SQLite still owns it. */
        fflush(NULL);
        abort();
    }
    return false;
}

static bool artifact_snapshot_exec(cbm_store_t *store, const char *path, const char *stage,
                                   const char *sql) {
    cbm_store_clear_error(store);
    if (cbm_store_exec(store, sql) == CBM_STORE_OK) {
        return true;
    }

    int sqlite_error = cbm_store_error_code(store);
    const char *sqlite_detail = cbm_store_error(store);
    snprintf(g_export_error, sizeof(g_export_error),
             "%s: sqlite_error=%d detail=%s path=%s", stage, sqlite_error,
             sqlite_detail ? sqlite_detail : "SQLite execution failed", path ? path : "");
    cbm_log_error("artifact.export", "stage", stage, "err", "sqlite_execution_failed",
                  "sqlite_error", itoa_buf(sqlite_error), "sqlite_detail",
                  sqlite_detail ? sqlite_detail : "SQLite execution failed", "path",
                  path ? path : "");
    return false;
}

static bool artifact_sidecars_absent_exact(const char *db_path, const char *stage) {
    char wal_path[CBM_SZ_4K];
    char shm_path[CBM_SZ_4K];
    int wal_len = snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    int shm_len = snprintf(shm_path, sizeof(shm_path), "%s-shm", db_path);
    if (wal_len < 0 || (size_t)wal_len >= sizeof(wal_path) || shm_len < 0 ||
        (size_t)shm_len >= sizeof(shm_path)) {
        artifact_export_fail(stage, db_path, "family_path_too_long", 0);
        return false;
    }

    unsigned long wal_error = 0;
    unsigned long shm_error = 0;
    cbm_path_probe_result_t wal_probe = cbm_path_probe(wal_path, &wal_error);
    cbm_path_probe_result_t shm_probe = cbm_path_probe(shm_path, &shm_error);
    if (wal_probe != CBM_PATH_PROBE_ABSENT || shm_probe != CBM_PATH_PROBE_ABSENT) {
        unsigned long error = wal_probe == CBM_PATH_PROBE_ERROR ? wal_error : shm_error;
        artifact_export_fail(stage, db_path,
                             "wal_or_shm_present_or_exact_absence_unevaluable", (int)error);
        return false;
    }
    return true;
}

static bool artifact_remove_closed_scratch(const char *db_path, const char *stage) {
    if (!artifact_sidecars_absent_exact(db_path, stage)) {
        return false;
    }
    errno = 0;
    if (cbm_unlink(db_path) != 0) {
        artifact_export_fail(stage, db_path, "closed_scratch_remove_failed", errno);
        return false;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(db_path, &probe_error);
    if (probe != CBM_PATH_PROBE_ABSENT) {
        artifact_export_fail(stage, db_path, "closed_scratch_absence_not_proven",
                             probe == CBM_PATH_PROBE_ERROR ? (int)probe_error : 0);
        return false;
    }
    return true;
}

static cbm_artifact_import_status_t artifact_import_fail_and_remove_private(
    cbm_artifact_import_result_t *result, const char *source_path, const char *operation,
    const char *detail) {
    if (!artifact_remove_closed_scratch(source_path, "import_publish_private_cleanup")) {
        return artifact_import_fail(
            result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
            "import_publish_private_cleanup",
            "publication did not start and the exact private database could not be removed");
    }
    return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION, operation,
                                detail);
}

#ifdef _WIN32
static void artifact_close_handle_or_abort(HANDLE *handle, const char *stage, const char *path) {
    if (!handle || *handle == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!CloseHandle(*handle)) {
        DWORD error = GetLastError();
        artifact_export_fail(stage, path, "exact_windows_handle_close_failed", (int)error);
        fflush(NULL);
        abort();
    }
    *handle = INVALID_HANDLE_VALUE;
}
#endif

static cbm_artifact_import_status_t artifact_publish_import_noreplace(
    const char *source_path, const char *destination_path,
    cbm_artifact_import_result_t *result) {
#ifdef _WIN32
    DWORD source_error = ERROR_SUCCESS;
    DWORD destination_error = ERROR_SUCCESS;
    wchar_t *wide_source = cbm_utf8_to_wide_path_checked(source_path, &source_error);
    wchar_t *wide_destination =
        cbm_utf8_to_wide_path_checked(destination_path, &destination_error);
    if (!wide_source || !wide_destination) {
        free(wide_source);
        free(wide_destination);
        artifact_export_fail("import_publish_path", destination_path, "utf16_conversion_failed",
                             (int)(source_error ? source_error : destination_error));
        return artifact_import_fail_and_remove_private(
            result, source_path, "import_publish_path", "utf16_conversion_failed");
    }

    HANDLE source = CreateFileW(
        wide_source, GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD open_error = source == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    free(wide_source);
    if (source == INVALID_HANDLE_VALUE) {
        free(wide_destination);
        artifact_export_fail("import_publish_noreplace", destination_path,
                             "exclusive_source_handle_open_failed", (int)open_error);
        return artifact_import_fail_and_remove_private(
            result, source_path, "import_publish_noreplace",
            "exclusive_source_handle_open_failed");
    }

    BY_HANDLE_FILE_INFORMATION before = {0};
    if (!GetFileInformationByHandle(source, &before) ||
        (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
            0 ||
        !FlushFileBuffers(source)) {
        DWORD error = GetLastError();
        free(wide_destination);
        artifact_close_handle_or_abort(&source, "import_publish_source_close", source_path);
        artifact_export_fail("import_publish_source_inspect", source_path,
                             "ordinary_file_identity_or_flush_failed", (int)error);
        return artifact_import_fail_and_remove_private(
            result, source_path, "import_publish_source_inspect",
            "ordinary_file_identity_or_flush_failed");
    }

    DWORD rename_bytes = 0;
    DWORD rename_record_error = ERROR_SUCCESS;
    FILE_RENAME_INFO *rename_info =
        artifact_rename_info_create(wide_destination, FALSE, &rename_bytes,
                                    &rename_record_error);
    if (!rename_info) {
        free(wide_destination);
        artifact_close_handle_or_abort(&source, "import_publish_source_close", source_path);
        const char *operation = rename_record_error == ERROR_BUFFER_OVERFLOW
                                    ? "import_publish_path"
                                    : "import_publish_allocate";
        const char *detail = rename_record_error == ERROR_BUFFER_OVERFLOW
                                 ? "destination_rename_record_too_large"
                                 : "rename_record_allocation_failed";
        artifact_export_fail(operation, destination_path, detail, (int)rename_record_error);
        return artifact_import_fail_and_remove_private(
            result, source_path, operation, detail);
    }
    free(wide_destination);

    bool renamed =
        SetFileInformationByHandle(source, FileRenameInfo, rename_info, rename_bytes) != 0;
    DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
    free(rename_info);
    if (!renamed) {
        artifact_close_handle_or_abort(&source, "import_publish_source_close", source_path);
        artifact_export_fail("import_publish_noreplace", destination_path,
                             "handle_bound_atomic_noreplace_rename_failed", (int)rename_error);
        return artifact_import_fail_and_remove_private(
            result, source_path, "import_publish_noreplace",
            "handle_bound_atomic_noreplace_rename_failed");
    }
    result->publication_started = 1;

    BY_HANDLE_FILE_INFORMATION after = {0};
    unsigned long source_probe_error = 0;
    unsigned long destination_probe_error = 0;
    cbm_path_probe_result_t source_probe = cbm_path_probe(source_path, &source_probe_error);
    cbm_path_probe_result_t destination_probe =
        cbm_path_probe(destination_path, &destination_probe_error);
    bool identity_stable = GetFileInformationByHandle(source, &after) &&
                           before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                           before.nFileIndexHigh == after.nFileIndexHigh &&
                           before.nFileIndexLow == after.nFileIndexLow &&
                           before.nFileSizeHigh == after.nFileSizeHigh &&
                           before.nFileSizeLow == after.nFileSizeLow;
    bool readback_ok = identity_stable && source_probe == CBM_PATH_PROBE_ABSENT &&
                       destination_probe == CBM_PATH_PROBE_PRESENT &&
                       artifact_sidecars_absent_exact(destination_path,
                                                      "import_publish_sidecars");
    artifact_close_handle_or_abort(&source, "import_publish_destination_close",
                                   destination_path);
    if (!readback_ok) {
        unsigned long error = source_probe == CBM_PATH_PROBE_ERROR
                                  ? source_probe_error
                                  : destination_probe == CBM_PATH_PROBE_ERROR
                                        ? destination_probe_error
                                        : ERROR_CRC;
        artifact_export_fail("import_publish_readback", destination_path,
                             "handle_identity_path_or_sidecar_contract_failed", (int)error);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_AFTER_PUBLICATION,
                                    "import_publish_readback",
                                    "handle_identity_path_or_sidecar_contract_failed");
    }
    result->publication_committed = 1;
    result->destination_probe = CBM_PATH_PROBE_PRESENT;
    result->destination_probe_native_error = 0;
    return CBM_ARTIFACT_IMPORT_OK;
#else
    if (link(source_path, destination_path) != 0 || cbm_unlink(source_path) != 0) {
        artifact_export_fail("import_publish_noreplace", destination_path,
                             "atomic_noreplace_link_or_source_unlink_failed", errno);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import_publish_noreplace",
                                    "atomic_noreplace_link_or_source_unlink_failed");
    }
    result->publication_started = 1;

    unsigned long source_probe_error = 0;
    unsigned long destination_probe_error = 0;
    cbm_path_probe_result_t source_probe = cbm_path_probe(source_path, &source_probe_error);
    cbm_path_probe_result_t destination_probe =
        cbm_path_probe(destination_path, &destination_probe_error);
    if (source_probe != CBM_PATH_PROBE_ABSENT ||
        destination_probe != CBM_PATH_PROBE_PRESENT ||
        !artifact_sidecars_absent_exact(destination_path, "import_publish_sidecars")) {
        unsigned long error = source_probe == CBM_PATH_PROBE_ERROR
                                  ? source_probe_error
                                  : destination_probe == CBM_PATH_PROBE_ERROR
                                        ? destination_probe_error
                                        : 0;
        artifact_export_fail("import_publish_readback", destination_path,
                             "source_absence_destination_presence_or_sidecar_contract_failed",
                             (int)error);
        return artifact_import_fail(
            result, CBM_ARTIFACT_IMPORT_FAILED_AFTER_PUBLICATION, "import_publish_readback",
            "source_absence_destination_presence_or_sidecar_contract_failed");
    }
    result->publication_committed = 1;
    result->destination_probe = CBM_PATH_PROBE_PRESENT;
    result->destination_probe_native_error = 0;
    return CBM_ARTIFACT_IMPORT_OK;
#endif
}

#ifdef _WIN32
static char *copy_frozen_delete_source(const char *db_path, const char *snapshot_path,
                                       size_t *out_size) {
    if (!artifact_sidecars_absent_exact(db_path, "freeze_source_sidecars")) {
        return NULL;
    }

    unsigned long probe_error = 0;
    wchar_t *wide = cbm_utf8_to_wide_path_checked(db_path, &probe_error);
    if (!wide) {
        artifact_export_fail("freeze_source_path", db_path, "utf16_conversion_failed",
                             (int)probe_error);
        return NULL;
    }
    /* A zero share mask is the durable publication barrier: an existing reader,
     * writer, mapping, or deleter prevents this open, and no new family user can
     * enter until the exact source bytes have been copied and checked. */
    HANDLE source = CreateFileW(wide, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                                    FILE_FLAG_OPEN_REPARSE_POINT,
                                NULL);
    DWORD open_error = source == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    free(wide);
    if (source == INVALID_HANDLE_VALUE) {
        artifact_export_fail("freeze_source_open", db_path, "exclusive_read_open_failed",
                             (int)open_error);
        return NULL;
    }

    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    LARGE_INTEGER length = {0};
    if (!GetFileInformationByHandleEx(source, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileSizeEx(source, &length) || length.QuadPart <= 0 ||
        (uint64_t)length.QuadPart > (uint64_t)INT_MAX) {
        DWORD error = GetLastError();
        artifact_close_handle_or_abort(&source, "freeze_source_inspect_close", db_path);
        artifact_export_fail("freeze_source_inspect", db_path,
                             (uint64_t)length.QuadPart > (uint64_t)INT_MAX
                                 ? "source_exceeds_current_2GiB_export_abi_issue_948"
                                 : "source_is_not_one_bounded_ordinary_file",
                             (int)error);
        return NULL;
    }

    size_t size = (size_t)length.QuadPart;
    char *data = malloc(size);
    if (!data) {
        artifact_close_handle_or_abort(&source, "freeze_source_allocate_close", db_path);
        artifact_export_fail("freeze_source_allocate", db_path, "source_buffer_allocation_failed",
                             ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    size_t offset = 0;
    DWORD read_error = ERROR_SUCCESS;
    while (offset < size) {
        DWORD request = (DWORD)((size - offset) > (size_t)(64 * 1024 * 1024)
                                      ? (64 * 1024 * 1024)
                                      : (size - offset));
        DWORD got = 0;
        if (!ReadFile(source, data + offset, request, &got, NULL) || got == 0) {
            read_error = GetLastError();
            if (read_error == ERROR_SUCCESS) {
                read_error = ERROR_HANDLE_EOF;
            }
            break;
        }
        offset += got;
    }
    if (read_error == ERROR_SUCCESS &&
        (size < 20 || (unsigned char)data[18] != 1 || (unsigned char)data[19] != 1)) {
        read_error = ERROR_INVALID_DATA;
    }
    artifact_close_handle_or_abort(&source, "freeze_source_read_close", db_path);
    if (read_error != ERROR_SUCCESS || offset != size) {
        free(data);
        artifact_export_fail("freeze_source_read", db_path,
                             "source_read_header_or_sidecar_contract_failed", (int)read_error);
        return NULL;
    }

    artifact_file_error_t ioerr;
    if (write_file_atomic(snapshot_path, data, size, &ioerr) != 0) {
        free(data);
        artifact_export_fail("snapshot_publish", snapshot_path, ioerr.err, ioerr.err_no);
        return NULL;
    }
    *out_size = size;
    return data;
}
#endif

/* Copy one DELETE-mode authoritative DB while a deny-write/delete handle binds
 * its bytes, then derive counts and optional index stripping only from that
 * private copy. The live source is never opened through SQLite. */
static char *prepare_export_snapshot(const char *db_path, const char *project_name, int quality,
                                     size_t *out_size, int *out_nodes, int *out_edges) {
#ifndef _WIN32
    (void)db_path;
    (void)project_name;
    (void)quality;
    (void)out_size;
    (void)out_nodes;
    (void)out_edges;
    artifact_export_fail("snapshot_platform", NULL, "native_windows_required", 0);
    return NULL;
#else
    static volatile LONG snapshot_sequence;
    LONG sequence = InterlockedIncrement(&snapshot_sequence);
    char snapshot_path[CBM_SZ_4K];
    int path_len = snprintf(snapshot_path, sizeof(snapshot_path),
                            "%s/cbm-artifact-export.pid-%lu.seq-%ld.db", cbm_tmpdir(),
                            (unsigned long)GetCurrentProcessId(), (long)sequence);
    if (path_len < 0 || (size_t)path_len >= sizeof(snapshot_path) ||
        cbm_path_exists(snapshot_path)) {
        artifact_export_fail("snapshot_path", snapshot_path,
                             "unique_snapshot_path_unavailable", 0);
        return NULL;
    }

    size_t source_size = 0;
    char *source_data = copy_frozen_delete_source(db_path, snapshot_path, &source_size);
    if (!source_data) {
        return NULL;
    }
    free(source_data);

    cbm_store_t *snapshot = NULL;
    cbm_store_verify_result_t verification;
    cbm_store_verify_status_t verify_status = cbm_store_open_path_project_writer_existing(
        snapshot_path, project_name, &snapshot, &verification);
    if (verify_status != CBM_STORE_VERIFY_OK || !snapshot) {
        if (snapshot) {
            (void)artifact_close_snapshot_store(&snapshot, snapshot_path);
        }
        artifact_export_fail("snapshot_verify", snapshot_path,
                             verification.detail[0] ? verification.detail
                                                    : "snapshot_writer_verification_failed",
                             0);
        if (!snapshot) {
            (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_verify_cleanup");
        }
        return NULL;
    }

    /* Keep snapshot maintenance ahead of all query-statement preparation so
     * its connection state and diagnostics are isolated from later metadata
     * reads. Execute and diagnose each maintenance boundary independently;
     * there is no skip or retry. */
    bool stripped = true;
    if (quality == CBM_ARTIFACT_BEST) {
        stripped = artifact_snapshot_exec(snapshot, snapshot_path,
                                          "snapshot_strip.drop_indexes", DROP_INDEXES_SQL);
        if (stripped) {
            stripped = artifact_snapshot_exec(snapshot, snapshot_path, "snapshot_strip.vacuum",
                                              "VACUUM;");
        }
        if (stripped) {
            stripped = artifact_snapshot_exec(snapshot, snapshot_path, "snapshot_strip.optimize",
                                              "PRAGMA optimize;");
        }
    }
    if (!stripped) {
        (void)artifact_close_snapshot_store(&snapshot, snapshot_path);
        if (!snapshot) {
            (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_strip_cleanup");
        }
        return NULL;
    }

    int nodes = cbm_store_count_nodes(snapshot, project_name);
    if (nodes < 0) {
        const char *detail = cbm_store_error(snapshot);
        int sqlite_error = cbm_store_error_code(snapshot);
        char count_error[CBM_SZ_512];
        snprintf(count_error, sizeof(count_error), "sqlite_error=%d detail=%s", sqlite_error,
                 detail ? detail : "node count query failed");
        (void)artifact_close_snapshot_store(&snapshot, snapshot_path);
        artifact_export_fail("snapshot_counts.nodes", snapshot_path, count_error, 0);
        if (!snapshot) {
            (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_counts_cleanup");
        }
        return NULL;
    }
    int edges = cbm_store_count_edges(snapshot, project_name);
    if (edges < 0) {
        const char *detail = cbm_store_error(snapshot);
        int sqlite_error = cbm_store_error_code(snapshot);
        char count_error[CBM_SZ_512];
        snprintf(count_error, sizeof(count_error), "sqlite_error=%d detail=%s", sqlite_error,
                 detail ? detail : "edge count query failed");
        (void)artifact_close_snapshot_store(&snapshot, snapshot_path);
        artifact_export_fail("snapshot_counts.edges", snapshot_path, count_error, 0);
        if (!snapshot) {
            (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_counts_cleanup");
        }
        return NULL;
    }
    cbm_store_normalize_result_t normalization;
    bool normalized = cbm_store_normalize_journal_mode_delete(snapshot, &normalization) ==
                      CBM_STORE_NORMALIZE_OK;
    bool integrity_ok = normalized && cbm_store_check_integrity(snapshot);
    bool close_ok = artifact_close_snapshot_store(&snapshot, snapshot_path);
    if (!normalized || !integrity_ok || !close_ok) {
        if (close_ok) {
            artifact_export_fail("snapshot_finalize", snapshot_path,
                                 !normalized ? "journal_normalization_failed"
                                             : "post_normalization_integrity_failed",
                                 0);
        }
        if (!snapshot) {
            (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_finalize_cleanup");
        }
        return NULL;
    }

    if (!artifact_sidecars_absent_exact(snapshot_path, "snapshot_sidecar_readback")) {
        return NULL;
    }

    char *artifact_data = read_file_alloc(snapshot_path, out_size);
    if (!artifact_data || *out_size == 0) {
        free(artifact_data);
        artifact_export_fail("snapshot_readback", snapshot_path, "empty_or_unreadable", errno);
        (void)artifact_remove_closed_scratch(snapshot_path, "snapshot_readback_cleanup");
        return NULL;
    }
    if (!artifact_remove_closed_scratch(snapshot_path, "snapshot_cleanup")) {
        free(artifact_data);
        return NULL;
    }
    *out_nodes = nodes;
    *out_edges = edges;
    (void)source_size;
    return artifact_data;
#endif
}

/* ── Export ───────────────────────────────────────────────────────── */

int cbm_artifact_export(const char *db_path, const char *repo_path, const char *project_name,
                        int quality) {
    clear_export_error();

    if (!db_path || !repo_path || !project_name) {
        return artifact_export_fail("validate_args", NULL, "missing_argument", 0);
    }

    /* Ensure .codebase-memory/ directory exists */
    char art_dir[CBM_SZ_4K];
    int dir_len = snprintf(art_dir, sizeof(art_dir), "%s/%s", repo_path, CBM_ARTIFACT_DIR);
    if (dir_len < 0 || (size_t)dir_len >= sizeof(art_dir)) {
        return artifact_export_fail("prepare_artifact_dir", repo_path, "path_too_long", 0);
    }
    errno = 0;
    if (!cbm_mkdir_p(art_dir, ART_DIR_PERMS)) {
        return artifact_export_fail("prepare_artifact_dir", art_dir, "mkdir_or_not_directory",
                                    errno);
    }
    if (!cbm_is_dir(art_dir)) {
        return artifact_export_fail("prepare_artifact_dir", art_dir, "not_directory", 0);
    }

    size_t db_size = 0;
    int nodes = 0;
    int edges = 0;
    int compression_level = quality == CBM_ARTIFACT_BEST ? ART_ZSTD_BEST : ART_ZSTD_FAST;
    char *db_data = prepare_export_snapshot(db_path, project_name, quality, &db_size, &nodes,
                                            &edges);

    if (!db_data || db_size == 0) {
        free(db_data);
        if (cbm_artifact_export_last_error()) {
            return CBM_NOT_FOUND;
        }
        return artifact_export_fail("read_db", db_path, "empty_or_unreadable", errno);
    }
    char database_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(db_data, db_size, database_sha256);

    /* Compress with zstd */
    size_t bound = cbm_zstd_compress_bound((int)db_size);
    if (bound == 0 || bound > (size_t)INT_MAX) {
        free(db_data);
        return artifact_export_fail("compress_bound", db_path,
                                    "compressed_bound_exceeds_current_2GiB_abi_issue_948", 0);
    }
    char *compressed = malloc(bound);
    if (!compressed) {
        free(db_data);
        return artifact_export_fail("compress", NULL, "alloc_compressed_buffer", 0);
    }

    int clen = cbm_zstd_compress(db_data, (int)db_size, compressed, (int)bound, compression_level);
    free(db_data);

    if (clen <= 0) {
        free(compressed);
        return artifact_export_fail("compress", NULL, "zstd_compress", 0);
    }
    char compressed_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(compressed, (size_t)clen, compressed_sha256);

    /* Write compressed artifact */
    char zst_path[CBM_SZ_4K];
    if (!artifact_path(zst_path, sizeof(zst_path), repo_path, CBM_ARTIFACT_FILENAME)) {
        free(compressed);
        return artifact_export_fail("write_artifact", repo_path, "path_too_long", 0);
    }
    artifact_file_error_t ioerr;
    int wrc = write_file_atomic(zst_path, compressed, (size_t)clen, &ioerr);
    free(compressed);

    if (wrc != 0) {
        return artifact_export_fail("write_artifact", zst_path, ioerr.err, ioerr.err_no);
    }

    /* Write metadata */
    if (write_metadata(repo_path, project_name, nodes, edges, db_size, (size_t)clen,
                       compression_level, compressed_sha256, database_sha256) != 0) {
        cbm_unlink(zst_path);
        return CBM_NOT_FOUND;
    }

    /* Ensure .gitattributes for merge conflict prevention */
    ensure_gitattributes(repo_path);

    double ratio = db_size > 0 ? (double)db_size / (double)clen : 0.0;
    cbm_log_info("artifact.export", "quality", quality == CBM_ARTIFACT_BEST ? "best" : "fast",
                 "original_mb", itoa_buf((int)(db_size / ART_BYTES_PER_MB)), "compressed_mb",
                 itoa_buf((int)((size_t)clen / ART_BYTES_PER_MB)), "ratio",
                 itoa_buf((int)(ratio * ART_RATIO_SCALE)));

    return 0;
}

/* ── Import ──────────────────────────────────────────────────────── */

cbm_artifact_import_status_t cbm_artifact_import(
    const char *repo_path, const char *cache_db_path, const char *expected_project,
    cbm_artifact_import_result_t *result) {
    clear_export_error();
    if (!result) {
        return CBM_ARTIFACT_IMPORT_INVALID_ARGUMENT;
    }
    if (!artifact_import_result_init(result, cache_db_path)) {
        result->status = CBM_ARTIFACT_IMPORT_INVALID_ARGUMENT;
        cbm_log_error("artifact.import", "code", "CBM_ARTIFACT_DESTINATION_PATH_TOO_LONG",
                      "message", result->detail, "remediation",
                      "shorten the configured cache root so the exact destination path fits the ABI");
        return result->status;
    }
    if (!repo_path || !cache_db_path || !expected_project ||
        !cbm_validate_project_name(expected_project)) {
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_INVALID_ARGUMENT,
                                    "import.validate_args",
                                    "repository, destination, and valid expected project are required");
    }

    artifact_metadata_t metadata;
    if (!read_artifact_metadata(repo_path, &metadata) ||
        strcmp(metadata.project, expected_project) != 0) {
        cbm_log_error("artifact.import", "code", "CBM_ARTIFACT_METADATA_MISMATCH", "project",
                      expected_project, "message",
                      "artifact metadata is malformed, incompatible, or names a different project",
                      "remediation", "export one exact artifact generation for this project");
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.read_metadata",
                                    "metadata contract or expected project mismatch");
    }

    char zst_path[CBM_SZ_4K];
    if (!artifact_path(zst_path, sizeof(zst_path), repo_path, CBM_ARTIFACT_FILENAME)) {
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.artifact_path", "artifact path is too long");
    }
    size_t compressed_size = 0;
    char *compressed = read_file_alloc(zst_path, &compressed_size);
    if (!compressed || compressed_size != metadata.compressed_size) {
        free(compressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.read_artifact",
                                    "compressed artifact size does not match metadata");
    }
    char compressed_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(compressed, compressed_size, compressed_sha256);
    if (strcmp(compressed_sha256, metadata.compressed_sha256) != 0) {
        free(compressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.verify_compressed_hash",
                                    "compressed artifact SHA-256 does not match metadata");
    }

    size_t frame_size = cbm_zstd_frame_content_size(compressed, compressed_size);
    if (frame_size == 0 || frame_size > ART_MAX_DECOMPRESSED_BYTES ||
        frame_size != metadata.original_size) {
        free(compressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.verify_frame_size",
                                    "zstd frame size does not match bounded metadata");
    }
    char *decompressed = malloc(frame_size);
    if (!decompressed) {
        free(compressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.allocate_database",
                                    "decompressed database allocation failed");
    }
    int64_t decompressed_size =
        cbm_zstd_decompress(compressed, compressed_size, decompressed, frame_size);
    free(compressed);
    if (decompressed_size <= 0 || (size_t)decompressed_size != frame_size) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.decompress",
                                    "zstd decompression did not produce the exact declared bytes");
    }
    char database_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(decompressed, frame_size, database_sha256);
    if (strcmp(database_sha256, metadata.database_sha256) != 0) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.verify_database_hash",
                                    "decompressed database SHA-256 does not match metadata");
    }

    unsigned long destination_error = 0;
    cbm_path_probe_result_t destination_probe =
        cbm_path_probe(cache_db_path, &destination_error);
    result->destination_probe = destination_probe;
    result->destination_probe_native_error = (uint32_t)destination_error;
    if (destination_probe != CBM_PATH_PROBE_ABSENT ||
        !artifact_sidecars_absent_exact(cache_db_path, "import_destination_sidecars")) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.destination_preflight",
                                    "destination database family is not exactly absent");
    }

    static _Atomic unsigned long import_sequence;
    unsigned long sequence =
        atomic_fetch_add_explicit(&import_sequence, 1UL, memory_order_relaxed) + 1UL;
    char tmp_path[CBM_SZ_4K];
    int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.import.pid-%lu.seq-%lu.tmp",
                           cache_db_path, (unsigned long)getpid(), sequence);
    if (sequence == 0 || tmp_len < 0 || (size_t)tmp_len >= sizeof(tmp_path)) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.private_path",
                                    "unique private database path is unavailable");
    }
    unsigned long tmp_error = 0;
    if (cbm_path_probe(tmp_path, &tmp_error) != CBM_PATH_PROBE_ABSENT ||
        !artifact_sidecars_absent_exact(tmp_path, "import_temp_sidecars")) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.private_preflight",
                                    "unique private database family is not exactly absent");
    }

    char cache_dir[CBM_SZ_4K];
    int cache_len = snprintf(cache_dir, sizeof(cache_dir), "%s", cache_db_path);
    char *last_slash = cache_len > 0 && (size_t)cache_len < sizeof(cache_dir)
                           ? strrchr(cache_dir, '/')
                           : NULL;
    if (!last_slash) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.cache_directory",
                                    "destination cache directory cannot be represented");
    }
    *last_slash = '\0';
    if (!cbm_mkdir_p(cache_dir, ART_DIR_PERMS) || !cbm_is_dir(cache_dir)) {
        free(decompressed);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.cache_directory",
                                    "destination cache directory could not be created and read back");
    }

    artifact_file_error_t ioerr;
    int write_status =
        write_file_atomic(tmp_path, decompressed, (size_t)decompressed_size, &ioerr);
    free(decompressed);
    if (write_status != 0) {
        artifact_export_fail("import.write_private", tmp_path, ioerr.err, ioerr.err_no);
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.write_private",
                                    "private database could not be durably written");
    }

    cbm_store_t *store = cbm_store_open_path(tmp_path);
    if (!store) {
        if (!artifact_remove_closed_scratch(tmp_path, "import_open_cleanup")) {
            return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                        "import.open_cleanup",
                                        "private database open and exact cleanup both failed");
        }
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.open_private", "private database could not be opened");
    }

    cbm_project_t *projects = NULL;
    int project_count = 0;
    int project_status = cbm_store_list_projects(store, &projects, &project_count);
    int node_count = cbm_store_count_nodes(store, expected_project);
    int edge_count = cbm_store_count_edges(store, expected_project);
    bool content_matches = project_status == CBM_STORE_OK && project_count == 1 && projects &&
                           projects[0].name && strcmp(projects[0].name, expected_project) == 0 &&
                           node_count == metadata.nodes && edge_count == metadata.edges;
    cbm_store_free_projects(projects, project_count);
    if (!cbm_store_check_integrity(store) || !content_matches) {
        cbm_store_close_required(&store, "artifact.verify.content_failed");
        if (!artifact_remove_closed_scratch(tmp_path, "import_content_cleanup")) {
            return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                        "import.content_cleanup",
                                        "artifact content mismatch and private cleanup failed");
        }
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.verify_content",
                                    "database project or node/edge counts do not match metadata");
    }

    cbm_store_normalize_result_t normalization;
    if (cbm_store_exec(store, "PRAGMA optimize;") != CBM_STORE_OK ||
        cbm_store_normalize_journal_mode_delete(store, &normalization) !=
            CBM_STORE_NORMALIZE_OK) {
        cbm_store_close_required(&store, "artifact.verify.normalization_failed");
        if (!artifact_remove_closed_scratch(tmp_path, "import_normalization_cleanup")) {
            return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                        "import.normalization_cleanup",
                                        "normalization and private cleanup both failed");
        }
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.normalize_private",
                                    "private database could not be normalized to exact DELETE");
    }
    cbm_store_close_required(&store, "artifact.verify.complete");
    if (!artifact_sidecars_absent_exact(tmp_path, "import_normalized_sidecar_readback")) {
        return artifact_import_fail(result, CBM_ARTIFACT_IMPORT_FAILED_BEFORE_PUBLICATION,
                                    "import.normalized_sidecar_readback",
                                    "normalized private database sidecar absence is not proven");
    }

    cbm_artifact_import_status_t publication =
        artifact_publish_import_noreplace(tmp_path, cache_db_path, result);
    if (publication != CBM_ARTIFACT_IMPORT_OK) {
        return publication;
    }

    result->status = CBM_ARTIFACT_IMPORT_OK;
    snprintf(result->operation, sizeof(result->operation), "%s", "import.publish_complete");
    snprintf(result->detail, sizeof(result->detail), "%s",
             "exact project, hashes, counts, DELETE family, and no-replace publication verified");
    cbm_log_info("artifact.import", "db", cache_db_path, "project", expected_project, "nodes",
                 itoa_buf(metadata.nodes), "edges", itoa_buf(metadata.edges), "size_mb",
                 itoa_buf((int)((size_t)decompressed_size / ART_BYTES_PER_MB)));
    return result->status;
}

/* ── Existence check ─────────────────────────────────────────────── */

bool cbm_artifact_exists(const char *repo_path) {
    if (!repo_path) {
        return false;
    }

    artifact_metadata_t metadata;
    if (!read_artifact_metadata(repo_path, &metadata)) {
        return false;
    }
    char zst_path[CBM_SZ_4K];
    if (!artifact_path(zst_path, sizeof(zst_path), repo_path, CBM_ARTIFACT_FILENAME)) {
        return false;
    }
    size_t compressed_size = 0;
    char *compressed = read_file_alloc(zst_path, &compressed_size);
    if (!compressed || compressed_size != metadata.compressed_size) {
        free(compressed);
        return false;
    }
    char compressed_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(compressed, compressed_size, compressed_sha256);
    bool exact = strcmp(compressed_sha256, metadata.compressed_sha256) == 0 &&
                 cbm_zstd_frame_content_size(compressed, compressed_size) ==
                     metadata.original_size;
    free(compressed);
    return exact;
}

/* ── Commit hash extraction ──────────────────────────────────────── */

char *cbm_artifact_commit(const char *repo_path) {
    if (!repo_path) {
        return NULL;
    }

    artifact_metadata_t metadata;
    if (!read_artifact_metadata(repo_path, &metadata)) {
        return NULL;
    }
    char meta_path[CBM_SZ_4K];
    artifact_path(meta_path, sizeof(meta_path), repo_path, CBM_ARTIFACT_META);

    size_t len = 0;
    char *json = read_file_alloc(meta_path, &len);
    if (!json) {
        return NULL;
    }

    yyjson_doc *doc = yyjson_read(json, len, 0);
    free(json);
    if (!doc) {
        return NULL;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, "commit");
    char *result = NULL;
    if (val) {
        const char *s = yyjson_get_str(val);
        if (s && s[0]) {
            size_t slen = strlen(s);
            result = malloc(slen + ART_NUL);
            if (result) {
                memcpy(result, s, slen + ART_NUL);
            }
        }
    }
    yyjson_doc_free(doc);
    return result;
}
