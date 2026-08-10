/*
 * astro_spawn.c — shell-free process spawn with stdout capture (Astrolabe #227).
 *
 * See astro_spawn.h for the contract and the root cause this removes.
 *
 * This translation unit deliberately depends on nothing but the C library and
 * the platform process API: it is compiled into libcbm.a next to the vendored
 * CBM objects, and it is also compiled standalone by the #227 FSV harness
 * (scripts/test-cbm-spawn-fsv.py), which links it against a real git and reads
 * back the argv the child actually received.
 */

#include "astro_spawn.h"

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

enum { SPAWN_READ_CHUNK = 8192 };

/* ── Fail-closed error records ──────────────────────────────────── */

static int spawn_fail(cbm_spawn_error_t *err, cbm_spawn_code_t code, const char *code_name,
                      const char *message, const char *remediation, unsigned long os_error,
                      int exit_code) {
    if (err) {
        err->code = code;
        err->code_name = code_name;
        err->message = message;
        err->remediation = remediation;
        err->os_error = os_error;
        err->exit_code = exit_code;
    }
    return (int)code;
}

static int spawn_ok(cbm_spawn_error_t *err) {
    if (err) {
        err->code = CBM_SPAWN_OK;
        err->code_name = "CBM_SPAWN_OK";
        err->message = "";
        err->remediation = "";
        err->os_error = 0;
        err->exit_code = 0;
    }
    return 0;
}

/* ── Growable capture buffer ────────────────────────────────────── */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} spawn_buf_t;

static bool spawn_buf_append(spawn_buf_t *buf, const char *src, size_t n) {
    size_t needed = buf->len + n + 1;
    if (needed < n) {
        return false; /* size_t overflow */
    }
    if (needed > buf->cap) {
        size_t cap = buf->cap ? buf->cap : (size_t)SPAWN_READ_CHUNK;
        while (cap < needed) {
            if (cap > (size_t)-1 / 2) {
                return false;
            }
            cap *= 2;
        }
        char *grown = (char *)realloc(buf->data, cap);
        if (!grown) {
            return false;
        }
        buf->data = grown;
        buf->cap = cap;
    }
    memcpy(buf->data + buf->len, src, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return true;
}

static bool spawn_buf_seal(spawn_buf_t *buf) {
    /* An empty capture still owes the caller a NUL-terminated buffer. */
    return buf->data != NULL || spawn_buf_append(buf, "", 0);
}

typedef enum {
    SPAWN_PREFIX_OK = 0,
    SPAWN_PREFIX_NOMEM,
    SPAWN_PREFIX_OVERFLOW,
} spawn_prefix_result_t;

static spawn_prefix_result_t spawn_buf_append_prefix(spawn_buf_t *buf, const char *src, size_t n,
                                                      size_t retained_limit,
                                                      uint64_t *total_len, bool *truncated) {
    if (UINT64_MAX - *total_len < (uint64_t)n) {
        return SPAWN_PREFIX_OVERFLOW;
    }
    if (buf->len > retained_limit) {
        return SPAWN_PREFIX_OVERFLOW;
    }
    *total_len += (uint64_t)n;
    size_t available = retained_limit - buf->len;
    size_t retain = n < available ? n : available;
    if (buf->len == SIZE_MAX || retain > SIZE_MAX - buf->len - 1) {
        return SPAWN_PREFIX_OVERFLOW;
    }
    if (retain > 0 && !spawn_buf_append(buf, src, retain)) {
        return SPAWN_PREFIX_NOMEM;
    }
    if (retain < n) {
        *truncated = true;
    }
    return SPAWN_PREFIX_OK;
}

#ifdef _WIN32

/* ── Windows: CommandLineToArgvW-exact argv encoding ────────────── */

typedef struct {
    wchar_t *data;
    size_t len;
    size_t cap;
} wbuf_t;

static bool wbuf_push(wbuf_t *buf, wchar_t wc) {
    if (buf->len + 2 > buf->cap) {
        size_t cap = buf->cap ? buf->cap : 128;
        while (cap < buf->len + 2) {
            if (cap > ((size_t)-1 / sizeof(wchar_t)) / 2) {
                return false;
            }
            cap *= 2;
        }
        wchar_t *grown = (wchar_t *)realloc(buf->data, cap * sizeof(wchar_t));
        if (!grown) {
            return false;
        }
        buf->data = grown;
        buf->cap = cap;
    }
    buf->data[buf->len++] = wc;
    buf->data[buf->len] = L'\0';
    return true;
}

static bool wbuf_push_all(wbuf_t *buf, const wchar_t *s) {
    for (const wchar_t *p = s; *p; p++) {
        if (!wbuf_push(buf, *p)) {
            return false;
        }
    }
    return true;
}

static bool arg_needs_quotes(const wchar_t *arg) {
    if (*arg == L'\0') {
        return true; /* an empty argument only survives as "" */
    }
    for (const wchar_t *p = arg; *p; p++) {
        if (*p == L' ' || *p == L'\t' || *p == L'\n' || *p == L'\v' || *p == L'"') {
            return true;
        }
    }
    return false;
}

/* Encode one argument so CommandLineToArgvW (and the MSVC CRT startup code,
 * which git-for-Windows uses) decodes it back to exactly these bytes:
 *   - 2n backslashes + '"'  → n backslashes, quote toggles "in quotes"
 *   - 2n+1 backslashes + '"' → n backslashes + a literal '"'
 *   - backslashes not followed by '"' are literal
 * (Microsoft Learn, CommandLineToArgvW "Remarks"; Daniel Colascione,
 * "Everyone quotes command line arguments the wrong way".) */
static bool wbuf_push_encoded_arg(wbuf_t *buf, const wchar_t *arg) {
    if (!arg_needs_quotes(arg)) {
        return wbuf_push_all(buf, arg);
    }
    if (!wbuf_push(buf, L'"')) {
        return false;
    }
    for (const wchar_t *p = arg;; p++) {
        size_t slashes = 0;
        while (*p == L'\\') {
            slashes++;
            p++;
        }
        if (*p == L'\0') {
            /* Double the trailing run so the closing quote stays a delimiter. */
            for (size_t i = 0; i < slashes * 2; i++) {
                if (!wbuf_push(buf, L'\\')) {
                    return false;
                }
            }
            break;
        }
        if (*p == L'"') {
            for (size_t i = 0; i < slashes * 2 + 1; i++) {
                if (!wbuf_push(buf, L'\\')) {
                    return false;
                }
            }
            if (!wbuf_push(buf, L'"')) {
                return false;
            }
            continue;
        }
        for (size_t i = 0; i < slashes; i++) {
            if (!wbuf_push(buf, L'\\')) {
                return false;
            }
        }
        if (!wbuf_push(buf, *p)) {
            return false;
        }
    }
    return wbuf_push(buf, L'"');
}

static wchar_t *spawn_utf8_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) {
        return NULL;
    }
    wchar_t *out = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!out) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, n) != n) {
        free(out);
        return NULL;
    }
    return out;
}

/* Resolve argv[0] to an absolute image path. An explicit path is taken as
 * given; a bare name is searched ONLY in %PATH% (never the current directory —
 * see the header). Returns NULL when it cannot be resolved. */
static wchar_t *spawn_resolve_exe(const wchar_t *name) {
    if (wcschr(name, L'\\') || wcschr(name, L'/') || wcschr(name, L':')) {
        return _wcsdup(name);
    }
    DWORD path_size = GetEnvironmentVariableW(L"PATH", NULL, 0);
    if (path_size == 0) {
        return NULL;
    }
    wchar_t *path = (wchar_t *)malloc((size_t)path_size * sizeof(wchar_t));
    if (!path) {
        return NULL;
    }
    DWORD copied = GetEnvironmentVariableW(L"PATH", path, path_size);
    if (copied == 0 || copied >= path_size) {
        free(path);
        return NULL;
    }
    DWORD needed = SearchPathW(path, name, L".exe", 0, NULL, NULL);
    if (needed == 0) {
        free(path);
        return NULL;
    }
    wchar_t *full = (wchar_t *)malloc((size_t)needed * sizeof(wchar_t));
    if (!full) {
        free(path);
        return NULL;
    }
    DWORD written = SearchPathW(path, name, L".exe", needed, full, NULL);
    free(path);
    if (written == 0 || written >= needed) {
        free(full);
        return NULL;
    }
    return full;
}

static void free_wide_argv(wchar_t **wargv, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(wargv[i]);
    }
    free(wargv);
}

typedef struct {
    HANDLE read_handle;
    spawn_buf_t buffer;
    size_t retained_limit;
    uint64_t total_len;
    bool truncated;
    int capture_code;
    DWORD read_error;
    volatile LONG references;
} spawn_stderr_reader_t;

static void spawn_stderr_reader_release(spawn_stderr_reader_t *reader) {
    if (reader && InterlockedDecrement(&reader->references) == 0) {
        free(reader->buffer.data);
        free(reader);
    }
}

static DWORD WINAPI spawn_stderr_reader(LPVOID opaque) {
    spawn_stderr_reader_t *reader = (spawn_stderr_reader_t *)opaque;
    char chunk[SPAWN_READ_CHUNK];
    bool retain = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(reader->read_handle, chunk, (DWORD)sizeof(chunk), &got, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_BROKEN_PIPE) {
                reader->capture_code = CBM_SPAWN_E_READ;
                reader->read_error = error;
            }
            break;
        }
        if (got == 0) {
            break;
        }
        if (retain) {
            spawn_prefix_result_t append =
                spawn_buf_append_prefix(&reader->buffer, chunk, (size_t)got,
                                        reader->retained_limit, &reader->total_len,
                                        &reader->truncated);
            if (append != SPAWN_PREFIX_OK) {
                reader->capture_code =
                    append == SPAWN_PREFIX_NOMEM ? CBM_SPAWN_E_NOMEM : CBM_SPAWN_E_READ;
                reader->read_error = append == SPAWN_PREFIX_NOMEM
                                         ? ERROR_NOT_ENOUGH_MEMORY
                                         : ERROR_ARITHMETIC_OVERFLOW;
                retain = false;
            }
        } else if (!retain) {
            if (UINT64_MAX - reader->total_len < (uint64_t)got) {
                reader->capture_code = CBM_SPAWN_E_READ;
                reader->read_error = ERROR_ARITHMETIC_OVERFLOW;
            } else {
                reader->total_len += (uint64_t)got;
                reader->truncated = true;
            }
        }
    }
    CloseHandle(reader->read_handle);
    reader->read_handle = NULL;
    spawn_stderr_reader_release(reader);
    return 0;
}

static bool spawn_source_date_epoch_valid(const char *value) {
    if (!value || !value[0] || (value[0] == '0' && value[1])) {
        return false;
    }
    for (const unsigned char *at = (const unsigned char *)value; *at; at++) {
        if (*at < '0' || *at > '9') {
            return false;
        }
    }
    return true;
}

static bool spawn_environment_entry_has_name(const wchar_t *entry, const wchar_t *name) {
    if (!entry || !name || entry[0] == L'=') {
        return false;
    }
    size_t name_length = wcslen(name);
    size_t entry_length = wcslen(entry);
    return name_length <= INT_MAX && entry_length > name_length &&
           entry[name_length] == L'=' &&
           CompareStringOrdinal(entry, (int)name_length, name, (int)name_length, TRUE) ==
               CSTR_EQUAL;
}

static int spawn_environment_entry_order(const wchar_t *left, const wchar_t *right) {
    size_t left_length = left ? wcslen(left) : 0;
    size_t right_length = right ? wcslen(right) : 0;
    if (!left || !right || left_length > INT_MAX || right_length > INT_MAX) {
        return INT_MIN;
    }
    int order = CompareStringOrdinal(left, (int)left_length, right, (int)right_length, TRUE);
    if (order == CSTR_LESS_THAN) {
        return -1;
    }
    if (order == CSTR_GREATER_THAN) {
        return 1;
    }
    if (order != CSTR_EQUAL) {
        return INT_MIN;
    }

    /* Case-insensitive ordering is the Windows environment contract. Use an
     * ordinal case-sensitive tiebreaker so byte-distinct entries never depend
     * on qsort's unspecified equal-element order. */
    order = CompareStringOrdinal(left, (int)left_length, right, (int)right_length, FALSE);
    if (order == CSTR_LESS_THAN) {
        return -1;
    }
    if (order == CSTR_GREATER_THAN) {
        return 1;
    }
    return order == CSTR_EQUAL ? 0 : INT_MIN;
}

static int spawn_environment_entry_qsort_order(const void *left, const void *right) {
    const wchar_t *const *left_entry = (const wchar_t *const *)left;
    const wchar_t *const *right_entry = (const wchar_t *const *)right;
    int order = spawn_environment_entry_order(*left_entry, *right_entry);
    /* Every entry is length-checked before qsort. A native comparison fault is
     * detected again by the adjacent-order readback after sorting. */
    return order == INT_MIN ? 0 : order;
}

static wchar_t *spawn_executable_directory(const wchar_t *executable, DWORD *error_out) {
    const wchar_t *backslash = executable ? wcsrchr(executable, L'\\') : NULL;
    const wchar_t *slash = executable ? wcsrchr(executable, L'/') : NULL;
    const wchar_t *separator = backslash;
    if (!separator || (slash && slash > separator)) {
        separator = slash;
    }
    if (!separator || separator == executable) {
        *error_out = ERROR_BAD_PATHNAME;
        return NULL;
    }
    size_t length = (size_t)(separator - executable);
    if (length == 2 && executable[1] == L':') {
        length++; /* Preserve the separator for a drive-root directory. */
    }
    if (length > SIZE_MAX / sizeof(wchar_t) - 1) {
        *error_out = ERROR_ARITHMETIC_OVERFLOW;
        return NULL;
    }
    wchar_t *directory = (wchar_t *)malloc((length + 1) * sizeof(*directory));
    if (!directory) {
        *error_out = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    memcpy(directory, executable, length * sizeof(*directory));
    directory[length] = L'\0';
    return directory;
}

static bool spawn_path_starts_with_directory(const wchar_t *path,
                                              const wchar_t *directory) {
    if (!path || !directory) {
        return false;
    }
    const wchar_t *separator = wcschr(path, L';');
    size_t path_length = separator ? (size_t)(separator - path) : wcslen(path);
    size_t directory_length = wcslen(directory);
    while (path_length > 0 &&
           (path[path_length - 1] == L'\\' || path[path_length - 1] == L'/')) {
        path_length--;
    }
    while (directory_length > 0 &&
           (directory[directory_length - 1] == L'\\' ||
            directory[directory_length - 1] == L'/')) {
        directory_length--;
    }
    return path_length == directory_length && path_length <= INT_MAX &&
           CompareStringOrdinal(path, (int)path_length, directory,
                                (int)directory_length, TRUE) == CSTR_EQUAL;
}

static bool spawn_environment_size_add(size_t *required, size_t entry_length) {
    if (*required == SIZE_MAX || entry_length > SIZE_MAX - *required - 1) {
        return false;
    }
    *required += entry_length + 1;
    return true;
}

static wchar_t *spawn_environment_with_source_epoch_and_runtime(
    const char *value, const wchar_t *executable, DWORD *error_out) {
    *error_out = ERROR_SUCCESS;
    LPWCH inherited = NULL;
    wchar_t *wide_value = NULL;
    wchar_t *runtime_directory = NULL;
    wchar_t *path_entry = NULL;
    wchar_t *epoch_entry = NULL;
    const wchar_t **entries = NULL;
    wchar_t *block = NULL;
    if (!spawn_source_date_epoch_valid(value)) {
        *error_out = ERROR_INVALID_PARAMETER;
        goto done;
    }
    wide_value = spawn_utf8_to_wide(value);
    if (!wide_value) {
        *error_out = GetLastError();
        if (*error_out == ERROR_SUCCESS) {
            *error_out = ERROR_NO_UNICODE_TRANSLATION;
        }
        goto done;
    }
    inherited = GetEnvironmentStringsW();
    if (!inherited) {
        *error_out = GetLastError();
        goto done;
    }

    runtime_directory = spawn_executable_directory(executable, error_out);
    if (!runtime_directory) {
        goto done;
    }

    static const wchar_t path_name[] = L"Path";
    static const wchar_t epoch_name[] = L"SOURCE_DATE_EPOCH";
    const wchar_t *inherited_path = NULL;
    size_t path_entries = 0;
    size_t epoch_entries = 0;
    size_t retained_entries = 0;
    size_t required = 1;
    for (const wchar_t *entry = inherited; *entry; entry += wcslen(entry) + 1) {
        size_t entry_length = wcslen(entry);
        if (entry_length > INT_MAX) {
            *error_out = ERROR_ARITHMETIC_OVERFLOW;
            goto done;
        }
        if (spawn_environment_entry_has_name(entry, path_name)) {
            inherited_path = entry + (sizeof(path_name) / sizeof(path_name[0]));
            path_entries++;
            continue;
        }
        if (spawn_environment_entry_has_name(entry, epoch_name)) {
            epoch_entries++;
            continue;
        }
        if (!spawn_environment_size_add(&required, entry_length)) {
            *error_out = ERROR_ARITHMETIC_OVERFLOW;
            goto done;
        }
        retained_entries++;
    }
    if (path_entries > 1 || epoch_entries > 1) {
        *error_out = ERROR_INVALID_DATA;
        goto done;
    }

    static const wchar_t path_prefix[] = L"Path=";
    static const wchar_t epoch_prefix[] = L"SOURCE_DATE_EPOCH=";
    size_t path_prefix_length = sizeof(path_prefix) / sizeof(path_prefix[0]) - 1;
    size_t epoch_prefix_length = sizeof(epoch_prefix) / sizeof(epoch_prefix[0]) - 1;
    size_t runtime_length = wcslen(runtime_directory);
    size_t inherited_path_length = inherited_path ? wcslen(inherited_path) : 0;
    size_t value_length = wcslen(wide_value);
    bool runtime_already_first =
        spawn_path_starts_with_directory(inherited_path, runtime_directory);
    size_t path_value_length = inherited_path_length;
    if (!runtime_already_first) {
        size_t separator_length = inherited_path_length > 0 ? 1 : 0;
        if (inherited_path_length > SIZE_MAX - separator_length ||
            runtime_length > SIZE_MAX - inherited_path_length - separator_length) {
            *error_out = ERROR_ARITHMETIC_OVERFLOW;
            goto done;
        }
        path_value_length = runtime_length + separator_length + inherited_path_length;
    }
    if (path_value_length > SIZE_MAX - path_prefix_length ||
        value_length > SIZE_MAX - epoch_prefix_length) {
        *error_out = ERROR_ARITHMETIC_OVERFLOW;
        goto done;
    }
    size_t path_entry_length = path_prefix_length + path_value_length;
    size_t epoch_entry_length = epoch_prefix_length + value_length;
    if (!spawn_environment_size_add(&required, path_entry_length) ||
        !spawn_environment_size_add(&required, epoch_entry_length) ||
        path_entry_length > SIZE_MAX / sizeof(wchar_t) - 1 ||
        epoch_entry_length > SIZE_MAX / sizeof(wchar_t) - 1 ||
        required > SIZE_MAX / sizeof(wchar_t)) {
        *error_out = ERROR_ARITHMETIC_OVERFLOW;
        goto done;
    }

    path_entry = (wchar_t *)malloc((path_entry_length + 1) * sizeof(*path_entry));
    epoch_entry = (wchar_t *)malloc((epoch_entry_length + 1) * sizeof(*epoch_entry));
    if (!path_entry || !epoch_entry) {
        *error_out = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    wchar_t *path_cursor = path_entry;
    memcpy(path_cursor, path_prefix, path_prefix_length * sizeof(*path_cursor));
    path_cursor += path_prefix_length;
    if (runtime_already_first) {
        memcpy(path_cursor, inherited_path, inherited_path_length * sizeof(*path_cursor));
        path_cursor += inherited_path_length;
    } else {
        memcpy(path_cursor, runtime_directory, runtime_length * sizeof(*path_cursor));
        path_cursor += runtime_length;
        if (inherited_path_length > 0) {
            *path_cursor++ = L';';
            memcpy(path_cursor, inherited_path,
                   inherited_path_length * sizeof(*path_cursor));
            path_cursor += inherited_path_length;
        }
    }
    *path_cursor = L'\0';
    memcpy(epoch_entry, epoch_prefix, epoch_prefix_length * sizeof(*epoch_entry));
    memcpy(epoch_entry + epoch_prefix_length, wide_value,
           (value_length + 1) * sizeof(*epoch_entry));

    if (retained_entries > SIZE_MAX / sizeof(*entries) - 2) {
        *error_out = ERROR_ARITHMETIC_OVERFLOW;
        goto done;
    }
    size_t entry_count = retained_entries + 2;
    entries = (const wchar_t **)malloc(entry_count * sizeof(*entries));
    if (!entries) {
        *error_out = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    size_t entry_index = 0;
    for (const wchar_t *entry = inherited; *entry; entry += wcslen(entry) + 1) {
        if (!spawn_environment_entry_has_name(entry, path_name) &&
            !spawn_environment_entry_has_name(entry, epoch_name)) {
            entries[entry_index++] = entry;
        }
    }
    entries[entry_index++] = path_entry;
    entries[entry_index++] = epoch_entry;
    if (entry_index != entry_count) {
        *error_out = ERROR_INVALID_DATA;
        goto done;
    }
    qsort(entries, entry_count, sizeof(*entries), spawn_environment_entry_qsort_order);
    for (size_t i = 1; i < entry_count; i++) {
        int order = spawn_environment_entry_order(entries[i - 1], entries[i]);
        if (order == INT_MIN || order > 0) {
            *error_out = ERROR_INVALID_DATA;
            goto done;
        }
    }

    block = (wchar_t *)calloc(required, sizeof(*block));
    if (!block) {
        *error_out = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    wchar_t *cursor = block;
    for (size_t i = 0; i < entry_count; i++) {
        size_t entry_length = wcslen(entries[i]);
        memcpy(cursor, entries[i], (entry_length + 1) * sizeof(*cursor));
        cursor += entry_length + 1;
    }
    *cursor = L'\0';
    if ((size_t)(cursor - block) != required - 1) {
        *error_out = ERROR_INVALID_DATA;
        free(block);
        block = NULL;
    }

done:
    if (inherited) {
        FreeEnvironmentStringsW(inherited);
    }
    free(entries);
    free(epoch_entry);
    free(path_entry);
    free(runtime_directory);
    free(wide_value);
    return block;
}

static int spawn_capture_impl(const char *const *argv, const char *working_directory,
                              char **out_data, size_t *out_len,
                              size_t stderr_limit, cbm_spawn_bounded_capture_t *out_stderr,
                              bool capture_stderr, const char *source_date_epoch,
                              cbm_spawn_error_t *err) {
    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (out_stderr) {
        memset(out_stderr, 0, sizeof(*out_stderr));
    }
    if (!argv || !argv[0] || !argv[0][0] || !out_data || !out_len ||
        (source_date_epoch && !spawn_source_date_epoch_valid(source_date_epoch)) ||
        (capture_stderr && (!out_stderr || stderr_limit == 0))) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "spawn requires a non-empty argv and output pointers",
                          "pass argv[0] plus a NULL-terminated argument array", 0, -1);
    }

    size_t argc = 0;
    while (argv[argc]) {
        argc++;
    }

    wchar_t **wargv = (wchar_t **)calloc(argc, sizeof(wchar_t *));
    if (!wargv) {
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory widening the child argument vector",
                          "retry after reducing memory pressure on the host", 0, -1);
    }
    for (size_t i = 0; i < argc; i++) {
        wargv[i] = spawn_utf8_to_wide(argv[i]);
        if (!wargv[i]) {
            free_wide_argv(wargv, argc);
            return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                              "argument is not valid UTF-8 or memory was exhausted",
                              "pass UTF-8 arguments; check host memory pressure",
                              (unsigned long)GetLastError(), -1);
        }
    }

    wchar_t *app = spawn_resolve_exe(wargv[0]);
    if (!app) {
        DWORD gle = GetLastError();
        free_wide_argv(wargv, argc);
        return spawn_fail(err, CBM_SPAWN_E_EXEC_NOT_FOUND, "CBM_SPAWN_E_EXEC_NOT_FOUND",
                          "the child executable was not found on PATH",
                          "install the program and add its directory to PATH "
                          "(the current directory is deliberately not searched)",
                          (unsigned long)gle, -1);
    }

    wbuf_t cmdline = {NULL, 0, 0};
    bool encoded = wbuf_push_encoded_arg(&cmdline, wargv[0]);
    for (size_t i = 1; encoded && i < argc; i++) {
        encoded = wbuf_push(&cmdline, L' ') && wbuf_push_encoded_arg(&cmdline, wargv[i]);
    }
    free_wide_argv(wargv, argc);
    if (!encoded || !cmdline.data) {
        free(cmdline.data);
        free(app);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory encoding the child command line",
                          "retry after reducing memory pressure on the host", 0, -1);
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE rd = NULL;
    HANDLE wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        DWORD gle = GetLastError();
        free(cmdline.data);
        free(app);
        return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                          "could not create the child stdout pipe",
                          "check process handle limits and retry", (unsigned long)gle, -1);
    }
    /* The parent read-end must never cross into the child. */
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        CloseHandle(rd);
        CloseHandle(wr);
        free(cmdline.data);
        free(app);
        return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                          "could not open the NUL device for the child's stdin/stderr",
                          "verify the NUL device is reachable in this session", (unsigned long)gle,
                          -1);
    }

    HANDLE stderr_wr = NULL;
    HANDLE stderr_thread = NULL;
    spawn_stderr_reader_t *stderr_reader = NULL;
    if (capture_stderr) {
        HANDLE stderr_rd = NULL;
        if (!CreatePipe(&stderr_rd, &stderr_wr, &sa, 0)) {
            DWORD gle = GetLastError();
            CloseHandle(rd);
            CloseHandle(wr);
            CloseHandle(nul);
            free(cmdline.data);
            free(app);
            return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                              "could not create the child stderr pipe",
                              "check process handle limits and retry", (unsigned long)gle, -1);
        }
        (void)SetHandleInformation(stderr_rd, HANDLE_FLAG_INHERIT, 0);
        stderr_reader = (spawn_stderr_reader_t *)calloc(1, sizeof(*stderr_reader));
        if (!stderr_reader) {
            CloseHandle(stderr_rd);
            CloseHandle(stderr_wr);
            CloseHandle(rd);
            CloseHandle(wr);
            CloseHandle(nul);
            free(cmdline.data);
            free(app);
            return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                              "out of memory creating the child stderr reader",
                              "retry after reducing memory pressure on the host", 0, -1);
        }
        stderr_reader->read_handle = stderr_rd;
        stderr_reader->retained_limit = stderr_limit;
        stderr_reader->references = 2;
        stderr_thread = CreateThread(NULL, 0, spawn_stderr_reader, stderr_reader, 0, NULL);
        if (!stderr_thread) {
            DWORD gle = GetLastError();
            CloseHandle(stderr_rd);
            CloseHandle(stderr_wr);
            CloseHandle(rd);
            CloseHandle(wr);
            CloseHandle(nul);
            free(cmdline.data);
            free(app);
            free(stderr_reader);
            return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                              "could not start the child stderr drain",
                              "check process thread limits and retry", (unsigned long)gle, -1);
        }
    }

    /* Inherit ONLY the exact standard-stream handles (CBM #798): a
     * git-for-Windows child classifies every inherited handle at startup and
     * deadlocks on an inherited socket/AFD handle. */
    HANDLE inherit[3];
    size_t inherit_count = 0;
    inherit[0] = wr;
    inherit[1] = nul;
    inherit_count = 2;
    if (capture_stderr) {
        inherit[inherit_count++] = stderr_wr;
    }

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
    bool attr_init = attr && InitializeProcThreadAttributeList(attr, 1, 0, &attr_size);
    bool prepared =
        attr_init && UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                               inherit_count * sizeof(inherit[0]), NULL, NULL);
    DWORD attr_gle = prepared ? 0 : GetLastError();

    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = wr;
    si.StartupInfo.hStdError = capture_stderr ? stderr_wr : nul;
    si.lpAttributeList = attr;

    wchar_t *cwd = NULL;
    bool cwd_encoded = true;
    if (working_directory) {
        cwd = spawn_utf8_to_wide(working_directory);
        cwd_encoded = cwd != NULL;
    }

    DWORD environment_gle = ERROR_SUCCESS;
    wchar_t *environment =
        source_date_epoch
            ? spawn_environment_with_source_epoch_and_runtime(source_date_epoch, app,
                                                               &environment_gle)
            : NULL;
    bool environment_ready = !source_date_epoch || environment != NULL;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL created = FALSE;
    DWORD spawn_gle = !cwd_encoded        ? ERROR_NO_UNICODE_TRANSLATION
                      : !environment_ready ? environment_gle
                                           : attr_gle;
    if (prepared && cwd_encoded && environment_ready) {
        /* lpApplicationName is explicit, so CreateProcessW performs NO path
         * search: no CWD binary planting, and no shell anywhere. */
        DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT |
                               (environment ? CREATE_UNICODE_ENVIRONMENT : 0);
        created = CreateProcessW(app, cmdline.data, NULL, NULL, TRUE, creation_flags,
                                 environment, cwd, &si.StartupInfo, &pi);
        spawn_gle = created ? 0 : GetLastError();
    }

    if (attr) {
        if (attr_init) {
            DeleteProcThreadAttributeList(attr);
        }
        free(attr);
    }
    free(cmdline.data);
    free(app);
    free(cwd);
    free(environment);
    CloseHandle(wr); /* the child owns the write-end now */
    if (capture_stderr) {
        CloseHandle(stderr_wr);
    }
    CloseHandle(nul);

    if (!created) {
        CloseHandle(rd);
        if (capture_stderr) {
            (void)WaitForSingleObject(stderr_thread, INFINITE);
            CloseHandle(stderr_thread);
            spawn_stderr_reader_release(stderr_reader);
        }
        if (!environment_ready) {
            return spawn_fail(err, CBM_SPAWN_E_ENVIRONMENT, "CBM_SPAWN_E_ENVIRONMENT",
                              "the sorted compiler child environment could not be materialized",
                              "inspect the resolved compiler directory, inherited environment "
                              "ordering, source epoch, and native environment error",
                              (unsigned long)spawn_gle, -1);
        }
        return spawn_fail(err, CBM_SPAWN_E_SPAWN, "CBM_SPAWN_E_SPAWN",
                          "the child process could not be created",
                          "verify the executable is runnable and the host is not out of handles",
                          (unsigned long)spawn_gle, -1);
    }
    CloseHandle(pi.hThread);

    spawn_buf_t buf = {NULL, 0, 0};
    spawn_buf_t stderr_buf = {NULL, 0, 0};
    uint64_t stderr_total_len = 0;
    bool stderr_truncated = false;
    char chunk[SPAWN_READ_CHUNK];
    bool read_ok = true;
    int read_failure_code = CBM_SPAWN_OK;
    DWORD read_gle = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(rd, chunk, (DWORD)sizeof(chunk), &got, NULL)) {
            DWORD gle = GetLastError();
            if (gle != ERROR_BROKEN_PIPE) {
                read_ok = false;
                read_failure_code = CBM_SPAWN_E_READ;
                read_gle = gle;
            }
            break;
        }
        if (got == 0) {
            break;
        }
        if (!spawn_buf_append(&buf, chunk, (size_t)got)) {
            read_ok = false;
            read_failure_code = CBM_SPAWN_E_NOMEM;
            read_gle = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
    }
    CloseHandle(rd);

    DWORD wait_rc = WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    BOOL got_code = (wait_rc == WAIT_OBJECT_0) && GetExitCodeProcess(pi.hProcess, &code);
    DWORD wait_gle = got_code ? 0 : GetLastError();
    CloseHandle(pi.hProcess);

    bool stderr_read_ok = true;
    int stderr_failure_code = CBM_SPAWN_OK;
    DWORD stderr_read_gle = 0;
    if (capture_stderr) {
        DWORD stderr_wait = WaitForSingleObject(stderr_thread, INFINITE);
        if (stderr_wait != WAIT_OBJECT_0) {
            stderr_read_ok = false;
            stderr_failure_code = CBM_SPAWN_E_READ;
            stderr_read_gle =
                stderr_wait == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        } else {
            stderr_buf = stderr_reader->buffer;
            stderr_reader->buffer.data = NULL;
            stderr_reader->buffer.len = 0;
            stderr_reader->buffer.cap = 0;
            stderr_total_len = stderr_reader->total_len;
            stderr_truncated = stderr_reader->truncated;
            if (stderr_reader->capture_code != CBM_SPAWN_OK || stderr_reader->read_error != 0) {
                stderr_read_ok = false;
                stderr_failure_code = stderr_reader->capture_code != CBM_SPAWN_OK
                                          ? stderr_reader->capture_code
                                          : CBM_SPAWN_E_READ;
                stderr_read_gle = stderr_reader->read_error;
            }
        }
        CloseHandle(stderr_thread);
        spawn_stderr_reader_release(stderr_reader);
        stderr_reader = NULL;
    }

    if (!read_ok || !stderr_read_ok) {
        free(buf.data);
        free(stderr_buf.data);
        int failure_code =
            read_failure_code == CBM_SPAWN_E_READ || stderr_failure_code == CBM_SPAWN_E_READ
                ? CBM_SPAWN_E_READ
                : CBM_SPAWN_E_NOMEM;
        return spawn_fail(
            err, failure_code,
            failure_code == CBM_SPAWN_E_NOMEM ? "CBM_SPAWN_E_NOMEM" : "CBM_SPAWN_E_READ",
            failure_code == CBM_SPAWN_E_NOMEM
                ? "out of memory retaining the child's bounded output"
                : "the child's output streams could not be captured completely",
            failure_code == CBM_SPAWN_E_NOMEM
                ? "retry after reducing memory pressure on the host"
                : "retry; if it persists, capture the OS error and file an issue",
            (unsigned long)(!read_ok ? read_gle : stderr_read_gle),
            got_code ? (int)code : -1);
    }
    if (!got_code) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_WAIT, "CBM_SPAWN_E_WAIT",
                          "the child process could not be reaped",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)wait_gle, -1);
    }
    if (!spawn_buf_seal(&buf)) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured output",
                          "retry after reducing memory pressure on the host", 0, (int)code);
    }
    if (capture_stderr && !spawn_buf_seal(&stderr_buf)) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured stderr",
                          "retry after reducing memory pressure on the host", 0, (int)code);
    }

    *out_data = buf.data;
    *out_len = buf.len;
    if (capture_stderr) {
        out_stderr->data = stderr_buf.data;
        out_stderr->len = stderr_buf.len;
        out_stderr->total_len = stderr_total_len;
        out_stderr->truncated = stderr_truncated;
    }
    if (code != 0) {
        return spawn_fail(err, CBM_SPAWN_E_EXIT, "CBM_SPAWN_E_EXIT",
                          "the child process exited with a non-zero status",
                          "inspect the child's exit code and requested captured streams", 0,
                          (int)code);
    }
    return spawn_ok(err);
}

int cbm_spawn_capture(const char *const *argv, char **out_data, size_t *out_len,
                      cbm_spawn_error_t *err) {
    return spawn_capture_impl(argv, NULL, out_data, out_len, 0, NULL, false, NULL, err);
}

int cbm_spawn_capture_with_stderr(const char *const *argv, char **out_data, size_t *out_len,
                                  size_t stderr_limit,
                                  cbm_spawn_bounded_capture_t *out_stderr,
                                  cbm_spawn_error_t *err) {
    return spawn_capture_impl(argv, NULL, out_data, out_len, stderr_limit, out_stderr, true, NULL,
                              err);
}

int cbm_spawn_capture_with_stderr_cwd(const char *const *argv, const char *working_directory,
                                      char **out_data, size_t *out_len, size_t stderr_limit,
                                      cbm_spawn_bounded_capture_t *out_stderr,
                                      cbm_spawn_error_t *err) {
    if (!working_directory || !working_directory[0]) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "spawn requires an explicit non-empty working directory",
                          "bind the child to its captured compiler working directory", 0, -1);
    }
    return spawn_capture_impl(argv, working_directory, out_data, out_len, stderr_limit,
                              out_stderr, true, NULL, err);
}

int cbm_spawn_capture_with_stderr_cwd_source_epoch(
    const char *const *argv, const char *working_directory, const char *source_date_epoch,
    char **out_data, size_t *out_len, size_t stderr_limit,
    cbm_spawn_bounded_capture_t *out_stderr, cbm_spawn_error_t *err) {
    if (!working_directory || !working_directory[0] || !source_date_epoch ||
        !source_date_epoch[0]) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "source-epoch spawn requires an explicit cwd and source epoch",
                          "bind the child to its captured compiler cwd and Git source epoch", 0,
                          -1);
    }
    return spawn_capture_impl(argv, working_directory, out_data, out_len, stderr_limit,
                              out_stderr, true, source_date_epoch, err);
}

#else /* !_WIN32 */

static int spawn_file_actions_addclose_nonstandard(posix_spawn_file_actions_t *actions, int fd) {
    /* pipe() may legitimately reuse a closed standard descriptor.  In that
     * case addopen/adddup2 above installs the final 0/1/2 stream, so a later
     * close action for the original numeric descriptor would close that final
     * stream rather than an obsolete duplicate. */
    return fd <= STDERR_FILENO ? 0 : posix_spawn_file_actions_addclose(actions, fd);
}

static int spawn_capture_impl(const char *const *argv, const char *working_directory,
                              char **out_data, size_t *out_len,
                              size_t stderr_limit, cbm_spawn_bounded_capture_t *out_stderr,
                              bool capture_stderr, const char *source_date_epoch,
                              cbm_spawn_error_t *err) {
    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (out_stderr) {
        memset(out_stderr, 0, sizeof(*out_stderr));
    }
    if (working_directory && working_directory[0]) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "explicit child working directories are deferred on this platform",
                          "run the native Windows shipping target", 0, -1);
    }
    if (source_date_epoch) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "source-epoch child environments are deferred on this platform",
                          "run the native Windows shipping target", 0, -1);
    }
    if (!argv || !argv[0] || !argv[0][0] || !out_data || !out_len ||
        (capture_stderr && (!out_stderr || stderr_limit == 0))) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "spawn requires a non-empty argv and output pointers",
                          "pass argv[0] plus a NULL-terminated argument array", 0, -1);
    }

    int fds[2];
    if (pipe(fds) != 0) {
        return spawn_fail(
            err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE", "could not create the child stdout pipe",
            "check the process file-descriptor limit and retry", (unsigned long)errno, -1);
    }
    /* Neither end leaks into an unrelated child; the dup2 file action below
     * clears FD_CLOEXEC on the descriptor this child actually needs. */
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);

    int stderr_fds[2] = {-1, -1};
    if (capture_stderr) {
        if (pipe(stderr_fds) != 0) {
            int saved = errno;
            close(fds[0]);
            close(fds[1]);
            return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                              "could not create the child stderr pipe",
                              "check the process file-descriptor limit and retry",
                              (unsigned long)saved, -1);
        }
        (void)fcntl(stderr_fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(stderr_fds[1], F_SETFD, FD_CLOEXEC);
    }

    int stdout_flags = fcntl(fds[0], F_GETFL, 0);
    int stderr_flags = capture_stderr ? fcntl(stderr_fds[0], F_GETFL, 0) : 0;
    if (stdout_flags < 0 || (capture_stderr && stderr_flags < 0) ||
        fcntl(fds[0], F_SETFL, stdout_flags | O_NONBLOCK) != 0 ||
        (capture_stderr &&
         fcntl(stderr_fds[0], F_SETFL, stderr_flags | O_NONBLOCK) != 0)) {
        int saved = errno;
        close(fds[0]);
        close(fds[1]);
        if (capture_stderr) {
            close(stderr_fds[0]);
            close(stderr_fds[1]);
        }
        return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                          "could not configure nonblocking child-output drains",
                          "check process file-descriptor state and retry", (unsigned long)saved,
                          -1);
    }

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        int saved = errno;
        close(fds[0]);
        close(fds[1]);
        if (capture_stderr) {
            close(stderr_fds[0]);
            close(stderr_fds[1]);
        }
        return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                          "could not initialise the child file actions",
                          "retry after reducing memory pressure on the host", (unsigned long)saved,
                          -1);
    }

    int rc = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (rc == 0) {
        rc = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    }
    if (rc == 0) {
        if (capture_stderr) {
            rc = posix_spawn_file_actions_adddup2(&actions, stderr_fds[1], STDERR_FILENO);
        } else {
            rc = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY,
                                                  0);
        }
    }
    if (rc == 0) {
        rc = spawn_file_actions_addclose_nonstandard(&actions, fds[0]);
    }
    if (rc == 0) {
        rc = spawn_file_actions_addclose_nonstandard(&actions, fds[1]);
    }
    if (rc == 0 && capture_stderr) {
        rc = spawn_file_actions_addclose_nonstandard(&actions, stderr_fds[0]);
    }
    if (rc == 0 && capture_stderr) {
        rc = spawn_file_actions_addclose_nonstandard(&actions, stderr_fds[1]);
    }
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(fds[0]);
        close(fds[1]);
        if (capture_stderr) {
            close(stderr_fds[0]);
            close(stderr_fds[1]);
        }
        return spawn_fail(err, CBM_SPAWN_E_PIPE, "CBM_SPAWN_E_PIPE",
                          "could not describe the child's standard streams",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)rc, -1);
    }

    /* posix_spawnp execs the program directly: no /bin/sh, so argv elements are
     * never re-parsed for metacharacters. */
    pid_t pid = 0;
    rc = posix_spawnp(&pid, argv[0], &actions, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (capture_stderr) {
        close(stderr_fds[1]);
    }
    if (rc != 0) {
        close(fds[0]);
        if (capture_stderr) {
            close(stderr_fds[0]);
        }
        if (rc == ENOENT) {
            return spawn_fail(err, CBM_SPAWN_E_EXEC_NOT_FOUND, "CBM_SPAWN_E_EXEC_NOT_FOUND",
                              "the child executable was not found on PATH",
                              "install the program and add its directory to PATH",
                              (unsigned long)rc, -1);
        }
        return spawn_fail(err, CBM_SPAWN_E_SPAWN, "CBM_SPAWN_E_SPAWN",
                          "the child process could not be created",
                          "verify the executable is runnable and the host is not out of processes",
                          (unsigned long)rc, -1);
    }

    spawn_buf_t buf = {NULL, 0, 0};
    spawn_buf_t stderr_buf = {NULL, 0, 0};
    uint64_t stderr_total_len = 0;
    bool stderr_truncated = false;
    bool stderr_retain = true;
    char chunk[SPAWN_READ_CHUNK];
    bool read_ok = true;
    bool stderr_read_ok = true;
    int stdout_failure_code = CBM_SPAWN_OK;
    int stderr_failure_code = CBM_SPAWN_OK;
    unsigned long read_errno = 0;
    struct pollfd streams[2];
    streams[0].fd = fds[0];
    streams[0].events = POLLIN | POLLHUP;
    streams[0].revents = 0;
    streams[1].fd = capture_stderr ? stderr_fds[0] : -1;
    streams[1].events = POLLIN | POLLHUP;
    streams[1].revents = 0;
    int open_streams = capture_stderr ? 2 : 1;
    while (open_streams > 0) {
        int poll_rc;
        do {
            poll_rc = poll(streams, 2, -1);
        } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc < 0) {
            read_ok = false;
            stderr_read_ok = false;
            stdout_failure_code = CBM_SPAWN_E_READ;
            stderr_failure_code = CBM_SPAWN_E_READ;
            read_errno = (unsigned long)errno;
            break;
        }
        for (int stream = 0; stream < 2; stream++) {
            if (streams[stream].fd < 0 || streams[stream].revents == 0) {
                continue;
            }
            if ((streams[stream].revents & POLLNVAL) != 0) {
                if (stream == 0) {
                    read_ok = false;
                    stdout_failure_code = CBM_SPAWN_E_READ;
                } else {
                    stderr_read_ok = false;
                    stderr_failure_code = CBM_SPAWN_E_READ;
                }
                if (read_errno == 0) {
                    read_errno = (unsigned long)EBADF;
                }
                close(streams[stream].fd);
                streams[stream].fd = -1;
                open_streams--;
                continue;
            }
            for (;;) {
                ssize_t got = read(streams[stream].fd, chunk, sizeof(chunk));
                if (got > 0) {
                    if (stream == 0) {
                        if (read_ok && !spawn_buf_append(&buf, chunk, (size_t)got)) {
                            read_ok = false;
                            stdout_failure_code = CBM_SPAWN_E_NOMEM;
                            if (read_errno == 0) {
                                read_errno = (unsigned long)ENOMEM;
                            }
                        }
                    } else if (stderr_retain) {
                        spawn_prefix_result_t append = spawn_buf_append_prefix(
                            &stderr_buf, chunk, (size_t)got, stderr_limit, &stderr_total_len,
                            &stderr_truncated);
                        if (append != SPAWN_PREFIX_OK) {
                            stderr_read_ok = false;
                            stderr_failure_code = append == SPAWN_PREFIX_NOMEM
                                                      ? CBM_SPAWN_E_NOMEM
                                                      : CBM_SPAWN_E_READ;
                            if (read_errno == 0) {
                                read_errno = (unsigned long)(append == SPAWN_PREFIX_NOMEM
                                                                 ? ENOMEM
                                                                 : EOVERFLOW);
                            }
                            stderr_retain = false;
                        }
                    } else if (UINT64_MAX - stderr_total_len < (uint64_t)got) {
                        stderr_read_ok = false;
                        stderr_failure_code = CBM_SPAWN_E_READ;
                        if (read_errno == 0) {
                            read_errno = (unsigned long)EOVERFLOW;
                        }
                    } else {
                        stderr_total_len += (uint64_t)got;
                        stderr_truncated = true;
                    }
                    continue;
                }
                if (got == 0) {
                    close(streams[stream].fd);
                    streams[stream].fd = -1;
                    open_streams--;
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (stream == 0) {
                    read_ok = false;
                    stdout_failure_code = CBM_SPAWN_E_READ;
                } else {
                    stderr_read_ok = false;
                    stderr_failure_code = CBM_SPAWN_E_READ;
                }
                if (read_errno == 0) {
                    read_errno = (unsigned long)errno;
                }
                close(streams[stream].fd);
                streams[stream].fd = -1;
                open_streams--;
                break;
            }
            streams[stream].revents = 0;
        }
    }
    for (int stream = 0; stream < 2; stream++) {
        if (streams[stream].fd >= 0) {
            close(streams[stream].fd);
        }
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (!read_ok || !stderr_read_ok) {
        free(buf.data);
        free(stderr_buf.data);
        int failure_code =
            stdout_failure_code == CBM_SPAWN_E_READ || stderr_failure_code == CBM_SPAWN_E_READ
                ? CBM_SPAWN_E_READ
                : CBM_SPAWN_E_NOMEM;
        return spawn_fail(
            err, failure_code,
            failure_code == CBM_SPAWN_E_NOMEM ? "CBM_SPAWN_E_NOMEM" : "CBM_SPAWN_E_READ",
            failure_code == CBM_SPAWN_E_NOMEM
                ? "out of memory retaining the child's bounded output"
                : "the child's output streams could not be captured completely",
            failure_code == CBM_SPAWN_E_NOMEM
                ? "retry after reducing memory pressure on the host"
                : "retry; if it persists, capture the OS error and file an issue",
            read_errno, -1);
    }
    if (waited < 0 || !WIFEXITED(status)) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_WAIT, "CBM_SPAWN_E_WAIT",
                          "the child process could not be reaped or did not exit normally",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)errno, -1);
    }
    if (!spawn_buf_seal(&buf)) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured output",
                          "retry after reducing memory pressure on the host", 0,
                          WEXITSTATUS(status));
    }
    if (capture_stderr && !spawn_buf_seal(&stderr_buf)) {
        free(buf.data);
        free(stderr_buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured stderr",
                          "retry after reducing memory pressure on the host", 0,
                          WEXITSTATUS(status));
    }

    *out_data = buf.data;
    *out_len = buf.len;
    if (capture_stderr) {
        out_stderr->data = stderr_buf.data;
        out_stderr->len = stderr_buf.len;
        out_stderr->total_len = stderr_total_len;
        out_stderr->truncated = stderr_truncated;
    }
    if (WEXITSTATUS(status) != 0) {
        return spawn_fail(err, CBM_SPAWN_E_EXIT, "CBM_SPAWN_E_EXIT",
                          "the child process exited with a non-zero status",
                          "inspect the child's exit code and requested captured streams", 0,
                          WEXITSTATUS(status));
    }
    return spawn_ok(err);
}

int cbm_spawn_capture(const char *const *argv, char **out_data, size_t *out_len,
                      cbm_spawn_error_t *err) {
    return spawn_capture_impl(argv, NULL, out_data, out_len, 0, NULL, false, NULL, err);
}

int cbm_spawn_capture_with_stderr(const char *const *argv, char **out_data, size_t *out_len,
                                  size_t stderr_limit,
                                  cbm_spawn_bounded_capture_t *out_stderr,
                                  cbm_spawn_error_t *err) {
    return spawn_capture_impl(argv, NULL, out_data, out_len, stderr_limit, out_stderr, true, NULL,
                              err);
}

int cbm_spawn_capture_with_stderr_cwd(const char *const *argv, const char *working_directory,
                                      char **out_data, size_t *out_len, size_t stderr_limit,
                                      cbm_spawn_bounded_capture_t *out_stderr,
                                      cbm_spawn_error_t *err) {
    if (!working_directory || !working_directory[0]) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "spawn requires an explicit non-empty working directory",
                          "bind the child to its captured compiler working directory", 0, -1);
    }
    return spawn_capture_impl(argv, working_directory, out_data, out_len, stderr_limit,
                              out_stderr, true, NULL, err);
}

int cbm_spawn_capture_with_stderr_cwd_source_epoch(
    const char *const *argv, const char *working_directory, const char *source_date_epoch,
    char **out_data, size_t *out_len, size_t stderr_limit,
    cbm_spawn_bounded_capture_t *out_stderr, cbm_spawn_error_t *err) {
    if (!working_directory || !working_directory[0] || !source_date_epoch ||
        !source_date_epoch[0]) {
        return spawn_fail(err, CBM_SPAWN_E_INVALID_ARGV, "CBM_SPAWN_E_INVALID_ARGV",
                          "source-epoch spawn requires an explicit cwd and source epoch",
                          "bind the child to its captured compiler cwd and Git source epoch", 0,
                          -1);
    }
    return spawn_capture_impl(argv, working_directory, out_data, out_len, stderr_limit,
                              out_stderr, true, source_date_epoch, err);
}

#endif /* _WIN32 */
