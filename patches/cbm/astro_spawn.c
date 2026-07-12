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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
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

int cbm_spawn_capture(const char *const *argv, char **out_data, size_t *out_len,
                      cbm_spawn_error_t *err) {
    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!argv || !argv[0] || !argv[0][0] || !out_data || !out_len) {
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

    /* Inherit ONLY the stdout write-end and NUL (CBM #798): a git-for-Windows
     * child classifies every inherited handle at startup and deadlocks on an
     * inherited socket/AFD handle. */
    HANDLE inherit[2];
    inherit[0] = wr;
    inherit[1] = nul;

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
    bool attr_init = attr && InitializeProcThreadAttributeList(attr, 1, 0, &attr_size);
    bool prepared =
        attr_init && UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                               sizeof(inherit), NULL, NULL);
    DWORD attr_gle = prepared ? 0 : GetLastError();

    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = wr;
    si.StartupInfo.hStdError = nul;
    si.lpAttributeList = attr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL created = FALSE;
    DWORD spawn_gle = attr_gle;
    if (prepared) {
        /* lpApplicationName is explicit, so CreateProcessW performs NO path
         * search: no CWD binary planting, and no shell anywhere. */
        created = CreateProcessW(app, cmdline.data, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT,
                                 NULL, NULL, &si.StartupInfo, &pi);
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
    CloseHandle(wr); /* the child owns the write-end now */
    CloseHandle(nul);

    if (!created) {
        CloseHandle(rd);
        return spawn_fail(err, CBM_SPAWN_E_SPAWN, "CBM_SPAWN_E_SPAWN",
                          "the child process could not be created",
                          "verify the executable is runnable and the host is not out of handles",
                          (unsigned long)spawn_gle, -1);
    }
    CloseHandle(pi.hThread);

    spawn_buf_t buf = {NULL, 0, 0};
    char chunk[SPAWN_READ_CHUNK];
    bool read_ok = true;
    DWORD read_gle = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(rd, chunk, (DWORD)sizeof(chunk), &got, NULL)) {
            DWORD gle = GetLastError();
            if (gle != ERROR_BROKEN_PIPE) {
                read_ok = false;
                read_gle = gle;
            }
            break;
        }
        if (got == 0) {
            break;
        }
        if (!spawn_buf_append(&buf, chunk, (size_t)got)) {
            read_ok = false;
            read_gle = 0;
            break;
        }
    }
    CloseHandle(rd);

    DWORD wait_rc = WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    BOOL got_code = (wait_rc == WAIT_OBJECT_0) && GetExitCodeProcess(pi.hProcess, &code);
    DWORD wait_gle = got_code ? 0 : GetLastError();
    CloseHandle(pi.hProcess);

    if (!read_ok) {
        free(buf.data);
        return spawn_fail(err, CBM_SPAWN_E_READ, "CBM_SPAWN_E_READ",
                          "the child's stdout could not be captured",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)read_gle, got_code ? (int)code : -1);
    }
    if (!got_code) {
        free(buf.data);
        return spawn_fail(err, CBM_SPAWN_E_WAIT, "CBM_SPAWN_E_WAIT",
                          "the child process could not be reaped",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)wait_gle, -1);
    }
    if (!spawn_buf_seal(&buf)) {
        free(buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured output",
                          "retry after reducing memory pressure on the host", 0, (int)code);
    }

    *out_data = buf.data;
    *out_len = buf.len;
    if (code != 0) {
        return spawn_fail(err, CBM_SPAWN_E_EXIT, "CBM_SPAWN_E_EXIT",
                          "the child process exited with a non-zero status",
                          "inspect the child's exit code; the captured stdout is still returned", 0,
                          (int)code);
    }
    return spawn_ok(err);
}

#else /* !_WIN32 */

int cbm_spawn_capture(const char *const *argv, char **out_data, size_t *out_len,
                      cbm_spawn_error_t *err) {
    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!argv || !argv[0] || !argv[0][0] || !out_data || !out_len) {
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

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        int saved = errno;
        close(fds[0]);
        close(fds[1]);
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
        rc = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    }
    if (rc == 0) {
        rc = posix_spawn_file_actions_addclose(&actions, fds[0]);
    }
    if (rc == 0) {
        rc = posix_spawn_file_actions_addclose(&actions, fds[1]);
    }
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(fds[0]);
        close(fds[1]);
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
    if (rc != 0) {
        close(fds[0]);
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
    char chunk[SPAWN_READ_CHUNK];
    bool read_ok = true;
    unsigned long read_errno = 0;
    for (;;) {
        ssize_t got = read(fds[0], chunk, sizeof(chunk));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            read_ok = false;
            read_errno = (unsigned long)errno;
            break;
        }
        if (got == 0) {
            break;
        }
        if (!spawn_buf_append(&buf, chunk, (size_t)got)) {
            read_ok = false;
            read_errno = 0;
            break;
        }
    }
    close(fds[0]);

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (!read_ok) {
        free(buf.data);
        return spawn_fail(
            err, CBM_SPAWN_E_READ, "CBM_SPAWN_E_READ", "the child's stdout could not be captured",
            "retry; if it persists, capture the OS error and file an issue", read_errno, -1);
    }
    if (waited < 0 || !WIFEXITED(status)) {
        free(buf.data);
        return spawn_fail(err, CBM_SPAWN_E_WAIT, "CBM_SPAWN_E_WAIT",
                          "the child process could not be reaped or did not exit normally",
                          "retry; if it persists, capture the OS error and file an issue",
                          (unsigned long)errno, -1);
    }
    if (!spawn_buf_seal(&buf)) {
        free(buf.data);
        return spawn_fail(err, CBM_SPAWN_E_NOMEM, "CBM_SPAWN_E_NOMEM",
                          "out of memory sealing the captured output",
                          "retry after reducing memory pressure on the host", 0,
                          WEXITSTATUS(status));
    }

    *out_data = buf.data;
    *out_len = buf.len;
    if (WEXITSTATUS(status) != 0) {
        return spawn_fail(err, CBM_SPAWN_E_EXIT, "CBM_SPAWN_E_EXIT",
                          "the child process exited with a non-zero status",
                          "inspect the child's exit code; the captured stdout is still returned", 0,
                          WEXITSTATUS(status));
    }
    return spawn_ok(err);
}

#endif /* _WIN32 */
