/*
 * subprocess.c — cross-platform spawn + supervise + classify.
 * See subprocess.h. The spawn/reap skeleton mirrors src/ui/http_server.c's
 * index subprocess; this generalizes it and adds crash/hang classification.
 */
#include "subprocess.h"

#include "compat.h"    /* cbm_nanosleep */
#include "compat_fs.h" /* cbm_fopen — #415 long-path-safe worker-log tail */
#include "log.h"       /* cbm_log_warn — structured fail-closed handle-scope error (#438) */
#include "platform.h"  /* cbm_now_ms */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include "win_utf8.h" /* cbm_utf8_to_wide — spawn the worker with a wide command line so a
                       * non-ASCII repo path survives CreateProcess (#423/#20) */
#include <stdlib.h>   /* free */
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* NTSTATUS severity ERROR (top two bits set) covers the Windows crash exception
 * exit codes: 0xC0000005 (access violation), 0xC00000FD (stack overflow),
 * 0xC000001D (illegal instruction), 0xC0000094 (integer divide by zero), …
 *
 * GCC/MinGW SEH C++ exception markers are user-defined exception codes with a
 * success severity nibble, so they do not satisfy >= 0xC0000000 even though a
 * worker terminating with one is an unhandled C++ exception, not a graceful
 * application exit. */
#define CBM_WIN_CRASH_CODE_MIN 0xC0000000u
#define CBM_WIN_GCC_THROW 0x20474343u
#define CBM_WIN_GCC_UNWIND 0x21474343u

#ifdef _WIN32
static bool cbm_env_truthy(const char *name) {
    const char *value = getenv(name);
    return value && value[0] && strcmp(value, "0") != 0;
}

/* CreateProcessW accepts at most 32,767 UTF-16 code units including the NUL.
 * Four UTF-8 bytes per UTF-16 unit is a conservative structural transport cap,
 * not a measured workload budget. */
enum { CBM_WIN_COMMAND_LINE_MAX_WCHARS = 32767 };
#define CBM_WIN_COMMAND_LINE_MAX_UTF8_BYTES \
    ((size_t)CBM_WIN_COMMAND_LINE_MAX_WCHARS * 4u)

static bool cbm_win_utf8_application_path_absolute(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
        return true;
    }
    if (strncmp(path, "\\\\?\\UNC\\", 8) == 0) {
        return path[8] != '\0';
    }
    if (strncmp(path, "\\\\?\\", 4) == 0) {
        return ((path[4] >= 'A' && path[4] <= 'Z') ||
                (path[4] >= 'a' && path[4] <= 'z')) &&
               path[5] == ':' && (path[6] == '\\' || path[6] == '/');
    }
    return path[0] == '\\' && path[1] == '\\' && path[2] != '\0' && path[2] != '?' &&
           path[2] != '.';
}

static int cbm_win_spawn_refused(cbm_proc_result_t *out, const char *code, const char *stage,
                                 DWORD native_error, const char *application,
                                 const char *message, const char *remediation) {
    char native_error_text[32];
    snprintf(native_error_text, sizeof(native_error_text), "%lu", (unsigned long)native_error);
    cbm_log_error("subprocess.win.spawn_refused", "code", code, "stage", stage,
                  "win32_error", native_error_text, "application",
                  application ? application : "<null>", "message", message, "remediation",
                  remediation);
    out->outcome = CBM_PROC_SPAWN_FAILED;
    out->exit_code = -1;
    out->term_signal = 0;
    return -1;
}

static int cbm_win_log_spawn_refused(cbm_proc_result_t *out, const char *code,
                                     const char *stage, DWORD native_error,
                                     const char *application, const char *log_path,
                                     const char *message, const char *remediation) {
    char native_error_text[32];
    snprintf(native_error_text, sizeof(native_error_text), "%lu", (unsigned long)native_error);
    cbm_log_error("subprocess.win.spawn_refused", "code", code, "stage", stage,
                  "win32_error", native_error_text, "application",
                  application ? application : "<null>", "log_path",
                  log_path ? log_path : "<null>", "message", message, "remediation",
                  remediation);
    out->outcome = CBM_PROC_SPAWN_FAILED;
    out->exit_code = -1;
    out->term_signal = 0;
    return -1;
}

/* A failed pre-spawn must not strand a requested delete-on-exit log. Delete the
 * exact already-widened path once, then independently read the namespace back.
 * PRESENT or an unevaluable readback is preserving: never retry through another
 * spelling or claim cleanup from DeleteFileW's return value alone. */
static void cbm_win_cleanup_failed_spawn_log(const char *log_path, const wchar_t *wide_log,
                                             const char *spawn_stage) {
    SetLastError(ERROR_SUCCESS);
    BOOL deleted = DeleteFileW(wide_log);
    DWORD delete_error = deleted ? ERROR_SUCCESS : GetLastError();

    SetLastError(ERROR_SUCCESS);
    DWORD attributes = GetFileAttributesW(wide_log);
    DWORD readback_error =
        attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;

    char delete_error_text[32];
    char readback_error_text[32];
    snprintf(delete_error_text, sizeof(delete_error_text), "%lu",
             (unsigned long)delete_error);
    snprintf(readback_error_text, sizeof(readback_error_text), "%lu",
             (unsigned long)readback_error);
    if (attributes == INVALID_FILE_ATTRIBUTES &&
        (readback_error == ERROR_FILE_NOT_FOUND || readback_error == ERROR_PATH_NOT_FOUND)) {
        cbm_log_info("subprocess.win.log_cleanup", "code",
                     "CBM_SUBPROCESS_LOG_CLEANUP_VERIFIED_ABSENT", "stage", spawn_stage,
                     "log_path", log_path, "delete_win32_error", delete_error_text,
                     "readback_win32_error", readback_error_text, "message",
                     "the failed-spawn log path is absent after exact cleanup readback");
        return;
    }
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        cbm_log_error("subprocess.win.log_cleanup", "code",
                      "CBM_SUBPROCESS_LOG_CLEANUP_PRESERVED_PRESENT", "stage", spawn_stage,
                      "log_path", log_path, "delete_win32_error", delete_error_text,
                      "readback_win32_error", readback_error_text, "message",
                      "the failed-spawn log remains present after its one exact cleanup attempt",
                      "remediation",
                      "inspect and remove the reported exact log only after confirming no process owns it");
        return;
    }
    cbm_log_error("subprocess.win.log_cleanup", "code",
                  "CBM_SUBPROCESS_LOG_CLEANUP_READBACK_FAILED", "stage", spawn_stage,
                  "log_path", log_path, "delete_win32_error", delete_error_text,
                  "readback_win32_error", readback_error_text, "message",
                  "the failed-spawn log cleanup result could not be read back", "remediation",
                  "preserve the reported path and inspect the Win32 readback error before cleanup");
}

static wchar_t *cbm_win_utf8_to_wide_strict(const char *value, DWORD *native_error) {
    *native_error = ERROR_SUCCESS;
    if (!value) {
        *native_error = ERROR_INVALID_PARAMETER;
        return NULL;
    }
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, NULL, 0);
    if (needed <= 0) {
        DWORD error = GetLastError();
        *native_error = error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION;
        return NULL;
    }
    if (needed > CBM_WIN_COMMAND_LINE_MAX_WCHARS ||
        (size_t)needed > SIZE_MAX / sizeof(wchar_t)) {
        *native_error = ERROR_INSUFFICIENT_BUFFER;
        return NULL;
    }
    wchar_t *wide = malloc((size_t)needed * sizeof(*wide));
    if (!wide) {
        *native_error = ERROR_OUTOFMEMORY;
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, wide, needed) != needed) {
        DWORD error = GetLastError();
        free(wide);
        *native_error = error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION;
        return NULL;
    }
    return wide;
}
#endif

static bool cbm_is_windows_crash_exit(unsigned code) {
    return code >= CBM_WIN_CRASH_CODE_MIN || code == CBM_WIN_GCC_THROW ||
           code == CBM_WIN_GCC_UNWIND;
}

#ifndef _WIN32
static bool cbm_is_fault_signal(int sig) {
    switch (sig) {
    case SIGSEGV:
    case SIGBUS:
    case SIGILL:
    case SIGFPE:
    case SIGABRT:
    case SIGSYS:
        return true;
    default:
        return false;
    }
}
#endif

cbm_proc_outcome_t cbm_proc_classify(bool exited_normally, int exit_code, int term_signal,
                                     bool timed_out) {
    if (timed_out) {
        return CBM_PROC_HANG;
    }
    if (!exited_normally) {
        /* POSIX signal death. */
#ifndef _WIN32
        if (cbm_is_fault_signal(term_signal)) {
            return CBM_PROC_CRASH;
        }
#else
        (void)term_signal;
#endif
        return CBM_PROC_KILLED;
    }
    /* Exited with a code. A Windows exception/GCC-SEH marker code is a crash; on POSIX
     * exit codes are 0..255 so this branch never misfires there. */
    if (cbm_is_windows_crash_exit((unsigned)exit_code)) {
        return CBM_PROC_CRASH;
    }
    return (exit_code == 0) ? CBM_PROC_CLEAN : CBM_PROC_EXIT_NONZERO;
}

const char *cbm_proc_outcome_str(cbm_proc_outcome_t o) {
    switch (o) {
    case CBM_PROC_CLEAN:
        return "clean";
    case CBM_PROC_EXIT_NONZERO:
        return "exit_nonzero";
    case CBM_PROC_CRASH:
        return "crash";
    case CBM_PROC_HANG:
        return "hang";
    case CBM_PROC_KILLED:
        return "killed";
    case CBM_PROC_CANCELLED:
        return "cancelled";
    case CBM_PROC_PROGRESS_FAILED:
        return "progress_failed";
    case CBM_PROC_SPAWN_FAILED:
    default:
        return "spawn_failed";
    }
}

/* Tail newly-appended complete diagnostic lines from the child log, starting at
 * *tail_pos. A partial final line remains buffered. Log bytes never constitute
 * semantic work and therefore never affect the quiet-timeout. */
static void cbm_tail_log(const char *log_file, long *tail_pos, cbm_proc_log_cb cb, void *ud) {
    if (!log_file) {
        return;
    }
    /* #415: cbm_fopen widens + adds "\\?\" so a worker log under a deep store
     * (<store>/logs/.worker-<pid>.log) is tailable instead of failing at MAX_PATH. */
    FILE *lf = cbm_fopen(log_file, "r");
    if (!lf) {
        return;
    }
    if (fseek(lf, *tail_pos, SEEK_SET) == 0) {
        char line[1024];
        for (;;) {
            long before = ftell(lf);
            if (!fgets(line, sizeof(line), lf)) {
                break;
            }
            size_t l = strlen(line);
            bool complete = (l > 0 && line[l - 1] == '\n');
            if (complete) {
                line[l - 1] = '\0';
                *tail_pos = ftell(lf);
                if (line[0] && cb) {
                    cb(line, ud);
                }
            } else if (l == sizeof(line) - 1) {
                /* Oversized line filled the buffer without a newline — consume it
                 * so diagnostic delivery never stalls on one long line. */
                *tail_pos = ftell(lf);
                if (cb) {
                    cb(line, ud);
                }
            } else {
                /* Genuine partial final line — keep it buffered for next poll. */
                *tail_pos = before;
                break;
            }
        }
    }
    fclose(lf);
}

/* ── Windows command-line quoting (pure; unit-tested on every platform) ─────── */

/* Append char `c` to buf[cap], reserving the final byte for a NUL terminator.
 * On overflow: sets *ovf, stops writing, and returns pos UNCHANGED — callers detect
 * the overflow via the *ovf flag (not via the return value). */
static size_t cbm_cmdline_put(char *buf, size_t cap, size_t pos, char c, bool *ovf) {
    if (cap == 0 || pos >= cap - 1) {
        *ovf = true;
        return pos;
    }
    if (buf) {
        buf[pos] = c;
    }
    return pos + 1;
}

/* Append one argv element to the command line using the Microsoft C runtime
 * quoting rules (see MS "Parsing C Command-Line Arguments"). CreateProcess takes
 * a SINGLE string that the child re-parses back into argv, so any element with a
 * space, tab or double-quote must be wrapped in quotes and its embedded quotes /
 * preceding backslashes escaped. Without this a JSON argument like
 * {"repo_path":"C:/r"} loses its inner quotes and the child receives the invalid
 * {repo_path:C:/r} — the Windows-only index-worker cmdline-quoting bug (the worker exited
 * non-zero at JSON-arg parse, misattributed to the last-marked file). POSIX is
 * unaffected: cbm_run_posix passes the argv array straight to execv. */
static size_t cbm_cmdline_append_arg(char *buf, size_t cap, size_t pos, const char *arg, bool first,
                                     bool *ovf) {
    if (!first) {
        pos = cbm_cmdline_put(buf, cap, pos, ' ', ovf);
    }
    pos = cbm_cmdline_put(buf, cap, pos, '"', ovf);
    for (const char *p = arg; *p;) {
        size_t nbs = 0;
        while (*p == '\\') {
            nbs++;
            p++;
        }
        if (*p == '\0') {
            /* Trailing backslashes precede the closing quote: double them so the
             * quote stays a delimiter, not an escaped literal. */
            if (nbs > (SIZE_MAX - 1) / 2) {
                *ovf = true;
                return pos;
            }
            for (size_t k = 0; k < nbs * 2; k++) {
                pos = cbm_cmdline_put(buf, cap, pos, '\\', ovf);
            }
            break;
        }
        if (*p == '"') {
            /* N backslashes then a quote -> 2N+1 backslashes then an escaped quote. */
            if (nbs > (SIZE_MAX - 2) / 2) {
                *ovf = true;
                return pos;
            }
            for (size_t k = 0; k < nbs * 2 + 1; k++) {
                pos = cbm_cmdline_put(buf, cap, pos, '\\', ovf);
            }
            pos = cbm_cmdline_put(buf, cap, pos, '"', ovf);
            p++;
        } else {
            for (size_t k = 0; k < nbs; k++) {
                pos = cbm_cmdline_put(buf, cap, pos, '\\', ovf);
            }
            pos = cbm_cmdline_put(buf, cap, pos, *p, ovf);
            p++;
        }
    }
    pos = cbm_cmdline_put(buf, cap, pos, '"', ovf);
    return pos;
}

/* Build a full Windows CreateProcess command line from a NULL-terminated argv,
 * applying the MS C runtime quoting rules so the child re-parses byte-identical
 * argv. Returns true on success, false if the result would overflow `buf`.
 *
 * Defined unconditionally (pure string logic, no Windows headers) so the quoting
 * contract is unit-tested on Linux/macOS CI too — even though the real spawn path
 * only runs on Windows. Shared by cbm_run_win AND the UI http_server index spawn
 * so both escape identically; a naive `"%s"` wrap silently corrupts any argument
 * containing a quote (e.g. the index JSON {"repo_path":"…"}), corrupting the
 * spawned child's argv. */
bool cbm_build_win_cmdline(char *buf, size_t cap, const char *const *argv) {
    if (!buf || cap == 0 || !argv) {
        return false;
    }
    size_t pos = 0;
    bool ovf = false;
    for (int i = 0; argv[i]; i++) {
        pos = cbm_cmdline_append_arg(buf, cap, pos, argv[i], i == 0, &ovf);
        if (ovf) {
            buf[0] = '\0'; /* overflow: leave buf a valid (empty) string, never unterminated */
            return false;
        }
    }
    buf[pos] = '\0';
    return true;
}

#ifdef _WIN32

static bool cbm_win_cmdline_required_capacity(const char *const *argv, size_t *capacity) {
    if (!argv || !capacity) {
        return false;
    }
    size_t pos = 0;
    bool ovf = false;
    for (int i = 0; argv[i]; i++) {
        pos = cbm_cmdline_append_arg(NULL, SIZE_MAX, pos, argv[i], i == 0, &ovf);
        if (ovf) {
            return false;
        }
    }
    if (pos == SIZE_MAX) {
        return false;
    }
    *capacity = pos + 1;
    return true;
}

static int cbm_run_win(const cbm_proc_opts_t *opts, cbm_proc_result_t *out) {
    const char *bin = opts->bin;
    const char *const default_argv[] = {bin, NULL};
    const char *const *argv = opts->argv ? opts->argv : default_argv;

    if (!cbm_win_utf8_application_path_absolute(bin)) {
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_APPLICATION_PATH_NOT_ABSOLUTE", "application_path",
            ERROR_BAD_PATHNAME, bin,
            "the process application identity is not one exact absolute Windows path",
            "bind the absolute shipping executable path before requesting a child process");
    }
    DWORD application_error = ERROR_SUCCESS;
    wchar_t *wbin = cbm_utf8_to_wide_path_checked(bin, &application_error);
    if (!wbin) {
        const char *code = "CBM_SUBPROCESS_APPLICATION_PATH_PREPARATION_FAILED";
        const char *message =
            "the exact executable path could not be prepared as a native Windows path";
        const char *remediation =
            "inspect the reported Win32 path error and bind the ordinary shipping executable";
        if (application_error == ERROR_NOT_ENOUGH_MEMORY ||
            application_error == ERROR_OUTOFMEMORY) {
            code = "CBM_SUBPROCESS_APPLICATION_PATH_ALLOCATION_FAILED";
            message = "memory allocation failed while preparing the exact executable path";
            remediation = "free memory and retry without changing the executable identity";
        } else if (application_error == ERROR_FILENAME_EXCED_RANGE ||
                   application_error == ERROR_INSUFFICIENT_BUFFER) {
            code = "CBM_SUBPROCESS_APPLICATION_PATH_TOO_LONG";
            message = "the exact executable path exceeds the native Windows path limit";
            remediation = "place the shipping executable within the native Windows path limit";
        } else if (application_error == ERROR_NO_UNICODE_TRANSLATION) {
            code = "CBM_SUBPROCESS_APPLICATION_PATH_ENCODING_FAILED";
            message = "the exact executable path is not valid UTF-8";
            remediation = "bind one absolute UTF-8 shipping executable path";
        }
        return cbm_win_spawn_refused(out, code, "application_path", application_error, bin,
                                     message, remediation);
    }
    size_t application_wchars = wcslen(wbin) + 1;
    if (application_wchars > CBM_WIN_COMMAND_LINE_MAX_WCHARS) {
        free(wbin);
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_APPLICATION_PATH_TOO_LONG", "application_path",
            ERROR_INSUFFICIENT_BUFFER, bin,
            "the exact executable path exceeds the CreateProcessW application-name limit",
            "place the shipping executable within the native Windows path limit");
    }

    size_t cmdline_cap = 0;
    if (!cbm_win_cmdline_required_capacity(argv, &cmdline_cap) ||
        cmdline_cap > CBM_WIN_COMMAND_LINE_MAX_UTF8_BYTES) {
        free(wbin);
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_COMMAND_LINE_TOO_LONG", "command_line_size",
            ERROR_INSUFFICIENT_BUFFER, bin,
            "the exact child argument vector cannot fit in a Windows process command line",
            "shorten the exact argument paths; do not remove or truncate worker arguments");
    }
    char *cmdline = malloc(cmdline_cap);
    if (!cmdline) {
        free(wbin);
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_COMMAND_LINE_ALLOCATION_FAILED", "command_line_allocation",
            ERROR_OUTOFMEMORY, bin,
            "memory allocation failed while encoding the exact child argument vector",
            "free memory and retry without changing the worker argument contract");
    }
    if (!cbm_build_win_cmdline(cmdline, cmdline_cap, argv)) {
        free(cmdline);
        free(wbin);
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_COMMAND_LINE_ENCODING_FAILED", "command_line_encoding",
            ERROR_INSUFFICIENT_BUFFER, bin,
            "the exact child argument vector changed size while it was being encoded",
            "keep the immutable argument vector live through process creation and retry");
    }

    DWORD command_error = ERROR_SUCCESS;
    wchar_t *wcmd = cbm_win_utf8_to_wide_strict(cmdline, &command_error);
    free(cmdline);
    if (!wcmd) {
        const char *code = "CBM_SUBPROCESS_COMMAND_LINE_ENCODING_FAILED";
        const char *message = "the exact child argument vector is not valid UTF-8";
        const char *remediation = "supply every worker argument as exact valid UTF-8";
        if (command_error == ERROR_OUTOFMEMORY) {
            code = "CBM_SUBPROCESS_COMMAND_LINE_ALLOCATION_FAILED";
            message = "memory allocation failed while widening the exact child argument vector";
            remediation = "free memory and retry without changing the worker argument contract";
        } else if (command_error == ERROR_INSUFFICIENT_BUFFER) {
            code = "CBM_SUBPROCESS_COMMAND_LINE_TOO_LONG";
            message = "the exact child argument vector exceeds the Windows command-line limit";
            remediation = "shorten the exact argument paths; do not truncate worker arguments";
        }
        free(wbin);
        return cbm_win_spawn_refused(out, code, "command_line_utf8", command_error, bin,
                                     message, remediation);
    }

    /* Spawn via CreateProcessW with an explicit WIDE application identity and a
     * separate WIDE command line. CreateProcessA would
     * re-interpret our UTF-8 cmdline bytes through the ANSI code page (CP_ACP),
     * re-mangling a non-ASCII repo path at the parent->worker boundary — so the
     * worker's own wide-argv read could never recover it (#423/#20). Passing
     * wbin as lpApplicationName makes executable selection independent of
     * command-line token parsing while argv[0] remains byte-equivalent. */

    HANDLE hlog = INVALID_HANDLE_VALUE;
    wchar_t *wlog = NULL;
    /* Use the EXTENDED startup info so we can attach a PROC_THREAD_ATTRIBUTE_HANDLE_LIST
     * that scopes inheritance to exactly the log handle (#438). Its first member IS a
     * STARTUPINFOW, so &six.StartupInfo is the CreateProcessW startup pointer either way. */
    STARTUPINFOEXW six = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;
    if (opts->log_file) {
        /* #415: create the worker log via CreateFileW with an extended-length
         * ("\\?\") widened path so a log under a deep store (<store>/logs/…)
         * opens instead of failing at MAX_PATH — which would drop the worker's
         * stdout/stderr and the exit-capture the reap surfaces on failure. */
        DWORD log_path_error = ERROR_SUCCESS;
        wlog = cbm_utf8_to_wide_path_checked(opts->log_file, &log_path_error);
        if (!wlog) {
            const char *code = "CBM_SUBPROCESS_LOG_PATH_PREPARATION_FAILED";
            const char *message =
                "the requested worker log path could not be prepared as a native Windows path";
            const char *remediation =
                "inspect the reported Win32 path error and the exact requested log path";
            if (log_path_error == ERROR_NOT_ENOUGH_MEMORY ||
                log_path_error == ERROR_OUTOFMEMORY) {
                code = "CBM_SUBPROCESS_LOG_PATH_ALLOCATION_FAILED";
                message = "memory allocation failed while preparing the requested worker log path";
                remediation = "free memory and retry without dropping worker-log redirection";
            } else if (log_path_error == ERROR_FILENAME_EXCED_RANGE ||
                       log_path_error == ERROR_INSUFFICIENT_BUFFER) {
                code = "CBM_SUBPROCESS_LOG_PATH_TOO_LONG";
                message = "the requested worker log path exceeds the native Windows path limit";
                remediation = "shorten the exact log path; do not run the worker without its log";
            } else if (log_path_error == ERROR_NO_UNICODE_TRANSLATION) {
                code = "CBM_SUBPROCESS_LOG_PATH_ENCODING_FAILED";
                message = "the requested worker log path is not valid UTF-8";
                remediation = "supply one exact valid UTF-8 log path";
            }
            free(wcmd);
            free(wbin);
            return cbm_win_log_spawn_refused(out, code, "log_path", log_path_error, bin,
                                             opts->log_file, message, remediation);
        }
        /* #435: the log handle MUST be created inheritable, or the child never
         * receives it. CreateProcessW hands a handle to the child as a std
         * handle (STARTF_USESTDHANDLES) only when the handle itself is
         * inheritable AND bInheritHandles=TRUE. With NULL security attributes
         * this handle was NON-inheritable, so the worker's stdout/stderr were
         * wired to an invalid child handle: the log file stayed 0 bytes and
         * GET /api/logs never showed a single worker pipeline line (indexing
         * still succeeded because the graph is written straight to the store,
         * not via the log — which is why the empty log went unnoticed until
         * #435). bInheritHandle=TRUE fixes the actual defect. FILE_SHARE_WRITE
         * additionally lets the parent open the file for reading to tail it
         * while the worker still holds it open for write, so progress streams
         * live instead of only surfacing after the worker exits. */
        SECURITY_ATTRIBUTES sa = {
            .nLength = sizeof(sa), .lpSecurityDescriptor = NULL, .bInheritHandle = TRUE};
        hlog = CreateFileW(wlog, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hlog == INVALID_HANDLE_VALUE) {
            DWORD log_open_error = GetLastError();
            free(wlog);
            free(wcmd);
            free(wbin);
            return cbm_win_log_spawn_refused(
                out, "CBM_SUBPROCESS_LOG_OPEN_FAILED", "log_open", log_open_error, bin,
                opts->log_file,
                "the requested worker log could not be created for exact stdout/stderr redirection",
                "inspect the reported Win32 error and make the exact log directory writable");
        }
        {
            /* #438: because the log handle is now inheritable (#435), a bare
             * CreateProcessW(bInheritHandles=TRUE) would leak EVERY inheritable
             * handle in the parent into this child — a second concurrent index
             * worker could inherit the first job's still-open log handle and keep
             * that log file alive past its delete-on-exit unlink. Scope inheritance
             * to EXACTLY hlog with PROC_THREAD_ATTRIBUTE_HANDLE_LIST (STARTUPINFOEXW
             * + EXTENDED_STARTUPINFO_PRESENT). Requirements observed (MS "Inheritance"
             * docs + Raymond Chen, The Old New Thing 2011-12-16): the listed handle
             * is itself inheritable (sa.bInheritHandle=TRUE above); it is a real
             * kernel handle, never a pseudo-handle; the attribute buffer is
             * heap-allocated with the size the first InitializeProcThreadAttributeList
             * call reports; UpdateProcThreadAttribute takes a BYTE count
             * (1 * sizeof(HANDLE)), not a handle count; and DeleteProcThreadAttributeList
             * + free run on every path. hStdInput stays NULL (unchanged from the prior
             * spawn) so no other std handle needs listing. */
            SIZE_T attr_size = 0;
            (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size); /* sizing call */
            bool attr_inited = false;
            bool attr_ok = false;
            const char *attr_stage = "size";
            DWORD attr_error = GetLastError();
            if (attr_size > 0) {
                attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
                if (!attr_list) {
                    attr_stage = "alloc";
                    attr_error = ERROR_OUTOFMEMORY;
                } else if (InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
                    attr_inited = true;
                    if (cbm_env_truthy("CBM_DEBUG_HANDLE_SCOPE_FAIL")) {
                        attr_stage = "forced_debug";
                        attr_error = ERROR_INVALID_PARAMETER;
                    } else if (UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                         &hlog, sizeof(HANDLE), NULL, NULL)) {
                        attr_ok = true;
                    } else {
                        attr_stage = "update";
                        attr_error = GetLastError();
                    }
                } else {
                    attr_stage = "init";
                    attr_error = GetLastError();
                }
            }
            if (!attr_ok) {
                /* Fail closed: NEVER fall back to inherit-all (that IS the #438 leak).
                 * Surface a structured {code, message, remediation} through the
                 * subprocess spawn-error surface (CBM_PROC_SPAWN_FAILED); the caller
                 * turns it into the user-facing index-worker spawn error. */
                char win32_error[16];
                snprintf(win32_error, sizeof(win32_error), "%lu", (unsigned long)attr_error);
                cbm_log_warn("subprocess.win.handle_scope_failed", "code", "handle_scope_failed",
                             "stage", attr_stage, "win32_error", win32_error,
                             "message",
                             "could not build per-spawn PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
                             "remediation",
                             "no inherit-all fallback (would leak concurrent workers' log "
                             "handles); retry the index job — if persistent, check process "
                             "handle/memory limits");
                if (attr_inited) {
                    DeleteProcThreadAttributeList(attr_list);
                }
                free(attr_list);
                CloseHandle(hlog);
                if (opts->log_file && opts->delete_log_on_exit) {
                    cbm_win_cleanup_failed_spawn_log(opts->log_file, wlog,
                                                     "handle_scope");
                }
                free(wlog);
                free(wcmd);
                free(wbin);
                out->outcome = CBM_PROC_SPAWN_FAILED;
                out->exit_code = -1;
                out->term_signal = 0;
                return -1;
            }
            six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            six.StartupInfo.hStdError = hlog;
            six.StartupInfo.hStdOutput = hlog;
            six.lpAttributeList = attr_list;
        }
    }

    /* With a scoped attribute list, inherit ONLY the listed handle; with no log
     * handle at all, inherit NOTHING (bInheritHandles=FALSE) — the pre-#438 code
     * passed TRUE unconditionally, which is exactly the leak this closes. When the
     * extended block is present, cb must be sizeof(STARTUPINFOEXW). */
    BOOL inherit = attr_list ? TRUE : FALSE;
    DWORD create_flags = attr_list ? EXTENDED_STARTUPINFO_PRESENT : 0;
    six.StartupInfo.cb = attr_list ? sizeof(six) : sizeof(six.StartupInfo);

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessW(wbin, wcmd, NULL, NULL, inherit, create_flags, NULL, NULL,
                             &six.StartupInfo, &pi);
    DWORD create_error = ok ? ERROR_SUCCESS : GetLastError();
    free(wcmd);
    free(wbin);
    if (attr_list) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_list);
    }
    if (hlog != INVALID_HANDLE_VALUE) {
        CloseHandle(hlog);
    }
    if (!ok) {
        if (opts->log_file && opts->delete_log_on_exit) {
            cbm_win_cleanup_failed_spawn_log(opts->log_file, wlog, "CreateProcessW");
        }
        free(wlog);
        return cbm_win_spawn_refused(
            out, "CBM_SUBPROCESS_CREATE_PROCESS_FAILED", "CreateProcessW", create_error, bin,
            "Windows refused to create the exact configured executable process",
            "inspect the reported Win32 error and the bound executable path; do not retry through PATH or argv discovery");
    }
    free(wlog);
    if (opts->on_spawn) {
        opts->on_spawn((long)pi.dwProcessId, opts->spawn_ud);
    }

    long tail_pos = 0;
    uint64_t last_activity = cbm_now_ms();
    bool timed_out = false;
    bool cancelled = false;
    bool progress_failed = false;
    for (;;) {
        DWORD w = WaitForSingleObject(pi.hProcess, 200);
        cbm_tail_log(opts->log_file, &tail_pos, opts->on_log_line, opts->log_ud);
        bool done = w == WAIT_OBJECT_0;
        if (opts->on_progress) {
            cbm_proc_progress_result_t progress =
                opts->on_progress(done, opts->progress_ud);
            if (progress == CBM_PROC_PROGRESS_INVALID) {
                if (!done) {
                    (void)TerminateProcess(pi.hProcess, 1);
                    (void)WaitForSingleObject(pi.hProcess, INFINITE);
                }
                progress_failed = true;
                break;
            }
            if (progress == CBM_PROC_PROGRESS_ADVANCED) {
                last_activity = cbm_now_ms();
            }
        }
        if (done) {
            break;
        }
        if (opts->should_cancel && opts->should_cancel(opts->cancel_ud)) {
            (void)TerminateProcess(pi.hProcess, 1);
            (void)WaitForSingleObject(pi.hProcess, INFINITE);
            if (opts->on_progress) {
                (void)opts->on_progress(true, opts->progress_ud);
            }
            cancelled = true;
            break;
        }
        if (opts->quiet_timeout_ms > 0 &&
            (cbm_now_ms() - last_activity) >= (uint64_t)opts->quiet_timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, INFINITE);
            cbm_proc_progress_result_t terminal =
                opts->on_progress(true, opts->progress_ud);
            progress_failed = terminal == CBM_PROC_PROGRESS_INVALID;
            timed_out = !progress_failed;
            break;
        }
    }

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (opts->log_file && opts->delete_log_on_exit) {
        /* #415: long-path-safe delete of the worker log under a deep store. */
        (void)cbm_unlink(opts->log_file);
    }

    out->exit_code = (int)code;
    out->term_signal = 0;
    out->outcome = cancelled       ? CBM_PROC_CANCELLED
                   : progress_failed ? CBM_PROC_PROGRESS_FAILED
                                     : cbm_proc_classify(true, (int)code, 0, timed_out);
    return 0;
}

#else /* POSIX */

static int cbm_run_posix(const cbm_proc_opts_t *opts, cbm_proc_result_t *out) {
    pid_t pid = fork();
    if (pid < 0) {
        out->outcome = CBM_PROC_SPAWN_FAILED;
        out->exit_code = -1;
        out->term_signal = 0;
        return -1;
    }
    if (pid == 0) {
        /* Child: redirect stdout+stderr to the log (or discard), then exec.
         * Use open()+dup2() (async-signal-safe, no malloc) rather than freopen():
         * the parent may be multithreaded (the MCP server holds worker/watcher/http
         * threads plus mimalloc/sqlite global state), and a fork() copies
         * only the calling thread — a malloc between fork and exec could deadlock on
         * a lock another thread held at fork time. open/dup2/execv touch no heap. */
        const char *bin = opts->bin;
        const char *const default_argv[] = {bin, NULL};
        const char *const *argv = opts->argv ? opts->argv : default_argv;
        const char *target = opts->log_file ? opts->log_file : "/dev/null";
        int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) {
                (void)close(fd);
            }
        }
        execv(bin, (char *const *)argv);
        _exit(127); /* exec failed */
    }

    if (opts->on_spawn) {
        opts->on_spawn((long)pid, opts->spawn_ud);
    }

    long tail_pos = 0;
    uint64_t last_activity = cbm_now_ms();
    bool timed_out = false;
    bool cancelled = false;
    bool progress_failed = false;
    int wstatus = 0;
    for (;;) {
        pid_t wr;
        do {
            wr = waitpid(pid, &wstatus, WNOHANG);
        } while (wr < 0 && errno == EINTR);
        bool done = (wr == pid);

        cbm_tail_log(opts->log_file, &tail_pos, opts->on_log_line, opts->log_ud);
        if (opts->on_progress) {
            cbm_proc_progress_result_t progress =
                opts->on_progress(done, opts->progress_ud);
            if (progress == CBM_PROC_PROGRESS_INVALID) {
                if (!done) {
                    (void)kill(pid, SIGKILL);
                    do {
                        wr = waitpid(pid, &wstatus, 0);
                    } while (wr < 0 && errno == EINTR);
                }
                progress_failed = true;
                break;
            }
            if (progress == CBM_PROC_PROGRESS_ADVANCED) {
                last_activity = cbm_now_ms();
            }
        }
        if (done) {
            break;
        }
        if (opts->should_cancel && opts->should_cancel(opts->cancel_ud)) {
            (void)kill(pid, SIGKILL);
            do {
                wr = waitpid(pid, &wstatus, 0);
            } while (wr < 0 && errno == EINTR);
            if (opts->on_progress) {
                (void)opts->on_progress(true, opts->progress_ud);
            }
            cancelled = true;
            break;
        }
        if (opts->quiet_timeout_ms > 0 &&
            (cbm_now_ms() - last_activity) >= (uint64_t)opts->quiet_timeout_ms) {
            kill(pid, SIGKILL);
            do {
                wr = waitpid(pid, &wstatus, 0);
            } while (wr < 0 && errno == EINTR);
            cbm_proc_progress_result_t terminal =
                opts->on_progress(true, opts->progress_ud);
            progress_failed = terminal == CBM_PROC_PROGRESS_INVALID;
            timed_out = !progress_failed;
            break;
        }
        struct timespec ts = {0, 100000000L}; /* 100 ms poll */
        cbm_nanosleep(&ts, NULL);
    }

    if (opts->log_file && opts->delete_log_on_exit) {
        (void)unlink(opts->log_file);
    }

    if (cancelled) {
        out->exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
        out->term_signal = WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : 0;
        out->outcome = CBM_PROC_CANCELLED;
    } else if (progress_failed) {
        out->exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
        out->term_signal = WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : 0;
        out->outcome = CBM_PROC_PROGRESS_FAILED;
    } else if (WIFEXITED(wstatus)) {
        out->exit_code = WEXITSTATUS(wstatus);
        out->term_signal = 0;
        out->outcome = cbm_proc_classify(true, out->exit_code, 0, timed_out);
    } else if (WIFSIGNALED(wstatus)) {
        out->exit_code = -1;
        out->term_signal = WTERMSIG(wstatus);
        out->outcome = cbm_proc_classify(false, -1, out->term_signal, timed_out);
    } else {
        out->exit_code = -1;
        out->term_signal = 0;
        out->outcome = timed_out ? CBM_PROC_HANG : CBM_PROC_KILLED;
    }
    return 0;
}

#endif

int cbm_subprocess_run(const cbm_proc_opts_t *opts, cbm_proc_result_t *out) {
    cbm_proc_result_t local;
    if (!out) {
        out = &local;
    }
    out->outcome = CBM_PROC_SPAWN_FAILED;
    out->exit_code = -1;
    out->term_signal = 0;
    if (!opts || !opts->bin || !opts->bin[0]) {
        return -1;
    }
    if (opts->quiet_timeout_ms > 0 && !opts->on_progress) {
        cbm_log_error("subprocess.progress_contract_missing", "code",
                      "CBM_PROC_PROGRESS_CALLBACK_REQUIRED", "message",
                      "a quiet timeout requires an application-semantic progress reader",
                      "remediation",
                      "bind the supervised operation to its exact semantic progress source");
        return -1;
    }
#ifdef _WIN32
    return cbm_run_win(opts, out);
#else
    return cbm_run_posix(opts, out);
#endif
}
