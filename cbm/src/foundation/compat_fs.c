/*
 * compat_fs.c — Portable file system operations.
 *
 * POSIX: direct wrappers around opendir/readdir/closedir, popen/pclose, mkdir, unlink.
 * Windows: FindFirstFile/FindNextFile, _popen/_pclose, _mkdir, _unlink.
 */
#include "foundation/constants.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_fs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

/* ── Windows implementation ────────────────────────────────── */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h> /* _wmkdir */
#include <errno.h>  /* errno for spawn-failure logging */
#include <fcntl.h>  /* _O_RDONLY */
#include <io.h>     /* _wunlink, _open_osfhandle, _close */
#include <stdint.h> /* intptr_t */
#include "foundation/log.h"
#include "foundation/win_utf8.h"

struct cbm_dir {
    HANDLE find_handle;
    WIN32_FIND_DATAW find_data;
    cbm_dirent_t entry;
    bool first;
    bool done;
    DWORD error;
};

static _Thread_local unsigned long g_cbm_fs_last_error;

unsigned long cbm_fs_last_error(void) {
    return g_cbm_fs_last_error;
}

unsigned long cbm_dir_error(const cbm_dir_t *d) {
    return d ? (unsigned long)d->error : (unsigned long)ERROR_INVALID_PARAMETER;
}

cbm_dir_t *cbm_opendir(const char *path) {
    g_cbm_fs_last_error = ERROR_SUCCESS;
    if (!path) {
        g_cbm_fs_last_error = ERROR_INVALID_PARAMETER;
        return NULL;
    }
    /* #383: extended-length widen so directories deeper than MAX_PATH (260) are
     * enumerable (FindFirstFileW below) instead of silently skipped by the walk. */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        g_cbm_fs_last_error = GetLastError();
        if (g_cbm_fs_last_error == ERROR_SUCCESS) {
            g_cbm_fs_last_error = ERROR_NOT_ENOUGH_MEMORY;
        }
        return NULL;
    }

    size_t wlen = wcslen(wpath);
    if (wlen == 0 || wlen > (SIZE_MAX / sizeof(wchar_t)) - 3) {
        free(wpath);
        g_cbm_fs_last_error = ERROR_FILENAME_EXCED_RANGE;
        return NULL;
    }

    cbm_dir_t *d = (cbm_dir_t *)calloc(CBM_ALLOC_ONE, sizeof(cbm_dir_t));
    if (!d) {
        free(wpath);
        g_cbm_fs_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }

    wchar_t *wide_pattern = malloc((wlen + 3) * sizeof(wchar_t));
    if (!wide_pattern) {
        free(wpath);
        free(d);
        g_cbm_fs_last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    wmemcpy(wide_pattern, wpath, wlen + 1);
    wchar_t *p = wide_pattern + wlen - SKIP_ONE;
    if (*p != L'\\' && *p != L'/') {
        ++p;
        *p++ = L'\\';
    } else {
        ++p;
    }
    *p++ = L'*';
    *p = L'\0';
    free(wpath);

    d->find_handle = FindFirstFileW(wide_pattern, &d->find_data);
    free(wide_pattern);
    if (d->find_handle == INVALID_HANDLE_VALUE) {
        g_cbm_fs_last_error = GetLastError();
        free(d);
        return NULL;
    }
    d->first = true;
    d->done = false;
    return d;
}

cbm_dirent_t *cbm_readdir(cbm_dir_t *d) {
    if (!d || d->done) {
        return NULL;
    }
    if (!d->first) {
        if (!FindNextFileW(d->find_handle, &d->find_data)) {
            d->done = true;
            d->error = GetLastError();
            if (d->error == ERROR_NO_MORE_FILES) {
                d->error = ERROR_SUCCESS;
            }
            return NULL;
        }
    }
    d->first = false;

    while (d->find_data.cFileName[0] == L'.' &&
           (d->find_data.cFileName[1] == L'\0' ||
            (d->find_data.cFileName[1] == L'.' && d->find_data.cFileName[2] == L'\0'))) {
        if (!FindNextFileW(d->find_handle, &d->find_data)) {
            d->done = true;
            d->error = GetLastError();
            if (d->error == ERROR_NO_MORE_FILES) {
                d->error = ERROR_SUCCESS;
            }
            return NULL;
        }
    }

    char *u8 = cbm_wide_to_utf8(d->find_data.cFileName);
    if (!u8) {
        d->done = true;
        d->error = GetLastError();
        if (d->error == ERROR_SUCCESS) {
            d->error = ERROR_NO_UNICODE_TRANSLATION;
        }
        return NULL;
    }
    size_t nlen = strlen(u8);
    if (nlen >= CBM_DIRENT_NAME_MAX) {
        free(u8);
        d->done = true;
        d->error = ERROR_FILENAME_EXCED_RANGE;
        return NULL;
    }
    memcpy(d->entry.name, u8, nlen);
    d->entry.name[nlen] = '\0';
    free(u8);
    d->entry.is_dir = (d->find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    d->entry.d_type = 0;
    return &d->entry;
}

void cbm_closedir(cbm_dir_t *d) {
    if (d) {
        if (d->find_handle != INVALID_HANDLE_VALUE) {
            FindClose(d->find_handle);
        }
        free(d);
    }
}

/* Windows _popen replacement that inherits ONLY the child's stdout pipe.
 *
 * The CRT's _popen uses CreateProcess(bInheritHandles=TRUE), which leaks EVERY
 * inheritable handle we hold into the child — listening/client sockets, the
 * Winsock/AFD helper handles created by WSAStartup, the MCP stdio pipe, etc.
 * When the child is git-for-Windows (MSYS2/Cygwin runtime), its startup walks
 * every inherited handle and calls NtQueryObject on each to classify it; on an
 * inherited socket/AFD handle NtQueryObject deadlocks. Since our UI server runs
 * requests on a single thread, that wedges the whole server (list_projects,
 * which shells out to git per project, never returns → the web UI hangs).
 *
 * The fix: spawn via CreateProcessW with STARTUPINFOEXW + an explicit
 * PROC_THREAD_ATTRIBUTE_HANDLE_LIST containing only the stdout write-end and a
 * NUL handle for stdin/stderr. Nothing else crosses into git, so there is no
 * foreign handle to deadlock on. POSIX popen() already sets O_CLOEXEC on its
 * pipe, so the POSIX path is unchanged.
 *
 * There is deliberately NO fallback to _popen when the isolated spawn fails:
 * falling back would silently re-arm the deadlock. cbm_popen logs a structured
 * warning and returns NULL instead (every call site handles NULL). */

enum { CBM_POPEN_MAX = 16 };
static struct {
    FILE *fp;
    HANDLE proc;
} g_popen_tab[CBM_POPEN_MAX];
static CRITICAL_SECTION g_popen_lock;
static INIT_ONCE g_popen_once = INIT_ONCE_STATIC_INIT;

/* Test hook (declared in compat_fs_internal.h): 1 when the most recent
 * cbm_popen(..., "r") stream came from the isolated spawn. Test-only
 * observable; not synchronized across threads. */
static volatile LONG g_popen_last_isolated = 0;

int cbm_popen_last_was_isolated(void) {
    return (int)g_popen_last_isolated;
}

static BOOL CALLBACK cbm_popen_init(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    InitializeCriticalSection(&g_popen_lock);
    return TRUE;
}

/* Resolve the shell explicitly — %COMSPEC%, else <system dir>\cmd.exe — so it
 * can be passed as lpApplicationName and CreateProcess never walks the search
 * path (no cmd.exe planting from a hostile CWD). Heap string; caller frees. */
static wchar_t *cbm_resolve_comspec(void) {
    wchar_t buf[MAX_PATH];
    const wchar_t suffix[] = L"\\cmd.exe";
    DWORD n = GetEnvironmentVariableW(L"COMSPEC", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        UINT sn = GetSystemDirectoryW(buf, MAX_PATH);
        if (sn == 0 || (size_t)sn + wcslen(suffix) >= MAX_PATH) {
            return NULL;
        }
        wmemcpy(buf + sn, suffix, wcslen(suffix) + 1);
    }
    return _wcsdup(buf);
}

/* On failure returns NULL with *stage naming the failing step and *gle the
 * GetLastError value captured at that step (0 when errno is the signal). */
static FILE *cbm_popen_isolated(const char *cmd, const char **stage, DWORD *gle) {
    *stage = "";
    *gle = 0;
    InitOnceExecuteOnce(&g_popen_once, cbm_popen_init, NULL, NULL);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        *stage = "pipe";
        *gle = GetLastError();
        return NULL;
    }
    /* The parent read-end must never cross into the child. */
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    /* NUL for the child's stdin/stderr so it never touches our real stdin
     * pipe. If NUL cannot be opened, fail: STARTF_USESTDHANDLES slots must
     * never carry INVALID_HANDLE_VALUE. */
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    if (nul == INVALID_HANDLE_VALUE) {
        *stage = "nul";
        *gle = GetLastError();
        CloseHandle(rd);
        CloseHandle(wr);
        return NULL;
    }

    HANDLE inherit[2];
    inherit[0] = wr;
    inherit[1] = nul;

    SIZE_T attr_sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_sz);
    BOOL attr_init = attr && InitializeProcThreadAttributeList(attr, 1, 0, &attr_sz);
    BOOL prepared =
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

    /* Run through cmd.exe /c so command quoting and `2>NUL` behave as under
     * _popen. The command line is heap-composed (no fixed-size truncation)
     * and widened via UTF-8 so non-ASCII repo paths survive intact. */
    wchar_t *app = cbm_resolve_comspec();
    wchar_t *wcmdline = NULL;
    if (app) {
        size_t u8len = strlen(cmd) + sizeof("cmd.exe /c ");
        char *u8 = (char *)malloc(u8len);
        if (u8) {
            snprintf(u8, u8len, "cmd.exe /c %s", cmd);
            wcmdline = cbm_utf8_to_wide(u8);
            free(u8);
        }
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL created = FALSE;
    if (!prepared) {
        *stage = "attr";
        *gle = attr_gle;
    } else if (!app || !wcmdline) {
        *stage = "cmdline";
        *gle = ERROR_NOT_ENOUGH_MEMORY;
    } else {
        created = CreateProcessW(app, wcmdline, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT,
                                 NULL, NULL, &si.StartupInfo, &pi);
        if (!created) {
            *stage = "spawn";
            *gle = GetLastError();
        }
    }

    free(app);
    free(wcmdline);
    if (attr) {
        if (attr_init) {
            DeleteProcThreadAttributeList(attr);
        }
        free(attr);
    }
    CloseHandle(wr); /* the child owns the write-end now */
    CloseHandle(nul);
    if (!created) {
        CloseHandle(rd);
        return NULL;
    }
    CloseHandle(pi.hThread);

    int fd = _open_osfhandle((intptr_t)rd, _O_RDONLY);
    if (fd == -1) {
        *stage = "osfhandle";
        CloseHandle(rd);
        CloseHandle(pi.hProcess);
        return NULL;
    }
    FILE *fp = _fdopen(fd, "r"); /* takes ownership of fd/rd */
    if (!fp) {
        *stage = "fdopen";
        _close(fd);
        CloseHandle(pi.hProcess);
        return NULL;
    }

    EnterCriticalSection(&g_popen_lock);
    for (int i = 0; i < CBM_POPEN_MAX; i++) {
        if (!g_popen_tab[i].fp) {
            g_popen_tab[i].fp = fp;
            g_popen_tab[i].proc = pi.hProcess;
            LeaveCriticalSection(&g_popen_lock);
            return fp;
        }
    }
    LeaveCriticalSection(&g_popen_lock);
    /* Table full (shouldn't happen): don't leak the process handle. */
    *stage = "table";
    CloseHandle(pi.hProcess);
    fclose(fp);
    return NULL;
}

FILE *cbm_popen(const char *cmd, const char *mode) {
    /* Our git shell-outs are all read-mode; they MUST use the isolated
     * spawn. On failure, log and fail the call — never fall back to
     * _popen, whose full handle inheritance re-arms the UI hang (#798). */
    if (mode && mode[0] == 'r' && mode[1] == '\0') {
        const char *stage = "";
        DWORD gle = 0;
        FILE *fp = cbm_popen_isolated(cmd, &stage, &gle);
        g_popen_last_isolated = (fp != NULL);
        if (!fp) {
            char glebuf[CBM_SZ_16];
            char errnobuf[CBM_SZ_16];
            snprintf(glebuf, sizeof(glebuf), "%lu", (unsigned long)gle);
            snprintf(errnobuf, sizeof(errnobuf), "%d", errno);
            cbm_log_warn("compat.popen_isolated_failed", "stage", stage, "gle", glebuf, "errno",
                         errnobuf);
        }
        return fp;
    }
    g_popen_last_isolated = 0;
    return _popen(cmd, mode);
}

int cbm_pclose(FILE *f) {
    InitOnceExecuteOnce(&g_popen_once, cbm_popen_init, NULL, NULL);

    HANDLE proc = NULL;
    EnterCriticalSection(&g_popen_lock);
    for (int i = 0; i < CBM_POPEN_MAX; i++) {
        if (g_popen_tab[i].fp == f) {
            proc = g_popen_tab[i].proc;
            g_popen_tab[i].fp = NULL;
            g_popen_tab[i].proc = NULL;
            break;
        }
    }
    LeaveCriticalSection(&g_popen_lock);

    if (!proc) {
        return _pclose(f); /* opened via _popen (non-read mode) */
    }
    fclose(f);
    WaitForSingleObject(proc, INFINITE);
    DWORD code = 0;
    BOOL got = GetExitCodeProcess(proc, &code);
    CloseHandle(proc);
    return got ? (int)code : -1;
}

FILE *cbm_fopen(const char *path, const char *mode) {
    /* #383: extended-length widen for the path (not the mode) so files deeper than
     * MAX_PATH (260) open instead of returning NULL (a silent scan skip). */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return NULL;
    }
    wchar_t *wmode = cbm_utf8_to_wide(mode);
    if (!wmode) {
        free(wpath);
        return NULL;
    }
    FILE *f = _wfopen(wpath, wmode);
    free(wpath);
    free(wmode);
    return f;
}

bool cbm_mkdir_p(const char *path, int mode) {
    (void)mode;
    /* #415: extended-length widen so a directory whose absolute path exceeds
     * MAX_PATH (260) — e.g. <deep-store>/logs for the index-worker plumbing — can
     * actually be created instead of failing at _wmkdir. Without this the worker
     * args/log/exit-capture writes under a deep store fail closed at the missing
     * parent dir (ASTRO_SHADOW_INDEX_PASS_CRASHED outcome=spawn_failed). Short
     * paths (< 240 chars) widen byte-identically to the historical behavior.
     * On a "\\?\"-prefixed path the component walk below issues a few harmless
     * _wmkdir calls on the prefix bytes ("\", "\\?", <drive>) whose errors are
     * ignored exactly like every other intermediate component. */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return false;
    }

    size_t wlen = wcslen(wpath);
    wchar_t *tmp = (wchar_t *)malloc((wlen + 1) * sizeof(wchar_t));
    if (!tmp) {
        free(wpath);
        return false;
    }
    wmemcpy(tmp, wpath, wlen + 1);
    wchar_t *start = tmp;
    if (wlen >= 8 && wcsncmp(tmp, L"\\\\?\\UNC\\", 8) == 0) {
        start = tmp + 8;
        for (int separators = 0; *start && separators < 2; start++) {
            if (*start == L'\\' || *start == L'/') {
                separators++;
            }
        }
    } else if (wlen >= 7 && wcsncmp(tmp, L"\\\\?\\", 4) == 0 && tmp[5] == L':' &&
               (tmp[6] == L'\\' || tmp[6] == L'/')) {
        start = tmp + 7;
    } else if (wlen >= 3 && tmp[1] == L':' && (tmp[2] == L'\\' || tmp[2] == L'/')) {
        start = tmp + 3;
    } else if (wlen > 0 && (tmp[0] == L'\\' || tmp[0] == L'/')) {
        start = tmp + 1;
    }
    bool ok = true;
    for (wchar_t *p = start; *p; p++) {
        if (*p == L'/' || *p == L'\\') {
            wchar_t separator = *p;
            *p = L'\0';
            int mkdir_rc = _wmkdir(tmp);
            if (mkdir_rc != 0) {
                if (errno != EEXIST) {
                    ok = false;
                } else {
                    DWORD attributes = GetFileAttributesW(tmp);
                    ok = attributes != INVALID_FILE_ATTRIBUTES &&
                         (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                }
            }
            *p = separator;
            if (!ok) {
                break;
            }
        }
    }
    if (ok && _wmkdir(tmp) != 0) {
        if (errno != EEXIST) {
            ok = false;
        } else {
            DWORD attributes = GetFileAttributesW(tmp);
            ok = attributes != INVALID_FILE_ATTRIBUTES &&
                 (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }
    }
    free(tmp);
    free(wpath);
    return ok;
}

int cbm_unlink(const char *path) {
    /* #412: extended-length widen so store-family sidecars whose full path
     * exceeds MAX_PATH (e.g. <cache>/<project>.db-wal, <db>.corrupt under a deep
     * store) can be removed instead of failing. Short paths widen identically. */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return CBM_NOT_FOUND;
    }
    int ret = _wunlink(wpath);
    free(wpath);
    return ret;
}

bool cbm_path_exists(const char *path) {
    /* #430: extended-length widen so an existence probe on a store-family path
     * deeper than MAX_PATH (e.g. <deep-store>/<project>.db that delete_project's
     * not_found gate checks) reports the file that is really there, instead of
     * the false "not found" the ANSI access()/stat() probe returns past 260
     * chars. GetFileAttributesW honors the "\\?\" prefix cbm_utf8_to_wide_path
     * applies; short paths widen byte-identically to the historical access(). */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return false;
    }
    DWORD attrs = GetFileAttributesW(wpath);
    free(wpath);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

char *cbm_canonicalize_existing_path(const char *path) {
    /* #432: replaces the MAX_PATH-bound `_access(...,0) + _fullpath` pair used at
     * the repo-path (mcp.c) and source-file FQN (fqn.c) canonicalization sites.
     * cbm_utf8_to_wide_path fully-qualifies + "\\?\"-widens a >MAX_PATH input so
     * GetFullPathNameW accepts it (its documented way to take >260-char input);
     * for short inputs it returns the plain widened path and GetFullPathNameW does
     * the relative->absolute + '.'/'..' + '/'→'\\' resolution _fullpath did. The
     * extended-length prefix (if any) is stripped from the result so the canonical
     * path is a clean drive/UNC form. Existence is then confirmed via
     * cbm_path_exists (GetFileAttributesW, "\\?\"-widened). Fail-closed: any step
     * failing returns NULL (no ANSI fallback). */
    if (!path) {
        return NULL;
    }
    wchar_t *win = cbm_utf8_to_wide_path(path);
    if (!win) {
        return NULL;
    }
    DWORD need = GetFullPathNameW(win, 0, NULL, NULL);
    if (need == 0) {
        free(win);
        return NULL;
    }
    wchar_t *full = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
    if (!full) {
        free(win);
        return NULL;
    }
    DWORD got = GetFullPathNameW(win, need, full, NULL);
    free(win);
    if (got == 0 || got >= need) {
        free(full);
        return NULL;
    }
    char *result = cbm_wide_final_path_to_utf8(full);
    free(full);
    if (!result) {
        return NULL;
    }
    if (!cbm_path_exists(result)) {
        free(result);
        return NULL;
    }
    return result;
}

char *cbm_real_path_final(const char *path) {
    /* #437: junction/symlink- and 8.3-resolving canonicalizer for the MCP
     * path-containment guard (cbm_path_within_root). The guard previously
     * canonicalized with the MAX_PATH-bound ANSI _fullpath, which (1) returns NULL
     * past 260 chars — refusing legitimate reads inside a deep repo root — and (2)
     * is purely lexical, so a junction/symlink planted under the root would slip a
     * read past the prefix check, and an 8.3 short-name spelling of the root would
     * too. GetFinalPathNameByHandleW on an opened handle resolves reparse points to
     * their real target and normalizes 8.3 → long names, closing both bypasses; it
     * is long-path-safe (no MAX_PATH bound) and the wide handle open goes through
     * cbm_utf8_to_wide_path's "\\?\" widening. Fail-closed: NULL on any failure. */
    if (!path) {
        return NULL;
    }
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return NULL;
    }
    /* dwDesiredAccess=0: metadata-only query, so a read-restricted or exclusively
     * held file still resolves. FILE_FLAG_BACKUP_SEMANTICS is required to obtain a
     * handle to a directory (the root side is a directory). Share every mode so the
     * probe never contends with a concurrent open. */
    HANDLE h = CreateFileW(wpath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    /* Zero-size probe returns the required length INCLUDING the null terminator. */
    DWORD need = GetFinalPathNameByHandleW(h, NULL, 0, flags);
    if (need == 0) {
        CloseHandle(h);
        return NULL;
    }
    wchar_t *buf = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
    if (!buf) {
        CloseHandle(h);
        return NULL;
    }
    /* On success the return value EXCLUDES the null terminator, so got < need. */
    DWORD got = GetFinalPathNameByHandleW(h, buf, need, flags);
    CloseHandle(h);
    if (got == 0 || got >= need) {
        free(buf);
        return NULL;
    }
    char *u8 = cbm_wide_final_path_to_utf8(buf);
    free(buf);
    return u8;
}

int cbm_rmdir(const char *path) {
    /* #412: extended-length widen for deep store-family directories. */
    wchar_t *wpath = cbm_utf8_to_wide_path(path);
    if (!wpath) {
        return CBM_NOT_FOUND;
    }
    int ret = _wrmdir(wpath);
    free(wpath);
    return ret;
}

/* #762: SQLite store-family replacement may race a short-lived Windows reader.
 * Retry only handle-contention errors; structural filesystem failures remain
 * single-attempt, and persistent contention exhausts this 10.575-second budget
 * with the final native error intact. */
enum {
    CBM_RENAME_REPLACE_MAX_RETRIES = 15,
    CBM_RENAME_REPLACE_BACKOFF_BASE_MS = 25,
    CBM_RENAME_REPLACE_BACKOFF_MAX_MS = 1000,
};

static bool rename_replace_error_is_transient(DWORD error) {
    switch (error) {
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_USER_MAPPED_FILE:
        return true;
    default:
        return false;
    }
}

int cbm_rename_replace(const char *old_path, const char *new_path) {
    /* #415: extended-length widen both paths so a deep store-family atomic swap
     * (dump/import temp -> final, corrupt-db -> .corrupt backup) is not
     * MAX_PATH-bound. MOVEFILE_REPLACE_EXISTING matches POSIX rename's replace
     * semantics (plain Win32 rename/MoveFile FAILS when the destination exists);
     * MOVEFILE_WRITE_THROUGH flushes the rename to disk for crash safety. */
    wchar_t *wold = cbm_utf8_to_wide_path(old_path);
    wchar_t *wnew = cbm_utf8_to_wide_path(new_path);
    if (!wold || !wnew) {
        DWORD error = GetLastError();
        g_cbm_fs_last_error = (unsigned long)(error ? error : ERROR_NO_UNICODE_TRANSLATION);
        free(wold);
        free(wnew);
        return CBM_NOT_FOUND;
    }
    BOOL ok = FALSE;
    DWORD error = ERROR_SUCCESS;
    DWORD last_retry_error = ERROR_SUCCESS;
    DWORD backoff_ms = CBM_RENAME_REPLACE_BACKOFF_BASE_MS;
    char max_retries_buf[CBM_SZ_32];
    (void)snprintf(max_retries_buf, sizeof(max_retries_buf), "%d", CBM_RENAME_REPLACE_MAX_RETRIES);
    int attempt = 0;
    for (; attempt <= CBM_RENAME_REPLACE_MAX_RETRIES; attempt++) {
        ok = MoveFileExW(wold, wnew, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        if (ok) {
            error = ERROR_SUCCESS;
            break;
        }
        error = GetLastError();
        if (!rename_replace_error_is_transient(error) ||
            attempt == CBM_RENAME_REPLACE_MAX_RETRIES) {
            break;
        }
        last_retry_error = error;

        char attempt_buf[CBM_SZ_32];
        char error_buf[CBM_SZ_32];
        char backoff_buf[CBM_SZ_32];
        (void)snprintf(attempt_buf, sizeof(attempt_buf), "%d", attempt + 1);
        (void)snprintf(error_buf, sizeof(error_buf), "%lu", (unsigned long)error);
        (void)snprintf(backoff_buf, sizeof(backoff_buf), "%lu", (unsigned long)backoff_ms);
        cbm_log_warn(
            "filesystem.rename_replace.retry", "code", "CBM_FS_RENAME_REPLACE_TRANSIENT", "source",
            old_path, "destination", new_path, "attempt", attempt_buf, "max_retries",
            max_retries_buf, "native_error_kind", "win32", "native_error", error_buf, "backoff_ms",
            backoff_buf, "message", "a transient Windows handle prevented atomic replacement",
            "remediation",
            "waiting for the current reader to close before retrying the same atomic move");
        Sleep(backoff_ms);
        if (backoff_ms < CBM_RENAME_REPLACE_BACKOFF_MAX_MS) {
            backoff_ms *= 2;
            if (backoff_ms > CBM_RENAME_REPLACE_BACKOFF_MAX_MS) {
                backoff_ms = CBM_RENAME_REPLACE_BACKOFF_MAX_MS;
            }
        }
    }
    if (ok && attempt > 0) {
        char attempts_buf[CBM_SZ_32];
        char error_buf[CBM_SZ_32];
        (void)snprintf(attempts_buf, sizeof(attempts_buf), "%d", attempt + 1);
        (void)snprintf(error_buf, sizeof(error_buf), "%lu", (unsigned long)last_retry_error);
        cbm_log_info("filesystem.rename_replace.recovered", "code",
                     "CBM_FS_RENAME_REPLACE_RECOVERED", "source", old_path, "destination", new_path,
                     "attempts", attempts_buf, "last_transient_error", error_buf,
                     "native_error_kind", "win32", "message",
                     "the atomic replacement succeeded after bounded transient contention",
                     "remediation", "none");
    }
    g_cbm_fs_last_error = (unsigned long)error;
    if (!ok) {
        char attempts_buf[CBM_SZ_32];
        char error_buf[CBM_SZ_32];
        (void)snprintf(attempts_buf, sizeof(attempts_buf), "%d", attempt + 1);
        (void)snprintf(error_buf, sizeof(error_buf), "%lu", (unsigned long)error);
        cbm_log_error(
            "filesystem.rename_replace.failed", "code", "CBM_FS_RENAME_REPLACE_FAILED", "source",
            old_path, "destination", new_path, "attempts", attempts_buf, "native_error_kind",
            "win32", "native_error", error_buf, "message",
            "the bounded atomic replacement protocol did not publish the source", "remediation",
            "close persistent handles or correct the reported filesystem error, then retry");
    }
    free(wold);
    free(wnew);
    return ok ? 0 : CBM_NOT_FOUND;
}

/* Build a properly-quoted Windows command line from an argv array.
 * Returns a heap-allocated wide string, or NULL on allocation failure.
 * Quoting follows the MSVC CRT convention: arguments containing spaces,
 * tabs, or double-quotes are wrapped in double-quotes, with backslashes
 * before a closing quote doubled and the quote itself escaped. Argument
 * bytes are treated as UTF-8 and converted to wide via cbm_utf8_to_wide,
 * so non-ASCII arguments (e.g. a non-ASCII %USERPROFILE%) survive intact.
 * Declared in compat_fs_internal.h so the test suite can drive it. */
wchar_t *cbm_build_cmdline(const char *const *argv) {
    /* First pass: compute required buffer size. */
    size_t total = 1; /* NUL terminator */
    for (int i = 0; argv[i]; i++) {
        const char *arg = argv[i];
        bool needs_quote = (arg[0] == '\0');
        for (const char *p = arg; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '"') {
                needs_quote = true;
            }
        }
        if (i > 0) {
            total++; /* space separator */
        }
        if (needs_quote) {
            total += 2; /* opening and closing quote */
            size_t backslashes = 0;
            for (const char *p = arg; *p; p++) {
                if (*p == '\\') {
                    backslashes++;
                } else if (*p == '"') {
                    total += backslashes + 1; /* double backslashes + escape backslash */
                    backslashes = 0;
                } else {
                    backslashes = 0;
                }
                total++;
            }
            /* Trailing backslashes before closing quote must be doubled. */
            total += backslashes;
        } else {
            total += strlen(arg);
        }
    }

    /* Build the quoted command line in UTF-8 first, then widen it as a
     * whole via cbm_utf8_to_wide. Every character the quoting logic acts
     * on (space, tab, '"', '\\') is ASCII and, by UTF-8's design, never
     * appears inside a multibyte sequence, so operating on raw bytes here
     * is safe and keeps multibyte argument bytes intact for conversion. */
    char *buf = (char *)malloc(total);
    if (!buf) {
        return NULL;
    }

    /* Second pass: write the command line bytes. */
    char *w = buf;
    for (int i = 0; argv[i]; i++) {
        const char *arg = argv[i];
        bool needs_quote = (arg[0] == '\0');
        for (const char *p = arg; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '"') {
                needs_quote = true;
                break;
            }
        }
        if (i > 0) {
            *w++ = ' ';
        }
        if (needs_quote) {
            *w++ = '"';
            size_t backslashes = 0;
            for (const char *p = arg; *p; p++) {
                if (*p == '\\') {
                    backslashes++;
                    *w++ = '\\';
                } else if (*p == '"') {
                    /* Double the preceding backslashes, then escape the quote. */
                    for (size_t b = 0; b < backslashes; b++) {
                        *w++ = '\\';
                    }
                    *w++ = '\\';
                    *w++ = '"';
                    backslashes = 0;
                } else {
                    backslashes = 0;
                    *w++ = *p;
                }
            }
            /* Double trailing backslashes before the closing quote. */
            for (size_t b = 0; b < backslashes; b++) {
                *w++ = '\\';
            }
            *w++ = '"';
        } else {
            for (const char *p = arg; *p; p++) {
                *w++ = *p;
            }
        }
    }
    *w = '\0';

    wchar_t *out = cbm_utf8_to_wide(buf);
    free(buf);
    return out;
}

int cbm_exec_no_shell(const char *const *argv) {
    if (!argv || !argv[0]) {
        return CBM_NOT_FOUND;
    }

    wchar_t *cmdline = cbm_build_cmdline(argv);
    if (!cmdline) {
        return CBM_NOT_FOUND;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdline);
        return CBM_NOT_FOUND;
    }
    free(cmdline);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = (DWORD)CBM_NOT_FOUND;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)exit_code;
}

#else /* POSIX */

/* ── POSIX implementation ────────────────────────────────── */

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct cbm_dir {
    DIR *dir;
    cbm_dirent_t entry;
    int error;
};

static _Thread_local unsigned long g_cbm_fs_last_error;

unsigned long cbm_fs_last_error(void) {
    return g_cbm_fs_last_error;
}

unsigned long cbm_dir_error(const cbm_dir_t *d) {
    return d ? (unsigned long)d->error : (unsigned long)EINVAL;
}

cbm_dir_t *cbm_opendir(const char *path) {
    g_cbm_fs_last_error = 0;
    if (!path) {
        g_cbm_fs_last_error = EINVAL;
        return NULL;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        g_cbm_fs_last_error = (unsigned long)errno;
        return NULL;
    }
    cbm_dir_t *d = (cbm_dir_t *)calloc(CBM_ALLOC_ONE, sizeof(cbm_dir_t));
    if (!d) {
        g_cbm_fs_last_error = ENOMEM;
        closedir(dir);
        return NULL;
    }
    d->dir = dir;
    return d;
}

cbm_dirent_t *cbm_readdir(cbm_dir_t *d) {
    if (!d || !d->dir) {
        return NULL;
    }
    struct dirent *de;
    errno = 0;
    while ((de = readdir(d->dir)) != NULL) {
        /* Skip "." and ".." */
        if (de->d_name[0] == '.' &&
            (de->d_name[SKIP_ONE] == '\0' ||
             (de->d_name[SKIP_ONE] == '.' && de->d_name[PAIR_LEN] == '\0'))) {
            continue;
        }
        size_t nlen = strlen(de->d_name);
        if (nlen >= CBM_DIRENT_NAME_MAX) {
            d->error = ENAMETOOLONG;
            return NULL;
        }
        memcpy(d->entry.name, de->d_name, nlen);
        d->entry.name[nlen] = '\0';
        d->entry.is_dir = (de->d_type == DT_DIR);
        d->entry.d_type = de->d_type;
        return &d->entry;
    }
    d->error = errno;
    return NULL;
}

void cbm_closedir(cbm_dir_t *d) {
    if (d) {
        if (d->dir) {
            closedir(d->dir);
        }
        free(d);
    }
}

FILE *cbm_popen(const char *cmd, const char *mode) {
    return popen(cmd, mode);
}

int cbm_pclose(FILE *f) {
    return pclose(f);
}

FILE *cbm_fopen(const char *path, const char *mode) {
    return fopen(path, mode);
}

bool cbm_mkdir_p(const char *path, int mode) {
    /* Try direct mkdir first */
    if (mkdir(path, (mode_t)mode) == 0) {
        return true;
    }
    /* Walk path and create each component */
    char *tmp = strdup(path);
    if (!tmp) {
        return false;
    }
    for (char *p = tmp + SKIP_ONE; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, (mode_t)mode); /* ignore intermediate errors */
            *p = '/';
        }
    }
    bool ok = (mkdir(tmp, (mode_t)mode) == 0 || errno == EEXIST) != 0;
    free(tmp);
    return ok;
}

int cbm_unlink(const char *path) {
    return unlink(path);
}

bool cbm_path_exists(const char *path) {
    /* POSIX access() is not MAX_PATH-bound; the Windows counterpart carries the
     * #430 long-path work. */
    return access(path, F_OK) == 0;
}

char *cbm_canonicalize_existing_path(const char *path) {
    /* POSIX realpath already requires the path to exist, resolves symlinks and
     * '.'/'..', and (with a NULL buffer, POSIX.1-2008) returns a malloc'd string
     * the caller frees — matching this wrapper's contract. It is not MAX_PATH-
     * bound; the Windows counterpart carries the #432 long-path work. */
    if (!path) {
        return NULL;
    }
    return realpath(path, NULL);
}

char *cbm_real_path_final(const char *path) {
    /* POSIX realpath already resolves symlinks and '.'/'..' to the real final
     * target (the junction/symlink resolution the Windows #437 counterpart obtains
     * via GetFinalPathNameByHandleW), requires the path to exist, and mallocs the
     * result with a NULL buffer. Fail-closed NULL on failure. Not MAX_PATH-bound. */
    if (!path) {
        return NULL;
    }
    return realpath(path, NULL);
}

int cbm_rmdir(const char *path) {
    return rmdir(path);
}

int cbm_rename_replace(const char *old_path, const char *new_path) {
    /* POSIX rename() already replaces an existing destination and is not
     * MAX_PATH-bound; the Windows counterpart carries the #415 long-path work. */
    return rename(old_path, new_path);
}

int cbm_exec_no_shell(const char *const *argv) {
    if (!argv || !argv[0]) {
        return CBM_NOT_FOUND;
    }
    pid_t pid = fork();
    if (pid < 0) {
        return CBM_NOT_FOUND;
    }
    if (pid == 0) {
        /* Child: exec directly — no shell interpretation */
        /* 127 = standard "command not found" exit code (POSIX convention) */
        enum { EXEC_NOT_FOUND = 127 };
        execvp(argv[0], (char *const *)argv);
        _exit(EXEC_NOT_FOUND);
    }
    /* Parent: wait for child */
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return CBM_NOT_FOUND;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return CBM_NOT_FOUND; /* killed by signal */
}

#endif /* _WIN32 */
