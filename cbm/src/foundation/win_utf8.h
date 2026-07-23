#ifndef CBM_WIN_UTF8_H
#define CBM_WIN_UTF8_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

static inline wchar_t *cbm_utf8_to_wide(const char *utf8) {
    if (!utf8) {
        return NULL;
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (len <= 0) {
        return NULL;
    }
    wchar_t *w = (wchar_t *)malloc((size_t)len * sizeof(wchar_t));
    if (w) {
        MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w, len);
    }
    return w;
}

/* Widen a UTF-8 *filesystem path* and, for paths at/over the Windows MAX_PATH
 * (260) barrier, add the extended-length "\\?\" prefix so the CRT/Win32 wide file
 * APIs (_wfopen, _wstat64, GetFileAttributesW, GetFileAttributesExW, FindFirstFileW,
 * CreateFileW) can reach files whose absolute path exceeds 260 chars. Without the
 * prefix those APIs fail on such paths (verified: err on this host, LongPathsEnabled
 * unset), which the discover directory walk turns into a SILENT skip — the forbidden
 * outcome in #383. This function must be used ONLY for filesystem paths, never for
 * open modes ("rb") or command lines, which is why it is a separate entry point from
 * cbm_utf8_to_wide (those callers stay on the plain widen).
 *
 * The "\\?\" prefix disables Win32 path normalization, so the path is first
 * canonicalized to a fully-qualified backslash form via GetFullPathNameW (which
 * resolves '.'/'..', converts '/'→'\\', and makes a relative path absolute against
 * the CWD — the same base the CRT would use). Paths below the barrier are returned
 * byte-identical to cbm_utf8_to_wide, so existing short-path behavior (and the C
 * test floor) is unchanged. On any canonicalization/allocation failure the function
 * degrades to the plain widened path rather than dropping the request. */
static inline wchar_t *cbm_utf8_to_wide_path(const char *utf8) {
    wchar_t *w = cbm_utf8_to_wide(utf8);
    if (!w) {
        return NULL;
    }
    size_t wlen = wcslen(w);
    /* Below the barrier (with margin for a directory's trailing "\\*" and the CRT's
     * 8.3 reservation): leave the path exactly as the historical widen produced it. */
    if (wlen < 240) {
        return w;
    }
    /* Already an extended-length ("\\?\") or device ("\\.\") path: never double-prefix. */
    if (w[0] == L'\\' && w[1] == L'\\' && (w[2] == L'?' || w[2] == L'.')) {
        return w;
    }
    DWORD need = GetFullPathNameW(w, 0, NULL, NULL);
    if (need == 0) {
        return w; /* canonicalization unavailable — best-effort plain path */
    }
    wchar_t *full = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
    if (!full) {
        return w;
    }
    DWORD got = GetFullPathNameW(w, need, full, NULL);
    if (got == 0 || got >= need) {
        free(full);
        return w;
    }
    free(w);
    wchar_t *out;
    if (full[0] == L'\\' && full[1] == L'\\') {
        /* UNC "\\server\share\..." -> "\\?\UNC\server\share\..." */
        out = (wchar_t *)malloc((size_t)(got + 8) * sizeof(wchar_t));
        if (!out) {
            return full;
        }
        wcscpy(out, L"\\\\?\\UNC\\");
        wcscat(out, full + 2);
    } else {
        /* Drive path "C:\..." -> "\\?\C:\..." */
        out = (wchar_t *)malloc((size_t)(got + 5) * sizeof(wchar_t));
        if (!out) {
            return full;
        }
        wcscpy(out, L"\\\\?\\");
        wcscat(out, full);
    }
    free(full);
    return out;
}

static inline char *cbm_wide_to_utf8(const wchar_t *wide) {
    if (!wide) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, NULL, 0, NULL, NULL);
    if (len <= 0) {
        return NULL;
    }
    char *u8 = (char *)malloc((size_t)len);
    if (!u8) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, u8, len, NULL, NULL) != len) {
        DWORD error = GetLastError();
        free(u8);
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION);
        return NULL;
    }
    return u8;
}

#endif /* _WIN32 */
#endif /* CBM_WIN_UTF8_H */
