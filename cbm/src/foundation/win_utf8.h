#ifndef CBM_WIN_UTF8_H
#define CBM_WIN_UTF8_H

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
#include <string.h>
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

/* Strictly widen a UTF-8 filesystem path and, at/over the Windows MAX_PATH
 * barrier, convert it to an absolute extended-length "\\?\" spelling. Every
 * conversion/canonicalization/allocation failure is returned to the caller as
 * one native error; this is the variant for admission decisions where a failed
 * probe must never be collapsed into "absent". */
static inline wchar_t *cbm_utf8_to_wide_path_checked(const char *utf8, DWORD *native_error) {
    if (native_error) {
        *native_error = ERROR_SUCCESS;
    }
    if (!utf8 || !utf8[0]) {
        if (native_error) {
            *native_error = ERROR_INVALID_PARAMETER;
        }
        return NULL;
    }
    int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, NULL, 0);
    if (len <= 0) {
        DWORD error = GetLastError();
        if (native_error) {
            *native_error = error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION;
        }
        return NULL;
    }
    wchar_t *w = (wchar_t *)malloc((size_t)len * sizeof(wchar_t));
    if (!w) {
        if (native_error) {
            *native_error = ERROR_NOT_ENOUGH_MEMORY;
        }
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, w, len) != len) {
        DWORD error = GetLastError();
        free(w);
        if (native_error) {
            *native_error = error != ERROR_SUCCESS ? error : ERROR_NO_UNICODE_TRANSLATION;
        }
        return NULL;
    }
    size_t wlen = wcslen(w);
    /* Below the barrier (with margin for a directory's trailing "\\*" and the
     * CRT's 8.3 reservation), the ordinary wide spelling is lossless. */
    if (wlen < 240) {
        return w;
    }
    /* Already an extended-length ("\\?\") or device ("\\.\") path: never double-prefix. */
    if (w[0] == L'\\' && w[1] == L'\\' && (w[2] == L'?' || w[2] == L'.')) {
        return w;
    }
    DWORD need = GetFullPathNameW(w, 0, NULL, NULL);
    if (need == 0) {
        DWORD error = GetLastError();
        free(w);
        if (native_error) {
            *native_error = error != ERROR_SUCCESS ? error : ERROR_INVALID_NAME;
        }
        return NULL;
    }
    wchar_t *full = (wchar_t *)malloc((size_t)need * sizeof(wchar_t));
    if (!full) {
        free(w);
        if (native_error) {
            *native_error = ERROR_NOT_ENOUGH_MEMORY;
        }
        return NULL;
    }
    DWORD got = GetFullPathNameW(w, need, full, NULL);
    if (got == 0 || got >= need) {
        DWORD error = GetLastError();
        free(full);
        free(w);
        if (native_error) {
            *native_error = error != ERROR_SUCCESS ? error : ERROR_FILENAME_EXCED_RANGE;
        }
        return NULL;
    }
    free(w);
    wchar_t *out;
    if (full[0] == L'\\' && full[1] == L'\\') {
        /* UNC "\\server\share\..." -> "\\?\UNC\server\share\..." */
        out = (wchar_t *)malloc((size_t)(got + 8) * sizeof(wchar_t));
        if (!out) {
            free(full);
            if (native_error) {
                *native_error = ERROR_NOT_ENOUGH_MEMORY;
            }
            return NULL;
        }
        wcscpy(out, L"\\\\?\\UNC\\");
        wcscat(out, full + 2);
    } else {
        /* Drive path "C:\..." -> "\\?\C:\..." */
        out = (wchar_t *)malloc((size_t)(got + 5) * sizeof(wchar_t));
        if (!out) {
            free(full);
            if (native_error) {
                *native_error = ERROR_NOT_ENOUGH_MEMORY;
            }
            return NULL;
        }
        wcscpy(out, L"\\\\?\\");
        wcscat(out, full);
    }
    free(full);
    return out;
}

/* Widen a UTF-8 filesystem path for ordinary file operations. This shares the
 * strict conversion contract: an operation never retries through a narrower or
 * non-extended spelling after path preparation failed. */
static inline wchar_t *cbm_utf8_to_wide_path(const char *utf8) {
    DWORD error = ERROR_SUCCESS;
    wchar_t *w = cbm_utf8_to_wide_path_checked(utf8, &error);
    if (!w) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE);
    }
    return w;
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

/* Convert GetFinalPathNameByHandleW(VOLUME_NAME_DOS) output to the ordinary
 * DOS/UNC spelling used by persisted repository roots and the rest of the C
 * pipeline. The Win32 API normally emits "\\?\C:\..." or
 * "\\?\UNC\server\share\..."; keeping that prefix and then normalizing path
 * separators produces the non-filesystem spelling "//?/C:/...".
 *
 * Removing the presentation prefix does not weaken long-path support:
 * cbm_utf8_to_wide_path adds it back at every Win32 filesystem boundary. Do the
 * conversion in place so all handle-final-path callers share one exact rule and
 * no second allocation can fail after the UTF-8 conversion succeeds. */
static inline char *cbm_wide_final_path_to_utf8(const wchar_t *wide) {
    char *u8 = cbm_wide_to_utf8(wide);
    if (!u8) {
        return NULL;
    }
    if (strncmp(u8, "\\\\?\\UNC\\", 8) == 0) {
        size_t rest = strlen(u8 + 8);
        memmove(u8 + 2, u8 + 8, rest + 1);
        u8[0] = '\\';
        u8[1] = '\\';
    } else if (strncmp(u8, "\\\\?\\", 4) == 0) {
        memmove(u8, u8 + 4, strlen(u8 + 4) + 1);
    }
    return u8;
}

#endif /* _WIN32 */
#endif /* CBM_WIN_UTF8_H */
