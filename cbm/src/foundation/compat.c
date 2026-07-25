#ifdef _WIN32
#ifndef _CRT_RAND_S
#define _CRT_RAND_S
#endif
#endif

/*
 * compat.c — Implementations for Windows-only shims.
 *
 * On POSIX, these functions are provided by the standard library via
 * macros in compat.h. On Windows, we implement them here.
 */
#include "foundation/compat.h"
#include "foundation/constants.h"
#include "foundation/platform.h"

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#endif

/* ── strndup (Windows lacks it) ───────────────────────────────── */

#ifdef _WIN32
char *cbm_strndup(const char *s, size_t n) {
    if (!s) {
        return NULL;
    }
    size_t len = 0;
    while (len < n && s[len]) {
        len++;
    }
    char *d = (char *)malloc(len + SKIP_ONE);
    if (d) {
        memcpy(d, s, len);
        d[len] = '\0';
    }
    return d;
}
#endif

/* ── strcasestr (Windows lacks it) ────────────────────────────── */

#ifdef _WIN32
char *cbm_strcasestr(const char *haystack, const char *needle) {
    if (!needle[0])
        return (char *)haystack;
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (_strnicmp(haystack, needle, nlen) == 0)
            return (char *)haystack;
    }
    return NULL;
}
#endif

/* ── mkdtemp (Windows lacks it) ───────────────────────────────── */

#ifdef _WIN32
#include <direct.h>
static int cbm_replace_temp_suffix(char *tmpl, size_t capacity, const char *original) {
    static const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t len = strlen(original);
    if (len < 6 || capacity <= len || strcmp(original + len - 6, "XXXXXX") != 0) {
        errno = EINVAL;
        return -1;
    }
    memcpy(tmpl, original, len + 1);
    for (size_t i = len - 6; i < len; i++) {
        unsigned int random_value = 0;
        if (rand_s(&random_value) != 0) {
            errno = EIO;
            return -1;
        }
        tmpl[i] = ALPHABET[random_value % (sizeof(ALPHABET) - 1)];
    }
    return 0;
}

char *cbm_mkdtemp(char *tmpl, size_t capacity) {
    if (!tmpl || capacity == 0) {
        errno = EINVAL;
        return NULL;
    }
    size_t len = strnlen(tmpl, capacity);
    if (len == capacity) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    char *original = malloc(len + 1);
    if (!original) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(original, tmpl, len + 1);
    for (int attempt = 0; attempt < 128; attempt++) {
        if (cbm_replace_temp_suffix(tmpl, capacity, original) != 0) {
            free(original);
            return NULL;
        }
        if (_mkdir(tmpl) == 0) {
            free(original);
            return tmpl;
        }
        if (errno != EEXIST) {
            free(original);
            return NULL;
        }
    }
    memcpy(tmpl, original, len + 1);
    free(original);
    errno = EEXIST;
    return NULL;
}
#endif

/* ── mkstemp (Windows lacks it) ───────────────────────────────── */

#ifdef _WIN32
int cbm_mkstemp(char *tmpl, size_t capacity) {
    if (!tmpl || capacity == 0) {
        errno = EINVAL;
        return CBM_NOT_FOUND;
    }
    size_t len = strnlen(tmpl, capacity);
    if (len == capacity) {
        errno = ENAMETOOLONG;
        return CBM_NOT_FOUND;
    }
    char *original = malloc(len + 1);
    if (!original) {
        errno = ENOMEM;
        return CBM_NOT_FOUND;
    }
    memcpy(original, tmpl, len + 1);
    for (int attempt = 0; attempt < 128; attempt++) {
        if (cbm_replace_temp_suffix(tmpl, capacity, original) != 0) {
            free(original);
            return CBM_NOT_FOUND;
        }
        int fd = _open(tmpl, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
        if (fd >= 0) {
            free(original);
            return fd;
        }
        if (errno != EEXIST) {
            free(original);
            return CBM_NOT_FOUND;
        }
    }
    memcpy(tmpl, original, len + 1);
    free(original);
    errno = EEXIST;
    return CBM_NOT_FOUND;
}
#endif

/* ── clock_gettime (Windows lacks it) ─────────────────────────── */

#ifdef _WIN32
int cbm_clock_gettime(int clk_id, struct timespec *tp) {
    if (clk_id != CLOCK_MONOTONIC || !tp) {
        errno = EINVAL;
        return -1;
    }
    uint64_t now_ns = cbm_now_ns();
    tp->tv_sec = (time_t)(now_ns / CBM_NSEC_PER_SEC);
    tp->tv_nsec = (long)(now_ns % CBM_NSEC_PER_SEC);
    return 0;
}
#endif

/* ── getline (Windows lacks it) ───────────────────────────────── */

#ifdef _WIN32
ssize_t cbm_getline(char **lineptr, size_t *n, FILE *stream) {
    if (!lineptr || !n || !stream) {
        return CBM_NOT_FOUND;
    }
    if (!*lineptr || *n == 0) {
        *n = CBM_SZ_128;
        *lineptr = (char *)malloc(*n);
        if (!*lineptr) {
            return CBM_NOT_FOUND;
        }
    }
    size_t pos = 0;
    int c;
    while ((c = fgetc(stream)) != EOF) {
        if (pos + 1 >= *n) {
            size_t new_n = *n * PAIR_LEN;
            char *tmp = (char *)realloc(*lineptr, new_n);
            if (!tmp) {
                return CBM_NOT_FOUND;
            }
            *lineptr = tmp;
            *n = new_n;
        }
        (*lineptr)[pos++] = (char)c;
        if (c == '\n') {
            break;
        }
    }
    if (pos == 0 && c == EOF) {
        return CBM_NOT_FOUND;
    }
    (*lineptr)[pos] = '\0';
    return (ssize_t)pos;
}
#endif
