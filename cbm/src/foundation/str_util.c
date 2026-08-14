#ifdef ASTRO_SHELLARG
/*
 * str_util.c — Safe string operations (arena-allocated).
 */
#include "str_util.h"
#include "arena.h" // CBMArena, cbm_arena_alloc/strdup/strndup
#include "foundation/constants.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

enum {
    JSON_ESC_LEN = 2,       /* escaped char takes 2 bytes (backslash + char) */
    JSON_NUL_RESERVE = 1,   /* reserve 1 byte for NUL terminator */
    JSON_CTRL_LIMIT = 0x20, /* ASCII control character upper bound */
};

char *cbm_path_join(CBMArena *a, const char *base, const char *name) {
    if (!base || !name) {
        return NULL;
    }
    size_t blen = strlen(base);
    size_t nlen = strlen(name);

    /* Handle empty components */
    if (blen == 0) {
        return cbm_arena_strdup(a, name);
    }
    if (nlen == 0) {
        return cbm_arena_strdup(a, base);
    }

    /* Strip trailing slash from base */
    while (blen > 0 && base[blen - SKIP_ONE] == '/') {
        blen--;
    }
    /* Strip leading slash from name */
    while (nlen > 0 && *name == '/') {
        name++;
        nlen--;
    }

    if (blen == 0) {
        return cbm_arena_strndup(a, name, nlen);
    }
    if (nlen == 0) {
        return cbm_arena_strndup(a, base, blen);
    }

    char *result = (char *)cbm_arena_alloc(a, blen + SKIP_ONE + nlen + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    memcpy(result, base, blen);
    result[blen] = '/';
    memcpy(result + blen + SKIP_ONE, name, nlen);
    result[blen + SKIP_ONE + nlen] = '\0';
    return result;
}

char *cbm_path_join_n(CBMArena *a, const char **parts, int n) {
    if (n <= 0 || !parts) {
        return cbm_arena_strdup(a, "");
    }
    if (n == SKIP_ONE) {
        return cbm_arena_strdup(a, parts[0]);
    }

    char *result = cbm_arena_strdup(a, parts[0]);
    for (int i = SKIP_ONE; i < n; i++) {
        result = cbm_path_join(a, result, parts[i]);
    }
    return result;
}

const char *cbm_path_ext(const char *path) {
    if (!path) {
        return "";
    }
    const char *dot = NULL;
    const char *slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '.') {
            dot = p;
        }
        if (*p == '/') {
            slash = p;
        }
    }
    /* dot must be after last slash and not at start of basename */
    if (!dot) {
        return "";
    }
    if (slash && dot < slash) {
        return "";
    }
    return dot + SKIP_ONE;
}

const char *cbm_path_base(const char *path) {
    if (!path) {
        return "";
    }
    const char *last_slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }
    return last_slash ? last_slash + SKIP_ONE : path;
}

char *cbm_path_dir(CBMArena *a, const char *path) {
    if (!path) {
        return cbm_arena_strdup(a, ".");
    }
    const char *last_slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }
    if (!last_slash) {
        return cbm_arena_strdup(a, ".");
    }
    return cbm_arena_strndup(a, path, (size_t)(last_slash - path));
}

bool cbm_str_starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return false;
    }
    size_t plen = strlen(prefix);
    return strncmp(s, prefix, plen) == 0;
}

bool cbm_str_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) {
        return false;
    }
    size_t slen = strlen(s);
    size_t xlen = strlen(suffix);
    if (xlen > slen) {
        return false;
    }
    return strcmp(s + slen - xlen, suffix) == 0;
}

bool cbm_str_contains(const char *s, const char *sub) {
    if (!s || !sub) {
        return false;
    }
    if (sub[0] == '\0') {
        return true;
    }
    return strstr(s, sub) != NULL;
}

char *cbm_str_tolower(CBMArena *a, const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *result = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        result[i] = (char)tolower((unsigned char)s[i]);
    }
    result[len] = '\0';
    return result;
}

char *cbm_str_replace_char(CBMArena *a, const char *s, char from, char to) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *result = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        result[i] = (s[i] == from) ? to : s[i];
    }
    result[len] = '\0';
    return result;
}

char *cbm_str_strip_ext(CBMArena *a, const char *path) {
    if (!path) {
        return NULL;
    }
    const char *dot = NULL;
    const char *slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '.') {
            dot = p;
        }
        if (*p == '/') {
            slash = p;
        }
    }
    if (!dot || (slash && dot < slash)) {
        return cbm_arena_strdup(a, path);
    }
    return cbm_arena_strndup(a, path, (size_t)(dot - path));
}

char **cbm_str_split(CBMArena *a, const char *s, char delim, int *out_count) {
    if (!s || !out_count) {
        return NULL;
    }

    /* Count parts */
    int count = SKIP_ONE;
    for (const char *p = s; *p; p++) {
        if (*p == delim) {
            count++;
        }
    }

    char **result = (char **)cbm_arena_alloc(a, (size_t)(count + SKIP_ONE) * sizeof(char *));
    if (!result) {
        return NULL;
    }

    int idx = 0;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p == delim || *p == '\0') {
            size_t part_len = (size_t)(p - start);
            result[idx++] = cbm_arena_strndup(a, start, part_len);
            if (*p == '\0') {
                break;
            }
            start = p + SKIP_ONE;
        }
    }

    result[idx] = NULL;
    *out_count = count;
    return result;
}

bool cbm_validate_shell_arg(const char *s) {
    if (!s) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '\'':
        case '"':
        case ';':
        case '|':
        case '&':
        case '$':
        case '`':
        case '<':
        case '>':
        case '\n':
        case '\r':
#ifndef _WIN32
        case '\\':
#else
        /* cmd.exe substitutes %VAR% and %X:~n,m% at parse time, defers !VAR!
         * under delayed expansion, and treats ^ as its escape character — all
         * BEFORE quoting applies, so quotes cannot make these inert. Mirrors the
         * Rust bridge validator (#136). */
        case '%':
        case '^':
        case '!':
#endif
#else
/*
 * str_util.c — Safe string operations (arena-allocated).
 */
#include "str_util.h"
#include "arena.h" // CBMArena, cbm_arena_alloc/strdup/strndup
#include "foundation/constants.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

enum {
    JSON_ESC_LEN = 2,       /* escaped char takes 2 bytes (backslash + char) */
    JSON_NUL_RESERVE = 1,   /* reserve 1 byte for NUL terminator */
    JSON_CTRL_LIMIT = 0x20, /* ASCII control character upper bound */
};

char *cbm_path_join(CBMArena *a, const char *base, const char *name) {
    if (!base || !name) {
        return NULL;
    }
    size_t blen = strlen(base);
    size_t nlen = strlen(name);

    /* Handle empty components */
    if (blen == 0) {
        return cbm_arena_strdup(a, name);
    }
    if (nlen == 0) {
        return cbm_arena_strdup(a, base);
    }

    /* Strip trailing slash from base */
    while (blen > 0 && base[blen - SKIP_ONE] == '/') {
        blen--;
    }
    /* Strip leading slash from name */
    while (nlen > 0 && *name == '/') {
        name++;
        nlen--;
    }

    if (blen == 0) {
        return cbm_arena_strndup(a, name, nlen);
    }
    if (nlen == 0) {
        return cbm_arena_strndup(a, base, blen);
    }

    char *result = (char *)cbm_arena_alloc(a, blen + SKIP_ONE + nlen + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    memcpy(result, base, blen);
    result[blen] = '/';
    memcpy(result + blen + SKIP_ONE, name, nlen);
    result[blen + SKIP_ONE + nlen] = '\0';
    return result;
}

char *cbm_path_join_n(CBMArena *a, const char **parts, int n) {
    if (n <= 0 || !parts) {
        return cbm_arena_strdup(a, "");
    }
    if (n == SKIP_ONE) {
        return cbm_arena_strdup(a, parts[0]);
    }

    char *result = cbm_arena_strdup(a, parts[0]);
    for (int i = SKIP_ONE; i < n; i++) {
        result = cbm_path_join(a, result, parts[i]);
    }
    return result;
}

const char *cbm_path_ext(const char *path) {
    if (!path) {
        return "";
    }
    const char *dot = NULL;
    const char *slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '.') {
            dot = p;
        }
        if (*p == '/') {
            slash = p;
        }
    }
    /* dot must be after last slash and not at start of basename */
    if (!dot) {
        return "";
    }
    if (slash && dot < slash) {
        return "";
    }
    return dot + SKIP_ONE;
}

const char *cbm_path_base(const char *path) {
    if (!path) {
        return "";
    }
    const char *last_slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }
    return last_slash ? last_slash + SKIP_ONE : path;
}

char *cbm_path_dir(CBMArena *a, const char *path) {
    if (!path) {
        return cbm_arena_strdup(a, ".");
    }
    const char *last_slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/') {
            last_slash = p;
        }
    }
    if (!last_slash) {
        return cbm_arena_strdup(a, ".");
    }
    return cbm_arena_strndup(a, path, (size_t)(last_slash - path));
}

bool cbm_str_starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return false;
    }
    size_t plen = strlen(prefix);
    return strncmp(s, prefix, plen) == 0;
}

bool cbm_str_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) {
        return false;
    }
    size_t slen = strlen(s);
    size_t xlen = strlen(suffix);
    if (xlen > slen) {
        return false;
    }
    return strcmp(s + slen - xlen, suffix) == 0;
}

bool cbm_str_contains(const char *s, const char *sub) {
    if (!s || !sub) {
        return false;
    }
    if (sub[0] == '\0') {
        return true;
    }
    return strstr(s, sub) != NULL;
}

char *cbm_str_tolower(CBMArena *a, const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *result = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        result[i] = (char)tolower((unsigned char)s[i]);
    }
    result[len] = '\0';
    return result;
}

char *cbm_str_replace_char(CBMArena *a, const char *s, char from, char to) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *result = (char *)cbm_arena_alloc(a, len + SKIP_ONE);
    if (!result) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        result[i] = (s[i] == from) ? to : s[i];
    }
    result[len] = '\0';
    return result;
}

char *cbm_str_strip_ext(CBMArena *a, const char *path) {
    if (!path) {
        return NULL;
    }
    const char *dot = NULL;
    const char *slash = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '.') {
            dot = p;
        }
        if (*p == '/') {
            slash = p;
        }
    }
    if (!dot || (slash && dot < slash)) {
        return cbm_arena_strdup(a, path);
    }
    return cbm_arena_strndup(a, path, (size_t)(dot - path));
}

char **cbm_str_split(CBMArena *a, const char *s, char delim, int *out_count) {
    if (!s || !out_count) {
        return NULL;
    }

    /* Count parts */
    int count = SKIP_ONE;
    for (const char *p = s; *p; p++) {
        if (*p == delim) {
            count++;
        }
    }

    char **result = (char **)cbm_arena_alloc(a, (size_t)(count + SKIP_ONE) * sizeof(char *));
    if (!result) {
        return NULL;
    }

    int idx = 0;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p == delim || *p == '\0') {
            size_t part_len = (size_t)(p - start);
            result[idx++] = cbm_arena_strndup(a, start, part_len);
            if (*p == '\0') {
                break;
            }
            start = p + SKIP_ONE;
        }
    }

    result[idx] = NULL;
    *out_count = count;
    return result;
}

bool cbm_validate_shell_arg(const char *s) {
    if (!s) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '\'':
        case '"':
        case ';':
        case '|':
        case '&':
        case '$':
        case '`':
        case '<':
        case '>':
        case '\n':
        case '\r':
#ifndef _WIN32
        case '\\':
#endif
#endif
            return false;
        default:
            break;
        }
    }
    return true;
}

bool cbm_validate_project_name(const char *name) {
    if (!name || !*name)
        return false;
    /* Reject directory traversal */
    if (strcmp(name, "..") == 0 || strstr(name, "..") != NULL)
        return false;
    /* Reject path separators */
    if (strchr(name, '/') || strchr(name, '\\'))
        return false;
    /* Reject leading dot (hidden files / relative refs) */
    if (name[0] == '.')
        return false;
    /* Allow only alphanumeric, dash, underscore, dot */
    for (const char *p = name; *p; p++) {
        if (!(((*p >= 'a') && (*p <= 'z')) || ((*p >= 'A') && (*p <= 'Z')) ||
              ((*p >= '0') && (*p <= '9')) || *p == '-' || *p == '_' || *p == '.')) {
            return false;
        }
    }
    return true;
}

static bool path_marker_char_equal(char actual, char expected) {
    if (expected == '/') {
        return actual == '/' || actual == '\\';
    }
#ifdef _WIN32
    if (actual >= 'A' && actual <= 'Z') {
        actual = (char)(actual - 'A' + 'a');
    }
#endif
    return actual == expected;
}

bool cbm_path_is_ephemeral_launcher_root(const char *path) {
    static const char marker[] = ".tmp/windows-gnu-toolchain-";
    if (!path || !path[0]) {
        return false;
    }

    size_t marker_len = sizeof(marker) - 1;
    size_t path_len = strlen(path);
    for (size_t i = 0; i + marker_len <= path_len; i++) {
        if (i > 0 && path[i - 1] != '/' && path[i - 1] != '\\') {
            continue;
        }
        size_t j = 0;
        while (j < marker_len && path_marker_char_equal(path[i + j], marker[j])) {
            j++;
        }
        if (j == marker_len) {
            return true;
        }
    }
    return false;
}

enum {
    UTF8_REPLACEMENT_LEN = 3, /* U+FFFD encodes as EF BF BD */
};

/* Length of the UTF-8 sequence starting at src[0] under RFC 3629 (overlong
 * encodings, UTF-16 surrogates, and code points above U+10FFFF are invalid).
 * Returns the sequence length (2-4) when valid, 0 when invalid. Never reads
 * past a NUL: a NUL continuation byte fails the range checks first (#493).
 * Exported (#503) so the raw-text UTF-8 sanitizer at the SQLite insert boundary
 * reuses the identical RFC 3629 validation the JSON escaper uses. */
int cbm_utf8_sequence_len_n(const unsigned char *src, size_t available) {
    if (!src || available == 0) {
        return 0;
    }
    unsigned char lead = src[0];
    unsigned char lo = 0x80, hi = 0xBF;
    int len;
    if (lead >= 0xC2 && lead <= 0xDF) {
        len = 2;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
        len = 3;
        if (lead == 0xE0) {
            lo = 0xA0; /* reject overlong */
        } else if (lead == 0xED) {
            hi = 0x9F; /* reject UTF-16 surrogates */
        }
    } else if (lead >= 0xF0 && lead <= 0xF4) {
        len = 4;
        if (lead == 0xF0) {
            lo = 0x90; /* reject overlong */
        } else if (lead == 0xF4) {
            hi = 0x8F; /* reject > U+10FFFF */
        }
    } else {
        return 0; /* 0x80-0xC1, 0xF5-0xFF: never a valid lead byte */
    }
    if (available < (size_t)len) {
        return 0;
    }
    if (src[1] < lo || src[1] > hi) {
        return 0;
    }
    for (int k = 2; k < len; k++) {
        if ((src[k] & 0xC0) != 0x80) {
            return 0;
        }
    }
    return len;
}

int cbm_utf8_sequence_len(const unsigned char *src) {
    if (!src) {
        return 0;
    }
    size_t available = 1;
    while (available < 4 && src[available] != '\0') {
        available++;
    }
    return cbm_utf8_sequence_len_n(src, available);
}

size_t cbm_utf8_invalid_byte_count(const unsigned char *src, size_t len) {
    if (!src) {
        return 0;
    }
    size_t invalid = 0;
    for (size_t at = 0; at < len;) {
        if (src[at] < 0x80) {
            at++;
            continue;
        }
        int sequence_len = cbm_utf8_sequence_len_n(src + at, len - at);
        if (sequence_len > 0) {
            at += (size_t)sequence_len;
            continue;
        }
        invalid++;
        at++;
    }
    return invalid;
}

int cbm_json_escape(char *buf, int bufsize, const char *src) {
    if (!buf || bufsize <= 0) {
        return 0;
    }
    if (!src) {
        buf[0] = '\0';
        return 0;
    }
    int pos = 0;
    for (int i = 0; src[i] && pos < bufsize - JSON_NUL_RESERVE; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (pos + JSON_ESC_LEN > bufsize - JSON_NUL_RESERVE) {
                break;
            }
            buf[pos++] = '\\';
            buf[pos++] = (char)c;
        } else if (c == '\n') {
            if (pos + JSON_ESC_LEN > bufsize - JSON_NUL_RESERVE) {
                break;
            }
            buf[pos++] = '\\';
            buf[pos++] = 'n';
        } else if (c == '\r') {
            if (pos + JSON_ESC_LEN > bufsize - JSON_NUL_RESERVE) {
                break;
            }
            buf[pos++] = '\\';
            buf[pos++] = 'r';
        } else if (c == '\t') {
            if (pos + JSON_ESC_LEN > bufsize - JSON_NUL_RESERVE) {
                break;
            }
            buf[pos++] = '\\';
            buf[pos++] = 't';
        } else if (c < JSON_CTRL_LIMIT) {
            /* Other control chars: escape as \u00XX */
            if (pos + 6 > bufsize - JSON_NUL_RESERVE) {
                break;
            }
            pos += snprintf(buf + pos, 7, "\\u%04x", c);
        } else if (c < 0x80) {
            buf[pos++] = (char)c;
        } else {
            /* Multi-byte UTF-8 (#493): a valid sequence is copied atomically, so
             * buffer-cap truncation can only land on a character boundary; any
             * invalid byte (bad lead/continuation, overlong, surrogate, out of
             * range) becomes U+FFFD. The emitted JSON is therefore always valid
             * UTF-8 — the write contract the vault importer's fail-closed UTF-8
             * boundary depends on. */
            int seq = cbm_utf8_sequence_len((const unsigned char *)src + i);
            if (seq > 0) {
                if (pos + seq > bufsize - JSON_NUL_RESERVE) {
                    break;
                }
                memcpy(buf + pos, src + i, (size_t)seq);
                pos += seq;
                i += seq - 1; /* the loop's i++ consumes the final byte */
            } else {
                if (pos + UTF8_REPLACEMENT_LEN > bufsize - JSON_NUL_RESERVE) {
                    break;
                }
                buf[pos++] = (char)0xEF;
                buf[pos++] = (char)0xBF;
                buf[pos++] = (char)0xBD;
            }
        }
    }
    buf[pos] = '\0';
    return pos;
}

int cbm_utf8_sanitize(char *buf, int bufsize, const char *src) {
    if (!buf || bufsize <= 0) {
        return 0;
    }
    if (!src) {
        buf[0] = '\0';
        return 0;
    }
    int pos = 0;
    /* Reserve one byte for the terminating NUL (JSON_NUL_RESERVE == 1). */
    for (int i = 0; src[i] && pos < bufsize - JSON_NUL_RESERVE; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c < 0x80) {
            /* ASCII (including control chars and NUL-free bytes) is always valid
             * UTF-8; unlike cbm_json_escape this is raw text, not JSON, so control
             * chars are copied verbatim rather than backslash-escaped. */
            buf[pos++] = (char)c;
        } else {
            /* Multi-byte UTF-8 (#503): a valid sequence is copied atomically so a
             * buffer-cap truncation can only land on a character boundary; any
             * invalid byte (bad lead/continuation, overlong, surrogate, out of
             * range) becomes U+FFFD. The emitted bytes are therefore always valid
             * UTF-8 — the same write contract cbm_json_escape guarantees for JSON
             * property columns, now enforced for the raw parser-derived identifier
             * and path columns bound into the SQLite `nodes`/`edges` tables. */
            int seq = cbm_utf8_sequence_len((const unsigned char *)src + i);
            if (seq > 0) {
                if (pos + seq > bufsize - JSON_NUL_RESERVE) {
                    break;
                }
                memcpy(buf + pos, src + i, (size_t)seq);
                pos += seq;
                i += seq - 1; /* the loop's i++ consumes the final byte */
            } else {
                if (pos + UTF8_REPLACEMENT_LEN > bufsize - JSON_NUL_RESERVE) {
                    break;
                }
                buf[pos++] = (char)0xEF;
                buf[pos++] = (char)0xBF;
                buf[pos++] = (char)0xBD;
            }
        }
    }
    buf[pos] = '\0';
    return pos;
}
