
/*
 * gitignore.c — Gitignore-style pattern matching.
 *
 * Implements the core gitignore pattern matching algorithm:
 *   - * matches anything except /
 *   - ** matches any number of path components
 *   - ? matches any single character except /
 *   - [abc] and [a-z] character classes
 *   - ! prefix for negation
 *   - trailing / for directory-only matching
 *   - patterns with / are rooted (anchored to base)
 */
#include "foundation/constants.h"
#include "foundation/compat_fs.h"

enum { GI_INIT_CAP = 16, GI_CHAR_IDX1 = 1, GI_CHAR_IDX2 = 2, GI_SKIP3 = 3 };
#include "discover/discover.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Pattern representation ──────────────────────────────────────── */

typedef struct {
    char *pattern; /* the glob pattern (normalized) */
    bool negated;  /* starts with ! */
    bool dir_only; /* ends with / */
    bool rooted;   /* contains / (anchored to root) */
} gi_pattern_t;

struct cbm_gitignore {
    gi_pattern_t *patterns;
    int count;
    int capacity;
};

/* ── Pattern matching engine ─────────────────────────────────────── */

/* Forward declaration for recursive calls. */
static bool glob_match(const char *pat, const char *str); // NOLINT(misc-no-recursion)

/* Match a ** (doublestar-slash) pattern: try rest at every / boundary. */
static bool glob_match_doublestar_slash(const char *pat, // NOLINT(misc-no-recursion)
                                        const char *str) {
    if (glob_match(pat, str)) {
        return true;
    }
    for (const char *s = str; *s; s++) {
        if (*s == '/' && glob_match(pat, s + SKIP_ONE)) {
            return true;
        }
    }
    return false;
}

/* Match a ** (doublestar) followed by non-slash: try at every position. */
static bool glob_match_doublestar_any(const char *pat, // NOLINT(misc-no-recursion)
                                      const char *str) {
    for (const char *s = str;; s++) {
        if (glob_match(pat, s)) {
            return true;
        }
        if (!*s) {
            return false;
        }
    }
}

/* Match a * (single star): match any sequence not containing /. */
static bool glob_match_star(const char *pat, const char *str) { // NOLINT(misc-no-recursion)
    for (const char *s = str;; s++) {
        if (glob_match(pat, s)) {
            return true;
        }
        if (!*s || *s == '/') {
            return false;
        }
    }
}

/* Match a [...] character class at current position.
 * Returns true if matched. Advances *pat_out past the closing ']'. */
static bool glob_match_charclass(const char *pat, char ch, const char **pat_out) {
    bool negate_class = false;
    if (*pat == '!' || *pat == '^') {
        negate_class = true;
        pat++;
    }
    bool matched = false;
    char prev = 0;
    while (*pat && *pat != ']') {
        if (*pat == '-' && prev && pat[GI_CHAR_IDX1] && pat[GI_CHAR_IDX1] != ']') {
            pat++;
            if (ch >= prev && ch <= *pat) {
                matched = true;
            }
            prev = *pat;
            pat++;
        } else {
            if (ch == *pat) {
                matched = true;
            }
            prev = *pat;
            pat++;
        }
    }
    if (*pat == ']') {
        pat++;
    }
    *pat_out = pat;
    return negate_class ? !matched : matched;
}

/*
 * Match a glob pattern against a string.
 * Handles: * (non-slash), ** (any path), ? (single non-slash), [class]
 */
/* Handle ** at current position. Returns match result. */
static bool glob_match_doublestar(const char *pat, const char *str) { // NOLINT(misc-no-recursion)
    if (pat[GI_CHAR_IDX2] == '/') {
        return glob_match_doublestar_slash(pat + GI_SKIP3, str);
    }
    if (pat[GI_CHAR_IDX2] == '\0') {
        return true;
    }
    return glob_match_doublestar_any(pat + GI_CHAR_IDX2, str);
}

static bool glob_match(const char *pat, const char *str) { // NOLINT(misc-no-recursion)
    while (*pat && *str) {
        if (pat[0] == '*' && pat[GI_CHAR_IDX1] == '*') {
            return glob_match_doublestar(pat, str);
        }

        if (*pat == '*') {
            return glob_match_star(pat + SKIP_ONE, str);
        }

        if (*pat == '?') {
            if (*str == '/') {
                return false;
            }
            pat++;
            str++;
            continue;
        }

        if (*pat == '[') {
            const char *new_pat = NULL;
            if (!glob_match_charclass(pat + SKIP_ONE, *str, &new_pat)) {
                return false;
            }
            pat = new_pat;
            str++;
            continue;
        }

        if (*pat != *str) {
            return false;
        }
        pat++;
        str++;
    }

    while (*pat == '*') {
        pat++;
    }
    return *pat == '\0' && *str == '\0';
}

/* ── Pattern parsing ─────────────────────────────────────────────── */

static bool gi_add_pattern(cbm_gitignore_t *gi, const char *line, int len) {
    /* Trim trailing whitespace */
    while (len > 0 && (line[len - SKIP_ONE] == ' ' || line[len - SKIP_ONE] == '\t' ||
                       line[len - SKIP_ONE] == '\r')) {
        len--;
    }
    if (len == 0) {
        return true;
    }

    gi_pattern_t p = {0};

    /* Check for negation */
    const char *start = line;
    if (*start == '!') {
        p.negated = true;
        start++;
        len--;
    }

    if (len == 0) {
        return true;
    }

    /* Check for trailing / (directory-only) */
    if (start[len - SKIP_ONE] == '/') {
        p.dir_only = true;
        len--;
    }

    if (len == 0) {
        return true;
    }

    /* Check for leading / (rooted) */
    if (*start == '/') {
        p.rooted = true;
        start++;
        len--;
    }

    if (len == 0) {
        return true;
    }

    /* Check if pattern contains / anywhere (makes it rooted) */
    if (!p.rooted) {
        for (int i = 0; i < len; i++) {
            if (start[i] == '/') {
                p.rooted = true;
                break;
            }
        }
    }

    /* Copy pattern */
    p.pattern = malloc(len + SKIP_ONE);
    if (!p.pattern) {
        return false;
    }
    memcpy(p.pattern, start, len);
    p.pattern[len] = '\0';

    /* Grow array if needed */
    if (gi->count >= gi->capacity) {
        int new_cap = gi->capacity ? gi->capacity * PAIR_LEN : GI_INIT_CAP;
        gi_pattern_t *new_patterns = realloc(gi->patterns, new_cap * sizeof(gi_pattern_t));
        if (!new_patterns) {
            free(p.pattern);
            return false;
        }
        gi->patterns = new_patterns;
        gi->capacity = new_cap;
    }

    gi->patterns[gi->count++] = p;
    return true;
}

/* ── Public API ──────────────────────────────────────────────────── */

static int gitignore_parse_checked(const char *content, cbm_gitignore_t **out) {
    if (!content || !out) {
        errno = EINVAL;
        return CBM_NOT_FOUND;
    }
    *out = NULL;

    cbm_gitignore_t *gi = calloc(CBM_ALLOC_ONE, sizeof(cbm_gitignore_t));
    if (!gi) {
        errno = ENOMEM;
        return CBM_NOT_FOUND;
    }

    const char *line = content;
    while (*line) {
        /* Find end of line */
        const char *eol = strchr(line, '\n');
        size_t line_len = eol ? (size_t)(eol - line) : strlen(line);
        /* CRLF tolerance: a file opened in binary mode (required so the
         * ftell-size vs fread-count completeness check in the loader is not
         * defeated by Windows text-mode CRLF->LF translation) keeps the
         * '\r' before every '\n'. Strip it here so patterns never carry a
         * trailing carriage return, which would silently break every match. */
        if (line_len > 0 && line[line_len - 1] == '\r') {
            line_len--;
        }
        if (line_len > INT_MAX) {
            cbm_gitignore_free(gi);
            errno = EOVERFLOW;
            return CBM_NOT_FOUND;
        }
        int len = (int)line_len;

        /* Skip comments and blank lines */
        if (len > 0 && line[0] != '#') {
            if (!gi_add_pattern(gi, line, len)) {
                cbm_gitignore_free(gi);
                errno = ENOMEM;
                return CBM_NOT_FOUND;
            }
        }

        if (!eol) {
            break;
        }
        line = eol + SKIP_ONE;
    }

    *out = gi;
    return 0;
}

cbm_gitignore_t *cbm_gitignore_parse(const char *content) {
    cbm_gitignore_t *gi = NULL;
    return gitignore_parse_checked(content, &gi) == 0 ? gi : NULL;
}

int cbm_gitignore_load_checked(const char *path, bool optional, cbm_gitignore_t **out) {
    if (!path || !out) {
        errno = EINVAL;
        return CBM_NOT_FOUND;
    }
    *out = NULL;

    /* Binary mode is mandatory: this reader validates completeness by comparing
     * the ftell(SEEK_END) byte size against the fread byte count. Windows text
     * mode ("r") translates CRLF->LF, so fread returns FEWER bytes than the
     * on-disk size and the completeness check below fails closed with errno=EIO
     * on any file that has CRLF endings (e.g. a .gitignore saved on Windows) --
     * a deterministic index_repository failure. The parser strips a trailing
     * '\r' per line, so binary mode does not leave carriage returns in patterns. */
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        if (optional && (errno == ENOENT || errno == ENOTDIR)) {
            return 0;
        }
        return CBM_NOT_FOUND;
    }

    /* Read entire file */
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return CBM_NOT_FOUND;
    }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return CBM_NOT_FOUND;
    }
    if ((uintmax_t)size > SIZE_MAX - SKIP_ONE) {
        (void)fclose(f);
        errno = EOVERFLOW;
        return CBM_NOT_FOUND;
    }

    char *buf = malloc((size_t)size + SKIP_ONE);
    if (!buf) {
        (void)fclose(f);
        errno = ENOMEM;
        return CBM_NOT_FOUND;
    }

    size_t n = fread(buf, SKIP_ONE, (size_t)size, f);
    bool complete = n == (size_t)size && ferror(f) == 0;
    if (fclose(f) != 0) {
        complete = false;
    }
    if (!complete) {
        free(buf);
        errno = EIO;
        return CBM_NOT_FOUND;
    }
    buf[n] = '\0';

    int rc = gitignore_parse_checked(buf, out);
    free(buf);
    return rc;
}

/* Match a non-rooted pattern against basename and path suffixes. */
static bool match_unrooted(const char *pattern, const char *rel_path, const char *basename) {
    if (glob_match(pattern, basename)) {
        return true;
    }
    if (!strchr(rel_path, '/')) {
        return false;
    }
    /* Try matching at every / boundary */
    const char *s = rel_path;
    while (*s) {
        if (glob_match(pattern, s)) {
            return true;
        }
        const char *next = strchr(s, '/');
        if (!next) {
            break;
        }
        s = next + SKIP_ONE;
    }
    return false;
}

int cbm_gitignore_match_result(const cbm_gitignore_t *gi, const char *rel_path, bool is_dir) {
    if (!gi || !rel_path) {
        return 0;
    }

    /* Extract the basename for non-rooted pattern matching */
    const char *basename = strrchr(rel_path, '/');
    basename = basename ? basename + SKIP_ONE : rel_path;

    int matched = 0;

    for (int i = 0; i < gi->count; i++) {
        const gi_pattern_t *p = &gi->patterns[i];

        if (p->dir_only && !is_dir) {
            continue;
        }

        bool this_match = p->rooted ? glob_match(p->pattern, rel_path)
                                    : match_unrooted(p->pattern, rel_path, basename);

        if (this_match) {
            matched = p->negated ? -1 : 1;
        }
    }

    return matched;
}

bool cbm_gitignore_matches(const cbm_gitignore_t *gi, const char *rel_path, bool is_dir) {
    return cbm_gitignore_match_result(gi, rel_path, is_dir) > 0;
}

void cbm_gitignore_free(cbm_gitignore_t *gi) {
    if (!gi) {
        return;
    }
    for (int i = 0; i < gi->count; i++) {
        free(gi->patterns[i].pattern);
    }
    free(gi->patterns);
    free(gi);
}

/* Test seam: lets a unit test simulate strdup() failure mid-merge so the
 * atomic-rollback path can be exercised without real OOM. NULL = use strdup. */
char *(*cbm_gitignore_merge_dup_hook_for_test)(const char *) = NULL;

bool cbm_gitignore_merge(cbm_gitignore_t *dst, const cbm_gitignore_t *src) {
    if (!dst) {
        return false;
    }
    if (!src || src->count == 0) {
        return true; /* nothing to merge */
    }
    int needed = dst->count + src->count;
    if (needed > dst->capacity) {
        gi_pattern_t *grown = realloc(dst->patterns, (size_t)needed * sizeof(gi_pattern_t));
        if (!grown) {
            return false; /* dst left unchanged */
        }
        dst->patterns = grown;
        dst->capacity = needed;
    }
    int start_count = dst->count;
    for (int i = 0; i < src->count; i++) {
        char *pat = cbm_gitignore_merge_dup_hook_for_test
                        ? cbm_gitignore_merge_dup_hook_for_test(src->patterns[i].pattern)
                        : strdup(src->patterns[i].pattern);
        if (!pat) {
            /* Roll back partial copies so dst is unchanged on failure (atomic
             * merge). A silent partial merge could drop the very exclude
             * pattern the caller relied on while keeping others. */
            for (int j = start_count; j < dst->count; j++) {
                free(dst->patterns[j].pattern);
            }
            dst->count = start_count;
            return false;
        }
        dst->patterns[dst->count].pattern = pat;
        dst->patterns[dst->count].negated = src->patterns[i].negated;
        dst->patterns[dst->count].dir_only = src->patterns[i].dir_only;
        dst->patterns[dst->count].rooted = src->patterns[i].rooted;
        dst->count++;
    }
    return true;
}
