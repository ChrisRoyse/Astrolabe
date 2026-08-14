/*
 * str_util.h — Safe string operations.
 *
 * All functions that return char* allocate via the provided arena
 * (no malloc, no free needed).
 */
#ifndef CBM_STR_UTIL_H
#define CBM_STR_UTIL_H

#include "arena.h"
#include <stdbool.h>
#include <stddef.h>

/* Join two path components with '/'. Handles trailing/leading slashes. */
char *cbm_path_join(CBMArena *a, const char *base, const char *name);

/* Join N path components. parts is an array of N strings. */
char *cbm_path_join_n(CBMArena *a, const char **parts, int n);

/* Get the file extension (without dot). Returns "" if none. */
const char *cbm_path_ext(const char *path);

/* Get the base name (after last '/'). Returns path if no '/'. */
const char *cbm_path_base(const char *path);

/* Get the directory part (before last '/'). Returns "." if no '/'. */
char *cbm_path_dir(CBMArena *a, const char *path);

/* Check if string starts with prefix. */
bool cbm_str_starts_with(const char *s, const char *prefix);

/* Check if string ends with suffix. */
bool cbm_str_ends_with(const char *s, const char *suffix);

/* Check if string contains substring. */
bool cbm_str_contains(const char *s, const char *sub);

/* Convert to lowercase (arena-allocated copy). */
char *cbm_str_tolower(CBMArena *a, const char *s);

/* Replace all occurrences of 'from' char with 'to' char (arena copy). */
char *cbm_str_replace_char(CBMArena *a, const char *s, char from, char to);

/* Strip file extension: "foo.go" → "foo" (arena copy). */
char *cbm_str_strip_ext(CBMArena *a, const char *path);

/* Split string by delimiter. Returns arena-allocated array + count.
 * The array itself and all substrings are arena-allocated. */
char **cbm_str_split(CBMArena *a, const char *s, char delim, int *out_count);

/* Validate a string is safe for shell interpolation inside single quotes.
 * Rejects: ' " ; | & $ ` < > \n \r \0 (embedded NULs via len check).
 * The Windows search path wraps shell args in cmd.exe-level "powershell -Command
 * \"...'%s'...\"", so " can close the cmd.exe outer quote even if PowerShell's
 * single quotes hold; < > would then become cmd.exe redirection (file-write
 * primitive). Blocking these unconditionally hardens both POSIX and Windows.
 * Returns true if safe, false if the string contains shell metacharacters. */
bool cbm_validate_shell_arg(const char *s);

/* Validate a project name is safe for file path construction.
 * Allows: alphanumeric, dash, underscore, dot (but not leading dot or dot-dot).
 * Rejects: path separators (/ \), directory traversal (..), and control chars.
 * Returns true if safe, false if the name could escape the cache directory. */
bool cbm_validate_project_name(const char *name);

/* Return true when an existing canonical path is inside an Astrolabe native
 * launcher generation root (`.tmp/windows-gnu-toolchain-*`).  Those roots are
 * disposable build/verification state and can never be durable project-store
 * provenance, even when a caller supplies an otherwise stable project alias.
 * Both slash spellings are recognized; Windows matching is case-insensitive. */
bool cbm_path_is_ephemeral_launcher_root(const char *path);

/* Safe snprintf append: clamps offset to prevent buffer overflow on truncation.
 * When snprintf truncates, it returns what it WOULD have written, which can make
 * offset > bufsize. Next call: bufsize - offset wraps unsigned → huge → overflow.
 * This macro guards against that by checking bounds before writing and clamping after.
 *
 * Usage: CBM_SNPRINTF_APPEND(buf, sizeof(buf), off, "fmt %s", arg);
 * Requires: <stdio.h> included by caller. */
#define CBM_SNPRINTF_APPEND(buf, sz, off, ...)                                       \
    do {                                                                             \
        if ((off) >= 0 && (off) < (int)(sz)) {                                       \
            int _cbm_r = snprintf((buf) + (off), (sz) - (size_t)(off), __VA_ARGS__); \
            if (_cbm_r > 0)                                                          \
                (off) += _cbm_r;                                                     \
            if ((off) >= (int)(sz))                                                  \
                (off) = (int)(sz) - 1;                                               \
        }                                                                            \
    } while (0)

/* Escape a string for safe embedding in JSON: escapes " \ and control chars.
 * Writes into buf (including NUL). Returns number of chars written (excl NUL).
 * If buf is too small, output is truncated but always NUL-terminated.
 *
 * UTF-8 write contract (#493): the output is always valid UTF-8. Valid
 * multi-byte sequences are copied atomically (truncation lands only on
 * character boundaries); invalid bytes (bad lead/continuation, overlong,
 * surrogate, > U+10FFFF) are replaced with U+FFFD. The vault importer's
 * fail-closed UTF-8 boundary depends on this contract. */
int cbm_json_escape(char *buf, int bufsize, const char *src);

/* Length of the UTF-8 sequence starting at src[0] under RFC 3629. Returns the
 * sequence length (2-4) when valid, 0 when the lead/continuation bytes form an
 * invalid, overlong, surrogate, or out-of-range encoding. Never reads past a
 * NUL. Shared (#503) by the JSON escaper and the raw-text sanitizer below. */
int cbm_utf8_sequence_len(const unsigned char *src);

/* Bounded form of cbm_utf8_sequence_len for byte-exact source slices. It never
 * reads beyond `available`, so parser diagnostics do not borrow validation
 * authority from bytes outside their persisted span. */
int cbm_utf8_sequence_len_n(const unsigned char *src, size_t available);

/* Count bytes that cannot participate in any RFC 3629 sequence. Valid
 * multibyte sequences advance atomically; an invalid byte advances by one,
 * matching cbm_sem_tokenize's stripped-byte accounting exactly. */
size_t cbm_utf8_invalid_byte_count(const unsigned char *src, size_t len);

/* Sanitize raw text into a valid-UTF-8 copy for a non-JSON SQLite text column
 * (#503): valid multi-byte sequences are copied atomically (truncation lands
 * only on a character boundary) and every invalid byte becomes U+FFFD, so the
 * persisted bytes are always valid UTF-8. ASCII and control characters pass
 * through verbatim (this is raw text, not JSON). Writes into buf including the
 * terminating NUL and returns the byte count written (excl. NUL); a NULL src
 * yields an empty string. This enforces the same UTF-8 write contract
 * cbm_json_escape gives JSON properties for the parser-derived identifier/path
 * columns (nodes.name/qualified_name/file_path/label, edges.type, ...) that are
 * bound raw into SQLite, which the Rust vault importer reads fail-closed. */
int cbm_utf8_sanitize(char *buf, int bufsize, const char *src);

#endif /* CBM_STR_UTIL_H */
