/*
 * compat_fs.h — Portable directory iteration, popen, and file operations.
 *
 * POSIX: thin wrappers around opendir/readdir, popen/pclose, mkdir, unlink.
 * Windows: FindFirstFile/FindNextFile, _popen/_pclose, _mkdir, _unlink.
 */
#ifndef CBM_COMPAT_FS_H
#define CBM_COMPAT_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* ── Directory iteration ──────────────────────────────────────── */

/* Max filename length (MAX_PATH on Windows, NAME_MAX on POSIX). */
#define CBM_DIRENT_NAME_MAX 260

typedef struct cbm_dir cbm_dir_t;

typedef struct {
    char name[CBM_DIRENT_NAME_MAX];
    bool is_dir;
    unsigned char d_type; /* DT_REG, DT_DIR, DT_LNK, etc. (POSIX only, 0 on Windows) */
} cbm_dirent_t;

/* Open a directory for iteration. Returns NULL on error. */
cbm_dir_t *cbm_opendir(const char *path);

/* Read next entry. Returns NULL when done. The returned pointer is
 * valid until the next cbm_readdir call on the same handle. */
cbm_dirent_t *cbm_readdir(cbm_dir_t *d);

/* Close directory handle. */
void cbm_closedir(cbm_dir_t *d);

/* ── Portable popen/pclose ────────────────────────────────────── */

FILE *cbm_popen(const char *cmd, const char *mode);
int cbm_pclose(FILE *f);

/* ── File operations ──────────────────────────────────────────── */

/* Create directory (and parents). mode is ignored on Windows. Returns true on success. */
bool cbm_mkdir_p(const char *path, int mode);

/* Delete a file. Returns 0 on success. */
int cbm_unlink(const char *path);

/* Test whether a filesystem entry (file or directory) exists at path.
 * Long-path safe on Windows: GetFileAttributesW with extended-length "\\?\"
 * widening via cbm_utf8_to_wide_path, so a store-family path deeper than
 * MAX_PATH (260) — e.g. <deep-store>/<project>.db — is probed correctly instead
 * of reporting a false "not found" the way MAX_PATH-bound access()/stat() does.
 * POSIX uses access(F_OK). Returns true iff the path exists. */
bool cbm_path_exists(const char *path);

/* Canonicalize an *existing* filesystem path to its fully-qualified absolute
 * form. Returns a heap-allocated UTF-8 string (caller frees with free()) on
 * success, or NULL when the path does not exist or cannot be canonicalized.
 *
 * Long-path safe on Windows: the fixed-buffer ANSI `_access(...,0)` + `_fullpath`
 * pair it replaces is MAX_PATH-bound — on a repo/root path longer than 260 chars
 * `_access` reports a false "not found" and `_fullpath` returns NULL (its result
 * cannot exceed _MAX_PATH), so a deep repo silently loses canonicalization. Here
 * the resolution runs through GetFullPathNameW with a grow-on-demand buffer
 * (accepting the "\\?\"-widened input cbm_utf8_to_wide_path produces for >MAX_PATH
 * inputs) and the existence probe runs through cbm_path_exists (GetFileAttributesW,
 * "\\?\"-widened), so a >260-char path is resolved correctly. The returned path is
 * a clean drive/UNC form with OS-native separators and NO "\\?\" prefix (matching
 * the historical _fullpath output shape); callers that need forward slashes call
 * cbm_normalize_path_sep afterward. Resolution is lexical on Windows (GetFullPathNameW,
 * like _fullpath: resolves '.'/'..', '/'→'\\', relative→absolute against the CWD)
 * and symlink-resolving on POSIX (realpath), preserving each platform's prior
 * behavior. On any canonicalization/allocation failure it returns NULL — never a
 * silent ANSI fallback — leaving the caller to keep the un-canonicalized input. */
char *cbm_canonicalize_existing_path(const char *path);

/* Delete an empty directory. Returns 0 on success. */
int cbm_rmdir(const char *path);

/* Atomically rename old_path -> new_path, replacing new_path if it already
 * exists. Long-path safe on Windows (MoveFileExW with extended-length "\\?\"
 * widening via cbm_utf8_to_wide_path, MOVEFILE_REPLACE_EXISTING to match POSIX
 * rename's replace semantics); POSIX rename() already replaces and is not
 * MAX_PATH-bound. Returns 0 on success, non-zero on failure. */
int cbm_rename_replace(const char *old_path, const char *new_path);

/* Open a file by UTF-8 path.
 * On Windows, converts to wide-char and calls _wfopen so paths with
 * non-ASCII characters (accents, CJK, etc.) are handled correctly.
 * On POSIX, delegates to fopen. mode must be an ASCII string. */
FILE *cbm_fopen(const char *path, const char *mode);

/* Execute a command without shell interpretation.
 * argv is a NULL-terminated array: {"cmd", "arg1", "arg2", NULL}.
 * Returns the process exit code, or -1 on fork/exec failure.
 * POSIX: fork() + execvp(). Windows: CreateProcess with proper quoting. */
int cbm_exec_no_shell(const char *const *argv);

#endif /* CBM_COMPAT_FS_H */
