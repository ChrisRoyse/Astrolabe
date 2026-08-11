/*
 * astro_spawn.h — shell-free process spawn with stdout capture (Astrolabe #227).
 *
 * CBM's git helpers used to compose a single command STRING and hand it to
 * cbm_popen(), which on Windows executes `cmd.exe /c <string>` (the CRT's
 * _popen "executes a spawned copy of the command processor and uses command as
 * the command line") and on POSIX executes `/bin/sh -c <string>`. A shell
 * re-parses those bytes: cmd.exe performs %VAR% / %X:~n,m% substitution and ^
 * escaping at PARSE time — before quoting is applied — so no amount of quoting
 * around an interpolated repo path can make the string inert. Every newly
 * discovered metacharacter class then becomes a fresh blocklist entry in the
 * argument validator.
 *
 * This helper removes the shell instead of guarding it. The child is launched
 * with an explicit argv array — CreateProcessW with a CommandLineToArgvW-exact
 * quoting of each element on Windows, posix_spawnp on POSIX — so no shell ever
 * sees the bytes, and there is no expansion, redirection, or word splitting to
 * defend against. cbm_validate_shell_arg() stays at the call sites as
 * defence-in-depth; it is no longer the only barrier.
 *
 * Windows specifics preserved from the previous isolated spawn (CBM #798):
 * only the exact standard-stream handles are inherited (STARTUPINFOEXW +
 * PROC_THREAD_ATTRIBUTE_HANDLE_LIST), so unrelated socket/AFD handles cannot
 * enter a git-for-Windows child and deadlock its handle-classifying startup.
 *
 * Windows executable resolution is deliberately PATH-only (SearchPathW with an
 * explicit lpPath taken from %PATH%): CreateProcess's implicit search order
 * includes "the current directory for the parent process", which would let a
 * git.exe planted in a hostile CWD win. Passing lpApplicationName suppresses
 * that search entirely.
 */
#ifndef ASTRO_SPAWN_H
#define ASTRO_SPAWN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Named, fail-closed outcomes. Never silently degraded: every non-OK value is
 * reported to the caller with a message and a remediation. */
typedef enum {
    CBM_SPAWN_OK = 0,
    CBM_SPAWN_E_INVALID_ARGV = 1,   /* argv/out pointers unusable */
    CBM_SPAWN_E_EXEC_NOT_FOUND = 2, /* argv[0] not resolvable on PATH */
    CBM_SPAWN_E_PIPE = 3,           /* stdout pipe / null device unavailable */
    CBM_SPAWN_E_SPAWN = 4,          /* CreateProcessW / posix_spawnp failed */
    CBM_SPAWN_E_READ = 5,           /* reading the child's stdout failed */
    CBM_SPAWN_E_NOMEM = 6,          /* allocation failed */
    CBM_SPAWN_E_WAIT = 7,           /* could not reap the child */
    CBM_SPAWN_E_EXIT = 8,           /* child ran and exited non-zero */
    CBM_SPAWN_E_ENVIRONMENT = 9,    /* exact child environment could not be built */
    CBM_SPAWN_E_PROGRESS = 10       /* semantic stdout progress could not be published */
} cbm_spawn_code_t;

/* Fail-closed error record: {code, message, remediation} plus the OS-level
 * detail needed to diagnose it. */
typedef struct {
    cbm_spawn_code_t code;
    const char *code_name;   /* stable identifier, e.g. "CBM_SPAWN_E_SPAWN" */
    const char *message;     /* what failed */
    const char *remediation; /* what the operator can do about it */
    unsigned long os_error;  /* GetLastError() on Windows, errno on POSIX; 0 if N/A */
    int exit_code;           /* child exit status; -1 when the child never ran */
} cbm_spawn_error_t;

typedef struct {
    char *data;         /* heap-owned retained prefix; free() after use */
    size_t len;         /* retained bytes, excluding the NUL terminator */
    uint64_t total_len; /* every stderr byte drained from the child */
    bool truncated;     /* total_len exceeded the caller's retained prefix */
} cbm_spawn_bounded_capture_t;

/* Called only after another non-empty stdout byte range has been captured.
 * Returning false terminates the exact child and reports CBM_SPAWN_E_PROGRESS. */
typedef bool (*cbm_spawn_stdout_progress_cb)(uint64_t captured_bytes, void *ud);

/*
 * Spawn argv[0] with the NULL-terminated argv array — no shell — and capture
 * the child's stdout in full. stdin and stderr are bound to the null device.
 *
 * argv       NULL-terminated array; argv[0] is the program (resolved on PATH,
 *            never from the current directory), argv[1..] are passed to the
 *            child verbatim. No element is ever re-parsed for metacharacters.
 * out_data   receives a heap buffer (free() it) holding the captured stdout,
 *            always NUL-terminated. Set on CBM_SPAWN_OK and on
 *            CBM_SPAWN_E_EXIT (the child ran, so its partial output exists);
 *            NULL for every other outcome.
 * out_len    receives the captured byte count, excluding the NUL terminator.
 * err        optional; filled with the fail-closed error record on any
 *            non-zero return.
 *
 * Returns 0 only when the child was spawned, its stdout was read to EOF, and
 * it exited with status 0. Otherwise returns the cbm_spawn_code_t value.
 */
int cbm_spawn_capture(const char *const *argv, char **out_data, size_t *out_len,
                      cbm_spawn_error_t *err);

/* The same exact shell-free spawn contract, but capture stderr independently
 * rather than binding it to the null device. Both returned streams are
 * heap-owned, binary-clean, and NUL-terminated; their explicit lengths remain
 * authoritative when a stream contains embedded NUL bytes. The caller must
 * free both buffers. A child exit still returns CBM_SPAWN_E_EXIT with both
 * streams available, so the caller can persist the real diagnostic. */
int cbm_spawn_capture_with_stderr(const char *const *argv, char **out_data, size_t *out_len,
                                  size_t stderr_limit,
                                  cbm_spawn_bounded_capture_t *out_stderr,
                                  cbm_spawn_error_t *err);

/* Execute the same exact capture contract from one explicit working
 * directory. An empty/NULL directory is invalid for this entry point: compiler
 * contexts must reproduce their recorded cwd, never inherit the worker cwd. */
int cbm_spawn_capture_with_stderr_cwd(const char *const *argv, const char *working_directory,
                                      char **out_data, size_t *out_len,
                                      size_t stderr_limit,
                                      cbm_spawn_bounded_capture_t *out_stderr,
                                      cbm_spawn_error_t *err);

/* Execute the exact cwd/capture contract with one private, sorted child
 * environment. It binds SOURCE_DATE_EPOCH to source provenance and puts the
 * resolved compiler executable's directory first in the child's Path so that
 * compiler subprograms inherit the same runtime-DLL closure. The parent process
 * and concurrent compiler children are never mutated. The epoch value must be
 * a canonical unsigned decimal Unix timestamp. */
int cbm_spawn_capture_with_stderr_cwd_source_epoch(
    const char *const *argv, const char *working_directory, const char *source_date_epoch,
    char **out_data, size_t *out_len, size_t stderr_limit,
    cbm_spawn_bounded_capture_t *out_stderr, cbm_spawn_error_t *err);

int cbm_spawn_capture_with_stderr_cwd_source_epoch_progress(
    const char *const *argv, const char *working_directory, const char *source_date_epoch,
    char **out_data, size_t *out_len, size_t stderr_limit,
    cbm_spawn_bounded_capture_t *out_stderr, cbm_spawn_stdout_progress_cb on_stdout_progress,
    void *progress_ud, cbm_spawn_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* ASTRO_SPAWN_H */
