/*
 * subprocess.h — spawn a child process, supervise it, and classify how it ended.
 *
 * Generalized from the crash-isolating index spawn in src/ui/http_server.c so the
 * crash/hang supervisor (Track C) can reuse one primitive across platforms.
 *
 * Beyond a plain spawn+wait it adds the two things a supervisor needs and the
 * ad-hoc harness lacked:
 *   1. Exit CLASSIFICATION — {clean, exit-nonzero, crash, hang, killed} — from
 *      POSIX WIFSIGNALED/WTERMSIG, Windows NTSTATUS exception exit codes
 *      (0xC0000005 access-violation, 0xC00000FD stack-overflow, …), and
 *      GCC/MinGW SEH C++ exception markers (0x20474343 / 0x21474343).
 *   2. A quiet-timeout — kill + report HANG when an application-semantic
 *      progress reader observes no validated forward work for a configurable
 *      window. Logs are diagnostics and never reset this correctness budget.
 *
 * The reap loop is EINTR-safe. Diagnostic line tailing keeps a partial final
 * line buffered so it is not mis-read as a completed log event.
 */
#ifndef CBM_SUBPROCESS_H
#define CBM_SUBPROCESS_H

#include <stdbool.h>
#include <stddef.h> /* size_t (cbm_build_win_cmdline) */

/* How a supervised child ended. */
typedef enum {
    CBM_PROC_CLEAN = 0,    /* exited with code 0 */
    CBM_PROC_EXIT_NONZERO, /* exited with a nonzero code (a graceful failure) */
    CBM_PROC_CRASH,        /* died from a fault: POSIX SIGSEGV/BUS/ILL/FPE/ABRT/SYS,
                            * a Windows NTSTATUS exception exit code (>= 0xC0000000),
                            * or a GCC/MinGW SEH C++ exception marker */
    CBM_PROC_HANG,         /* made no progress within the quiet-timeout; we killed it */
    CBM_PROC_KILLED,       /* terminated by a non-fault signal we did not initiate */
    CBM_PROC_CANCELLED,    /* exact owning host requested bounded shutdown */
    CBM_PROC_PROGRESS_FAILED, /* semantic progress stream was invalid/unreadable */
    CBM_PROC_SPAWN_FAILED  /* fork/exec/CreateProcess failed — no child ever ran */
} cbm_proc_outcome_t;

typedef struct {
    cbm_proc_outcome_t outcome;
    int exit_code;   /* WEXITSTATUS / GetExitCodeProcess; -1 when terminated by a POSIX signal */
    int term_signal; /* WTERMSIG on POSIX; 0 otherwise */
} cbm_proc_result_t;

/* Called for each newly-completed (newline-terminated) diagnostic log line. */
typedef void (*cbm_proc_log_cb)(const char *line, void *ud);

typedef enum {
    CBM_PROC_PROGRESS_INVALID = -1,
    CBM_PROC_PROGRESS_IDLE = 0,
    CBM_PROC_PROGRESS_ADVANCED = 1,
} cbm_proc_progress_result_t;

/* Poll one caller-owned semantic progress source. terminal is true after the
 * exact child has exited and asks the consumer to validate its complete stream.
 * INVALID terminates a still-live child and classifies it as PROGRESS_FAILED. */
typedef cbm_proc_progress_result_t (*cbm_proc_progress_cb)(bool terminal, void *ud);

/* Read one caller-owned cancellation source. Cancellation is sticky for the
 * supervised operation: true terminates the exact child and classifies it as
 * CANCELLED, never HANG/CRASH or a successful partial result. */
typedef bool (*cbm_proc_cancel_cb)(void *ud);

/* Called once, immediately after the child is successfully spawned, with the
 * child's OS process id (POSIX pid / Windows PID). Lets a supervisor record the
 * live child for out-of-band control — e.g. the UI "kill job" endpoint validating
 * that a kill target is a server-spawned index job. Optional; NULL => not called. */
typedef void (*cbm_proc_spawn_cb)(long child_pid, void *ud);

typedef struct {
    const char *bin;             /* exact absolute executable path; Windows passes it separately
                                  * as CreateProcessW lpApplicationName. Also argv[0] when argv is
                                  * NULL; an explicit argv keeps its existing argv[0]. */
    const char *const *argv;     /* NULL-terminated argv; NULL => { bin, NULL } */
    const char *log_file;        /* child stdout+stderr are redirected here and tailed;
                                  * NULL => discard child output, no tailing. A non-NULL
                                  * path is required state: preparation/open failure refuses
                                  * the spawn rather than continuing without diagnostics. */
    cbm_proc_log_cb on_log_line; /* optional per-line callback */
    void *log_ud;                /* user data for on_log_line */
    cbm_proc_progress_cb on_progress; /* required when quiet_timeout_ms > 0 */
    void *progress_ud;                /* user data for on_progress */
    cbm_proc_cancel_cb should_cancel; /* optional exact-owner shutdown observation */
    void *cancel_ud;                  /* user data for should_cancel */
    cbm_proc_spawn_cb on_spawn;  /* optional: called with the child PID right after spawn */
    void *spawn_ud;              /* user data for on_spawn */
    int quiet_timeout_ms;        /* <= 0 => no timeout; else kill+HANG after this many
                                  * ms with no semantic advance */
    bool delete_log_on_exit;     /* unlink log_file after reaping */
} cbm_proc_opts_t;

/* Spawn the exact absolute opts->bin without PATH/current-image discovery,
 * supervise (tail + optional quiet-timeout), block until it ends, and classify
 * the result into *out. Returns 0 if a child was spawned and reaped (out filled),
 * or -1 if the spawn itself failed (out->outcome == CBM_PROC_SPAWN_FAILED). */
int cbm_subprocess_run(const cbm_proc_opts_t *opts, cbm_proc_result_t *out);

/* Pure outcome classifier — exposed so the platform-specific exit-code mapping
 * (notably the Windows NTSTATUS/GCC-SEH crash codes) is unit-testable on every platform.
 *   exited_normally: the child returned an exit code (POSIX WIFEXITED; always true
 *                    on Windows, which has no signals — crashes surface as codes).
 *   exit_code:       the exit / exception code (meaningful when exited_normally).
 *   term_signal:     POSIX terminating signal (meaningful when !exited_normally).
 *   timed_out:       we killed the child for exceeding the quiet-timeout. */
cbm_proc_outcome_t cbm_proc_classify(bool exited_normally, int exit_code, int term_signal,
                                     bool timed_out);

/* Stable lowercase name for an outcome (for structured logs / skip reasons). */
const char *cbm_proc_outcome_str(cbm_proc_outcome_t o);

/* Build a Windows CreateProcess command line from a NULL-terminated argv, applying
 * the Microsoft C runtime quoting rules (quote-wrap + escape embedded quotes and
 * their preceding backslashes) so the spawned child re-parses byte-identical argv.
 * Returns true on success, false on overflow (on overflow buf is set to an empty
 * string, never left unterminated).
 *
 * CreateProcess re-parses a SINGLE command string into argv, so a naive `"%s"` wrap
 * silently corrupts any element containing a double-quote — e.g. the index worker's
 * JSON arg {"repo_path":"…"} arrives as {repo_path:…}, the Windows index-worker bug.
 * Exposed (and compiled on every platform — it is pure string logic) so the quoting
 * is unit-tested on Linux/macOS CI, and so both spawn sites (cbm_subprocess_run and
 * the UI http_server index spawn) escape through one shared, tested implementation. */
bool cbm_build_win_cmdline(char *buf, size_t cap, const char *const *argv);

#endif /* CBM_SUBPROCESS_H */
