/*
 * main.c — Entry point for codebase-memory-mcp.
 *
 * Modes:
 *   (default)       Run as MCP server on stdin/stdout (JSON-RPC 2.0)
 *   cli <tool> <json>  Run a single tool call and print result
 *   --version       Print version and exit
 *   --help          Print usage and exit
 *   --ui=true/false Enable/disable HTTP UI server (persisted)
 *   --port=N        Set HTTP UI port (persisted, default 9749)
 *
 * Signal handling: SIGTERM/SIGINT trigger graceful shutdown.
 * Watcher runs in a background thread, polling for git changes.
 * HTTP UI server (optional) runs in a background thread on localhost.
 */
#include "cbm.h" // cbm_alloc_init — bind SQLite allocator and Tree-sitter slab before sqlite/git init
#include "mcp/mcp.h"
#include "mcp/index_supervisor.h"
#include "watcher/watcher.h"
#include "pipeline/pipeline.h"
#include "store/store.h"
#include "cli/cli.h"
#include "cli/progress_sink.h"
#include "foundation/constants.h"

enum {
    MAIN_MIN_ARGC = 1,
    MAIN_CLI_ARGC = 2,
    MAIN_FLAG_OFF = 5, /* strlen("--ui=") */
    MAIN_PORT_OFF = 7, /* strlen("--port=") */
    MAIN_MAX_PORT = 65536,
    MAIN_WORKER_RESPONSE_WRITE_FAILED = 2,
    MAIN_WORKER_PROGRESS_COMPLETE_FAILED = 3,
    PARENT_WATCHDOG_STACK_SIZE = 64 * CBM_SZ_1K, /* watchdog only polls — tiny stack suffices */
};
#define SLEN(s) (sizeof(s) - 1)
#include "foundation/log.h"
#include "foundation/diagnostics.h"
#include "foundation/platform.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/mem.h"
#include "foundation/profile.h"
#include "foundation/win_utf8.h" /* cbm_wide_to_utf8 — Windows UTF-8 argv (#423/#20); no-op on POSIX */
#ifdef _WIN32
#include <shellapi.h> /* CommandLineToArgvW — not pulled in by windows.h under WIN32_LEAN_AND_MEAN */
#endif
#include "ui/config.h"
#include "ui/http_server.h"
#include "ui/embedded_assets.h"
#include <yyjson/yyjson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#ifndef CBM_VERSION
#define CBM_VERSION "dev"
#endif

/* ── Globals for signal handling ────────────────────────────────── */

static cbm_watcher_t *g_watcher = NULL;
static cbm_mcp_server_t *g_server = NULL;
static cbm_http_server_t *g_http_server = NULL;
static atomic_int g_shutdown = 0;

/* Idempotent shutdown: cancels the active pipeline, stops background servers,
 * and closes stdin to unblock the MCP read loop. Invoked from the signal
 * handler and from the parent-death watchdog, hence the atomic_exchange guard
 * so the body runs at most once. Body is async-signal-safe (only atomic stores
 * and stop calls that themselves only set atomics). */
static void request_shutdown(void) {
    if (atomic_exchange(&g_shutdown, 1)) {
        return; /* already shutting down */
    }

    /* Cancel any in-progress pipeline (async-signal-safe: only does atomic_store) */
    if (g_server) {
        cbm_pipeline_t *p = cbm_mcp_server_active_pipeline(g_server);
        if (p) {
            cbm_pipeline_cancel(p);
        }
    }
    /* Release pipeline lock to prevent stale lock on restart */
    cbm_pipeline_unlock();

    if (g_watcher) {
        cbm_watcher_stop(g_watcher);
    }
    if (g_http_server) {
        cbm_http_server_stop(g_http_server);
    }
    /* Close stdin to unblock getline in the MCP server loop */
    (void)fclose(stdin);
}

static void signal_handler(int sig) {
    (void)sig;
    request_shutdown();
}

/* ── Parent-process watchdog ────────────────────────────────────── */
/* parent-death watchdog — distilled from #407 (fixes #406, thanks @nvt-pankajsharma).
 *
 * When this stdio MCP server is launched by an agent that later dies without a
 * clean SIGTERM (e.g. the editor is force-killed), the orphaned server would
 * otherwise linger forever blocked on stdin. POSIX has no portable "notify on
 * parent death" primitive (PR_SET_PDEATHSIG is Linux-only), so we poll getppid:
 * once the parent dies the process is reparented (ppid changes, typically to 1)
 * and we shut down. Windows is unaffected (job objects handle this) — #ifndef. */

#ifndef _WIN32
static void *parent_watchdog_thread(void *arg) {
    pid_t initial_ppid = *(pid_t *)arg;
    const unsigned int poll_interval_us = 500000; /* 500ms */

    while (!atomic_load(&g_shutdown)) {
        cbm_usleep(poll_interval_us);
        if (atomic_load(&g_shutdown)) {
            break;
        }
        /* initial_ppid > 1 guards against an already-orphaned start (ppid==1),
         * where a changing ppid carries no signal. */
        if (initial_ppid > 1 && getppid() != initial_ppid) {
            static const char msg[] = "level=warn msg=parent.exited reason=ppid_changed\n";
            (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
            _exit(0);
        }
    }
    return NULL;
}
#endif

/* ── Watcher background thread ──────────────────────────────────── */

static void *watcher_thread(void *arg) {
    cbm_watcher_t *w = arg;
#define WATCHER_BASE_INTERVAL_MS 5000

    cbm_watcher_run(w, WATCHER_BASE_INTERVAL_MS);
    return NULL;
}

/* ── HTTP UI background thread ──────────────────────────────────── */

static void *http_thread(void *arg) {
    cbm_http_server_t *srv = arg;
    cbm_http_server_run(srv);
    return NULL;
}

/* ── Index callback for watcher ─────────────────────────────────── */

static int cli_mcp_result_exit_code(const char *result);

static int watcher_index_fn(const char *project_name, const char *root_path,
                            const char *trigger_code, void *user_data) {
    (void)user_data;

    if (trigger_code && strcmp(trigger_code, CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED) == 0) {
        cbm_log_info("watcher.observation_recovered", "project", project_name, "path", root_path);
        return 0;
    }
    if (!trigger_code || strcmp(trigger_code, CBM_WATCHER_SOURCE_CHANGED) != 0) {
        cbm_log_error("watcher.observation_failed", "code",
                      trigger_code ? trigger_code : "CBM_WATCHER_TRIGGER_INVALID", "project",
                      project_name, "path", root_path, "remediation",
                      "repair the exact registered Git repository before watcher retry");
        return CBM_NOT_FOUND;
    }

    /* A skipped callback is not a successful transaction: returning success
     * would let the watcher commit the observed source fingerprint even though
     * no index publication occurred. Preserve the baseline so a later live
     * owner can process this exact change. */
    if (atomic_load(&g_shutdown)) {
        cbm_log_warn("watcher.reindex_refused", "code", "CBM_WATCHER_SHUTDOWN_IN_PROGRESS",
                     "project", project_name, "path", root_path, "message",
                     "shutdown began before the observed source change could be indexed",
                     "remediation", "restart the server so the unchanged watcher baseline retries");
        return CBM_NOT_FOUND;
    }

    /* Non-blocking admission preserves the observation baseline on contention;
     * the next ordinary poll observes the same change and retries it. */
    if (!cbm_pipeline_try_lock()) {
        cbm_log_warn(
            "watcher.reindex_refused", "code", "CBM_WATCHER_PIPELINE_BUSY", "project", project_name,
            "path", root_path, "message", "another pipeline owns the index publication boundary",
            "remediation",
            "allow the owning pipeline to finish; the unchanged watcher baseline will retry");
        return CBM_NOT_FOUND;
    }

    cbm_log_info("watcher.reindex", "project", project_name, "path", root_path);

    /* #832: route the re-index through the supervised worker subprocess so this
     * long-lived server process hands its RSS back to the OS on every cycle
     * instead of ratcheting (mimalloc v3 does not reclaim pages that worker
     * threads abandon at exit). The child writes the DB; the parent reads the
     * actual MCP result. The pipeline lock still serialises re-indexes. */
    if (cbm_index_supervisor_should_wrap()) {
        char *resp = cbm_mcp_index_run_supervised_path(root_path);
        if (resp) {
            int result_rc = cli_mcp_result_exit_code(resp);
            free(resp);
            cbm_pipeline_unlock();
            return result_rc == 0 ? 0 : CBM_NOT_FOUND;
        }
        cbm_log_error("watcher.reindex_failed", "code", "CBM_WATCHER_SUPERVISOR_NO_RESPONSE",
                      "project", project_name, "message",
                      "the isolated watcher index produced no response", "remediation",
                      "inspect supervisor process diagnostics before retrying");
        cbm_pipeline_unlock();
        return CBM_NOT_FOUND;
    }

    cbm_pipeline_t *p = cbm_pipeline_new(root_path, NULL, CBM_MODE_FULL);
    if (!p) {
        cbm_pipeline_unlock();
        return CBM_NOT_FOUND;
    }

    int rc = cbm_pipeline_run(p);
    cbm_pipeline_free(p);
    cbm_pipeline_unlock();
    return rc;
}

/* ── CLI mode ───────────────────────────────────────────────────── */

#define CLI_USAGE                                                              \
    "Usage: codebase-memory-mcp cli [--progress] [--json] <tool_name> "        \
    "[--args-file <path> | (JSON on stdin)]\n"                                 \
    "  --json prints the raw tool result JSON on stdout and exits 1 when the " \
    "result is isError:true (0 otherwise), so RC-based callers see tool "      \
    "failures (#419).\n"

/* Exit code for an MCP tool result string: SKIP_ONE (1) for isError:true, else 0.
 * MCP results: {"content":[{"type":"text","text":"..."}],"isError":...}
 *
 * Single source of truth for the CLI exit code, shared by BOTH the pretty
 * (cli_print_mcp_result) and the raw `--json` paths so the two never diverge
 * — the whole point of #425 / #419. An absent/malformed envelope fails closed:
 * a worker response that cannot prove isError:false is not successful. */
static int cli_mcp_result_exit_code(const char *result) {
    if (!result) {
        return SKIP_ONE;
    }
    yyjson_doc *doc = yyjson_read(result, strlen(result), 0);
    if (!doc) {
        return SKIP_ONE;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *err_val = yyjson_obj_get(root, "isError");
    bool is_error = !err_val || !yyjson_is_bool(err_val) || yyjson_get_bool(err_val);
    yyjson_doc_free(doc);
    return is_error ? SKIP_ONE : 0;
}

/* Extract text content from MCP tool result envelope and print it.
 * MCP results: {"content":[{"type":"text","text":"..."}],"isError":...}
 * Returns 1 if the result was an error, 0 otherwise (via the shared
 * cli_mcp_result_exit_code detector — no separate isError logic here). */
static int cli_print_mcp_result(const char *result) {
    int exit_code = cli_mcp_result_exit_code(result);
    bool is_error = (exit_code != 0);

    yyjson_doc *doc = yyjson_read(result, strlen(result), 0);
    if (!doc) {
        printf("%s\n", result);
        return exit_code;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);

    const char *text = NULL;
    yyjson_val *content = yyjson_obj_get(root, "content");
    if (yyjson_is_arr(content) && yyjson_arr_size(content) > 0) {
        yyjson_val *tv = yyjson_obj_get(yyjson_arr_get_first(content), "text");
        text = tv ? yyjson_get_str(tv) : NULL;
    }

    if (text) {
        (void)fprintf(is_error ? stderr : stdout, "%s\n", text);
    } else {
        printf("%s\n", result);
    }

    yyjson_doc_free(doc);
    return exit_code;
}

/* Fully write and close the supervised-worker response before exit. Exit code 1 is
 * reserved for a validated MCP isError:true result, so transport publication
 * failure must use a distinct code that the parent can never misclassify as an
 * intentional tool error. */
static bool cli_write_worker_response(const char *path, const char *result) {
    FILE *file = cbm_fopen(path, "wb");
    if (!file) {
        return false;
    }
    int write_rc = fputs(result, file);
    int flush_rc = fflush(file);
    int close_rc = fclose(file);
    if (write_rc == EOF || flush_rc != 0 || close_rc != 0) {
        (void)cbm_unlink(path);
        return false;
    }
    return true;
}

/* Strip a flag from argv, returning true if found. */
static bool cli_strip_flag(int *argc, char **argv, const char *flag) {
    for (int i = 0; i < *argc; i++) {
        if (strcmp(argv[i], flag) != 0) {
            continue;
        }
        for (int j = i; j < *argc - SKIP_ONE; j++) {
            argv[j] = argv[j + SKIP_ONE];
        }
        (*argc)--;
        return true;
    }
    return false;
}

/* Strip a flag AND its following value from argv, returning the value (a pointer
 * into the original argv strings, valid for the process lifetime) or NULL if the
 * flag is absent. */
static const char *cli_strip_flag_value(int *argc, char **argv, const char *flag) {
    for (int i = 0; i < *argc; i++) {
        if (strcmp(argv[i], flag) != 0) {
            continue;
        }
        const char *value = (i + SKIP_ONE < *argc) ? argv[i + SKIP_ONE] : NULL;
        int remove_count = value ? 2 : 1;
        for (int j = i; j < *argc - remove_count; j++) {
            argv[j] = argv[j + remove_count];
        }
        *argc -= remove_count;
        return value;
    }
    return NULL;
}

/* Portable "is fd a terminal?" — _isatty on Windows, isatty on POSIX. */
#ifdef _WIN32
#define cli_isatty(fd) _isatty(fd)
#else
#define cli_isatty(fd) isatty(fd)
#endif

enum { CLI_SLURP_CHUNK = 4096 };

/* Read an open stream fully into a heap, NUL-terminated string. Caller frees.
 * Returns NULL on allocation failure. Reads binary-clean (UTF-8 JSON, no shell
 * quoting needed). */
static char *cli_slurp_stream(FILE *f) {
    size_t cap = CLI_SLURP_CHUNK;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        return NULL;
    }
    char tmp[CLI_SLURP_CHUNK];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) {
        if (len + n + 1 > cap) {
            while (len + n + 1 > cap) {
                cap *= 2;
            }
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
        }
        memcpy(buf + len, tmp, n);
        len += n;
    }
    buf[len] = '\0';
    return buf;
}

/* Slurp a file path into a heap, NUL-terminated string. Caller frees. */
static char *cli_slurp_file(const char *path) {
    /* #426: cbm_fopen widens + "\\?\"-prefixes the path so a --args-file handed to
     * the index worker under a deep %TEMP% (UI spawn) or a deep store's logs/ dir
     * (index_supervisor.c) opens instead of failing at MAX_PATH with raw fopen —
     * the last link in the one long-path-safe spawn chain. Short paths are
     * unaffected (cbm_fopen handles them identically). */
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    char *s = cli_slurp_stream(f);
    (void)fclose(f);
    return s;
}

/* True if the first non-whitespace byte of s is '{' (raw-JSON detection). */
static bool cli_first_nonspace_is_brace(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') {
        s++;
    }
    return *s == '{';
}

/* Minimal JSON string-body escaper for embedding an untrusted argv token (the
 * tool name) into the `--json` NULL-result diagnostic (#431). Writes an escaped
 * copy of `src` into `dst` (capacity `cap`, always NUL-terminated), escaping the
 * two structural characters (" and \) and control bytes < 0x20 as \uXXXX, and
 * truncating on a code-point boundary if the escaped form would overflow. Kept
 * allocation-free by design: the NULL-result guard's whole point is to stay
 * usable when the most likely cause of the NULL is an allocation failure, so it
 * must not itself depend on the heap. */
static void cli_json_escape(char *dst, size_t cap, const char *src) {
    if (cap == 0) {
        return;
    }
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        char esc[8];
        size_t need;
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = (char)c;
            need = 2;
        } else if (c < 0x20) {
            (void)snprintf(esc, sizeof(esc), "\\u%04x", c);
            need = 6;
        } else {
            esc[0] = (char)c;
            need = 1;
        }
        if (o + need >= cap) { /* keep room for the terminating NUL */
            break;
        }
        memcpy(dst + o, esc, need);
        o += need;
    }
    dst[o] = '\0';
}

static int run_cli(int argc, char **argv) {
    if (argc < MAIN_MIN_ARGC) {
        (void)fprintf(stderr, CLI_USAGE);
        return SKIP_ONE;
    }

    bool progress = cli_strip_flag(&argc, argv, "--progress");
    bool raw_json = cli_strip_flag(&argc, argv, "--json");

    /* Supervisor worker role: when this process was spawned as a supervised index
     * worker, run indexing in-process (never re-supervise) and write the result to
     * the given file for the parent to read back. Stripped here so the tool
     * dispatch below sees only the tool name + its args. */
    bool index_worker = cli_strip_flag(&argc, argv, "--index-worker");
    const char *response_out = cli_strip_flag_value(&argc, argv, "--response-out");
    const char *worker_progress_out =
        cli_strip_flag_value(&argc, argv, "--worker-progress-out");
    const char *worker_progress_attempt =
        cli_strip_flag_value(&argc, argv, "--worker-progress-attempt");
    if (cbm_index_set_worker_role(index_worker, response_out, worker_progress_out,
                                  worker_progress_attempt) != 0) {
        return SKIP_ONE;
    }

    if (index_worker) {
        /* #435: an index worker's stderr is redirected to the parent-tailed log
         * file (subprocess.c sets hStdError=hStdOutput=hlog, or dup2s the log fd on
         * POSIX). On the Windows CRT a redirected (non-console) stderr is opened
         * FULLY BUFFERED with a ~4 KB buffer — it is NOT line-buffered, because
         * Win32 treats _IOLBF as _IOFBF (MS setvbuf docs; mingw-w64 crt note). So
         * the pipeline's cbm_log_info progress lines (pass.start/done,
         * parallel.extract.progress, …) sit in the worker's CRT buffer and never
         * reach the log the UI tails until the buffer fills or the process exits —
         * and this worker exits via _Exit (the fast-exit below skips the multi-GB
         * kernel-graph teardown), which per C/POSIX does NOT flush stdio. Net
         * effect: GET /api/logs stayed blind to the whole indexing phase (#435).
         *
         * Class fix, from the start: force the worker's log stream unbuffered so
         * every emitted line is written straight through to the tailed log the
         * instant it is produced (the durable, measurement-checked choice — one
         * tiny write per log line is negligible vs the teardown _Exit avoids, and
         * far cheaper than losing live visibility). This mirrors how CPython
         * unbuffers child stdio on MS_WINDOWS (setvbuf(_IONBF)) and the mingw-w64
         * fix that keeps stderr non-fully-buffered. _IONBF (not _IOLBF, which is
         * full buffering on Win32) is the only mode that actually streams here. The
         * existing fflush(NULL) immediately before _Exit is kept as belt-and-braces
         * for anything still buffered (e.g. the final result on stdout). No-op-ish
         * on POSIX, where stderr is already unbuffered. Placed before any worker
         * stderr I/O so setvbuf's "no I/O since open" precondition holds. */
        (void)setvbuf(stderr, NULL, _IONBF, 0);
    }

#ifndef _WIN32
    /* #845: a supervised worker must not outlive its supervisor. If the parent
     * dies without reaping us (agent killed, supervisor crashed), an orphaned
     * worker would index on unsupervised — observed contributing to memory
     * pressure during the 2026-07-04 host panics. Reuse the parent-death
     * watchdog (safe outside server mode: on ppid change it only writes to
     * stderr and _exit(0)s — no cleanup dependencies). Detached: the worker
     * exits by returning from run_cli; exit() tears the thread down. Failure
     * to start is non-fatal, same policy as the MCP-server watchdog. */
    if (index_worker) {
        static pid_t worker_initial_ppid; /* static: outlives run_cli for the thread */
        worker_initial_ppid = getppid();
        cbm_thread_t worker_watchdog_tid;
        if (cbm_thread_create(&worker_watchdog_tid, PARENT_WATCHDOG_STACK_SIZE,
                              parent_watchdog_thread, &worker_initial_ppid) == 0) {
            (void)cbm_thread_detach(&worker_watchdog_tid);
            cbm_log_info("worker.watchdog.start");
        } else {
            cbm_log_warn("worker.watchdog.unavailable", "reason", "thread_create_failed");
        }
    }
#endif

    if (argc < MAIN_MIN_ARGC) {
        (void)fprintf(stderr, CLI_USAGE);
        return SKIP_ONE;
    }

    const char *tool_name = argv[0];
    int rem_argc = argc - SKIP_ONE; /* args following the tool name */
    char **rem_argv = argv + SKIP_ONE;

    /* --help / -h : print per-tool help (from the tool's input_schema) and exit
     * before any server work. */
    for (int i = 0; i < rem_argc; i++) {
        if (strcmp(rem_argv[i], "--help") == 0 || strcmp(rem_argv[i], "-h") == 0) {
            if (cbm_cli_print_tool_help(tool_name) != 0) {
                (void)fprintf(stderr, "error: unknown tool '%s'\n", tool_name);
                return SKIP_ONE;
            }
            return 0;
        }
    }

    /* Resolve the JSON arguments. Supported forms (one contract with the Rust
     * host, #378/#411): --args-file <path>, then piped stdin, then empty {}.
     * Raw-JSON argv and the `--flag value` form are REMOVED — the raw-JSON token
     * is refused fail-closed (ASTRO_CLI_RAW_JSON_ARGV_REMOVED), matching
     * crates/astrolabe-server/src/lib.rs. */
    char *heap_args = NULL; /* freed before return when set */
    const char *args_json = "{}";

    int args_file_idx = -1;
    for (int i = 0; i < rem_argc; i++) {
        if (strcmp(rem_argv[i], "--args-file") == 0) {
            args_file_idx = i;
            break;
        }
    }

    if (args_file_idx >= 0) {
        if (args_file_idx + SKIP_ONE >= rem_argc) {
            (void)fprintf(stderr, "error: --args-file requires a path argument\n");
            return SKIP_ONE;
        }
        const char *path = rem_argv[args_file_idx + SKIP_ONE];
        heap_args = cli_slurp_file(path);
        if (!heap_args) {
            (void)fprintf(stderr, "error: cannot read args file '%s'\n", path);
            return SKIP_ONE;
        }
        args_json = heap_args;
    } else if (rem_argc >= SKIP_ONE && cli_first_nonspace_is_brace(rem_argv[0])) {
        /* #378/#411: raw-JSON argv is removed. Fail closed with the same label
         * and remediation the Rust host emits — no silent divergence between the
         * two CLI surfaces. */
        (void)fprintf(stderr,
                      "ASTRO_CLI_RAW_JSON_ARGV_REMOVED: passing raw JSON as a 'cli' "
                      "argv token is no longer supported. remediation: write the JSON "
                      "to a file and pass `--args-file <path>`, or pipe it on stdin "
                      "(e.g. `codebase-memory-mcp cli %s --args-file args.json` or "
                      "`echo '<json>' | codebase-memory-mcp cli %s`).\n",
                      tool_name, tool_name);
        return SKIP_ONE;
    } else if (!cli_isatty(0)) {
        /* piped stdin (UTF-8 clean, no shell quoting): cli <tool> < args.json */
        heap_args = cli_slurp_stream(stdin);
        if (heap_args && heap_args[0]) {
            args_json = heap_args;
        } else {
            free(heap_args);
            heap_args = NULL;
            args_json = "{}";
        }
    }

    if (progress) {
        cbm_progress_sink_init(stderr);
    }

    cbm_mcp_server_t *srv = cbm_mcp_server_new(NULL);
    if (!srv) {
        (void)fprintf(stderr, "error: failed to create server\n");
        if (progress) {
            cbm_progress_sink_fini();
        }
        return SKIP_ONE;
    }

    char *result = cbm_mcp_handle_tool(srv, tool_name, args_json);
    int exit_code = 0;

    if (!result) {
        /* Fail closed (#431): cbm_mcp_handle_tool returned NULL — it produced NO
         * result envelope at all. In the current dispatcher this is reachable only
         * as an allocation failure inside the JSON serializer (cbm_mcp_text_result
         * / yy_doc_to_str → yyjson_mut_write returns NULL); every ordinary and
         * malformed-input path — unknown tool, missing/blank args, missing project
         * — instead returns a well-formed isError:true envelope, whose exit-code
         * contract #425 owns. A NULL is therefore categorically an INTERNAL error,
         * distinct from a tool-reported failure. Before this guard the `if (result)`
         * block below was simply skipped: the CLI printed nothing and returned 0,
         * so a scripted / agent / FSV caller saw silent success with empty stdout
         * on a dispatch failure — on BOTH the pretty and `--json` paths. The guard
         * also stands as defense-in-depth for any future dispatch path that
         * returns NULL.
         *
         * The diagnostic is emitted with a fixed-format fprintf (no heap, no JSON
         * builder) precisely because the likeliest cause of a NULL is that
         * allocation is already failing — a guard that itself allocated could die
         * the same way. stdout stays EMPTY so a `--json` consumer never mistakes
         * the diagnostic for a tool payload (data→stdout, diagnostics→stderr);
         * under `--json` the diagnostic is a single-line JSON object with stable
         * {code,message,remediation} fields so scripted callers branch on `code`,
         * and a human-readable block otherwise. */
        const char *ro = cbm_index_worker_response_out();
        if (ro) {
            /* Supervised index worker (#832 path): remove any file at that path
             * so the parent can NEVER read a stale/prior response as this run's
             * result. The non-zero exit below plus the missing response is an
             * unambiguous supervisor failure, never an intentional tool error. */
            (void)cbm_unlink(ro);
        }
        if (raw_json) {
            char esc_tool[CBM_SZ_256];
            cli_json_escape(esc_tool, sizeof(esc_tool), tool_name);
            (void)fprintf(stderr,
                          "{\"code\":\"CBM_E_TOOL_NULL_RESULT\","
                          "\"message\":\"tool '%s' produced no result (internal error: "
                          "the dispatcher returned no result envelope, most likely an "
                          "allocation failure)\","
                          "\"remediation\":\"retry the call; if it persists the host is "
                          "likely out of memory — free memory or reduce the workload "
                          "(e.g. index a smaller path), and report the tool name if the "
                          "failure reproduces\"}\n",
                          esc_tool);
        } else {
            (void)fprintf(stderr,
                          "error: CBM_E_TOOL_NULL_RESULT: tool '%s' produced no result\n"
                          "  the dispatcher returned no result envelope, most likely an "
                          "allocation failure.\n"
                          "  remediation: retry; if it persists the host is likely out of "
                          "memory — free memory or reduce the workload and report the tool "
                          "name if it reproduces.\n",
                          tool_name);
        }
        exit_code = SKIP_ONE;
        if (cbm_index_worker_active()) {
            /* Supervised worker: mirror the non-NULL fast-exit — skip teardown, let
             * the OS reclaim — but propagate the non-zero code so the parent sees a
             * non-CLEAN outcome instead of a false success. */
            cbm_log_error("index.worker.null_result", "tool", tool_name);
            fflush(NULL);
            _Exit(exit_code);
        }
        cbm_mcp_server_free(srv);
        if (progress) {
            cbm_progress_sink_fini();
        }
        free(heap_args);
        return exit_code;
    }

    if (result) {
        /* Supervised worker: hand the full result string to the parent via the
         * response file before printing. The parent validates this publication
         * together with the exact process outcome. */
        const char *ro = cbm_index_worker_response_out();
        bool worker_response_written =
            !cbm_index_worker_active() || (ro && cli_write_worker_response(ro, result));
        if (raw_json) {
            /* #425: the JSON payload is unchanged (byte-for-byte on stdout),
             * but the process exit code now reflects the tool outcome —
             * isError:true exits 1 so any RC-based caller (scripts, FSV
             * drivers, agents checking $?) sees the failure instead of reading
             * a `--json` success. Mirrors the astrolabe host's #419 fix and
             * shares the exact detector the pretty path uses; stdout format is
             * the only thing `--json` changes, never the failure signal. */
            printf("%s\n", result);
            exit_code = cli_mcp_result_exit_code(result);
        } else {
            exit_code = cli_print_mcp_result(result);
        }
        if (cbm_index_worker_active()) {
            if (!worker_response_written) {
                cbm_log_error(
                    "index.worker.response_write_failed", "code",
                    "CBM_INDEX_WORKER_RESPONSE_WRITE_FAILED", "message",
                    "the complete supervised worker response could not be published", "remediation",
                    "inspect the worker response path and storage device before retrying");
                fflush(NULL);
                _Exit(MAIN_WORKER_RESPONSE_WRITE_FAILED);
            }
            if (cbm_index_worker_progress_complete() != 0) {
                cbm_log_error(
                    "index.worker.progress_complete_failed", "code",
                    "CBM_INDEX_WORKER_PROGRESS_COMPLETE_FAILED", "message",
                    "the supervised worker response was written but its terminal semantic "
                    "progress record could not be published",
                    "remediation",
                    "preserve the worker workspace and inspect the progress-stream diagnostic");
                fflush(NULL);
                _Exit(MAIN_WORKER_PROGRESS_COMPLETE_FAILED);
            }
            /* Supervised worker: the response is delivered (file + stdout).
             * Skip the multi-GB teardown (server/store frees) — the process
             * dies now and the OS reclaims everything wholesale; piecemeal
             * free() of a kernel-scale graph costs minutes. _Exit skips
             * atexit/LSan by design for this prod worker path. */
            cbm_log_info("index.worker.fast_exit", "action", "_Exit");
            fflush(NULL);
            _Exit(exit_code);
        }
        free(result);
    }

    cbm_mcp_server_free(srv);
    if (progress) {
        cbm_progress_sink_fini();
    }
    free(heap_args);
    return exit_code;
}

/* ── Help ───────────────────────────────────────────────────────── */

static void print_help(void) {
    printf("codebase-memory-mcp %s\n\n", CBM_VERSION);
    printf("Usage:\n");
    printf("  codebase-memory-mcp              Run MCP server on stdio\n");
    printf("  codebase-memory-mcp cli <tool> [--args-file <path> | (JSON on stdin)]  Run a single "
           "tool\n");
    printf("      codebase-memory-mcp cli --json <tool> prints the raw result JSON on stdout and "
           "exits 1 when the result is isError:true, else 0 (#419).\n");
    printf("  codebase-memory-mcp install [-y|-n] [--force] [--dry-run]\n");
    printf("  codebase-memory-mcp uninstall [-y|-n] [--dry-run]\n");
    printf("  codebase-memory-mcp update [-y|-n]\n");
    printf("  codebase-memory-mcp config <list|get|set|reset>\n");
    printf("  codebase-memory-mcp --version    Print version\n");
    printf("  codebase-memory-mcp --help       Print this help\n");
    printf("\nUI options:\n");
    printf("  --ui=true    Enable HTTP graph visualization (persisted)\n");
    printf("  --ui=false   Disable HTTP graph visualization (persisted)\n");
    printf("  --port=N     Set UI port (default 9749, persisted)\n");
    printf("\nSupported agents (auto-detected):\n");
    printf("  Claude Code, Codex CLI, Gemini CLI, Zed, OpenCode,\n");
    printf("  Antigravity, Aider, KiloCode, Kiro\n");
    printf("\nTools: index_repository, search_graph, query_graph, trace_path,\n");
    printf("  get_code_snippet, get_graph_schema, get_architecture, search_code,\n");
    printf("  list_projects, delete_project, index_status, detect_changes,\n");
    printf("  manage_adr, ingest_traces\n");
}

/* ── Main ───────────────────────────────────────────────────────── */

/* Try to handle a subcommand (cli/install/uninstall/update/config/--version/--help).
 * Returns -1 if no subcommand matched, otherwise the exit code. */
static int handle_subcommand(int argc, char **argv) {
    /* First scan: global flags */
    for (int i = SKIP_ONE; i < argc; i++) {
        if (strcmp(argv[i], "--profile") == 0) {
            cbm_profile_enable();
        }
    }
    for (int i = SKIP_ONE; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("codebase-memory-mcp %s\n", CBM_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
        if (strcmp(argv[i], "cli") == 0) {
            cbm_mem_init(cbm_mem_ram_fraction_for_total(cbm_system_info().total_ram));
            return run_cli(argc - i - SKIP_ONE, argv + i + SKIP_ONE);
        }
        if (strcmp(argv[i], "hook-augment") == 0) {
            cbm_mem_init(cbm_mem_ram_fraction_for_total(cbm_system_info().total_ram));
            return cbm_cmd_hook_augment();
        }
        if (strcmp(argv[i], "install") == 0) {
            return cbm_cmd_install(argc - i - SKIP_ONE, argv + i + SKIP_ONE);
        }
        if (strcmp(argv[i], "uninstall") == 0) {
            return cbm_cmd_uninstall(argc - i - SKIP_ONE, argv + i + SKIP_ONE);
        }
        if (strcmp(argv[i], "update") == 0) {
            return cbm_cmd_update(argc - i - SKIP_ONE, argv + i + SKIP_ONE);
        }
        if (strcmp(argv[i], "config") == 0) {
            return cbm_cmd_config(argc - i - SKIP_ONE, argv + i + SKIP_ONE);
        }
    }
    return CBM_NOT_FOUND;
}

/* Parse --ui= and --port= flags. Returns true if config was modified. */
static bool parse_ui_flags(int argc, char **argv, cbm_ui_config_t *cfg, bool *explicit_enable) {
    bool changed = false;
    for (int i = SKIP_ONE; i < argc; i++) {
        if (strncmp(argv[i], "--ui=", SLEN("--ui=")) == 0) {
            cfg->ui_enabled = (strcmp(argv[i] + MAIN_FLAG_OFF, "true") == 0);
            if (explicit_enable && cfg->ui_enabled) {
                *explicit_enable = true;
            }
            changed = true;
        }
        if (strncmp(argv[i], "--port=", SLEN("--port=")) == 0) {
            int p = (int)strtol(argv[i] + MAIN_PORT_OFF, NULL, CBM_DECIMAL_BASE);
            if (p > 0 && p < MAIN_MAX_PORT) {
                cfg->ui_port = p;
                changed = true;
            }
        }
    }
    return changed;
}

/* Install platform-specific signal handlers. */
static void setup_signal_handlers(void) {
#ifdef _WIN32
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
#else
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
#endif
}

#ifdef _WIN32
/* On Windows the CRT hands main() an argv encoded in the active ANSI code page, so a
 * non-ASCII CLI argument (e.g. a repo path like café_日本語_repo) is mangled before the
 * program ever sees it — the documented `cli index_repository "<json>"` then fails with
 * "repo_path is required" (#423/#20). Rebuild argv from the wide command line
 * (GetCommandLineW → CommandLineToArgvW) and convert each element to UTF-8 so the rest
 * of the program receives the same UTF-8 bytes it gets on POSIX. Returns a
 * NULL-terminated argv and sets *out_argc, or NULL with the exact failed operation and
 * Win32 error. The returned block lives for the whole process (argv must stay valid
 * until exit), so it is intentionally never freed. */
static char **cbm_win_utf8_argv(int *out_argc, const char **out_operation, DWORD *out_error) {
    *out_operation = "CommandLineToArgvW";
    *out_error = ERROR_SUCCESS;
    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (!wargv) {
        *out_error = GetLastError();
        return NULL;
    }
    if (wargc <= 0) {
        LocalFree(wargv);
        *out_error = ERROR_INVALID_DATA;
        return NULL;
    }
    *out_operation = "allocate_utf8_argv";
    char **u8argv = (char **)calloc((size_t)wargc + 1, sizeof(char *));
    if (!u8argv) {
        LocalFree(wargv);
        *out_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    for (int i = 0; i < wargc; i++) {
        *out_operation = "WideCharToMultiByte";
        u8argv[i] = cbm_wide_to_utf8(wargv[i]);
        if (!u8argv[i]) {
            *out_error = GetLastError();
            for (int j = 0; j < i; j++) {
                free(u8argv[j]);
            }
            free(u8argv);
            LocalFree(wargv);
            return NULL;
        }
    }
    LocalFree(wargv);
    *out_argc = wargc;
    *out_operation = NULL;
    *out_error = ERROR_SUCCESS;
    return u8argv; /* NULL-terminated (calloc'd wargc+1) */
}
#endif /* _WIN32 */

static void report_invalid_log_format(const char *value) {
    const unsigned char *bytes = (const unsigned char *)(value ? value : "");
    size_t value_bytes = strlen((const char *)bytes);
    (void)fprintf(stderr,
                  "{\"level\":\"error\",\"event\":\"log.format_invalid\","
                  "\"code\":\"CBM_LOG_FORMAT_INVALID\",\"name\":\"CBM_LOG_FORMAT\","
                  "\"value_bytes\":%zu,\"value_hex\":\"",
                  value_bytes);
    for (size_t i = 0; i < value_bytes; i++) {
        (void)fprintf(stderr, "%02x", (unsigned int)bytes[i]);
    }
    (void)fprintf(stderr,
                  "\",\"message\":\"CBM_LOG_FORMAT must be exactly text or json "
                  "(case-insensitive) when present\",\"remediation\":\"set "
                  "CBM_LOG_FORMAT to text or json, or remove it to select the text "
                  "default\"}\n");
    (void)fflush(stderr);
}

int main(int argc, char **argv) {
    /* Defense-in-depth: bind tree-sitter and sqlite3 to mimalloc so a
     * correct binary does not rely on the fragile MI_OVERRIDE symbol override
     * (#424). MUST be the VERY FIRST statement: SQLITE_CONFIG_MALLOC has to run
     * before the first sqlite3_open* (cbm_mcp_server_new → cbm_store_open_memory
     * below opens sqlite early), else sqlite3_config returns SQLITE_MISUSE and
     * the bind is silently ignored. No-op in the test build. */
    int allocator_rc = cbm_alloc_init();
    if (allocator_rc != 0) {
        return EXIT_FAILURE;
    }
    /* The worker authority is the operating system's current process image,
     * never argv[0] or PATH. Bind and independently retain that identity before
     * changing any other process-global host configuration. */
    unsigned long binary_native_error = 0;
    cbm_worker_binary_status_t binary_status =
        cbm_http_server_bind_self_binary(&binary_native_error);
    if (binary_status != CBM_WORKER_BINARY_OK) {
        fprintf(stderr, "code=%s message=%s remediation=%s native_error=%lu\n",
                cbm_http_server_binary_status_code(binary_status),
                cbm_http_server_binary_status_message(binary_status),
                cbm_http_server_binary_status_remediation(binary_status), binary_native_error);
        return EXIT_FAILURE;
    }
    if (!cbm_http_server_binary_path()) {
        binary_status = CBM_WORKER_BINARY_UNBOUND;
        fprintf(stderr, "code=%s message=%s remediation=%s native_error=0\n",
                cbm_http_server_binary_status_code(binary_status),
                cbm_http_server_binary_status_message(binary_status),
                cbm_http_server_binary_status_remediation(binary_status));
        return EXIT_FAILURE;
    }
    /* Log-format admission precedes argv allocation, profile selection, host
     * publication, and every command/server path. Invalid input is reported
     * without installing a sink or committing either logging setting. */
    const char *invalid_log_format = cbm_log_init_from_env();
    if (invalid_log_format) {
        report_invalid_log_format(invalid_log_format);
        return EXIT_FAILURE;
    }
#ifdef _WIN32
    /* The wide command line is the sole Windows argv source. Continuing with the CRT
     * ANSI argv after a conversion failure changes repository/config path bytes and
     * therefore the indexed corpus. */
    {
        int win_argc = 0;
        const char *win_operation = NULL;
        DWORD win_error = ERROR_SUCCESS;
        char **win_argv = cbm_win_utf8_argv(&win_argc, &win_operation, &win_error);
        if (!win_argv) {
            char error_buf[CBM_SZ_32];
            snprintf(error_buf, sizeof(error_buf), "%lu", (unsigned long)win_error);
            cbm_log_error(
                "startup.argv_failed", "code", "CBM_WINDOWS_ARGV_UTF8_FAILED", "operation",
                win_operation ? win_operation : "windows_argv", "win32_error", error_buf, "message",
                "the Unicode Windows command line could not be reconstructed as exact UTF-8",
                "remediation", "resolve the reported Win32 or memory error and restart");
            return EXIT_FAILURE;
        }
        argc = win_argc;
        argv = win_argv;
    }
#endif
    /* #845: mark this process as the REAL binary so the index supervisor may
     * wrap index_repository in a worker subprocess. Must run before any
     * subcommand dispatch so MCP-server, CLI, and HTTP paths are all covered.
     * Embedders of cbm_mcp_handle_tool (test binaries) never mark themselves,
     * so they index in-process instead of re-invoking themselves as
     * `<self> cli --index-worker …` (recursive suite re-runs / spawn chains). */
    cbm_index_supervisor_mark_host();
    cbm_cli_set_version(CBM_VERSION);
    cbm_profile_init(); /* reads CBM_PROFILE env var, gates all prof macros */
    int subcmd = handle_subcommand(argc, argv);
    if (subcmd >= 0) {
        return subcmd;
    }

    /* parent-death watchdog — distilled from #407 (fixes #406). Start it early so
     * an orphaned server exits even if it dies before reaching the MCP loop. A
     * thread-create failure (or ppid<=1) is non-fatal: the server still runs, it
     * just won't auto-exit on parent death — same policy as the watcher/HTTP
     * threads below. We deliberately do NOT exit at startup when ppid<=1 (the PR's
     * original behaviour): a legitimately-launched server can transiently show
     * ppid==1 (early reparent races, double-fork/container launchers), and the
     * watchdog already no-ops safely in that case via its initial_ppid>1 guard. */
#ifndef _WIN32
    /* main() outlives the watchdog (it joins before returning), so a stack
     * local is a valid lifetime for the thread's argument. */
    pid_t initial_ppid = getppid();
    cbm_thread_t parent_watchdog_tid;
    bool parent_watchdog_started = false;
    if (cbm_thread_create(&parent_watchdog_tid, PARENT_WATCHDOG_STACK_SIZE, parent_watchdog_thread,
                          &initial_ppid) == 0) {
        parent_watchdog_started = true;
    } else {
        cbm_log_warn("parent.watchdog.unavailable", "reason", "thread_create_failed");
    }
#endif

    /* Default: MCP server on stdio */
    cbm_mem_init(cbm_mem_ram_fraction_for_total(cbm_system_info().total_ram));
    cbm_log_set_sink_ex(cbm_ui_log_append, CBM_LOG_SINK_TEE);
    cbm_log_info("server.start", "version", CBM_VERSION);
    cbm_diag_start(); /* starts if CBM_DIAGNOSTICS=1 */

    /* Parse --ui and --port flags (persisted config) */
    cbm_ui_config_t ui_cfg;
    cbm_ui_config_load(&ui_cfg);
    bool explicit_ui_enable = false;
    if (parse_ui_flags(argc, argv, &ui_cfg, &explicit_ui_enable)) {
        cbm_ui_config_save(&ui_cfg);
    }
    /* If the user explicitly asked for the UI but this binary has no embedded
     * frontend, the HTTP server can never start (see below). The warning that
     * covers this goes to the log sink, which a user running `--ui=true` on a
     * terminal won't see — so tell them plainly on stderr why nothing happens
     * and which build to use (#350). */
    if (explicit_ui_enable && CBM_EMBEDDED_FILE_COUNT == 0) {
        (void)fprintf(stderr,
                      "codebase-memory-mcp: --ui requested, but this binary was built without the "
                      "embedded UI, so the HTTP server will not start.\n"
                      "Use the UI release asset (codebase-memory-mcp-ui) or rebuild with: "
                      "make -f Makefile.cbm cbm-with-ui\n");
    }

    setup_signal_handlers();

    /* Open config store for runtime settings */
    char config_dir[CBM_SZ_1K];
    const char *cfg_home = cbm_get_home_dir();
    cbm_config_t *runtime_config = NULL;
    if (cfg_home) {
        snprintf(config_dir, sizeof(config_dir), "%s", cbm_resolve_cache_dir());
        runtime_config = cbm_config_open(config_dir);
    }

    /* Create MCP server */
    g_server = cbm_mcp_server_new(NULL);
    if (!g_server) {
        cbm_log_error("server.err", "msg", "failed to create server");
        cbm_config_close(runtime_config);
#ifndef _WIN32
        if (parent_watchdog_started) {
            atomic_store(&g_shutdown, 1);
            cbm_thread_join(&parent_watchdog_tid);
        }
#endif
        return SKIP_ONE;
    }

    /* Create and start watcher in background thread */
    /* Initialize log mutex before any threads are created */
    cbm_ui_log_init();

    cbm_store_t *watch_store = cbm_store_open_memory();
    g_watcher = cbm_watcher_new(watch_store, watcher_index_fn, NULL);

    /* Wire watcher + config into MCP server for session auto-index */
    cbm_mcp_server_set_watcher(g_server, g_watcher);
    cbm_mcp_server_set_config(g_server, runtime_config);
    cbm_thread_t watcher_tid;
    bool watcher_started = false;

    if (g_watcher) {
        if (cbm_thread_create(&watcher_tid, 0, watcher_thread, g_watcher) == 0) {
            watcher_started = true;
        }
    }

    /* Optionally start HTTP UI server in background thread */
    cbm_thread_t http_tid;
    bool http_started = false;

    if (ui_cfg.ui_enabled && CBM_EMBEDDED_FILE_COUNT > 0) {
        g_http_server = cbm_http_server_new(ui_cfg.ui_port);
        if (g_http_server) {
            cbm_http_server_set_watcher(g_http_server, g_watcher);
            if (cbm_thread_create(&http_tid, 0, http_thread, g_http_server) == 0) {
                http_started = true;
            }
        }
    } else if (ui_cfg.ui_enabled && CBM_EMBEDDED_FILE_COUNT == 0) {
        cbm_log_warn("ui.no_assets", "hint", "rebuild with: make -f Makefile.cbm cbm-with-ui");
    }

    /* Run MCP event loop (blocks until EOF or signal) */
    int rc = cbm_mcp_server_run(g_server, stdin, stdout);
    atomic_store(&g_shutdown, 1); /* unblock the watchdog poll loop */

    /* Shutdown */
    cbm_log_info("server.shutdown");

#ifndef _WIN32
    if (parent_watchdog_started) {
        cbm_thread_join(&parent_watchdog_tid);
    }
#endif

    if (http_started) {
        cbm_http_server_stop(g_http_server);
        cbm_thread_join(&http_tid);
        cbm_http_server_free(g_http_server);
        g_http_server = NULL;
    }

    if (watcher_started) {
        cbm_watcher_stop(g_watcher);
        cbm_thread_join(&watcher_tid);
    }
    cbm_watcher_free(g_watcher);
    cbm_store_close_required(&watch_store, "main.watch_store.complete");
    cbm_mcp_server_free(g_server);
    cbm_config_close(runtime_config);

    g_watcher = NULL;
    g_server = NULL;
    cbm_diag_stop();

    return rc;
}
