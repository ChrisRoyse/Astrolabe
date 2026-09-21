/*
 * index_supervisor.c — see index_supervisor.h.
 */
#include "index_supervisor.h"

#include "foundation/compat.h"    /* cbm_setenv, cbm_unsetenv */
#include "foundation/compat_fs.h" /* cbm_mkdir_p, cbm_fopen */
#include "foundation/log.h"
#include "foundation/platform.h" /* cbm_resolve_cache_dir */
#include "foundation/profile.h"  /* cbm_profile_active (keep worker log under CBM_PROFILE) */
#include "foundation/sha256.h"
#include "foundation/worker_progress.h"
#include "ui/http_server.h"      /* exact configured worker binary */
#include <yyjson/yyjson.h>

#ifdef ASTRO_ENV_STORE
/* #252: the in-process FFI store override (cbm_astro_set_cache_dir) that
 * cbm_resolve_cache_dir() consults is process-local — it is NOT inherited across
 * the boundary to a spawned index worker, which resolves its own store fresh. We
 * propagate the configured store to the child through the #240-sanctioned
 * CBM_CACHE_DIR env channel. Only compiled into libcbm (where ASTRO_ENV_STORE is
 * defined and -I$(ASTROLABE_PATCH_DIR) is on the include path); the CRT test build
 * does not define ASTRO_ENV_STORE, exactly like platform.c's guarded include. */
#include "env_store_config.h" /* cbm_astro_cache_dir_override, cbm_astro_env_record_fault */
#endif

#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h> /* _getpid */
#define cbm_getpid _getpid
#else
#include <unistd.h> /* getpid */
#define cbm_getpid getpid
#endif

/* ── Worker-role state ────────────────────────────────────────────── */

static bool g_worker_active = false;
static char g_worker_response_out[1024] = {0};
static char g_transition_writer_project[256] = {0};

int cbm_index_set_worker_role(bool is_worker, const char *response_out,
                              const char *progress_out, const char *progress_attempt) {
    bool has_progress_out = progress_out && progress_out[0];
    bool has_progress_attempt = progress_attempt && progress_attempt[0];
    if (!is_worker) {
        if (has_progress_out || has_progress_attempt) {
            cbm_log_error("index.worker.role_invalid", "code",
                          "CBM_INDEX_WORKER_PROGRESS_ROLE_INVALID", "message",
                          "semantic-progress arguments require the private worker role",
                          "remediation", "remove private worker arguments from ordinary CLI use");
            return -1;
        }
        cbm_worker_progress_reset();
        g_worker_active = false;
        g_worker_response_out[0] = '\0';
        return 0;
    }
    if (has_progress_out != has_progress_attempt) {
        cbm_log_error("index.worker.role_invalid", "code",
                      "CBM_INDEX_WORKER_PROGRESS_CONFIGURATION_MISSING", "message",
                      "the supervised worker has an incomplete semantic-progress binding",
                      "remediation", "start the worker only through its index supervisor");
        return -1;
    }
    if (has_progress_out) {
        if (cbm_worker_progress_configure(progress_out, progress_attempt) != 0 ||
            cbm_worker_progress_publish(CBM_WORKER_PROGRESS_STAGE_STARTUP, "startup", 1, 1, 1,
                                        "configured", 1, 1) != 0) {
            cbm_worker_progress_reset();
            return -1;
        }
    }
    g_worker_active = true;
    if (response_out && response_out[0]) {
        snprintf(g_worker_response_out, sizeof(g_worker_response_out), "%s", response_out);
    } else {
        g_worker_response_out[0] = '\0';
    }
    return 0;
}

void cbm_index_set_transition_writer_project(const char *project) {
    if (project && project[0]) {
        snprintf(g_transition_writer_project, sizeof(g_transition_writer_project), "%s", project);
    } else {
        g_transition_writer_project[0] = '\0';
    }
}

bool cbm_index_transition_writer_matches(const char *project) {
    return g_worker_active && project && project[0] && g_transition_writer_project[0] &&
           strcmp(g_transition_writer_project, project) == 0;
}

bool cbm_index_worker_active(void) {
    return g_worker_active;
}

const char *cbm_index_worker_response_out(void) {
    return g_worker_response_out[0] ? g_worker_response_out : NULL;
}

int cbm_index_worker_progress_complete(void) {
    return cbm_worker_progress_complete();
}

/* #845: opt-in host mark — see the header. Set once from the real binary's
 * main(); embedders never set it, so should_wrap() stays false for them. */
static bool g_host_marked = false;
static atomic_bool g_supervisor_cancel_requested = false;

void cbm_index_supervisor_mark_host(void) {
    g_host_marked = true;
}

bool cbm_index_supervisor_should_wrap(void) {
    if (!g_host_marked) {
        return false; /* embedder (#845): never spawn `<self> cli --index-worker` */
    }
    if (g_worker_active) {
        return false; /* I am the worker — run in-process, never re-supervise */
    }
    return true;
}

void cbm_index_supervisor_request_cancel(void) {
    atomic_store_explicit(&g_supervisor_cancel_requested, true, memory_order_release);
}

static bool supervisor_cancel_requested(void *ud) {
    (void)ud;
    return atomic_load_explicit(&g_supervisor_cancel_requested, memory_order_acquire);
}

/* Quiet-timeout (ms) for a supervised worker. Only a validated forward cursor
 * from the request-owned semantic progress stream resets this no-progress
 * budget; operational log level and log delivery are deliberately irrelevant.
 * This is not a total-time cap. */
static int worker_quiet_timeout_ms(void) {
    enum { DEFAULT_QUIET_TIMEOUT_MS = 900000 }; /* 15 min with no progress */
    _Static_assert(DEFAULT_QUIET_TIMEOUT_MS >=
                       2 * CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS,
                   "semantic report interval must stay below the no-progress budget");
    return DEFAULT_QUIET_TIMEOUT_MS;
}

#ifdef ASTRO_WORKER_DIAG
/* #282: bound on the worker-log excerpt carried in the failure result. The
 * panic/abort text lands at the END of the log, so a tail keeps it. */
enum { CBM_WORKER_LOG_TAIL_MAX = 2048 };

/* Read the last max_bytes of a file into a heap string (NUL-terminated).
 * NULL on error or empty file. */
static char *slurp_file_tail(const char *path, size_t max_bytes) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size <= 0) {
        (void)fclose(f);
        return NULL;
    }
    size_t want = (size_t)size > max_bytes ? max_bytes : (size_t)size;
    if (fseek(f, (long)((size_t)size - want), SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    char *buf = malloc(want + 1);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, want, f);
    (void)fclose(f);
    buf[rd] = '\0';
    return buf;
}
#endif

/* Read an entire file into a heap string (NUL-terminated). NULL on error. */
/* Write `data` to `path` whole, atomically enough for a single-consumer worker
 * handoff (fresh file, fully written + flushed before the child is spawned).
 * Returns 0 on success, -1 on any open/write failure. */
static int write_file_all(const char *path, const char *data) {
    FILE *f = cbm_fopen(path, "wb");
    if (!f) {
        return -1;
    }
    size_t len = strlen(data);
    size_t wrote = fwrite(data, 1, len, f);
    int flush_rc = fflush(f);
    int close_rc = fclose(f);
    if (wrote != len || flush_rc != 0 || close_rc != 0) {
        (void)cbm_unlink(path);
        return -1;
    }
    return 0;
}

static char *slurp_file(const char *path) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        (void)fclose(f);
        return NULL;
    }
    (void)fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)n, f);
    (void)fclose(f);
    buf[rd] = '\0';
    return buf;
}

/* Atomically create one request-owned workspace. A host PID is not a request
 * identity: the MCP server can supervise concurrent indexing calls. */
static int worker_tmp_dir(char *out, size_t out_sz, int pid) {
    const char *cdir = cbm_resolve_cache_dir();
    if (cdir && cdir[0]) {
        char dir[900];
        int dir_len = snprintf(dir, sizeof(dir), "%s/logs", cdir);
        if (dir_len < 0 || (size_t)dir_len >= sizeof(dir) || !cbm_mkdir_p(dir, 0755)) {
            return -1;
        }
        int path_len = snprintf(out, out_sz, "%s/.worker-%d-XXXXXX", dir, pid);
        if (path_len < 0 || (size_t)path_len >= out_sz) {
            return -1;
        }
    } else {
        int path_len = snprintf(out, out_sz, ".worker-%d-XXXXXX", pid);
        if (path_len < 0 || (size_t)path_len >= out_sz) {
            return -1;
        }
    }
    return cbm_mkdtemp(out, out_sz) ? 0 : -1;
}

static cbm_proc_progress_result_t worker_progress_poll(bool terminal, void *ud) {
    cbm_worker_progress_reader_t *reader = (cbm_worker_progress_reader_t *)ud;
    cbm_worker_progress_poll_result_t result =
        cbm_worker_progress_reader_poll(reader, terminal);
    if (result == CBM_WORKER_PROGRESS_POLL_ADVANCED) {
        return CBM_PROC_PROGRESS_ADVANCED;
    }
    if (result == CBM_WORKER_PROGRESS_POLL_IDLE) {
        return CBM_PROC_PROGRESS_IDLE;
    }
    return CBM_PROC_PROGRESS_INVALID;
}

#ifdef ASTRO_ENV_STORE
/* Bind the process-local store override into this request's private transport.
 * The Rust worker applies and reads it back before stripping it from the public
 * tool arguments. No process-global environment mutation is involved. */
static char *worker_args_bind_store(const char *args_json) {
    const char *store_override = cbm_astro_cache_dir_override();
    if (!store_override || !store_override[0]) {
        return cbm_strdup(args_json);
    }
    yyjson_doc *doc = yyjson_read(args_json, strlen(args_json), 0);
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    if (!root || !yyjson_is_obj(root)) {
        if (doc) {
            yyjson_doc_free(doc);
        }
        cbm_log_error("index.supervisor.args_bind", "code", "CBM_INDEX_WORKER_ARGS_INVALID",
                      "message", "worker arguments are not a JSON object", "remediation",
                      "submit a valid index_repository JSON object");
        return NULL;
    }
    static const char PRIVATE_CACHE_ARG[] = "_astrolabe_worker_cache_dir";
    yyjson_val *existing = yyjson_obj_get(root, PRIVATE_CACHE_ARG);
    if (existing) {
        bool valid = yyjson_is_str(existing) && yyjson_get_str(existing)[0];
        char *copy = valid ? cbm_strdup(args_json) : NULL;
        yyjson_doc_free(doc);
        if (!copy) {
            cbm_log_error("index.supervisor.args_bind", "code",
                          "CBM_INDEX_WORKER_CACHE_BINDING_INVALID", "message",
                          "reserved worker cache binding is not a non-empty string", "remediation",
                          "remove the reserved field and retry through the Astrolabe host");
        }
        return copy;
    }
    yyjson_mut_doc *mutable_doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *mutable_root = mutable_doc ? yyjson_val_mut_copy(mutable_doc, root) : NULL;
    yyjson_doc_free(doc);
    if (!mutable_doc || !mutable_root) {
        if (mutable_doc) {
            yyjson_mut_doc_free(mutable_doc);
        }
        return NULL;
    }
    yyjson_mut_doc_set_root(mutable_doc, mutable_root);
    if (!yyjson_mut_obj_add_strcpy(mutable_doc, mutable_root, PRIVATE_CACHE_ARG, store_override)) {
        yyjson_mut_doc_free(mutable_doc);
        return NULL;
    }
    char *bound = yyjson_mut_write(mutable_doc, 0, NULL);
    yyjson_mut_doc_free(mutable_doc);
    return bound;
}
#endif /* ASTRO_ENV_STORE */

int cbm_index_spawn_worker(const char *args_json, cbm_index_worker_result_t *result) {
    result->outcome = CBM_PROC_SPAWN_FAILED;
    result->exit_code = -1;
    result->term_signal = 0;
    result->response = NULL;
    result->log_tail = NULL;
    result->log_path = NULL;
    result->progress_path = NULL;
    result->progress_error_code = NULL;
    result->progress_error_detail = NULL;
    result->progress_stage = NULL;
    result->progress_record_count = 0;
    result->progress_completed = 0;
    result->progress_total = 0;

    if (supervisor_cancel_requested(NULL)) {
        result->outcome = CBM_PROC_CANCELLED;
        return 0;
    }

    const cbm_worker_binary_status_t binary_status = CBM_WORKER_BINARY_UNBOUND;
    const char *self = cbm_http_server_binary_path();
    if (!self) {
        result->progress_error_code =
            cbm_strdup(cbm_http_server_binary_status_code(binary_status));
        result->progress_error_detail =
            cbm_strdup(cbm_http_server_binary_status_message(binary_status));
        cbm_log_error("index.supervisor.binary_path", "code",
                      cbm_http_server_binary_status_code(binary_status), "message",
                      cbm_http_server_binary_status_message(binary_status), "remediation",
                      cbm_http_server_binary_status_remediation(binary_status));
        return -1;
    }
    cbm_log_info("index.supervisor.binary_path", "path", self, "source", "configured_exact");

    int pid = (int)cbm_getpid();
    char workspace[1024];
    if (worker_tmp_dir(workspace, sizeof(workspace), pid) != 0) {
        cbm_log_error("index.supervisor.workspace", "code",
                      "CBM_INDEX_WORKER_WORKSPACE_CREATE_FAILED", "message",
                      "could not atomically create a request-owned worker workspace", "remediation",
                      "inspect the configured store logs directory permissions and retry");
        return -1;
    }
    char resp_path[1200];
    char log_path[1200];
    char args_path[1200];
    char progress_path[1200];
    int resp_len = snprintf(resp_path, sizeof(resp_path), "%s/response.json", workspace);
    int log_len = snprintf(log_path, sizeof(log_path), "%s/worker.log", workspace);
    int args_len = snprintf(args_path, sizeof(args_path), "%s/args.json", workspace);
    int progress_len =
        snprintf(progress_path, sizeof(progress_path), "%s/progress.bin", workspace);
    if (resp_len < 0 || (size_t)resp_len >= sizeof(resp_path) || log_len < 0 ||
        (size_t)log_len >= sizeof(log_path) || args_len < 0 ||
        (size_t)args_len >= sizeof(args_path) || progress_len < 0 ||
        (size_t)progress_len >= sizeof(progress_path)) {
        (void)cbm_rmdir(workspace);
        cbm_log_error("index.supervisor.workspace", "code",
                      "CBM_INDEX_WORKER_WORKSPACE_PATH_FAILED", "message",
                      "worker artifact path exceeds the representable path buffer", "remediation",
                      "shorten the configured cache directory and retry");
        return -1;
    }

    /* Hand the tool JSON to the worker via --args-file, the public CLI argument
     * contract. A raw-JSON argv token is REFUSED fail-closed by the Rust host
     * (ASTRO_CLI_RAW_JSON_ARGV_REMOVED, #378), so passing args_json inline made
     * every supervised worker exit 1 before indexing anything (#405 FSV). The
     * file lives beside the response/log worker tmp files and is removed at the
     * same cleanup points. */
    char *worker_args = NULL;
#ifdef ASTRO_ENV_STORE
    worker_args = worker_args_bind_store(args_json);
#else
    worker_args = cbm_strdup(args_json);
#endif
    if (!worker_args || write_file_all(args_path, worker_args) != 0) {
        free(worker_args);
        (void)cbm_unlink(args_path);
        (void)cbm_rmdir(workspace);
        cbm_log_warn("index.supervisor.args_write_failed", "path", args_path);
        return -1;
    }
    free(worker_args);

    /* The workspace name was created atomically for this one request. Its digest
     * is the exact parent-generated attempt identity carried in every progress
     * record; it is an identity token, not a security primitive. */
    char progress_attempt[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(workspace, strlen(workspace), progress_attempt);
    cbm_worker_progress_reader_t *progress_reader =
        cbm_worker_progress_reader_new(progress_path, progress_attempt);
    if (!progress_reader) {
        (void)cbm_unlink(args_path);
        (void)cbm_rmdir(workspace);
        cbm_log_error("index.supervisor.progress_reader", "code",
                      "CBM_INDEX_WORKER_PROGRESS_READER_CREATE_FAILED", "message",
                      "the request-owned semantic progress reader could not be created",
                      "remediation", "free memory or shorten the configured cache path and retry");
        return -1;
    }

    /* Operational logging remains independent observability. Only the validated
     * private progress stream below can reset the no-progress budget. */
    const char *argv[14];
    int n = 0;
    argv[n++] = self;
    argv[n++] = "cli";
    argv[n++] = "--index-worker";
    argv[n++] = "index_repository";
    argv[n++] = "--args-file";
    argv[n++] = args_path;
    argv[n++] = "--response-out";
    argv[n++] = resp_path;
    argv[n++] = "--worker-progress-out";
    argv[n++] = progress_path;
    argv[n++] = "--worker-progress-attempt";
    argv[n++] = progress_attempt;
    argv[n] = NULL;

    cbm_proc_opts_t opts = {0};
    opts.bin = self;
    opts.argv = argv;
    opts.log_file = log_path;
    opts.on_progress = worker_progress_poll;
    opts.progress_ud = progress_reader;
    opts.should_cancel = supervisor_cancel_requested;
    opts.quiet_timeout_ms = worker_quiet_timeout_ms();
    /* We manage log deletion ourselves after reaping (below): keep it on failure
     * for post-mortem, delete it only on a clean run. See the observability
     * note at the reap site. */
    opts.delete_log_on_exit = false;

    cbm_proc_result_t r;
    int run_rc = cbm_subprocess_run(&opts, &r);

    if (run_rc != 0) {
        cbm_worker_progress_reader_free(progress_reader);
        (void)cbm_unlink(resp_path);
        (void)cbm_unlink(args_path);
        (void)cbm_unlink(progress_path);
        (void)cbm_unlink(log_path); /* empty/partial log from a failed spawn — nothing to keep */
        (void)cbm_rmdir(workspace);
        cbm_log_error("index.supervisor.spawn_failed", "code", "CBM_INDEX_WORKER_SPAWN_FAILED",
                      "message", "the isolated index worker could not be started", "remediation",
                      "inspect process-creation and worker-log diagnostics before retrying");
        return -1;
    }

    const char *progress_error_code =
        cbm_worker_progress_reader_error_code(progress_reader);
    const char *progress_error_detail =
        cbm_worker_progress_reader_error_detail(progress_reader);
    const char *progress_stage = cbm_worker_progress_reader_stage(progress_reader);
    result->progress_record_count =
        cbm_worker_progress_reader_record_count(progress_reader);
    result->progress_completed = cbm_worker_progress_reader_completed(progress_reader);
    result->progress_total = cbm_worker_progress_reader_total(progress_reader);
    bool result_bearing_exit =
        r.outcome == CBM_PROC_CLEAN || r.outcome == CBM_PROC_EXIT_NONZERO;
    if (result_bearing_exit && !cbm_worker_progress_reader_complete(progress_reader)) {
        r.outcome = CBM_PROC_PROGRESS_FAILED;
        progress_error_code = "CBM_INDEX_WORKER_PROGRESS_COMPLETION_MISSING";
        progress_error_detail =
            "the worker exited normally without its exact terminal semantic-progress record";
    }
    result->progress_error_code =
        progress_error_code ? cbm_strdup(progress_error_code) : NULL;
    result->progress_error_detail =
        progress_error_detail ? cbm_strdup(progress_error_detail) : NULL;
    result->progress_stage = progress_stage ? cbm_strdup(progress_stage) : NULL;
    cbm_worker_progress_reader_free(progress_reader);

    result->outcome = r.outcome;
    result->exit_code = r.exit_code;
    result->term_signal = r.term_signal;
    /* Read the response file on EVERY outcome, not only CLEAN. A valid MCP tool
     * execution error is fully written and closed before the CLI intentionally exits 1;
     * the MCP layer validates both facts before preserving that response. A
     * crash/hang/malformed response remains a process failure. */
    result->response = slurp_file(resp_path);
#ifdef ASTRO_WORKER_DIAG
    if (r.outcome != CBM_PROC_CLEAN) {
        /* #282 (attempt 15): the worker's panic/abort text goes only to its
         * log, which lives under a run-scoped dir the gate wipes — carry a
         * bounded tail in the result so the failure artifact names the
         * defect even after cleanup. The on-disk log is still kept below. */
        result->log_tail = slurp_file_tail(log_path, CBM_WORKER_LOG_TAIL_MAX);
    }
#endif
    (void)cbm_unlink(resp_path);
    (void)cbm_unlink(args_path);

    char sig[16];
    char exit_buf[16];
    snprintf(sig, sizeof(sig), "%d", r.term_signal);
    snprintf(exit_buf, sizeof(exit_buf), "%d", r.exit_code);
    cbm_log_info("index.supervisor.reap", "outcome", cbm_proc_outcome_str(r.outcome), "exit_code",
                 exit_buf, "signal", sig);

    /* Observability: a CLEAN response retains its complete phase metrics, so
     * the redundant worker log can be deleted without losing the performance
     * trail. On ANY failure keep it and surface its path + raw exit code, so the
     * worker's own stdout/stderr (pipeline logs, any assert/abort text, the exact
     * exit code) is available post-mortem instead of vanishing. Previously the
     * log was ALWAYS deleted and only outcome+signal were logged, so a worker
     * that exited non-zero left nothing to diagnose (a mangled JSON
     * arg → "repo_path is required" exit) behind a generic "crashed on a file".
     *
     * Exception: under CBM_PROFILE the log IS the deliverable — the worker's
     * msg=prof pass/sub-phase report is only written there, and deleting it on
     * success made profiling clean runs impossible. Keep it and say where it is. */
    if (r.outcome == CBM_PROC_CLEAN && !cbm_profile_active) {
        (void)cbm_unlink(progress_path);
        (void)cbm_unlink(log_path);
        (void)cbm_rmdir(workspace);
    } else if (r.outcome == CBM_PROC_CLEAN) {
        (void)cbm_unlink(progress_path);
        cbm_log_info("index.supervisor.profile_log", "log", log_path);
    } else {
        result->log_path = cbm_strdup(log_path);
        result->progress_path = cbm_strdup(progress_path);
        cbm_log_warn("index.supervisor.worker_failed", "outcome", cbm_proc_outcome_str(r.outcome),
                     "exit_code", exit_buf, "log", log_path);
    }
    return 0;
}

void cbm_index_worker_result_free(cbm_index_worker_result_t *result) {
    if (result) {
        free(result->response);
        result->response = NULL;
        free(result->log_tail);
        result->log_tail = NULL;
        free(result->log_path);
        result->log_path = NULL;
        free(result->progress_path);
        result->progress_path = NULL;
        free(result->progress_error_code);
        result->progress_error_code = NULL;
        free(result->progress_error_detail);
        result->progress_error_detail = NULL;
        free(result->progress_stage);
        result->progress_stage = NULL;
    }
}
