/*
 * index_supervisor.c — see index_supervisor.h.
 */
#include "index_supervisor.h"

#include "foundation/compat.h"    /* cbm_setenv, cbm_unsetenv */
#include "foundation/compat_fs.h" /* cbm_mkdir_p, cbm_fopen */
#include "foundation/log.h"
#include "foundation/platform.h" /* cbm_resolve_cache_dir */
#include "foundation/profile.h"  /* cbm_profile_active (keep worker log under CBM_PROFILE) */
#include "ui/http_server.h"      /* cbm_http_server_resolve_binary_path */
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

void cbm_index_set_worker_role(bool is_worker, const char *response_out) {
    g_worker_active = is_worker;
    if (response_out && response_out[0]) {
        snprintf(g_worker_response_out, sizeof(g_worker_response_out), "%s", response_out);
    } else {
        g_worker_response_out[0] = '\0';
    }
}

bool cbm_index_worker_active(void) {
    return g_worker_active;
}

const char *cbm_index_worker_response_out(void) {
    return g_worker_response_out[0] ? g_worker_response_out : NULL;
}

/* #845: opt-in host mark — see the header. Set once from the real binary's
 * main(); embedders never set it, so should_wrap() stays false for them. */
static bool g_host_marked = false;

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

/* Quiet-timeout (ms) for a supervised worker: killed + reported as a hang if it
 * emits no NEW log line within the window. This is a NO-PROGRESS timeout — every
 * completed log line the worker tails (per-batch parallel.extract.progress every
 * 10 files, plus each pass boundary) resets it — NOT a total-time cap, so a large
 * repo that keeps making progress is never falsely killed. Default: 15 min (a
 * genuinely stuck file emits nothing, so this fires only on a real hang). */
static int worker_quiet_timeout_ms(void) {
    enum { DEFAULT_QUIET_TIMEOUT_MS = 900000 }; /* 15 min with no progress */
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

    char self[1024] = {0};
    if (!cbm_http_server_resolve_binary_path(NULL, self, sizeof(self)) || !self[0]) {
        cbm_log_error("index.supervisor.no_self_path", "action", "fail_closed");
        return -1;
    }

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
    int resp_len = snprintf(resp_path, sizeof(resp_path), "%s/response.json", workspace);
    int log_len = snprintf(log_path, sizeof(log_path), "%s/worker.log", workspace);
    int args_len = snprintf(args_path, sizeof(args_path), "%s/args.json", workspace);
    if (resp_len < 0 || (size_t)resp_len >= sizeof(resp_path) || log_len < 0 ||
        (size_t)log_len >= sizeof(log_path) || args_len < 0 ||
        (size_t)args_len >= sizeof(args_path)) {
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

    /* No --progress: the worker's DEFAULT structured logging already provides the
     * no-progress heartbeat (INFO parallel.extract.progress every 10 files + each
     * pass boundary — all newline-terminated → tailed → reset the quiet-timeout).
     * --progress would be strictly worse here: it installs a REPLACE-mode sink that
     * suppresses those default lines and emits per-file extraction as a carriage-
     * return in-place update (no trailing '\n'), which cbm_tail_log does not count
     * as progress. (It would not corrupt the response either — that goes to the
     * separate --response-out file, not stdout.) */
    const char *argv[10];
    int n = 0;
    argv[n++] = self;
    argv[n++] = "cli";
    argv[n++] = "--index-worker";
    argv[n++] = "index_repository";
    argv[n++] = "--args-file";
    argv[n++] = args_path;
    argv[n++] = "--response-out";
    argv[n++] = resp_path;
    argv[n] = NULL;

    cbm_proc_opts_t opts = {0};
    opts.bin = self;
    opts.argv = argv;
    opts.log_file = log_path;
    opts.quiet_timeout_ms = worker_quiet_timeout_ms();
    /* We manage log deletion ourselves after reaping (below): keep it on failure
     * for post-mortem, delete it only on a clean run. See the observability
     * note at the reap site. */
    opts.delete_log_on_exit = false;

    cbm_proc_result_t r;
    int run_rc = cbm_subprocess_run(&opts, &r);

    if (run_rc != 0) {
        (void)cbm_unlink(resp_path);
        (void)cbm_unlink(args_path);
        (void)cbm_unlink(log_path); /* empty/partial log from a failed spawn — nothing to keep */
        (void)cbm_rmdir(workspace);
        cbm_log_error("index.supervisor.spawn_failed", "code", "CBM_INDEX_WORKER_SPAWN_FAILED",
                      "message", "the isolated index worker could not be started", "remediation",
                      "inspect process-creation and worker-log diagnostics before retrying");
        return -1;
    }

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
        (void)cbm_unlink(log_path);
        (void)cbm_rmdir(workspace);
    } else if (r.outcome == CBM_PROC_CLEAN) {
        cbm_log_info("index.supervisor.profile_log", "log", log_path);
    } else {
        result->log_path = cbm_strdup(log_path);
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
    }
}
