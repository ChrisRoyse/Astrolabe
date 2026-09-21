/*
 * http_server.c — Routing + endpoint handlers for the graph UI.
 *
 * Transport (sockets, parsing, limits) lives in httpd.c; this file owns
 * the routes and their handlers:
 *   GET /             → embedded index.html
 *   GET /assets/...   → embedded JS/CSS
 *   POST /rpc         → JSON-RPC dispatch via own cbm_mcp_server_t
 *   OPTIONS /rpc      → CORS preflight (for vite dev on :5173)
 *   GET/POST /api/... → UI support endpoints (layout, index, browse, …)
 *   *                 → 404
 *
 * Runs in a background pthread. Binds to 127.0.0.1 only (see httpd.c).
 * Has its own cbm_mcp_server_t with a separate SQLite connection (WAL reader).
 */
#include "ui/http_server.h"
#include "ui/httpd.h"
#include "ui/embedded_assets.h"
#include "ui/layout3d.h"
#include "mcp/mcp.h"
#include "store/store.h"
#include "watcher/watcher.h"
#include "cli/cli.h"
#include "git/git_context.h"

#if defined(HAVE_LIBGIT2)
#include <git2.h> /* git_repository_open, git_remote_lookup, git_remote_url */
#endif
/* pipeline.h no longer needed — indexing runs as subprocess */
#include "foundation/log.h"
#include "foundation/platform.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/str_util.h"
#include "foundation/compat_thread.h"
#include "foundation/subprocess.h" /* cbm_subprocess_run — the one long-path-safe spawn (#426) */
#ifdef _WIN32
#include "foundation/win_utf8.h"
#endif

#include <sqlite3/sqlite3.h>
#include <yyjson/yyjson.h>

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <psapi.h> /* GetProcessMemoryInfo */
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* ── Constants ────────────────────────────────────────────────── */

/* Max JSON-RPC request body size (1 MB) — transport enforces the same cap. */
#define MAX_BODY_SIZE CBM_HTTP_MAX_BODY

/* ── CORS: only allow localhost origins (blocks remote website attacks) ────── */

/* Per-request CORS header buffers. Updated at the start of each dispatch.
 * The server handles requests sequentially on one thread (see httpd.h),
 * which makes these statics safe. */
static char g_cors[256];      /* CORS headers only */
static char g_cors_json[512]; /* CORS + Content-Type: application/json */

/* Inspect the Origin header and only reflect it if it's a localhost URL.
 * This prevents remote websites from making cross-origin requests to the
 * local graph-ui server (the key defense against CORS-based data exfil). */
static void update_cors(const cbm_http_req_t *req) {
    if (req->origin[0] != '\0' && (cbm_http_path_match(req->origin, "http://localhost:*") ||
                                   cbm_http_path_match(req->origin, "http://127.0.0.1:*"))) {
        snprintf(g_cors, sizeof(g_cors),
                 "Access-Control-Allow-Origin: %s\r\n"
                 "Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS\r\n"
                 "Access-Control-Allow-Headers: Content-Type\r\n",
                 req->origin);
    } else {
        /* No Access-Control-Allow-Origin → browser blocks cross-origin access */
        snprintf(g_cors, sizeof(g_cors),
                 "Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS\r\n"
                 "Access-Control-Allow-Headers: Content-Type\r\n");
    }
    snprintf(g_cors_json, sizeof(g_cors_json), "%sContent-Type: application/json\r\n", g_cors);
}

static const char *detect_ui_lang(const char *accept_language) {
    if (accept_language && (strstr(accept_language, "zh-CN") || strstr(accept_language, "zh"))) {
        return "zh";
    }
    return "en";
}

static void handle_ui_config(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    const char *lang = NULL;
    char cache_dir[1024];
#ifdef ASTRO_ENV_STORE
    /* #241: this site passed cbm_resolve_cache_dir() straight to "%s" with no NULL
     * check at all. The resolver returns NULL whenever the store cannot be
     * resolved, which is undefined behaviour here. Serve the detected language
     * from the request instead of dereferencing NULL. */
    const char *resolved = cbm_resolve_cache_dir();
    cbm_config_t *cfg = NULL;
    if (resolved) {
        snprintf(cache_dir, sizeof(cache_dir), "%s", resolved);
        cfg = cbm_config_open(cache_dir);
    }
#else
    snprintf(cache_dir, sizeof(cache_dir), "%s", cbm_resolve_cache_dir());
    cbm_config_t *cfg = cbm_config_open(cache_dir);
#endif
    if (cfg) {
        const char *pinned = cbm_config_get(cfg, CBM_CONFIG_UI_LANG, "auto");
        if (strcmp(pinned, "zh") == 0 || strcmp(pinned, "en") == 0) {
            lang = pinned;
        }
    }

    char lang_buf[8];
    snprintf(lang_buf, sizeof(lang_buf), "%s", lang ? lang : detect_ui_lang(req->accept_language));
    if (cfg) {
        cbm_config_close(cfg);
    }
    cbm_http_replyf(c, 200, g_cors_json, "{\"lang\":\"%s\"}", lang_buf);
}

/* ── Server state ─────────────────────────────────────────────── */

struct cbm_http_server {
    cbm_httpd_t *listener;
    cbm_mcp_server_t *mcp;       /* own MCP server instance (read-only) */
    struct cbm_watcher *watcher; /* external watcher ref (not owned) */
    atomic_int stop_flag;
    int port;
    bool listener_ok;
};

/* ── Forward declarations for process-kill PID validation ──────── */

#define MAX_INDEX_JOBS 4

typedef struct {
    char root_path[1024];
    char project_name[256];
    int slot;
    unsigned int run_id;
    atomic_int status; /* 0=idle, 1=running, 2=done, 3=error */
    char error_msg[256];
#ifndef _WIN32
    pid_t child_pid; /* tracked for process-kill validation */
#endif
} index_job_t;

static index_job_t g_index_jobs[MAX_INDEX_JOBS];
static atomic_uint g_index_job_run_seq;

/* ── Serve embedded asset ─────────────────────────────────────── */

/* Content-Security-Policy for the served UI. No external host appears in any
 * directive, so the browser cannot load or connect to anything off-origin —
 * this ENFORCES the airgap (the code makes no external calls; this stops a
 * future dependency or injected content from doing so). connect-src 'self'
 * confines fetch/XHR/WebSocket to the local server. The 'self'/data:/blob:/
 * 'unsafe-inline'-style/'wasm-unsafe-eval' allowances cover the bundled app's
 * own needs (React inline styles, three.js textures/workers/WASM). */
#define CBM_UI_CSP                                                       \
    "Content-Security-Policy: default-src 'self'; connect-src 'self'; "  \
    "img-src 'self' data: blob:; script-src 'self' 'wasm-unsafe-eval'; " \
    "style-src 'self' 'unsafe-inline'; font-src 'self' data:; "          \
    "worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n"

static bool serve_embedded(cbm_http_conn_t *c, const char *path) {
    const cbm_embedded_file_t *f = cbm_embedded_lookup(path);
    if (!f)
        return false;

    /* Build headers with correct Content-Type for this asset */
    char hdrs[1024];
    snprintf(hdrs, sizeof(hdrs),
             "%sContent-Type: %s\r\n"
             "Cache-Control: public, max-age=31536000, immutable\r\n" CBM_UI_CSP,
             g_cors, f->content_type);

    cbm_http_reply_buf(c, 200, hdrs, f->data, (size_t)f->size);
    return true;
}

/* Build DB path for a project: <cache_dir>/<project>.db */
static void db_path_for_project(const char *project, char *buf, size_t bufsz) {
    if (!cbm_validate_project_name(project)) {
        buf[0] = '\0';
        return;
    }
    const char *dir = cbm_resolve_cache_dir();
    if (!dir) {
        dir = cbm_tmpdir();
    }
    snprintf(buf, bufsz, "%s/%s.db", dir, project);
}

/* ── Git remote → GitHub deep-link base (/api/repo-info) ───────── */

/* Return a copy of `url` with any "user[:password]@" userinfo removed from the
 * scheme://authority form, so credentials are never echoed back to the client.
 * scp-style (git@host:path) is returned unchanged: "git" there is a login name,
 * not a secret. malloc'd copy, or NULL when url is NULL. Caller frees. */
char *cbm_ui_git_strip_credentials(const char *url) {
    if (!url)
        return NULL;
    const char *sep = strstr(url, "://");
    if (!sep)
        return strdup(url); /* scp-style / opaque — no scheme userinfo to strip */
    const char *authority = sep + 3;
    const char *slash = strchr(authority, '/');
    const char *at = strchr(authority, '@');
    if (!at || (slash && at > slash))
        return strdup(url); /* '@' is in the path, not the authority → no creds */
    size_t prefix = (size_t)(authority - url); /* "scheme://" */
    const char *rest = at + 1;
    size_t out_len = prefix + strlen(rest) + 1;
    char *out = malloc(out_len);
    if (!out)
        return NULL;
    memcpy(out, url, prefix);
    memcpy(out + prefix, rest, strlen(rest) + 1);
    return out;
}

/* Normalize a git remote URL (scp-style, ssh://, https://) to a canonical
 * "https://host/org/repo" web base with any trailing ".git" and any embedded
 * credentials removed. Returns a malloc'd string or NULL if the shape isn't
 * recognized. Caller frees. */
char *cbm_ui_git_web_base(const char *url) {
    if (!url || !url[0])
        return NULL;
    char host_path[1024] = {0}; /* "host/org/repo" */
    if (strncmp(url, "git@", 4) == 0) {
        const char *at = url + 4;
        const char *colon = strchr(at, ':');
        if (!colon)
            return NULL;
        snprintf(host_path, sizeof(host_path), "%.*s/%s", (int)(colon - at), at, colon + 1);
    } else {
        const char *p = strstr(url, "://");
        if (!p)
            return NULL;
        p += 3;
        const char *at = strchr(p, '@'); /* strip any embedded credentials */
        if (at)
            p = at + 1;
        snprintf(host_path, sizeof(host_path), "%s", p);
    }
    size_t l = strlen(host_path);
    if (l > 4 && strcmp(host_path + l - 4, ".git") == 0)
        host_path[l - 4] = '\0';
    l = strlen(host_path);
    if (l > 0 && host_path[l - 1] == '/')
        host_path[l - 1] = '\0';
    size_t out_sz = strlen(host_path) + 9; /* "https://" (8) + NUL */
    char *out = malloc(out_sz);
    if (!out)
        return NULL;
    /* Legitimate GitHub blob-URL construction, not a network call — the scheme
     * is https-forced here so the frontend deep-link can never be downgraded.
     * Allow-listed in scripts/security-allowlist.txt (URL:https://%s). */
    snprintf(out, out_sz, "https://%s", host_path);
    return out;
}

/* Read the "origin" remote URL for the repo at root_path. malloc'd or NULL.
 * libgit2 is initialized once at process start by cbm_alloc_init() (which also
 * binds its allocator to mimalloc) — do NOT git_libgit2_init()/shutdown() here:
 * a per-request shutdown could drop the global refcount and tear down that
 * allocator binding mid-process. */
static char *git_origin_remote_url(const char *root_path) {
#if defined(HAVE_LIBGIT2)
    git_repository *repo = NULL;
    char *out = NULL;
    if (git_repository_open(&repo, root_path) == 0) {
        git_remote *rem = NULL;
        if (git_remote_lookup(&rem, repo, "origin") == 0) {
            const char *u = git_remote_url(rem);
            if (u)
                out = strdup(u);
            git_remote_free(rem);
        }
        git_repository_free(repo);
    }
    return out;
#else
    (void)root_path;
    return NULL;
#endif
}

/* GET /api/repo-info?project=NAME → { root_path, branch, remote_url, web_base,
 * blob_base }. blob_base is "<web_base>/blob/<branch>" ready for the frontend to
 * append "/<file_path>#L<start>-L<end>". remote_url is credential-stripped;
 * fields are empty strings when unknown (e.g. no git remote). */
static void handle_repo_info(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char project[256] = {0};
    if (!cbm_http_query_param(req->query, "project", project, (int)sizeof(project)) ||
        project[0] == '\0') {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing project parameter\"}");
        return;
    }

    char db_path[1024];
    db_path_for_project(project, db_path, sizeof(db_path));
    if (db_path[0] == '\0' || !cbm_file_exists(db_path)) {
        cbm_http_replyf(c, 404, g_cors_json, "{\"error\":\"project not found\"}");
        return;
    }
    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"cannot open store\"}");
        return;
    }

    char root_path[1024] = {0};
    cbm_project_t proj;
    memset(&proj, 0, sizeof(proj));
    if (cbm_store_get_project(store, project, &proj) == CBM_STORE_OK && proj.root_path) {
        snprintf(root_path, sizeof(root_path), "%s", proj.root_path);
    }
    cbm_project_free_fields(&proj);
    cbm_store_close_required(&store, "http.repo_info.complete");

    char branch[256] = {0};
    if (root_path[0]) {
        cbm_git_context_t gctx;
        memset(&gctx, 0, sizeof(gctx));
        if (cbm_git_context_resolve(root_path, &gctx) == 0 && gctx.branch) {
            snprintf(branch, sizeof(branch), "%s", gctx.branch);
        }
        cbm_git_context_free(&gctx);
    }

    char *remote = root_path[0] ? git_origin_remote_url(root_path) : NULL;
    char *remote_safe = cbm_ui_git_strip_credentials(remote); /* never echo secrets */
    char *web_base = cbm_ui_git_web_base(remote);

    char blob_base[1152] = {0};
    if (web_base && web_base[0] && branch[0]) {
        snprintf(blob_base, sizeof(blob_base), "%s/blob/%s", web_base, branch);
    }

    /* JSON-escape the free-form fields. */
    char esc_root[2048], esc_branch[512], esc_remote[2048], esc_web[2048], esc_blob[2304];
    cbm_json_escape(esc_root, (int)sizeof(esc_root), root_path);
    cbm_json_escape(esc_branch, (int)sizeof(esc_branch), branch);
    cbm_json_escape(esc_remote, (int)sizeof(esc_remote), remote_safe ? remote_safe : "");
    cbm_json_escape(esc_web, (int)sizeof(esc_web), web_base ? web_base : "");
    cbm_json_escape(esc_blob, (int)sizeof(esc_blob), blob_base);

    cbm_http_replyf(c, 200, g_cors_json,
                    "{\"root_path\":\"%s\",\"branch\":\"%s\",\"remote_url\":\"%s\","
                    "\"web_base\":\"%s\",\"blob_base\":\"%s\"}",
                    esc_root, esc_branch, esc_remote, esc_web, esc_blob);

    free(remote);
    free(remote_safe);
    free(web_base);
}

/* ── Log ring buffer ──────────────────────────────────────────── */

#define LOG_RING_SIZE 500
#define LOG_LINE_MAX 512

static char g_log_ring[LOG_RING_SIZE][LOG_LINE_MAX];
static int g_log_head = 0;
static int g_log_count = 0;
static cbm_mutex_t g_log_mutex;

enum { CBM_LOG_MUTEX_UNINIT = 0, CBM_LOG_MUTEX_INITING = 1, CBM_LOG_MUTEX_INITED = 2 };
static atomic_int g_log_mutex_init = CBM_LOG_MUTEX_UNINIT;

/* Safe for concurrent callers: only publishes INITED after cbm_mutex_init()
 * has completed. Callers that lose the CAS race spin until init finishes. */
void cbm_ui_log_init(void) {
    int state = atomic_load(&g_log_mutex_init);
    if (state == CBM_LOG_MUTEX_INITED)
        return;

    state = CBM_LOG_MUTEX_UNINIT;
    if (atomic_compare_exchange_strong(&g_log_mutex_init, &state, CBM_LOG_MUTEX_INITING)) {
        cbm_mutex_init(&g_log_mutex);
        atomic_store(&g_log_mutex_init, CBM_LOG_MUTEX_INITED);
        return;
    }

    /* Another thread is initializing — spin until done */
    while (atomic_load(&g_log_mutex_init) != CBM_LOG_MUTEX_INITED) {
        cbm_usleep(1000); /* 1ms */
    }
}

/* Called from a log hook — appends a line to the ring buffer (thread-safe) */
void cbm_ui_log_append(const char *line) {
    if (!line)
        return;
    /* Ensure mutex is initialized (safe for early single-threaded logging
     * and concurrent calls via atomic_exchange once-init pattern). */
    cbm_ui_log_init();
    cbm_mutex_lock(&g_log_mutex);
    snprintf(g_log_ring[g_log_head], LOG_LINE_MAX, "%s", line);
    g_log_head = (g_log_head + 1) % LOG_RING_SIZE;
    if (g_log_count < LOG_RING_SIZE)
        g_log_count++;
    cbm_mutex_unlock(&g_log_mutex);
}

/* Append a printf-formatted fragment at *pos within a bufsz buffer, never
 * advancing *pos past bufsz. snprintf returns the length it WOULD have written,
 * so `pos += snprintf(...)` runs pos past the end on truncation and the next
 * call computes a wrapped (huge) remaining size and writes out of bounds. This
 * clamps: on truncation *pos is pinned at bufsz and further appends are no-ops. */
static void http_appendf(char *buf, size_t bufsz, int *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void http_appendf(char *buf, size_t bufsz, int *pos, const char *fmt, ...) {
    if (*pos < 0) {
        return;
    }
    if ((size_t)*pos >= bufsz) {
        *pos = (int)bufsz;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, bufsz - (size_t)*pos, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if ((size_t)n >= bufsz - (size_t)*pos) {
        *pos = (int)bufsz;
    } else {
        *pos += n;
    }
}

/* GET /api/logs?lines=N — returns last N log lines */
static void handle_logs(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char lines_str[16] = {0};
    int max_lines = 100;
    if (cbm_http_query_param(req->query, "lines", lines_str, (int)sizeof(lines_str))) {
        int v = atoi(lines_str);
        if (v > 0 && v <= LOG_RING_SIZE)
            max_lines = v;
    }

    cbm_mutex_lock(&g_log_mutex);
    int count = g_log_count < max_lines ? g_log_count : max_lines;
    int start = (g_log_head - count + LOG_RING_SIZE) % LOG_RING_SIZE;
    int total = g_log_count;

    /* Copy lines under lock */
    size_t buf_size = (size_t)count * (LOG_LINE_MAX + 10) + 64;
    char *buf = malloc(buf_size);
    if (!buf) {
        cbm_mutex_unlock(&g_log_mutex);
        cbm_http_replyf(c, 500, g_cors, "oom");
        return;
    }

    int pos = 0;
    http_appendf(buf, buf_size, &pos, "{\"lines\":[");
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % LOG_RING_SIZE;
        if (i > 0)
            buf[pos++] = ',';
        /* Escape quotes in log lines */
        buf[pos++] = '"';
        for (int j = 0; g_log_ring[idx][j] && (size_t)pos < buf_size - 10; j++) {
            char ch = g_log_ring[idx][j];
            if (ch == '"') {
                buf[pos++] = '\\';
                buf[pos++] = '"';
            } else if (ch == '\\') {
                buf[pos++] = '\\';
                buf[pos++] = '\\';
            } else if (ch == '\n') {
                buf[pos++] = '\\';
                buf[pos++] = 'n';
            } else {
                buf[pos++] = ch;
            }
        }
        buf[pos++] = '"';
    }
    cbm_mutex_unlock(&g_log_mutex);
    http_appendf(buf, buf_size, &pos, "],\"total\":%d}", total);

    cbm_http_replyf(c, 200, g_cors_json, "%s", buf);
    free(buf);
}

/* ── Process monitoring ───────────────────────────────────────── */

#ifndef _WIN32
#include <sys/resource.h>
#endif
#include <signal.h>

/* GET /api/processes — list codebase-memory-mcp processes via ps */
static void handle_processes(cbm_http_conn_t *c) {
    char buf[8192];
    int pos = 0;

#ifdef _WIN32
    /* Windows: GetProcessMemoryInfo + GetProcessTimes */
    PROCESS_MEMORY_COUNTERS pmc;
    FILETIME ft_create, ft_exit, ft_kernel, ft_user;
    double user_s = 0, sys_s = 0;
    size_t rss_bytes = 0;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        rss_bytes = pmc.WorkingSetSize;
    if (GetProcessTimes(GetCurrentProcess(), &ft_create, &ft_exit, &ft_kernel, &ft_user)) {
        ULARGE_INTEGER u, k;
        u.LowPart = ft_user.dwLowDateTime;
        u.HighPart = ft_user.dwHighDateTime;
        k.LowPart = ft_kernel.dwLowDateTime;
        k.HighPart = ft_kernel.dwHighDateTime;
        user_s = (double)u.QuadPart / 1e7;
        sys_s = (double)k.QuadPart / 1e7;
    }
    http_appendf(buf, sizeof(buf), &pos,
                 "{\"self_pid\":%d,\"self_rss_mb\":%.1f,"
                 "\"self_user_cpu_s\":%.1f,\"self_sys_cpu_s\":%.1f,\"processes\":[]}",
                 (int)_getpid(), (double)rss_bytes / (1024.0 * 1024.0), user_s, sys_s);
#else
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    long rss_kb = ru.ru_maxrss;
#ifdef __APPLE__
    rss_kb /= 1024;
#endif
    http_appendf(buf, sizeof(buf), &pos,
                 "{\"self_pid\":%d,\"self_rss_mb\":%.1f,"
                 "\"self_user_cpu_s\":%.1f,\"self_sys_cpu_s\":%.1f,\"processes\":[",
                 (int)getpid(), (double)rss_kb / 1024.0,
                 (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6,
                 (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6);

    FILE *fp = popen("LC_ALL=C ps -eo pid,pcpu,rss,etime,comm 2>/dev/null"
                     " | grep '[c]odebase-memory-mcp'",
                     "r");
    int proc_count = 0;
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            int pid = 0;
            float cpu = 0;
            long rss = 0;
            char elapsed[64] = {0};
            char comm[256] = {0};

            if (sscanf(line, "%d %f %ld %63s %255s", &pid, &cpu, &rss, elapsed, comm) >= 4) {
                if (proc_count > 0)
                    buf[pos++] = ',';
                http_appendf(buf, sizeof(buf), &pos,
                             "{\"pid\":%d,\"cpu\":%.1f,\"rss_mb\":%.1f,"
                             "\"elapsed\":\"%s\",\"command\":\"%s\",\"is_self\":%s}",
                             pid, (double)cpu, (double)rss / 1024.0, elapsed, comm,
                             pid == (int)getpid() ? "true" : "false");
                if (pos >= (int)sizeof(buf)) {
                    pos = (int)sizeof(buf) - 1;
                }
                proc_count++;
            }
        }
        pclose(fp);
    }
    http_appendf(buf, sizeof(buf), &pos, "]}");
#endif

    cbm_http_replyf(c, 200, g_cors_json, "%s", buf);
}

/* POST /api/process-kill — kill a process by PID */
static void handle_process_kill(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    if (req->body_len == 0 || req->body_len > 256) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid body\"}");
        return;
    }

    yyjson_doc *doc = yyjson_read(req->body, req->body_len, 0);
    if (!doc) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid json\"}");
        return;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *v_pid = yyjson_obj_get(root, "pid");
    if (!v_pid || !yyjson_is_int(v_pid)) {
        yyjson_doc_free(doc);
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing pid\"}");
        return;
    }
    int target_pid = (int)yyjson_get_int(v_pid);
    yyjson_doc_free(doc);

#ifdef _WIN32
    if (target_pid == (int)_getpid()) {
#else
    if (target_pid == (int)getpid()) {
#endif
        cbm_http_replyf(c, 400, g_cors_json,
                        "{\"error\":\"cannot kill self (use the UI server's own shutdown)\"}");
        return;
    }

#ifndef _WIN32
    /* Only allow killing PIDs that were spawned by this server (indexing jobs) */
    {
        bool pid_is_ours = false;
        for (int i = 0; i < MAX_INDEX_JOBS; i++) {
            if (atomic_load(&g_index_jobs[i].status) == 1 &&
                g_index_jobs[i].child_pid == target_pid) {
                pid_is_ours = true;
                break;
            }
        }
        if (!pid_is_ours) {
            cbm_http_replyf(c, 403, g_cors_json,
                            "{\"error\":\"can only kill server-spawned processes\"}");
            return;
        }
    }
#endif

#ifdef _WIN32
    HANDLE hproc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)target_pid);
    if (!hproc || !TerminateProcess(hproc, 1)) {
        if (hproc)
            CloseHandle(hproc);
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"kill failed\"}");
        return;
    }
    CloseHandle(hproc);
#else
    if (kill(target_pid, SIGTERM) != 0) {
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"kill failed\"}");
        return;
    }
#endif

    cbm_http_replyf(c, 200, g_cors_json, "{\"killed\":%d}", target_pid);
}

/* ── Directory browser ────────────────────────────────────────── */

#include <dirent.h>

static void append_roots_json(char *buf, size_t bufsz, int *pos) {
    http_appendf(buf, bufsz, pos, ",\"roots\":[");
#ifdef _WIN32
    DWORD drives = GetLogicalDrives();
    int count = 0;
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1u << i))) {
            continue;
        }
        if (count++ > 0) {
            buf[(*pos)++] = ',';
        }
        http_appendf(buf, bufsz, pos, "\"%c:/\"", 'A' + i);
    }
#else
    http_appendf(buf, bufsz, pos, "\"/\"");
#endif
    http_appendf(buf, bufsz, pos, "]");
}

/* GET /api/browse?path=/some/dir — list subdirectories for file picker */
static void handle_browse(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char path[1024] = {0};
    const char *home = cbm_get_home_dir();
    if (!cbm_http_query_param(req->query, "path", path, (int)sizeof(path)) || path[0] == '\0') {
        /* Default to home directory */
        if (home)
            snprintf(path, sizeof(path), "%s", home);
        else
            snprintf(path, sizeof(path), "/");
    }

    /* The browser UI may send Windows backslash separators (e.g.
     * "D:\projects\demo"). Normalize to forward slashes before the cbm_is_dir
     * gate, exactly as the MCP repo_path handler and cbm_project_name_from_path
     * already do — otherwise a real D:/ directory is rejected (#548). */
    cbm_normalize_path_sep(path);

    if (!cbm_is_dir(path)) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"not a directory\"}");
        return;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        cbm_http_replyf(c, 403, g_cors_json, "{\"error\":\"cannot open directory\"}");
        return;
    }

    /* Build JSON response */
    char buf[32768];
    int pos = 0;
    http_appendf(buf, sizeof(buf), &pos, "{\"path\":\"%s\",\"dirs\":[", path);

    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(dir)) != NULL) {
        /* Skip hidden dirs and . / .. */
        if (ent->d_name[0] == '.')
            continue;

        /* Check if it's actually a directory */
        char full[2048];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        if (!cbm_is_dir(full))
            continue;

        if (count > 0)
            buf[pos++] = ',';
        /* Escape directory name to prevent XSS (e.g., names with quotes/angle brackets) */
        {
            char esc[512];
            cbm_json_escape(esc, (int)sizeof(esc), ent->d_name);
            http_appendf(buf, sizeof(buf), &pos, "\"%s\"", esc);
        }
        if (pos >= (int)sizeof(buf)) {
            pos = (int)sizeof(buf) - 1;
        }
        count++;

        if (count >= 200)
            break; /* safety limit */
    }
    closedir(dir);

    /* Parent path — escape to prevent injection */
    char parent[1024];
    snprintf(parent, sizeof(parent), "%s", path);
    char *last_slash = strrchr(parent, '/');
    /* A Windows drive root "X:/" is its own parent (like POSIX "/"): truncating
     * at the slash would yield the bare drive spec "X:", which the next browse
     * resolves to the wrong directory and strands the user at the root (#548). */
    size_t parent_len = strlen(parent);
    bool is_drive_root = parent_len == 3 && parent[1] == ':' && parent[2] == '/';
    if (is_drive_root) {
        /* leave "X:/" unchanged */
    } else if (last_slash && last_slash != parent) {
        *last_slash = '\0';
    } else {
        snprintf(parent, sizeof(parent), "/");
    }

    {
        char esc_parent[2048];
        cbm_json_escape(esc_parent, (int)sizeof(esc_parent), parent);
        http_appendf(buf, sizeof(buf), &pos, "],\"parent\":\"%s\"", esc_parent);
        append_roots_json(buf, sizeof(buf), &pos);
        http_appendf(buf, sizeof(buf), &pos, "}");
    }
    cbm_http_replyf(c, 200, g_cors_json, "%s", buf);
}

/* ── ADR endpoints ────────────────────────────────────────────── */

/* GET /api/adr?project=X — get ADR content for a project */
static void handle_adr_get(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char name[256] = {0};
    if (!cbm_http_query_param(req->query, "project", name, (int)sizeof(name)) || name[0] == '\0') {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing project\"}");
        return;
    }

    char db_path[1024];
    db_path_for_project(name, db_path, sizeof(db_path));

    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        cbm_http_replyf(c, 200, g_cors_json, "{\"has_adr\":false}");
        return;
    }

    cbm_adr_t adr;
    memset(&adr, 0, sizeof(adr));
    if (cbm_store_adr_get(store, name, &adr) == CBM_STORE_OK && adr.content) {
        /* Escape content for JSON — simple: replace quotes and newlines */
        size_t clen = strlen(adr.content);
        size_t buf_size = clen * 2 + 256;
        char *buf = malloc(buf_size);
        if (buf) {
            int pos = snprintf(buf, buf_size, "{\"has_adr\":true,\"content\":\"");
            for (size_t i = 0; i < clen && (size_t)pos < buf_size - 10; i++) {
                char ch = adr.content[i];
                if (ch == '"') {
                    buf[pos++] = '\\';
                    buf[pos++] = '"';
                } else if (ch == '\\') {
                    buf[pos++] = '\\';
                    buf[pos++] = '\\';
                } else if (ch == '\n') {
                    buf[pos++] = '\\';
                    buf[pos++] = 'n';
                } else if (ch == '\r') { /* skip */
                } else if (ch == '\t') {
                    buf[pos++] = '\\';
                    buf[pos++] = 't';
                } else {
                    buf[pos++] = ch;
                }
            }
            http_appendf(buf, buf_size, &pos, "\",\"updated_at\":\"%s\"}",
                         adr.updated_at ? adr.updated_at : "");
            cbm_http_replyf(c, 200, g_cors_json, "%s", buf);
            free(buf);
        } else {
            cbm_http_replyf(c, 500, g_cors, "oom");
        }
        cbm_store_adr_free(&adr);
    } else {
        cbm_http_replyf(c, 200, g_cors_json, "{\"has_adr\":false}");
    }
    cbm_store_close_required(&store, "http.adr_get.complete");
}

/* POST /api/adr — save ADR content. Body: {"project":"...","content":"..."} */
static void handle_adr_save(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    if (req->body_len == 0 || req->body_len > 16384) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid body\"}");
        return;
    }

    yyjson_doc *doc = yyjson_read(req->body, req->body_len, 0);
    if (!doc) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid json\"}");
        return;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *v_proj = yyjson_obj_get(root, "project");
    yyjson_val *v_content = yyjson_obj_get(root, "content");
    if (!v_proj || !yyjson_is_str(v_proj) || !v_content || !yyjson_is_str(v_content)) {
        yyjson_doc_free(doc);
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing project or content\"}");
        return;
    }

    const char *proj = yyjson_get_str(v_proj);
    const char *content = yyjson_get_str(v_content);

    char db_path[1024];
    db_path_for_project(proj, db_path, sizeof(db_path));

    cbm_store_t *store = cbm_store_open_path(db_path);
    yyjson_doc_free(doc);
    if (!store) {
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"cannot open store\"}");
        return;
    }

    int rc = cbm_store_adr_store(store, proj, content);
    cbm_store_close_required(&store, "http.adr_save.complete");

    if (rc == CBM_STORE_OK) {
        cbm_http_replyf(c, 200, g_cors_json, "{\"saved\":true}");
    } else {
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"save failed\"}");
    }
}

/* ── Background indexing ──────────────────────────────────────── */

static char *g_binary_path = NULL;
enum {
    CBM_BINARY_PATH_UNBOUND = 0,
    CBM_BINARY_PATH_BINDING = 1,
    CBM_BINARY_PATH_BOUND = 2,
};
static atomic_int g_binary_path_state = CBM_BINARY_PATH_UNBOUND;
#ifdef _WIN32
static HANDLE g_binary_handle = INVALID_HANDLE_VALUE;
static FILE_ID_INFO g_binary_identity;
#else
static int g_binary_fd = -1;
static dev_t g_binary_device;
static ino_t g_binary_inode;
#endif

const char *cbm_http_server_binary_status_code(int status) {
    switch (status) {
        case CBM_WORKER_BINARY_OK:
            return "CBM_WORKER_BINARY_OK";
        case CBM_WORKER_BINARY_UNBOUND:
            return "CBM_INDEX_WORKER_BINARY_PATH_UNBOUND";
        case CBM_WORKER_BINARY_INVALID_ARGUMENT:
            return "CBM_WORKER_BINARY_INVALID_ARGUMENT";
        case CBM_WORKER_BINARY_SELF_RESOLVE_FAILED:
            return "CBM_WORKER_BINARY_SELF_RESOLVE_FAILED";
        case CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE:
            return "CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE";
        case CBM_WORKER_BINARY_PATH_ENCODING_FAILED:
            return "CBM_WORKER_BINARY_PATH_ENCODING_FAILED";
        case CBM_WORKER_BINARY_OPEN_FAILED:
            return "CBM_WORKER_BINARY_OPEN_FAILED";
        case CBM_WORKER_BINARY_NOT_REGULAR_FILE:
            return "CBM_WORKER_BINARY_NOT_REGULAR_FILE";
        case CBM_WORKER_BINARY_REPARSE_POINT:
            return "CBM_WORKER_BINARY_REPARSE_POINT";
        case CBM_WORKER_BINARY_NOT_EXECUTABLE:
            return "CBM_WORKER_BINARY_NOT_EXECUTABLE";
        case CBM_WORKER_BINARY_IDENTITY_READ_FAILED:
            return "CBM_WORKER_BINARY_IDENTITY_READ_FAILED";
        case CBM_WORKER_BINARY_FINAL_PATH_FAILED:
            return "CBM_WORKER_BINARY_FINAL_PATH_FAILED";
        case CBM_WORKER_BINARY_PATH_TOO_LONG:
            return "CBM_WORKER_BINARY_PATH_TOO_LONG";
        case CBM_WORKER_BINARY_ALLOCATION_FAILED:
            return "CBM_WORKER_BINARY_ALLOCATION_FAILED";
        case CBM_WORKER_BINARY_CAPABILITY_MISMATCH:
            return "CBM_WORKER_BINARY_CAPABILITY_MISMATCH";
        case CBM_WORKER_BINARY_BIND_IN_PROGRESS:
            return "CBM_WORKER_BINARY_BIND_IN_PROGRESS";
        case CBM_WORKER_BINARY_CONFLICT:
            return "CBM_WORKER_BINARY_CONFLICT";
        default:
            return "CBM_WORKER_BINARY_UNKNOWN_STATUS";
    }
}

const char *cbm_http_server_binary_status_message(int status) {
    switch (status) {
        case CBM_WORKER_BINARY_OK:
            return "the exact worker executable identity is bound";
        case CBM_WORKER_BINARY_UNBOUND:
            return "no exact worker executable identity was bound before supervisor admission";
        case CBM_WORKER_BINARY_INVALID_ARGUMENT:
            return "the worker executable path argument is null or empty";
        case CBM_WORKER_BINARY_SELF_RESOLVE_FAILED:
            return "the operating system could not resolve the running process image";
        case CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE:
            return "the worker executable path is not absolute";
        case CBM_WORKER_BINARY_PATH_ENCODING_FAILED:
            return "the worker executable path is not valid platform text";
        case CBM_WORKER_BINARY_OPEN_FAILED:
            return "the worker executable could not be opened for retained identity binding";
        case CBM_WORKER_BINARY_NOT_REGULAR_FILE:
            return "the worker executable path is not a regular file";
        case CBM_WORKER_BINARY_REPARSE_POINT:
            return "the worker executable path names a reparse point";
        case CBM_WORKER_BINARY_NOT_EXECUTABLE:
            return "the bound ordinary file is not an operating-system executable image";
        case CBM_WORKER_BINARY_IDENTITY_READ_FAILED:
            return "the opened worker executable identity could not be read";
        case CBM_WORKER_BINARY_FINAL_PATH_FAILED:
            return "the opened worker executable final path could not be read";
        case CBM_WORKER_BINARY_PATH_TOO_LONG:
            return "the running process image path exceeds the operating-system limit";
        case CBM_WORKER_BINARY_ALLOCATION_FAILED:
            return "memory allocation failed while binding the worker executable";
        case CBM_WORKER_BINARY_CAPABILITY_MISMATCH:
            return "the executable does not publish the required private worker capability";
        case CBM_WORKER_BINARY_BIND_IN_PROGRESS:
            return "another thread is currently binding the worker executable identity";
        case CBM_WORKER_BINARY_CONFLICT:
            return "a different worker executable identity is already bound";
        default:
            return "the worker executable binding returned an unknown status";
    }
}

const char *cbm_http_server_binary_status_remediation(int status) {
    switch (status) {
        case CBM_WORKER_BINARY_OK:
            return "no remediation is required";
        case CBM_WORKER_BINARY_UNBOUND:
            return "bind the shipping executable before enabling supervised indexing";
        case CBM_WORKER_BINARY_INVALID_ARGUMENT:
            return "pass one non-empty absolute executable path";
        case CBM_WORKER_BINARY_SELF_RESOLVE_FAILED:
            return "inspect the native error and launch the existing shipping executable directly";
        case CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE:
            return "resolve the executable to an absolute path before binding it";
        case CBM_WORKER_BINARY_PATH_ENCODING_FAILED:
            return "supply the exact executable path as valid UTF-8";
        case CBM_WORKER_BINARY_OPEN_FAILED:
            return "inspect the native error and make the exact executable path readable";
        case CBM_WORKER_BINARY_NOT_REGULAR_FILE:
            return "bind an existing regular executable file, not a directory or device";
        case CBM_WORKER_BINARY_REPARSE_POINT:
            return "bind the final ordinary executable path instead of a reparse point";
        case CBM_WORKER_BINARY_NOT_EXECUTABLE:
            return "bind the existing native shipping executable image";
        case CBM_WORKER_BINARY_IDENTITY_READ_FAILED:
            return "inspect the native error and repair access to the executable filesystem "
                   "identity";
        case CBM_WORKER_BINARY_FINAL_PATH_FAILED:
            return "inspect the native error and repair final-path resolution for the executable";
        case CBM_WORKER_BINARY_PATH_TOO_LONG:
            return "place the shipping executable within the native process-image path limit";
        case CBM_WORKER_BINARY_ALLOCATION_FAILED:
            return "free memory and restart before enabling indexing";
        case CBM_WORKER_BINARY_CAPABILITY_MISMATCH:
            return "bind an Astrolabe executable with the exact worker and progress protocol "
                   "generation";
        case CBM_WORKER_BINARY_BIND_IN_PROGRESS:
            return "serialize host startup and bind the executable exactly once";
        case CBM_WORKER_BINARY_CONFLICT:
            return "restart the process and bind only the intended shipping executable identity";
        default:
            return "report the unknown status and do not enable supervised indexing";
    }
}

#ifdef _WIN32
static bool windows_absolute_path(const wchar_t *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (((path[0] >= L'A' && path[0] <= L'Z') ||
         (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }
    if (wcsncmp(path, L"\\\\?\\UNC\\", 8) == 0) {
        return path[8] != L'\0';
    }
    if (wcsncmp(path, L"\\\\?\\", 4) == 0) {
        return ((path[4] >= L'A' && path[4] <= L'Z') ||
                (path[4] >= L'a' && path[4] <= L'z')) &&
               path[5] == L':' && (path[6] == L'\\' || path[6] == L'/');
    }
    return path[0] == L'\\' && path[1] == L'\\' && path[2] != L'\0' && path[2] != L'?' &&
           path[2] != L'.';
}

static bool windows_utf8_absolute_path(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
        return true;
    }
    if (strncmp(path, "\\\\?\\UNC\\", 8) == 0) {
        return path[8] != '\0';
    }
    if (strncmp(path, "\\\\?\\", 4) == 0) {
        return ((path[4] >= 'A' && path[4] <= 'Z') ||
                (path[4] >= 'a' && path[4] <= 'z')) &&
               path[5] == ':' && (path[6] == '\\' || path[6] == '/');
    }
    return path[0] == '\\' && path[1] == '\\' && path[2] != '\0' && path[2] != '?' &&
           path[2] != '.';
}

static bool windows_identity_equal(const FILE_ID_INFO *a, const FILE_ID_INFO *b) {
    return a->VolumeSerialNumber == b->VolumeSerialNumber &&
           memcmp(a->FileId.Identifier, b->FileId.Identifier,
                  sizeof(a->FileId.Identifier)) == 0;
}

static cbm_worker_binary_status_t bind_windows_path(const wchar_t *path,
                                                    unsigned long *native_error) {
    if (!windows_absolute_path(path)) {
        return CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE;
    }
    HANDLE candidate =
        CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS |
                        FILE_FLAG_OPEN_REPARSE_POINT,
                    NULL);
    if (candidate == INVALID_HANDLE_VALUE) {
        if (native_error) {
            *native_error = (unsigned long)GetLastError();
        }
        return CBM_WORKER_BINARY_OPEN_FAILED;
    }

    FILE_ATTRIBUTE_TAG_INFO attributes = {0};
    FILE_STANDARD_INFO standard = {0};
    FILE_ID_INFO identity = {0};
    if (!GetFileInformationByHandleEx(candidate, FileAttributeTagInfo, &attributes,
                                      sizeof(attributes)) ||
        !GetFileInformationByHandleEx(candidate, FileStandardInfo, &standard,
                                      sizeof(standard))) {
        if (native_error) {
            *native_error = (unsigned long)GetLastError();
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_IDENTITY_READ_FAILED;
    }
    SetLastError(ERROR_SUCCESS);
    DWORD file_type = GetFileType(candidate);
    DWORD file_type_error = GetLastError();
    if (file_type == FILE_TYPE_UNKNOWN && file_type_error != ERROR_SUCCESS) {
        if (native_error) {
            *native_error = (unsigned long)file_type_error;
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_IDENTITY_READ_FAILED;
    }
    if (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_REPARSE_POINT;
    }
    if (file_type != FILE_TYPE_DISK || standard.Directory || standard.DeletePending ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_NOT_REGULAR_FILE;
    }
    if (!GetFileInformationByHandleEx(candidate, FileIdInfo, &identity, sizeof(identity))) {
        if (native_error) {
            *native_error = (unsigned long)GetLastError();
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_IDENTITY_READ_FAILED;
    }
    DWORD binary_type = 0;
    SetLastError(ERROR_SUCCESS);
    if (!GetBinaryTypeW(path, &binary_type) ||
        (binary_type != SCS_32BIT_BINARY && binary_type != SCS_64BIT_BINARY)) {
        if (native_error) {
            DWORD error = GetLastError();
            *native_error = (unsigned long)error;
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_NOT_EXECUTABLE;
    }

    const DWORD final_flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    DWORD needed = GetFinalPathNameByHandleW(candidate, NULL, 0, final_flags);
    if (needed == 0) {
        if (native_error) {
            *native_error = (unsigned long)GetLastError();
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_FINAL_PATH_FAILED;
    }
    wchar_t *final_wide = calloc((size_t)needed, sizeof(*final_wide));
    if (!final_wide) {
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_ALLOCATION_FAILED;
    }
    DWORD written = GetFinalPathNameByHandleW(candidate, final_wide, needed, final_flags);
    if (written == 0 || written >= needed) {
        if (native_error) {
            DWORD error = written == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
            *native_error = (unsigned long)error;
        }
        free(final_wide);
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_FINAL_PATH_FAILED;
    }
    char *final_path = cbm_wide_final_path_to_utf8(final_wide);
    free(final_wide);
    if (!final_path) {
        if (native_error) {
            DWORD error = GetLastError();
            *native_error = (unsigned long)(error != ERROR_SUCCESS ? error
                                                                   : ERROR_NO_UNICODE_TRANSLATION);
        }
        CloseHandle(candidate);
        return CBM_WORKER_BINARY_PATH_ENCODING_FAILED;
    }

    int expected = CBM_BINARY_PATH_UNBOUND;
    if (!atomic_compare_exchange_strong_explicit(
            &g_binary_path_state, &expected, CBM_BINARY_PATH_BINDING, memory_order_acq_rel,
            memory_order_acquire)) {
        cbm_worker_binary_status_t status = CBM_WORKER_BINARY_BIND_IN_PROGRESS;
        if (expected == CBM_BINARY_PATH_BOUND) {
            status = windows_identity_equal(&g_binary_identity, &identity)
                         ? CBM_WORKER_BINARY_OK
                         : CBM_WORKER_BINARY_CONFLICT;
        }
        free(final_path);
        CloseHandle(candidate);
        return status;
    }
    g_binary_handle = candidate;
    g_binary_identity = identity;
    g_binary_path = final_path;
    atomic_store_explicit(&g_binary_path_state, CBM_BINARY_PATH_BOUND, memory_order_release);
    return CBM_WORKER_BINARY_OK;
}
#else
static cbm_worker_binary_status_t bind_posix_path(const char *path,
                                                  unsigned long *native_error) {
    if (!path || path[0] != '/') {
        return CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE;
    }
    struct stat namespace_info;
    if (lstat(path, &namespace_info) != 0) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_WORKER_BINARY_OPEN_FAILED;
    }
    if (S_ISLNK(namespace_info.st_mode)) {
        return CBM_WORKER_BINARY_REPARSE_POINT;
    }
    if (!S_ISREG(namespace_info.st_mode)) {
        return CBM_WORKER_BINARY_NOT_REGULAR_FILE;
    }
    if (access(path, X_OK) != 0) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_WORKER_BINARY_NOT_EXECUTABLE;
    }
    int candidate = open(path, O_RDONLY);
    if (candidate < 0) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_WORKER_BINARY_OPEN_FAILED;
    }
    struct stat identity;
    if (fstat(candidate, &identity) != 0) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        close(candidate);
        return CBM_WORKER_BINARY_IDENTITY_READ_FAILED;
    }
    if (!S_ISREG(identity.st_mode) || identity.st_dev != namespace_info.st_dev ||
        identity.st_ino != namespace_info.st_ino) {
        close(candidate);
        return CBM_WORKER_BINARY_NOT_REGULAR_FILE;
    }
    char *final_path = realpath(path, NULL);
    if (!final_path) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        close(candidate);
        return CBM_WORKER_BINARY_FINAL_PATH_FAILED;
    }

    int expected = CBM_BINARY_PATH_UNBOUND;
    if (!atomic_compare_exchange_strong_explicit(
            &g_binary_path_state, &expected, CBM_BINARY_PATH_BINDING, memory_order_acq_rel,
            memory_order_acquire)) {
        cbm_worker_binary_status_t status = CBM_WORKER_BINARY_BIND_IN_PROGRESS;
        if (expected == CBM_BINARY_PATH_BOUND) {
            status = g_binary_device == identity.st_dev && g_binary_inode == identity.st_ino
                         ? CBM_WORKER_BINARY_OK
                         : CBM_WORKER_BINARY_CONFLICT;
        }
        free(final_path);
        close(candidate);
        return status;
    }
    g_binary_fd = candidate;
    g_binary_device = identity.st_dev;
    g_binary_inode = identity.st_ino;
    g_binary_path = final_path;
    atomic_store_explicit(&g_binary_path_state, CBM_BINARY_PATH_BOUND, memory_order_release);
    return CBM_WORKER_BINARY_OK;
}
#endif

cbm_worker_binary_status_t cbm_http_server_bind_explicit_binary(const char *path,
                                                                unsigned long *native_error) {
    if (native_error) {
        *native_error = 0;
    }
    if (!path || !path[0]) {
        return CBM_WORKER_BINARY_INVALID_ARGUMENT;
    }
#ifdef _WIN32
    if (!windows_utf8_absolute_path(path)) {
        return CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE;
    }
    DWORD error = ERROR_SUCCESS;
    wchar_t *wide = cbm_utf8_to_wide_path_checked(path, &error);
    if (!wide) {
        if (native_error) {
            *native_error = (unsigned long)error;
        }
        if (error == ERROR_NOT_ENOUGH_MEMORY) {
            return CBM_WORKER_BINARY_ALLOCATION_FAILED;
        }
        if (error == ERROR_FILENAME_EXCED_RANGE) {
            return CBM_WORKER_BINARY_PATH_TOO_LONG;
        }
        return CBM_WORKER_BINARY_PATH_ENCODING_FAILED;
    }
    cbm_worker_binary_status_t status = bind_windows_path(wide, native_error);
    free(wide);
    return status;
#else
    return bind_posix_path(path, native_error);
#endif
}

cbm_worker_binary_status_t cbm_http_server_bind_self_binary(unsigned long *native_error) {
    if (native_error) {
        *native_error = 0;
    }
#ifdef _WIN32
    DWORD capacity = 256;
    wchar_t *path = NULL;
    while (capacity <= 32768) {
        wchar_t *next = realloc(path, (size_t)capacity * sizeof(*next));
        if (!next) {
            free(path);
            return CBM_WORKER_BINARY_ALLOCATION_FAILED;
        }
        path = next;
        SetLastError(ERROR_SUCCESS);
        DWORD written = GetModuleFileNameW(NULL, path, capacity);
        if (written > 0 && written < capacity) {
            cbm_worker_binary_status_t status = bind_windows_path(path, native_error);
            free(path);
            return status;
        }
        if (written == 0) {
            if (native_error) {
                DWORD error = GetLastError();
                *native_error = (unsigned long)error;
            }
            free(path);
            return CBM_WORKER_BINARY_SELF_RESOLVE_FAILED;
        }
        capacity *= 2;
    }
    free(path);
    return CBM_WORKER_BINARY_PATH_TOO_LONG;
#else
    char *path = NULL;
#if defined(__APPLE__)
    uint32_t capacity = 0;
    if (_NSGetExecutablePath(NULL, &capacity) != -1 || capacity == 0) {
        return CBM_WORKER_BINARY_SELF_RESOLVE_FAILED;
    }
    path = malloc((size_t)capacity);
    if (!path) {
        return CBM_WORKER_BINARY_ALLOCATION_FAILED;
    }
    if (_NSGetExecutablePath(path, &capacity) != 0) {
        free(path);
        return CBM_WORKER_BINARY_SELF_RESOLVE_FAILED;
    }
#else
    path = realpath("/proc/self/exe", NULL);
    if (!path) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_WORKER_BINARY_SELF_RESOLVE_FAILED;
    }
#endif
    char *final_path;
#if defined(__APPLE__)
    final_path = realpath(path, NULL);
    free(path);
#else
    final_path = path;
#endif
    if (!final_path) {
        if (native_error) {
            *native_error = (unsigned long)errno;
        }
        return CBM_WORKER_BINARY_SELF_RESOLVE_FAILED;
    }
    cbm_worker_binary_status_t status = bind_posix_path(final_path, native_error);
    free(final_path);
    return status;
#endif
}

const char *cbm_http_server_binary_path(void) {
    if (atomic_load_explicit(&g_binary_path_state, memory_order_acquire) !=
        CBM_BINARY_PATH_BOUND) {
        return NULL;
    }
    return g_binary_path;
}

/* Tail-line sink for the UI index worker: forward each completed worker log line
 * to the in-memory UI log ring so GET /api/logs shows live indexing progress. */
static void ui_index_log_line_cb(const char *line, void *ud) {
    (void)ud;
    cbm_ui_log_append(line);
}

#ifndef _WIN32
/* Record the spawned worker PID so POST /api/process-kill can validate a kill
 * target is a server-spawned index job (POSIX only — Windows never tracked
 * per-job PIDs here; its kill endpoint gates on "not self" alone). */
static void ui_index_record_pid_cb(long child_pid, void *ud) {
    index_job_t *job = ud;
    job->child_pid = (pid_t)child_pid;
}
#endif

/* Index via subprocess — isolates crashes from the main process.
 *
 * #426: this ran a SECOND, parallel spawn implementation (CreateFileA / raw
 * fopen / DeleteFileA on Windows, fork+fopen+unlink on POSIX) alongside the
 * primary cbm_subprocess_run supervisor. Both are now one mechanism:
 * cbm_subprocess_run creates the worker log via CreateFileW + an extended-length
 * ("\\?\") widened path, tails it with cbm_fopen, and removes it with cbm_unlink,
 * so a deep %TEMP% no longer breaks the UI index spawn. One spawn implementation,
 * one long-path story. */
static void *index_thread_fn(void *arg) {
    index_job_t *job = arg;
    cbm_log_info("ui.index.start", "path", job->root_path);

    /* The server startup boundary must have bound the exact worker executable. */
    const cbm_worker_binary_status_t binary_status = CBM_WORKER_BINARY_UNBOUND;
    const char *bin = cbm_http_server_binary_path();
    if (!bin) {
        cbm_log_error("ui.index.binary_path", "code",
                      cbm_http_server_binary_status_code(binary_status), "message",
                      cbm_http_server_binary_status_message(binary_status), "remediation",
                      cbm_http_server_binary_status_remediation(binary_status));
        snprintf(job->error_msg, sizeof(job->error_msg),
                 "%s: %s; remediation: %s", cbm_http_server_binary_status_code(binary_status),
                 cbm_http_server_binary_status_message(binary_status),
                 cbm_http_server_binary_status_remediation(binary_status));
        atomic_store(&job->status, 3);
        cbm_log_info("ui.index.done", "path", job->root_path, "rc", "binary_path_unbound");
        return NULL;
    }

    /* JSON-escape root_path and optional project name. */
    char escaped_path[2048];
    cbm_json_escape(escaped_path, (int)sizeof(escaped_path), job->root_path);
    char escaped_name[512];
    cbm_json_escape(escaped_name, (int)sizeof(escaped_name), job->project_name);
    char json_arg[4096];
    if (job->project_name[0]) {
        snprintf(json_arg, sizeof(json_arg), "{\"repo_path\":\"%s\",\"name\":\"%s\"}", escaped_path,
                 escaped_name);
    } else {
        snprintf(json_arg, sizeof(json_arg), "{\"repo_path\":\"%s\"}", escaped_path);
    }

    /* Worker log + args-file paths. Both live under %TEMP% (or /tmp) and are
     * created / read / deleted via the extended-length ("\\?\") wide-path family
     * (cbm_fopen / cbm_unlink and cbm_subprocess_run's CreateFileW log), so a deep
     * %TEMP% is handled by the one shared mechanism. Buffers are generous so a
     * >MAX_PATH %TEMP% is not truncated before widening. */
    char log_file[1024];
    char args_file[1024];
#ifdef _WIN32
    const char *tmp_dir = getenv("TEMP");
    const char *tdir = tmp_dir && tmp_dir[0] ? tmp_dir : ".";
    int log_n = snprintf(log_file, sizeof(log_file), "%s\\cbm_index_%d_%d_%u.log", tdir,
                         (int)_getpid(), job->slot, job->run_id);
    int args_n = snprintf(args_file, sizeof(args_file), "%s\\cbm_index_%d_%d_%u.args.json", tdir,
                          (int)_getpid(), job->slot, job->run_id);
#else
    int log_n = snprintf(log_file, sizeof(log_file), "/tmp/cbm_index_%d_%d_%u.log", (int)getpid(),
                         job->slot, job->run_id);
    int args_n = snprintf(args_file, sizeof(args_file), "/tmp/cbm_index_%d_%d_%u.args.json",
                          (int)getpid(), job->slot, job->run_id);
#endif
    if (log_n < 0 || args_n < 0 || (size_t)log_n >= sizeof(log_file) ||
        (size_t)args_n >= sizeof(args_file)) {
        snprintf(job->error_msg, sizeof(job->error_msg),
                 "index worker temp path construction failed; remediation: shorten %s",
#ifdef _WIN32
                 "%TEMP%");
#else
                 "/tmp");
#endif
        atomic_store(&job->status, 3);
        cbm_log_info("ui.index.done", "path", job->root_path, "rc", "temp_path_failed");
        return NULL;
    }

    /* Hand the tool JSON to the worker via --args-file — the public CLI argument
     * contract (#378/#411 removed raw-JSON argv). This is exactly how the primary
     * index supervisor (mcp/index_supervisor.c) spawns its worker; converging onto
     * that one mechanism means matching its arg handoff too. cbm_fopen widens +
     * "\\?\"-prefixes so the args file writes even under a deep %TEMP%. */
    FILE *af = cbm_fopen(args_file, "w");
    if (!af || fputs(json_arg, af) == EOF) {
        if (af) {
            fclose(af);
        }
        (void)cbm_unlink(args_file);
        snprintf(job->error_msg, sizeof(job->error_msg),
                 "index args-file write failed; remediation: check that %s is writable",
#ifdef _WIN32
                 "%TEMP%");
#else
                 "/tmp");
#endif
        atomic_store(&job->status, 3);
        cbm_log_info("ui.index.done", "path", job->root_path, "rc", "args_write_failed");
        return NULL;
    }
    fclose(af);

    /* --index-worker: this http_server spawn is already the crash-isolation layer,
     * so the child indexes in-process rather than spawning its own supervisor
     * (avoids redundant process nesting). The shared cbm_subprocess_run builds the
     * command line through the MS-CRT quoter and spawns via CreateProcessW with a
     * wide command line, so the args-file path (and any non-ASCII repo path it
     * points at) survives the parent->worker boundary intact (#423/#20). */
    const char *const idx_argv[] = {bin,          "cli",     "--index-worker", "index_repository",
                                    "--args-file", args_file, NULL};

    char slot_buf[16];
    char run_id_buf[16];
    snprintf(slot_buf, sizeof(slot_buf), "%d", job->slot);
    snprintf(run_id_buf, sizeof(run_id_buf), "%u", job->run_id);
    cbm_log_info("ui.index.spawn", "project", job->project_name, "slot", slot_buf, "run_id",
                 run_id_buf, "bin", bin, "log", log_file, "args", args_file);

    cbm_proc_opts_t opts = {0};
    opts.bin = bin;
    opts.argv = idx_argv;
    opts.log_file = log_file;
    opts.on_log_line = ui_index_log_line_cb;
    opts.quiet_timeout_ms = 0; /* the UI index spawn never imposed a hang timeout */
    opts.delete_log_on_exit = true;
#ifndef _WIN32
    opts.on_spawn = ui_index_record_pid_cb; /* preserve POSIX process-kill PID validation */
    opts.spawn_ud = job;
#endif

    cbm_proc_result_t res = {0};
    int run_rc = cbm_subprocess_run(&opts, &res);
    /* Worker has been reaped by cbm_subprocess_run (it blocks until exit), so the
     * args file has been fully consumed — long-path-safe delete regardless of outcome. */
    (void)cbm_unlink(args_file);
    if (run_rc != 0 || res.outcome == CBM_PROC_SPAWN_FAILED) {
        /* Fail closed — no silent fallback to the retired ANSI spawn path. A spawn
         * failure here means the worker never ran (bad binary path, cmdline
         * overflow, or CreateProcess/fork error). */
        snprintf(job->error_msg, sizeof(job->error_msg),
                 "index worker spawn failed (%s); remediation: check the server binary path and %s",
                 cbm_proc_outcome_str(res.outcome),
#ifdef _WIN32
                 "%TEMP% is writable");
#else
                 "/tmp is writable");
#endif
        atomic_store(&job->status, 3);
        cbm_log_info("ui.index.done", "path", job->root_path, "rc", "spawn_failed");
        return NULL;
    }

    int exit_code = res.exit_code;
    if (exit_code != 0) {
        snprintf(job->error_msg, sizeof(job->error_msg), "indexing failed (exit code %d)",
                 exit_code);
        atomic_store(&job->status, 3);
    } else {
        atomic_store(&job->status, 2);
    }
    cbm_log_info("ui.index.done", "path", job->root_path, "rc", exit_code == 0 ? "ok" : "err");
    return NULL;
}

/* POST /api/index — body: {"root_path": "/abs/path", "project_name": "..."} */
static void handle_index_start(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    if (req->body_len == 0 || req->body_len > 4096) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid body\"}");
        return;
    }

    yyjson_doc *doc = yyjson_read(req->body, req->body_len, 0);
    if (!doc) {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"invalid json\"}");
        return;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *v_path = yyjson_obj_get(root, "root_path");
    if (!v_path || !yyjson_is_str(v_path)) {
        yyjson_doc_free(doc);
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing root_path\"}");
        return;
    }
    const char *rpath = yyjson_get_str(v_path);
    yyjson_val *v_project_name = yyjson_obj_get(root, "project_name");
    const char *project_name = yyjson_is_str(v_project_name) ? yyjson_get_str(v_project_name) : "";

    /* Check path exists */
    if (!cbm_is_dir(rpath)) {
        yyjson_doc_free(doc);
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"directory not found\"}");
        return;
    }

    /* Find free job slot */
    int slot = -1;
    for (int i = 0; i < MAX_INDEX_JOBS; i++) {
        int st = atomic_load(&g_index_jobs[i].status);
        if (st == 0 || st == 2 || st == 3) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        yyjson_doc_free(doc);
        cbm_http_replyf(c, 429, g_cors_json, "{\"error\":\"all index slots busy\"}");
        return;
    }

    index_job_t *job = &g_index_jobs[slot];
    snprintf(job->root_path, sizeof(job->root_path), "%s", rpath);
    snprintf(job->project_name, sizeof(job->project_name), "%s", project_name);
    job->slot = slot;
    job->run_id = atomic_fetch_add(&g_index_job_run_seq, 1) + 1;
    job->error_msg[0] = '\0';
    atomic_store(&job->status, 1);
    yyjson_doc_free(doc);

    /* Spawn background thread */
    cbm_thread_t tid;
    if (cbm_thread_create(&tid, 0, index_thread_fn, job) != 0) {
        atomic_store(&job->status, 3);
        snprintf(job->error_msg, sizeof(job->error_msg), "thread creation failed");
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"thread creation failed\"}");
        return;
    }
    cbm_thread_detach(&tid); /* Don't leak thread handle */

    char escaped_path[2048];
    cbm_json_escape(escaped_path, (int)sizeof(escaped_path), job->root_path);
    cbm_http_replyf(c, 202, g_cors_json, "{\"status\":\"indexing\",\"slot\":%d,\"path\":\"%s\"}",
                    slot, escaped_path);
}

/* GET /api/index-status — returns status of all index jobs */
static void handle_index_status(cbm_http_conn_t *c) {
    char buf[12288] = "[";
    int pos = 1;
    for (int i = 0; i < MAX_INDEX_JOBS; i++) {
        int st = atomic_load(&g_index_jobs[i].status);
        if (st == 0)
            continue;
        if ((size_t)pos >= sizeof(buf) - 2) {
            cbm_http_replyf(c, 500, g_cors_json,
                            "{\"error\":\"index status response too large\"}");
            return;
        }
        if (pos > 1)
            buf[pos++] = ',';
        const char *ss = st == 1 ? "indexing" : st == 2 ? "done" : "error";
        char escaped_path[2048];
        char escaped_error[512];
        cbm_json_escape(escaped_path, (int)sizeof(escaped_path), g_index_jobs[i].root_path);
        cbm_json_escape(escaped_error, (int)sizeof(escaped_error),
                        st == 3 ? g_index_jobs[i].error_msg : "");
        http_appendf(buf, sizeof(buf), &pos,
                     "{\"slot\":%d,\"status\":\"%s\",\"path\":\"%s\",\"error\":\"%s\"}", i, ss,
                     escaped_path, escaped_error);
        if ((size_t)pos >= sizeof(buf) - 2) {
            cbm_http_replyf(c, 500, g_cors_json,
                            "{\"error\":\"index status response too large\"}");
            return;
        }
    }
    buf[pos++] = ']';
    buf[pos] = '\0';
    cbm_http_replyf(c, 200, g_cors_json, "%s", buf);
}

static void unwatch_project(cbm_http_server_t *srv, const char *name) {
    if (srv && srv->watcher) {
        cbm_watcher_unwatch(srv->watcher, name);
    }
}

/* DELETE /api/project?name=X — deletes the .db file */
static void handle_delete_project(cbm_http_server_t *srv, cbm_http_conn_t *c,
                                  const cbm_http_req_t *req) {
    char name[256] = {0};
    if (!cbm_http_query_param(req->query, "name", name, (int)sizeof(name)) || name[0] == '\0') {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing name\"}");
        return;
    }

    char db_path[1024];
    db_path_for_project(name, db_path, sizeof(db_path));
    if (db_path[0] == '\0') {
        cbm_http_replyf(c, 404, g_cors_json, "{\"error\":\"project not found\"}");
        return;
    }

    /* #415: cbm_unlink widens + adds "\\?\" so a project DB under a deep cache
     * dir is deletable instead of failing at MAX_PATH; _wunlink still sets errno
     * (ENOENT preserved for the not-found reply). */
    if (cbm_unlink(db_path) != 0) {
        if (errno == ENOENT) {
            unwatch_project(srv, name);
            cbm_http_replyf(c, 404, g_cors_json, "{\"error\":\"project not found\"}");
            return;
        }
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"failed to delete\"}");
        return;
    }

    /* Also remove WAL and SHM files if they exist */
    char wal_path[1040], shm_path[1040];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", db_path);
    (void)cbm_unlink(wal_path);
    (void)cbm_unlink(shm_path);

    unwatch_project(srv, name);
    cbm_log_info("ui.project.deleted", "name", name);
    cbm_http_replyf(c, 200, g_cors_json, "{\"deleted\":true}");
}

/* GET /api/project-health?name=X — checks db integrity */
static void handle_project_health(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char name[256] = {0};
    if (!cbm_http_query_param(req->query, "name", name, (int)sizeof(name)) || name[0] == '\0') {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing name\"}");
        return;
    }

    char db_path[1024];
    db_path_for_project(name, db_path, sizeof(db_path));

    if (!cbm_file_exists(db_path)) {
        cbm_http_replyf(c, 200, g_cors_json, "{\"status\":\"missing\"}");
        return;
    }

    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        cbm_http_replyf(c, 200, g_cors_json, "{\"status\":\"corrupt\",\"reason\":\"cannot open\"}");
        return;
    }

    int node_count = cbm_store_count_nodes(store, name);
    int edge_count = cbm_store_count_edges(store, name);
    cbm_store_close_required(&store, "http.project_stats.complete");

    int64_t size = cbm_file_size(db_path);

    cbm_http_replyf(c, 200, g_cors_json,
                    "{\"status\":\"healthy\",\"nodes\":%d,\"edges\":%d,\"size_bytes\":%lld}",
                    node_count, edge_count, (long long)size);
}

/* ── Handle GET /api/layout ───────────────────────────────────── */

static void set_http_layout_error(cbm_layout_error_t *error, struct sqlite3 *db,
                                  const char *code, const char *operation, const char *message,
                                  const char *remediation) {
    const char *sqlite_message = db ? sqlite3_errmsg(db) : NULL;
    int sqlite_code = db ? sqlite3_errcode(db) : 0;
    if (error) {
        memset(error, 0, sizeof(*error));
        snprintf(error->code, sizeof(error->code), "%s", code ? code : "CBM_LAYOUT_FAILED");
        snprintf(error->operation, sizeof(error->operation), "%s",
                 operation ? operation : "layout");
        if (sqlite_message && sqlite_message[0] && sqlite_code != SQLITE_OK) {
            snprintf(error->message, sizeof(error->message), "%s: %s",
                     message ? message : "layout operation failed", sqlite_message);
        } else {
            snprintf(error->message, sizeof(error->message), "%s",
                     message ? message : "layout operation failed");
        }
        snprintf(error->remediation, sizeof(error->remediation), "%s",
                 remediation ? remediation : "inspect the layout failure and retry");
        error->store_error_code = sqlite_code;
    }

    char sqlite_code_text[32];
    snprintf(sqlite_code_text, sizeof(sqlite_code_text), "%d", sqlite_code);
    cbm_log_error("http.layout.failed", "code", code ? code : "CBM_LAYOUT_FAILED", "operation",
                  operation ? operation : "layout", "message",
                  message ? message : "layout operation failed", "sqlite_error",
                  sqlite_message ? sqlite_message : "", "sqlite_error_code", sqlite_code_text,
                  "remediation", remediation ? remediation : "inspect the layout failure and retry");
}

static void free_cross_repo_targets(char **targets, int count) {
    if (!targets)
        return;
    for (int i = 0; i < count; i++) {
        free(targets[i]);
        targets[i] = NULL;
    }
}

/* Find distinct target_project values from CROSS_* edges in deterministic
 * order. The persisted CROSS_* rows are the source of truth. A missing DB,
 * malformed row, allocation failure, SQL failure, or a 17th distinct project
 * is terminal: returning a shorter roster would publish a partial graph. */
static bool find_cross_repo_targets(cbm_store_t *store, const char *project, char **out,
                                    int max_out, int *out_count, cbm_layout_error_t *error) {
    if (out_count)
        *out_count = 0;
    if (!store || !project || !project[0] || !out || max_out <= 0 || !out_count) {
        set_http_layout_error(error, NULL, "CBM_LAYOUT_LINK_ROSTER_INPUT_INVALID",
                              "query_linked_projects",
                              "linked-project discovery received an invalid input",
                              "open the exact project store and retry the same layout request");
        return false;
    }
    for (int i = 0; i < max_out; i++)
        out[i] = NULL;

    struct sqlite3 *db = cbm_store_get_db(store);
    if (!db) {
        set_http_layout_error(error, NULL, "CBM_LAYOUT_LINK_ROSTER_DB_UNAVAILABLE",
                              "query_linked_projects",
                              "linked-project discovery could not access the project database",
                              "reopen the project store and retry the request");
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT DISTINCT json_extract(properties, '$.target_project') FROM edges "
            "WHERE project = ?1 AND type LIKE 'CROSS_%' "
            "AND json_extract(properties, '$.target_project') IS NOT NULL "
            "ORDER BY 1 LIMIT ?2",
            -1, &s, NULL) != SQLITE_OK) {
        set_http_layout_error(error, db, "CBM_LAYOUT_LINK_ROSTER_PREPARE_FAILED",
                              "query_linked_projects",
                              "linked-project roster query could not be prepared",
                              "inspect and repair the edges table or JSON1 runtime, then retry");
        return false;
    }
    if (sqlite3_bind_text(s, 1, project, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(s, 2, max_out + 1) != SQLITE_OK) {
        set_http_layout_error(error, db, "CBM_LAYOUT_LINK_ROSTER_BIND_FAILED",
                              "query_linked_projects",
                              "linked-project roster parameters could not be bound",
                              "inspect the SQLite diagnostic and retry the exact request");
        sqlite3_finalize(s);
        return false;
    }

    int count = 0;
    int step = SQLITE_OK;
    while ((step = sqlite3_step(s)) == SQLITE_ROW) {
        const char *tp = (const char *)sqlite3_column_text(s, 0);
        if (sqlite3_column_type(s, 0) != SQLITE_TEXT || !tp || !tp[0]) {
            set_http_layout_error(error, db, "CBM_LAYOUT_LINK_ROSTER_ROW_INVALID",
                                  "query_linked_projects",
                                  "a CROSS_* edge has a non-text or empty target_project",
                                  "repair that edge's target_project property, then retry");
            goto fail;
        }
        if (count >= max_out) {
            set_http_layout_error(error, NULL, "CBM_LAYOUT_LINK_ROSTER_LIMIT_EXCEEDED",
                                  "query_linked_projects",
                                  "the project links to more projects than one layout can render",
                                  "reduce the project fan-out below 17 linked projects before retrying");
            goto fail;
        }
        size_t len = strlen(tp);
        out[count] = malloc(len + 1);
        if (!out[count]) {
            set_http_layout_error(error, NULL, "CBM_LAYOUT_LINK_ROSTER_ALLOCATION_FAILED",
                                  "query_linked_projects",
                                  "a linked-project name could not be retained",
                                  "free memory and retry the exact layout request");
            goto fail;
        }
        memcpy(out[count], tp, len + 1);
        count++;
    }
    if (step != SQLITE_DONE) {
        set_http_layout_error(error, db, "CBM_LAYOUT_LINK_ROSTER_STEP_FAILED",
                              "query_linked_projects",
                              "linked-project roster query did not reach a complete result",
                              "inspect the SQLite diagnostic and repair the edges table before retrying");
        goto fail;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) {
        set_http_layout_error(error, db, "CBM_LAYOUT_LINK_ROSTER_FINALIZE_FAILED",
                              "query_linked_projects",
                              "linked-project roster statement did not finalize cleanly",
                              "inspect the SQLite diagnostic and retry the exact request");
        free_cross_repo_targets(out, count);
        return false;
    }
    *out_count = count;
    return true;

fail:
    sqlite3_finalize(s);
    free_cross_repo_targets(out, count);
    return false;
}

enum { LAYOUT_MAX_LINKED = 16 };
#define LAYOUT_GALAXY_SPACING 600.0
#define LAYOUT_GALAXY_PAD 400.0

/* Bounding-radius of a layout result: max distance from origin across all
 * nodes. Used to size galaxy spacing so satellites don't overlap the primary
 * cluster. Layouts with a 1000-node cluster have radius ~1500; the previous
 * fixed 600 spacing buried satellites inside the primary mass. */
static double layout_radius(const cbm_layout_result_t *r) {
    if (!r || r->node_count == 0)
        return 0.0;
    double max_r2 = 0.0;
    for (int i = 0; i < r->node_count; i++) {
        double x = (double)r->nodes[i].x;
        double y = (double)r->nodes[i].y;
        double z = (double)r->nodes[i].z;
        if (!isfinite(x) || !isfinite(y) || !isfinite(z))
            continue;
        double r2 = x * x + y * y + z * z;
        if (r2 > max_r2)
            max_r2 = r2;
    }
    return sqrt(max_r2);
}

static void reply_layout_error(cbm_http_conn_t *c, int status, const cbm_layout_error_t *error) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
    yyjson_mut_val *detail = doc ? yyjson_mut_obj(doc) : NULL;
    if (!doc || !root || !detail) {
        if (doc)
            yyjson_mut_doc_free(doc);
        cbm_log_error("http.layout.error_response_failed", "code",
                      "CBM_LAYOUT_ERROR_SERIALIZATION_FAILED", "message",
                      "layout error response document could not be allocated", "remediation",
                      "free memory and retry the request");
        cbm_http_replyf(c, 500, g_cors_json,
                        "{\"error\":{\"code\":\"CBM_LAYOUT_ERROR_SERIALIZATION_FAILED\","
                        "\"message\":\"layout error response could not be allocated\","
                        "\"remediation\":\"free memory and retry the request\"}}");
        return;
    }
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_strcpy(doc, detail, "code",
                              error && error->code[0] ? error->code : "CBM_LAYOUT_FAILED");
    yyjson_mut_obj_add_strcpy(doc, detail, "operation",
                              error && error->operation[0] ? error->operation : "layout");
    yyjson_mut_obj_add_strcpy(doc, detail, "message",
                              error && error->message[0] ? error->message
                                                        : "layout computation failed");
    yyjson_mut_obj_add_strcpy(doc, detail, "remediation",
                              error && error->remediation[0]
                                  ? error->remediation
                                  : "inspect the layout failure and retry");
    yyjson_mut_obj_add_int(doc, detail, "store_error_code", error ? error->store_error_code : 0);
    yyjson_mut_obj_add_val(doc, root, "error", detail);
    size_t length = 0;
    char *json = yyjson_mut_write(doc, 0, &length);
    yyjson_mut_doc_free(doc);
    if (!json) {
        cbm_log_error("http.layout.error_response_failed", "code",
                      "CBM_LAYOUT_ERROR_SERIALIZATION_FAILED", "message",
                      "layout error response could not be serialized", "remediation",
                      "inspect allocator state and retry the request");
        cbm_http_replyf(c, 500, g_cors_json,
                        "{\"error\":{\"code\":\"CBM_LAYOUT_ERROR_SERIALIZATION_FAILED\","
                        "\"message\":\"layout error response could not be serialized\","
                        "\"remediation\":\"inspect allocator state and retry the request\"}}");
        return;
    }
    cbm_http_replyf(c, status, g_cors_json, "%s", json);
    free(json);
}

static void handle_layout(cbm_http_conn_t *c, const cbm_http_req_t *req) {
    char project[256] = {0};
    char max_str[32] = {0};

    if (!cbm_http_query_param(req->query, "project", project, (int)sizeof(project)) ||
        project[0] == '\0') {
        cbm_http_replyf(c, 400, g_cors_json, "{\"error\":\"missing project parameter\"}");
        return;
    }

    int max_nodes = 0; /* 0 → layout default budget */
    if (cbm_http_query_param(req->query, "max_nodes", max_str, (int)sizeof(max_str))) {
        char *end = NULL;
        errno = 0;
        long value = strtol(max_str, &end, 10);
        if (errno != 0 || end == max_str || !end || *end != '\0' || value <= 0 ||
            value > INT_MAX) {
            cbm_layout_error_t input_error;
            set_http_layout_error(&input_error, NULL, "CBM_LAYOUT_MAX_NODES_INVALID",
                                  "validate_max_nodes",
                                  "max_nodes must be one complete positive base-10 integer",
                                  "pass max_nodes between 1 and the supported integer ceiling");
            reply_layout_error(c, 400, &input_error);
            return;
        }
        max_nodes = (int)value;
    }

    if (!cbm_validate_project_name(project)) {
        cbm_layout_error_t input_error;
        set_http_layout_error(&input_error, NULL, "CBM_LAYOUT_PROJECT_INVALID",
                              "validate_project",
                              "project is not a valid persisted project name",
                              "pass the exact name returned by list_projects");
        reply_layout_error(c, 400, &input_error);
        return;
    }

    char db_path[1024];
    db_path_for_project(project, db_path, sizeof(db_path));

    if (!cbm_file_exists(db_path)) {
        cbm_http_replyf(c, 404, g_cors_json, "{\"error\":\"project not found\"}");
        return;
    }

    cbm_store_t *store = cbm_store_open_path(db_path);
    if (!store) {
        cbm_http_replyf(c, 500, g_cors_json, "{\"error\":\"cannot open store\"}");
        return;
    }

    cbm_layout_error_t layout_error;
    cbm_layout_result_t *layout =
        cbm_layout_compute(store, project, CBM_LAYOUT_OVERVIEW, NULL, 0, max_nodes, &layout_error);

    if (!layout) {
        cbm_store_close_required(&store, "http.layout.query_failed");
        reply_layout_error(c, 500, &layout_error);
        return;
    }

    /* Find linked projects from CROSS_* edges. Keep `store` open through the
     * linked-projects loop below so we can resolve target Route QNs against
     * the linked stores when populating cross_edges. */
    char *linked[LAYOUT_MAX_LINKED] = {0};
    int linked_count = 0;
    if (!find_cross_repo_targets(store, project, linked, LAYOUT_MAX_LINKED, &linked_count,
                                 &layout_error)) {
        cbm_layout_free(layout);
        cbm_store_close_required(&store, "http.layout.link_roster_failed");
        reply_layout_error(c, 500, &layout_error);
        return;
    }

    /* Capture primary cluster radius before freeing the layout. */
    double primary_radius = layout_radius(layout);

    /* Build JSON: primary layout + linked_projects */
    char *primary_json = cbm_layout_to_json(layout, &layout_error);
    cbm_layout_free(layout);
    if (!primary_json) {
        free_cross_repo_targets(linked, linked_count);
        cbm_store_close_required(&store, "http.layout.query_empty");
        reply_layout_error(c, 500, &layout_error);
        return;
    }

    if (linked_count == 0) {
        cbm_store_close_required(&store, "http.layout.project_missing");
        cbm_http_replyf(c, 200, g_cors_json, "%s", primary_json);
        free(primary_json);
        return;
    }

    /* Parse primary JSON and append linked_projects array */
    yyjson_doc *pdoc = yyjson_read(primary_json, strlen(primary_json), 0);
    free(primary_json);
    if (!pdoc) {
        free_cross_repo_targets(linked, linked_count);
        cbm_store_close_required(&store, "http.layout.root_invalid");
        set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_PRIMARY_JSON_INVALID",
                              "parse_primary_layout",
                              "the freshly serialized primary layout JSON could not be parsed",
                              "inspect the layout serializer and retry after repairing it");
        reply_layout_error(c, 500, &layout_error);
        return;
    }

    yyjson_mut_doc *mdoc = yyjson_doc_mut_copy(pdoc, NULL);
    yyjson_doc_free(pdoc);
    yyjson_mut_val *mroot = mdoc ? yyjson_mut_doc_get_root(mdoc) : NULL;
    yyjson_mut_val *lp_arr = mdoc ? yyjson_mut_arr(mdoc) : NULL;
    if (!mdoc || !mroot || !lp_arr) {
        if (mdoc)
            yyjson_mut_doc_free(mdoc);
        free_cross_repo_targets(linked, linked_count);
        cbm_store_close_required(&store, "http.layout.response_allocation_failed");
        set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_RESPONSE_ALLOCATION_FAILED",
                              "allocate_layout_response",
                              "the complete layout response document could not be allocated",
                              "free memory and retry the exact layout request");
        reply_layout_error(c, 500, &layout_error);
        return;
    }

    cbm_store_t *lp_store = NULL;
    cbm_layout_result_t *lp_layout = NULL;
    char *lp_json = NULL;
    yyjson_doc *lpdoc = NULL;
    yyjson_mut_doc *lm = NULL;
    sqlite3_stmt *eq = NULL;
    sqlite3_stmt *lookup = NULL;

    for (int li = 0; li < linked_count; li++) {
        char lp_path[1024];
        db_path_for_project(linked[li], lp_path, sizeof(lp_path));
        if (!cbm_file_exists(lp_path)) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_STORE_MISSING",
                                  "open_linked_project",
                                  "a persisted CROSS_* edge names a project whose store is absent",
                                  "index the named linked project or remove the stale CROSS_* edge, then retry");
            goto linked_failure;
        }

        lp_store = cbm_store_open_path(lp_path);
        if (!lp_store) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_STORE_OPEN_FAILED",
                                  "open_linked_project",
                                  "a linked-project store exists but could not be opened",
                                  "inspect that exact store and retry after it opens cleanly");
            goto linked_failure;
        }

        /* Keep lp_store open through cross_edges resolution below. */
        cbm_layout_error_t linked_layout_error;
        lp_layout = cbm_layout_compute(
            lp_store, linked[li], CBM_LAYOUT_OVERVIEW, NULL, 0, max_nodes, &linked_layout_error);

        if (!lp_layout) {
            layout_error = linked_layout_error;
            cbm_store_close_required(&lp_store, "http.layout.lp_project_missing");
            goto linked_failure;
        }

        double sat_radius = layout_radius(lp_layout);
        lp_json = cbm_layout_to_json(lp_layout, &linked_layout_error);
        cbm_layout_free(lp_layout);
        lp_layout = NULL;
        if (!lp_json) {
            layout_error = linked_layout_error;
            cbm_store_close_required(&lp_store, "http.layout.lp_node_query_failed");
            goto linked_failure;
        }

        /* Parse linked project layout */
        lpdoc = yyjson_read(lp_json, strlen(lp_json), 0);
        free(lp_json);
        lp_json = NULL;
        if (!lpdoc) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_JSON_INVALID",
                                  "parse_linked_layout",
                                  "a freshly serialized linked layout JSON document could not be parsed",
                                  "inspect the layout serializer and repair it before retrying");
            cbm_store_close_required(&lp_store, "http.layout.lp_edge_query_failed");
            goto linked_failure;
        }

        lm = yyjson_doc_mut_copy(lpdoc, NULL);
        yyjson_doc_free(lpdoc);
        lpdoc = NULL;
        yyjson_mut_val *lmroot = lm ? yyjson_mut_doc_get_root(lm) : NULL;

        /* Build linked project entry */
        yyjson_mut_val *entry = yyjson_mut_obj(mdoc);
        if (!lm || !lmroot || !entry ||
            !yyjson_mut_obj_add_strcpy(mdoc, entry, "project", linked[li])) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_RESPONSE_ALLOCATION_FAILED",
                                  "allocate_linked_response",
                                  "a linked-project response entry could not be allocated",
                                  "free memory and retry the exact layout request");
            goto linked_failure;
        }

        /* Copy nodes and edges from linked layout */
        yyjson_mut_val *ln = yyjson_mut_obj_get(lmroot, "nodes");
        yyjson_mut_val *le = yyjson_mut_obj_get(lmroot, "edges");
        yyjson_mut_val *ln_copy = ln ? yyjson_mut_val_mut_copy(mdoc, ln) : NULL;
        yyjson_mut_val *le_copy = le ? yyjson_mut_val_mut_copy(mdoc, le) : NULL;
        if (!ln || !le || !ln_copy || !le_copy ||
            !yyjson_mut_obj_add_val(mdoc, entry, "nodes", ln_copy) ||
            !yyjson_mut_obj_add_val(mdoc, entry, "edges", le_copy)) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_RESPONSE_INVALID",
                                  "copy_linked_response",
                                  "a linked layout is missing its complete nodes or edges array",
                                  "repair the linked layout serializer and retry the exact request");
            goto linked_failure;
        }

        /* Compute galaxy offset: evenly spaced around primary, far enough out
         * that the primary cluster (radius primary_radius) and the satellite
         * cluster (radius sat_radius) don't overlap. Bounded below by
         * LAYOUT_GALAXY_SPACING for trivially small projects. */
        double angle = (2.0 * 3.14159265358979) * (double)li / (double)linked_count;
        double dist = primary_radius + sat_radius + LAYOUT_GALAXY_PAD;
        if (dist < LAYOUT_GALAXY_SPACING) {
            dist = LAYOUT_GALAXY_SPACING;
        }
        yyjson_mut_val *offset = yyjson_mut_obj(mdoc);
        if (!offset || !yyjson_mut_obj_add_real(mdoc, offset, "x", cos(angle) * dist) ||
            !yyjson_mut_obj_add_real(mdoc, offset, "y", sin(angle) * dist) ||
            !yyjson_mut_obj_add_real(mdoc, offset, "z", 0.0) ||
            !yyjson_mut_obj_add_val(mdoc, entry, "offset", offset)) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_OFFSET_ALLOCATION_FAILED",
                                  "allocate_linked_offset",
                                  "a linked-project galaxy offset could not be retained",
                                  "free memory and retry the exact layout request");
            goto linked_failure;
        }

        /* Populate cross_edges connecting primary→this linked galaxy. Each
         * entry: {source: <primary node id>, target: <linked node id>, type}.
         *
         * A CROSS_* edge in the source store points caller_id → local_route_id
         * (a Route node in the source store). The Route's qualified_name is
         * canonical and the same Route exists in the linked store too — that's
         * the cross-repo matching contract. Join edges → nodes in source to
         * pull the QN, then look it up in the linked store. */
        yyjson_mut_val *cross_arr = yyjson_mut_arr(mdoc);
        struct sqlite3 *src_db = cbm_store_get_db(store);
        struct sqlite3 *lp_db = cbm_store_get_db(lp_store);
        if (!cross_arr || !src_db || !lp_db) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_CROSS_DB_UNAVAILABLE",
                                  "resolve_cross_edges",
                                  "cross-edge resolution could not access both project databases",
                                  "reopen both exact project stores and retry the request");
            goto linked_failure;
        }
        if (sqlite3_prepare_v2(src_db,
                               "SELECT e.source_id, e.type, n.qualified_name "
                               "FROM edges e JOIN nodes n "
                               "  ON n.id = e.target_id AND n.project = e.project "
                               "WHERE e.project = ?1 AND e.type LIKE 'CROSS_%' "
                               "  AND json_extract(e.properties, '$.target_project') = ?2 "
                               "  AND n.qualified_name IS NOT NULL "
                               "ORDER BY e.id",
                               -1, &eq, NULL) != SQLITE_OK) {
            set_http_layout_error(&layout_error, src_db, "CBM_LAYOUT_CROSS_QUERY_PREPARE_FAILED",
                                  "resolve_cross_edges",
                                  "cross-edge source query could not be prepared",
                                  "inspect the source edges and nodes tables, then retry");
            goto linked_failure;
        }
        if (sqlite3_bind_text(eq, 1, project, -1, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_text(eq, 2, linked[li], -1, SQLITE_STATIC) != SQLITE_OK) {
            set_http_layout_error(&layout_error, src_db, "CBM_LAYOUT_CROSS_QUERY_BIND_FAILED",
                                  "resolve_cross_edges",
                                  "cross-edge source query parameters could not be bound",
                                  "inspect the SQLite diagnostic and retry the exact request");
            goto linked_failure;
        }
        if (sqlite3_prepare_v2(lp_db,
                               "SELECT id FROM nodes WHERE project = ?1 AND qualified_name = ?2 "
                               "ORDER BY id LIMIT 2",
                               -1, &lookup, NULL) != SQLITE_OK) {
            set_http_layout_error(&layout_error, lp_db, "CBM_LAYOUT_CROSS_LOOKUP_PREPARE_FAILED",
                                  "resolve_cross_edges",
                                  "linked-node lookup could not be prepared",
                                  "inspect the linked nodes table, then retry");
            goto linked_failure;
        }

        int edge_step = SQLITE_OK;
        while ((edge_step = sqlite3_step(eq)) == SQLITE_ROW) {
            int64_t src_id = sqlite3_column_int64(eq, 0);
            const char *etype = (const char *)sqlite3_column_text(eq, 1);
            const char *qn = (const char *)sqlite3_column_text(eq, 2);
            if (sqlite3_column_type(eq, 1) != SQLITE_TEXT ||
                sqlite3_column_type(eq, 2) != SQLITE_TEXT || !qn || !qn[0] || !etype ||
                !etype[0]) {
                set_http_layout_error(&layout_error, src_db, "CBM_LAYOUT_CROSS_ROW_INVALID",
                                      "resolve_cross_edges",
                                      "a CROSS_* edge lacks a non-empty type or target qualified name",
                                      "repair that persisted edge and route node, then retry");
                goto linked_failure;
            }
            if (sqlite3_reset(lookup) != SQLITE_OK ||
                sqlite3_clear_bindings(lookup) != SQLITE_OK ||
                sqlite3_bind_text(lookup, 1, linked[li], -1, SQLITE_STATIC) != SQLITE_OK ||
                sqlite3_bind_text(lookup, 2, qn, -1, SQLITE_STATIC) != SQLITE_OK) {
                set_http_layout_error(&layout_error, lp_db, "CBM_LAYOUT_CROSS_LOOKUP_BIND_FAILED",
                                      "resolve_cross_edges",
                                      "linked-node lookup could not be reset and bound",
                                      "inspect the SQLite diagnostic and retry the exact request");
                goto linked_failure;
            }
            int lookup_step = sqlite3_step(lookup);
            if (lookup_step == SQLITE_DONE) {
                set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_CROSS_TARGET_MISSING",
                                      "resolve_cross_edges",
                                      "a CROSS_* edge target qualified name is absent from the linked store",
                                      "index the matching route in the linked project or remove the stale edge, then retry");
                goto linked_failure;
            }
            if (lookup_step != SQLITE_ROW) {
                set_http_layout_error(&layout_error, lp_db, "CBM_LAYOUT_CROSS_LOOKUP_STEP_FAILED",
                                      "resolve_cross_edges",
                                      "linked-node lookup did not produce a complete result",
                                      "inspect the linked nodes table and retry after repair");
                goto linked_failure;
            }
            int64_t tgt_id = sqlite3_column_int64(lookup, 0);
            int uniqueness_step = sqlite3_step(lookup);
            if (uniqueness_step == SQLITE_ROW) {
                set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_CROSS_TARGET_AMBIGUOUS",
                                      "resolve_cross_edges",
                                      "a cross-edge target qualified name resolves to multiple linked nodes",
                                      "deduplicate that qualified name in the linked project, then retry");
                goto linked_failure;
            }
            if (uniqueness_step != SQLITE_DONE) {
                set_http_layout_error(&layout_error, lp_db, "CBM_LAYOUT_CROSS_LOOKUP_STEP_FAILED",
                                      "resolve_cross_edges",
                                      "linked-node uniqueness lookup did not reach a complete result",
                                      "inspect the linked nodes table and retry after repair");
                goto linked_failure;
            }
            yyjson_mut_val *ce = yyjson_mut_obj(mdoc);
            if (!ce || !yyjson_mut_obj_add_int(mdoc, ce, "source", src_id) ||
                !yyjson_mut_obj_add_int(mdoc, ce, "target", tgt_id) ||
                !yyjson_mut_obj_add_strcpy(mdoc, ce, "type", etype) ||
                !yyjson_mut_arr_append(cross_arr, ce)) {
                set_http_layout_error(&layout_error, NULL,
                                      "CBM_LAYOUT_CROSS_RESPONSE_ALLOCATION_FAILED",
                                      "serialize_cross_edges",
                                      "a resolved cross edge could not be retained in the response",
                                      "free memory and retry the exact layout request");
                goto linked_failure;
            }
        }
        if (edge_step != SQLITE_DONE) {
            set_http_layout_error(&layout_error, src_db, "CBM_LAYOUT_CROSS_QUERY_STEP_FAILED",
                                  "resolve_cross_edges",
                                  "cross-edge source query did not reach a complete result",
                                  "inspect the source edges table and retry after repair");
            goto linked_failure;
        }
        int lookup_finalize = sqlite3_finalize(lookup);
        lookup = NULL;
        int edge_finalize = sqlite3_finalize(eq);
        eq = NULL;
        if (lookup_finalize != SQLITE_OK || edge_finalize != SQLITE_OK) {
            set_http_layout_error(&layout_error,
                                  lookup_finalize != SQLITE_OK ? lp_db : src_db,
                                  "CBM_LAYOUT_CROSS_QUERY_FINALIZE_FAILED",
                                  "resolve_cross_edges",
                                  "a cross-edge statement did not finalize cleanly",
                                  "inspect the SQLite diagnostic and retry the exact request");
            goto linked_failure;
        }
        if (!yyjson_mut_obj_add_val(mdoc, entry, "cross_edges", cross_arr)) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_CROSS_RESPONSE_ALLOCATION_FAILED",
                                  "serialize_cross_edges",
                                  "the complete cross-edge array could not be attached to the response",
                                  "free memory and retry the exact layout request");
            goto linked_failure;
        }

        cbm_store_close_required(&lp_store, "http.layout.lp_complete");
        if (!yyjson_mut_arr_append(lp_arr, entry)) {
            set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_LINKED_RESPONSE_ALLOCATION_FAILED",
                                  "append_linked_response",
                                  "a complete linked-project entry could not be attached",
                                  "free memory and retry the exact layout request");
            goto linked_failure;
        }
        yyjson_mut_doc_free(lm);
        lm = NULL;
        free(linked[li]);
        linked[li] = NULL;
    }

    if (!yyjson_mut_obj_add_val(mdoc, mroot, "linked_projects", lp_arr)) {
        set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_RESPONSE_ALLOCATION_FAILED",
                              "append_linked_projects",
                              "the complete linked-project roster could not be attached",
                              "free memory and retry the exact layout request");
        goto linked_failure;
    }
    cbm_store_close_required(&store, "http.layout.complete");

    size_t len = 0;
    char *final_json = yyjson_mut_write(mdoc, 0, &len);
    yyjson_mut_doc_free(mdoc);
    mdoc = NULL;

    if (final_json) {
        cbm_http_replyf(c, 200, g_cors_json, "%s", final_json);
        free(final_json);
    } else {
        set_http_layout_error(&layout_error, NULL, "CBM_LAYOUT_RESPONSE_SERIALIZATION_FAILED",
                              "serialize_layout_response",
                              "the complete layout response could not be serialized",
                              "free memory and retry the exact layout request");
        reply_layout_error(c, 500, &layout_error);
    }
    return;

linked_failure:
    if (lookup)
        sqlite3_finalize(lookup);
    if (eq)
        sqlite3_finalize(eq);
    if (lpdoc)
        yyjson_doc_free(lpdoc);
    free(lp_json);
    cbm_layout_free(lp_layout);
    if (lm)
        yyjson_mut_doc_free(lm);
    if (mdoc)
        yyjson_mut_doc_free(mdoc);
    cbm_store_close_required(&lp_store, "http.layout.linked_failure");
    cbm_store_close_required(&store, "http.layout.failure");
    free_cross_repo_targets(linked, linked_count);
    reply_layout_error(c, 500, &layout_error);
}

/* ── Handle JSON-RPC request ──────────────────────────────────── */

static void handle_rpc(cbm_http_conn_t *c, const cbm_http_req_t *req, cbm_mcp_server_t *mcp) {
    if (req->body_len == 0 || req->body_len > MAX_BODY_SIZE || !req->body) {
        cbm_http_replyf(c, 400, g_cors_json,
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                        "\"message\":\"invalid request size\"},\"id\":null}");
        return;
    }

    /* req->body is NUL-terminated by the transport */
    char *response = cbm_mcp_server_handle(mcp, req->body);

    if (response) {
        cbm_http_replyf(c, 200, g_cors_json, "%s", response);
        free(response);
    } else {
        cbm_http_replyf(c, 204, g_cors, "%s", "");
    }
}

/* ── Request dispatch ─────────────────────────────────────────── */

/* True when the Host header names the loopback interface the server binds to
 * (with or without a port). Anything else means the request reached us under a
 * name that is not loopback — a rebinding DNS host or a proxy pointed at the
 * local port — which is the DNS-rebinding / cross-site vector against a
 * localhost-only service. */
static bool host_is_loopback(const char *host) {
    return cbm_http_path_match(host, "localhost") || cbm_http_path_match(host, "localhost:*") ||
           cbm_http_path_match(host, "127.0.0.1") || cbm_http_path_match(host, "127.0.0.1:*") ||
           cbm_http_path_match(host, "[::1]") || cbm_http_path_match(host, "[::1]:*");
}

static void dispatch_request(cbm_http_server_t *srv, cbm_http_conn_t *c,
                             const cbm_http_req_t *req) {
    /* Build per-request CORS headers (only reflects localhost origins) */
    update_cors(req);

    /* DNS-rebinding / cross-site guard: the server binds to loopback only, so a
     * request carrying any non-loopback Host was routed here under a foreign
     * name (a rebinding DNS record, a proxy) and must be refused before it can
     * reach a state-changing endpoint. A bare request with no Host header
     * (HTTP/1.0 local tooling) is still allowed. */
    if (req->host[0] != '\0' && !host_is_loopback(req->host)) {
        cbm_http_replyf(c, 403, g_cors, "%s", "{\"error\":\"forbidden host\"}");
        return;
    }

    bool is_get = strcmp(req->method, "GET") == 0;
    bool is_post = strcmp(req->method, "POST") == 0;
    bool is_delete = strcmp(req->method, "DELETE") == 0;

    /* OPTIONS preflight for CORS */
    if (strcmp(req->method, "OPTIONS") == 0) {
        cbm_http_replyf(c, 204, g_cors, "%s", "");
        return;
    }

    /* POST /rpc → JSON-RPC dispatch (reuses existing MCP tools) */
    if (is_post && cbm_http_path_match(req->path, "/rpc")) {
        handle_rpc(c, req, srv->mcp);
        return;
    }

    /* GET /api/layout → 3D graph layout */
    if (is_get && cbm_http_path_match(req->path, "/api/layout*")) {
        handle_layout(c, req);
        return;
    }

    /* GET /api/repo-info → git remote / branch for GitHub deep-links */
    if (is_get && cbm_http_path_match(req->path, "/api/repo-info*")) {
        handle_repo_info(c, req);
        return;
    }

    /* POST /api/index → start background indexing */
    if (is_post && cbm_http_path_match(req->path, "/api/index")) {
        handle_index_start(c, req);
        return;
    }

    /* GET /api/index-status → check indexing progress */
    if (is_get && cbm_http_path_match(req->path, "/api/index-status")) {
        handle_index_status(c);
        return;
    }

    /* GET /api/ui-config → language and local UI preferences */
    if (is_get && cbm_http_path_match(req->path, "/api/ui-config")) {
        handle_ui_config(c, req);
        return;
    }

    /* DELETE /api/project → delete a project's .db file */
    if (is_delete && cbm_http_path_match(req->path, "/api/project*")) {
        handle_delete_project(srv, c, req);
        return;
    }

    /* GET /api/browse → directory browser for file picker */
    if (is_get && cbm_http_path_match(req->path, "/api/browse*")) {
        handle_browse(c, req);
        return;
    }

    /* GET /api/adr → get ADR for project */
    if (is_get && cbm_http_path_match(req->path, "/api/adr*")) {
        handle_adr_get(c, req);
        return;
    }

    /* POST /api/adr → save ADR for project */
    if (is_post && cbm_http_path_match(req->path, "/api/adr")) {
        handle_adr_save(c, req);
        return;
    }

    /* GET /api/project-health → check db integrity */
    if (is_get && cbm_http_path_match(req->path, "/api/project-health*")) {
        handle_project_health(c, req);
        return;
    }

    /* GET /api/processes → list running codebase-memory-mcp processes */
    if (is_get && cbm_http_path_match(req->path, "/api/processes")) {
        handle_processes(c);
        return;
    }

    /* GET /api/logs → recent log lines */
    if (is_get && cbm_http_path_match(req->path, "/api/logs*")) {
        handle_logs(c, req);
        return;
    }

    /* POST /api/process-kill → kill a process */
    if (is_post && cbm_http_path_match(req->path, "/api/process-kill")) {
        handle_process_kill(c, req);
        return;
    }

    /* GET / → index.html (no-cache so browser always gets latest) */
    if (cbm_http_path_match(req->path, "/")) {
        const cbm_embedded_file_t *f = cbm_embedded_lookup("/index.html");
        if (f) {
            char html_hdrs[1024];
            snprintf(html_hdrs, sizeof(html_hdrs),
                     "%sContent-Type: text/html\r\nCache-Control: no-cache\r\n" CBM_UI_CSP, g_cors);
            cbm_http_reply_buf(c, 200, html_hdrs, f->data, (size_t)f->size);
            return;
        }
        cbm_http_replyf(c, 404, g_cors, "no frontend embedded");
        return;
    }

    /* GET /assets/... → embedded assets, then generic embedded fallback */
    if (serve_embedded(c, req->path))
        return;

    cbm_http_replyf(c, 404, g_cors, "not found");
}

/* ── Public API ───────────────────────────────────────────────── */

cbm_http_server_t *cbm_http_server_new(int port) {
    cbm_http_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv)
        return NULL;

    srv->port = port;
    atomic_store(&srv->stop_flag, 0);

    /* Create a dedicated MCP server for HTTP (own SQLite connection) */
    srv->mcp = cbm_mcp_server_new(NULL);
    if (!srv->mcp) {
        cbm_log_error("ui.http.mcp_fail", "reason", "cannot create MCP instance");
        free(srv);
        return NULL;
    }

    /* Bind to localhost only (httpd refuses anything else by construction) */
    srv->listener = cbm_httpd_listen(port);
    if (!srv->listener) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        cbm_log_warn("ui.unavailable", "port", port_str, "reason", "in_use", "hint",
                     "use --port=N to override");
        cbm_mcp_server_free(srv->mcp);
        free(srv);
        return NULL;
    }

    srv->port = cbm_httpd_port(srv->listener);
    srv->listener_ok = true;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", srv->port);
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", srv->port);
    cbm_log_info("ui.serving", "url", url, "port", port_str);

    return srv;
}

void cbm_http_server_free(cbm_http_server_t *srv) {
    if (!srv)
        return;
    cbm_httpd_close(srv->listener);
    cbm_mcp_server_free(srv->mcp);
    free(srv);
}

void cbm_http_server_stop(cbm_http_server_t *srv) {
    if (srv) {
        atomic_store(&srv->stop_flag, 1);
    }
}

void cbm_http_server_run(cbm_http_server_t *srv) {
    if (!srv || !srv->listener_ok)
        return;

    while (!atomic_load(&srv->stop_flag)) {
        cbm_http_conn_t *conn = cbm_httpd_accept(srv->listener, 200);
        if (!conn)
            continue; /* timeout — re-check stop flag */

        uint64_t request_start_ms = cbm_now_ms();
        cbm_http_req_t req;
        int rc = cbm_httpd_read_request(conn, &req);
        if (rc == 0) {
            dispatch_request(srv, conn, &req);
            cbm_log_http_request("graph_ui", req.method, req.path, cbm_http_conn_status(conn),
                                 (int64_t)(cbm_now_ms() - request_start_ms), req.body_len,
                                 cbm_http_conn_response_bytes(conn));
            cbm_http_req_free(&req);
        } else if (rc > 0) {
            /* Parse/transport error with a known HTTP status (400/408/411/413/431).
             * No CORS reflection here — the request was never parsed. */
            cbm_http_replyf(conn, rc, "", "bad request");
            cbm_log_http_request("graph_ui", "", "", cbm_http_conn_status(conn),
                                 (int64_t)(cbm_now_ms() - request_start_ms), 0,
                                 cbm_http_conn_response_bytes(conn));
        }
        cbm_httpd_conn_close(conn);
    }
}

bool cbm_http_server_is_running(const cbm_http_server_t *srv) {
    return srv && srv->listener_ok;
}

int cbm_http_server_port(const cbm_http_server_t *srv) {
    return (srv && srv->listener_ok) ? srv->port : -1;
}

void cbm_http_server_set_recv_deadline_ms(cbm_http_server_t *srv, int ms) {
    if (srv && srv->listener_ok) {
        cbm_httpd_set_recv_deadline_ms(srv->listener, ms);
    }
}

void cbm_http_server_set_watcher(cbm_http_server_t *srv, struct cbm_watcher *watcher) {
    if (srv) {
        srv->watcher = watcher;
    }
}
