/*
 * log.h — Structured key-value logging to stderr.
 *
 * Design:
 *   - All output goes to stderr (stdout is reserved for MCP JSON-RPC)
 *   - Structured text format: "level=info msg=pass.timing pass=defs elapsed_ms=42"
 *   - Optional JSON format for local structured parsing
 *   - Levels: DEBUG, INFO, WARN, ERROR
 *   - Level filtering at runtime via cbm_log_set_level() or the
 *     CBM_LOG_LEVEL env var (see cbm_log_init_from_env)
 *   - Thread-safe: one process-local mutex serializes runtime configuration,
 *     sink callback invocation, and stderr emission. Sink callbacks must not
 *     re-enter cbm_log.
 */
#ifndef CBM_LOG_H
#define CBM_LOG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
    CBM_LOG_DEBUG = 0,
    CBM_LOG_INFO = 1,
    CBM_LOG_WARN = 2,
    CBM_LOG_ERROR = 3,
    CBM_LOG_NONE = 4 /* disable all logging */
} CBMLogLevel;

typedef enum {
    CBM_LOG_FORMAT_TEXT = 0,
    CBM_LOG_FORMAT_JSON = 1,
} CBMLogFormat;

typedef enum {
    CBM_LOG_SINK_REPLACE = 0,
    CBM_LOG_SINK_TEE = 1,
} CBMLogSinkMode;

/* Apply the CBM_LOG_LEVEL environment variable to the runtime log level.
 * Accepts (case-insensitive) "debug", "info", "warn", "error", "none", or
 * the numeric equivalents 0..4 matching CBMLogLevel. Unknown, empty, or
 * unset values leave the level unchanged (fail-open).
 *
 * Also applies CBM_LOG_FORMAT=text|json. If unset, the current format is left
 * unchanged. Call once at startup before any threads or log lines. */
void cbm_log_init_from_env(void);

/* Set minimum log level (default: INFO). */
void cbm_log_set_level(CBMLogLevel level);

/* Get current log level. */
CBMLogLevel cbm_log_get_level(void);

/* Set/get output format. Default is text. */
void cbm_log_set_format(CBMLogFormat format);
CBMLogFormat cbm_log_get_format(void);

/* Core logging function. msg is a short semantic tag.
 * Variadic args are key-value pairs: (const char *key, const char *value)...
 * Terminated by NULL key.
 *
 * Example:
 *   cbm_log(CBM_LOG_INFO, "pass.timing",
 *           "pass", "defs", "elapsed_ms", "42", NULL);
 *
 * Output:
 *   level=info msg=pass.timing pass=defs elapsed_ms=42
 */
void cbm_log(CBMLogLevel level, const char *msg, ...);

/* ── First-error capture (#943) ───────────────────────────────────────────
 *
 * Passes log a fully structured {code, operation, message, remediation} and
 * then return a bare failure code. Where the caller has no pipeline handle to
 * record against -- cbm_pipeline_import_map_build being the case that motivated
 * this -- the specific cause reached ONLY the log, and the tool response
 * degraded to a generic "the authoritative indexing pipeline failed" with the
 * real reason buried in a worker log. That turned one-line defects into
 * multi-hour investigations.
 *
 * Capturing the FIRST error line at this funnel covers every such site at once,
 * including sites in passes that cannot reach a pipeline handle and sites added
 * later, instead of requiring each one to remember to record itself. Capture
 * runs inside the existing log mutex, so it is safe from the parallel resolve
 * workers.
 *
 * FIRST, not last, deliberately: later errors are usually consequences of the
 * first (a refused edge cascades into a failed dump into a failed persist), and
 * the root cause is what the caller needs.
 *
 * This is a diagnostic fallback, never a substitute for an explicit
 * cbm_pipeline_record_fatal_error: it must only be consulted on a path that has
 * already established the run failed. A captured error on a run that ultimately
 * succeeded is a recovered condition, not a failure. */
/* Object-like macros, not an enum: a new anonymous enum in this header would
 * renumber every bindgen `_bindgen_ty_N` in the committed FFI bindings, turning
 * a two-field addition into a churn diff across unrelated constants. */
#define CBM_LOG_ERR_CODE_MAX 128
#define CBM_LOG_ERR_TEXT_MAX 512

typedef struct {
    bool present;
    char code[CBM_LOG_ERR_CODE_MAX];
    char operation[CBM_LOG_ERR_CODE_MAX];
    char file[CBM_LOG_ERR_TEXT_MAX];
    char message[CBM_LOG_ERR_TEXT_MAX];
    char remediation[CBM_LOG_ERR_TEXT_MAX];
} cbm_log_first_error_t;

/* Clear and arm capture for a run. Call once at the start of the operation
 * whose failure you intend to attribute. */
void cbm_log_first_error_arm(void);

/* Stop capturing. Leaves any captured value readable. */
void cbm_log_first_error_disarm(void);

/* Copy out the captured error. Returns false when nothing was captured. */
bool cbm_log_first_error_get(cbm_log_first_error_t *out);

/* Convenience macros. */
#define cbm_log_debug(msg, ...) cbm_log(CBM_LOG_DEBUG, msg, ##__VA_ARGS__, NULL)
#define cbm_log_info(msg, ...) cbm_log(CBM_LOG_INFO, msg, ##__VA_ARGS__, NULL)
#define cbm_log_warn(msg, ...) cbm_log(CBM_LOG_WARN, msg, ##__VA_ARGS__, NULL)
#define cbm_log_error(msg, ...) cbm_log(CBM_LOG_ERROR, msg, ##__VA_ARGS__, NULL)

/* Log with integer value (avoids sprintf for common case). */
void cbm_log_int(CBMLogLevel level, const char *msg, const char *key, int64_t value);

/* Operational event helpers. They deliberately avoid request bodies, headers,
 * arguments, and query strings. */
void cbm_log_mcp_request(const char *method, const char *tool_name, bool is_error,
                         int64_t duration_us);
void cbm_log_http_request(const char *component, const char *method, const char *path, int status,
                          int64_t duration_ms, size_t request_bytes, size_t response_bytes);

/* Optional log sink callback — called with the formatted log line. */
typedef void (*cbm_log_sink_fn)(const char *line);
void cbm_log_set_sink(cbm_log_sink_fn fn);
void cbm_log_set_sink_ex(cbm_log_sink_fn fn, CBMLogSinkMode mode);

#endif /* CBM_LOG_H */
