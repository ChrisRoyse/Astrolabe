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

#include <stdarg.h>
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
 * Also applies case-insensitive CBM_LOG_FORMAT=text|json. An absent variable
 * selects text. A present empty, whitespace-only, or otherwise unrecognized
 * value is invalid: no level or format change is committed, and the exact
 * offending environment string is returned. NULL means the complete admission
 * succeeded. The returned non-NULL pointer borrows process-environment storage;
 * the caller must not free or modify it. Call once at startup before any threads
 * or log lines. */
const char *cbm_log_init_from_env(void);

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

/* va_list form of cbm_log, so a caller that must do something else with the
 * same key/value pairs (e.g. retain them as the pipeline's terminal error) can
 * forward them without duplicating the argument list at every call site. */
void cbm_logv(CBMLogLevel level, const char *msg, va_list ap);

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
