/*
 * log.c — Structured key-value logging to stderr.
 */
#include "log.h"
#include "foundation/compat_thread.h"
#include "foundation/constants.h"
#include "foundation/log_internal.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sched.h>
#endif

static CBMLogLevel g_log_level = CBM_LOG_INFO;
static CBMLogFormat g_log_format = CBM_LOG_FORMAT_TEXT;
static cbm_log_sink_fn g_log_sink = NULL;
static CBMLogSinkMode g_log_sink_mode = CBM_LOG_SINK_REPLACE;
static cbm_mutex_t g_log_mutex;
static atomic_int g_log_mutex_state = 0; /* 0=absent, 1=initializing, 2=ready */

static void log_mutex_wait_for_initializer(void) {
    while (atomic_load_explicit(&g_log_mutex_state, memory_order_acquire) != 2) {
#ifdef _WIN32
        Sleep(0);
#else
        sched_yield();
#endif
    }
}

static void ensure_log_mutex(void) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(&g_log_mutex_state, &expected, 1,
                                                memory_order_acq_rel, memory_order_acquire)) {
        cbm_mutex_init(&g_log_mutex);
        atomic_store_explicit(&g_log_mutex_state, 2, memory_order_release);
        return;
    }
    log_mutex_wait_for_initializer();
}

static void log_lock(void) {
    ensure_log_mutex();
    cbm_mutex_lock(&g_log_mutex);
}

static void log_unlock(void) {
    cbm_mutex_unlock(&g_log_mutex);
}

/* CBM_LOG_LEVEL support — distilled from #414 (closes #413, thanks @santanusinha). */
void cbm_log_init_from_env(void) {
    /* getenv() is safe here: this runs at startup before any thread is created,
     * so there is no concurrent setenv() to race against. */
    const char *raw = getenv("CBM_LOG_LEVEL");
    if (raw && raw[0] != '\0') {
        /* Textual form, case-insensitive. Index of each name == its enum value. */
        static const char *const names[] = {"debug", "info", "warn", "error", "none"};
        char lower[8];
        size_t i = 0;
        for (; i < sizeof(lower) - 1 && raw[i] != '\0'; i++) {
            lower[i] = (char)tolower((unsigned char)raw[i]);
        }
        lower[i] = '\0';
        if (raw[i] == '\0') { /* fully consumed — candidate textual match */
            for (size_t lvl = 0; lvl < sizeof(names) / sizeof(names[0]); lvl++) {
                if (strcmp(lower, names[lvl]) == 0) {
                    cbm_log_set_level((CBMLogLevel)lvl);
                    goto parse_format;
                }
            }
        }

        /* Numeric form: 0=debug .. 4=none, matching CBMLogLevel. */
        char *end = NULL;
        long n = strtol(raw, &end, CBM_DECIMAL_BASE);
        if (end != raw && *end == '\0' && n >= CBM_LOG_DEBUG && n <= CBM_LOG_NONE) {
            cbm_log_set_level((CBMLogLevel)n);
        }
    }

    /* Unrecognised value: leave the level unchanged (fail-open). */

parse_format:;
    const char *fmt = getenv("CBM_LOG_FORMAT");
    if (fmt && fmt[0] != '\0') {
        char lower_fmt[8];
        size_t i = 0;
        for (; i < sizeof(lower_fmt) - 1 && fmt[i] != '\0'; i++) {
            lower_fmt[i] = (char)tolower((unsigned char)fmt[i]);
        }
        lower_fmt[i] = '\0';
        if (fmt[i] == '\0' && strcmp(lower_fmt, "json") == 0) {
            cbm_log_set_format(CBM_LOG_FORMAT_JSON);
        } else if (fmt[i] == '\0' && strcmp(lower_fmt, "text") == 0) {
            cbm_log_set_format(CBM_LOG_FORMAT_TEXT);
        }
        return;
    }

    /* Format is intentionally explicit-only. Logs stay local to stderr and the
     * optional in-process sink; deployment environment variables must not
     * silently change the operator-selected output shape. */
}

void cbm_log_set_sink(cbm_log_sink_fn fn) {
    cbm_log_set_sink_ex(fn, CBM_LOG_SINK_REPLACE);
}

void cbm_log_set_sink_ex(cbm_log_sink_fn fn, CBMLogSinkMode mode) {
    log_lock();
    g_log_sink = fn;
    g_log_sink_mode = mode;
    log_unlock();
}

void cbm_log_set_level(CBMLogLevel level) {
    log_lock();
    g_log_level = level;
    log_unlock();
}

CBMLogLevel cbm_log_get_level(void) {
    log_lock();
    CBMLogLevel level = g_log_level;
    log_unlock();
    return level;
}

void cbm_log_set_format(CBMLogFormat format) {
    log_lock();
    g_log_format = format;
    log_unlock();
}

CBMLogFormat cbm_log_get_format(void) {
    log_lock();
    CBMLogFormat format = g_log_format;
    log_unlock();
    return format;
}

static const char *level_str(CBMLogLevel level) {
    switch (level) {
    case CBM_LOG_DEBUG:
        return "debug";
    case CBM_LOG_INFO:
        return "info";
    case CBM_LOG_WARN:
        return "warn";
    case CBM_LOG_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static void append_char(char *buf, size_t bufsz, size_t *pos, char ch) {
    if (buf && bufsz > 0 && *pos < bufsz - 1) {
        buf[*pos] = ch;
    }
    if (*pos < SIZE_MAX) {
        (*pos)++;
    }
}

static void append_raw(char *buf, size_t bufsz, size_t *pos, const char *s) {
    if (!s) {
        return;
    }
    while (*s) {
        append_char(buf, bufsz, pos, *s++);
    }
}

static void append_text_atom(char *buf, size_t bufsz, size_t *pos, const char *s) {
    if (!s) {
        return;
    }
    while (*s) {
        unsigned char ch = (unsigned char)*s++;
        if (ch <= ' ' || ch == 0x7f) {
            append_char(buf, bufsz, pos, '_');
        } else {
            append_char(buf, bufsz, pos, (char)ch);
        }
    }
}

static void append_json_string(char *buf, size_t bufsz, size_t *pos, const char *s) {
    append_char(buf, bufsz, pos, '"');
    if (s) {
        while (*s) {
            unsigned char ch = (unsigned char)*s++;
            switch (ch) {
            case '"':
                append_raw(buf, bufsz, pos, "\\\"");
                break;
            case '\\':
                append_raw(buf, bufsz, pos, "\\\\");
                break;
            case '\b':
                append_raw(buf, bufsz, pos, "\\b");
                break;
            case '\f':
                append_raw(buf, bufsz, pos, "\\f");
                break;
            case '\n':
                append_raw(buf, bufsz, pos, "\\n");
                break;
            case '\r':
                append_raw(buf, bufsz, pos, "\\r");
                break;
            case '\t':
                append_raw(buf, bufsz, pos, "\\t");
                break;
            default:
                if (ch < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    append_raw(buf, bufsz, pos, "\\u00");
                    append_char(buf, bufsz, pos, hex[ch >> 4]);
                    append_char(buf, bufsz, pos, hex[ch & 0xf]);
                } else {
                    append_char(buf, bufsz, pos, (char)ch);
                }
                break;
            }
        }
    }
    append_char(buf, bufsz, pos, '"');
}

static void append_i64(char *buf, size_t bufsz, size_t *pos, int64_t value) {
    char number[CBM_SZ_32];
    (void)snprintf(number, sizeof(number), "%" PRId64, value);
    append_raw(buf, bufsz, pos, number);
}

static void append_u64(char *buf, size_t bufsz, size_t *pos, uint64_t value) {
    char number[CBM_SZ_32];
    (void)snprintf(number, sizeof(number), "%" PRIu64, value);
    append_raw(buf, bufsz, pos, number);
}

static void append_size(char *buf, size_t bufsz, size_t *pos, size_t value) {
    char number[CBM_SZ_32];
    (void)snprintf(number, sizeof(number), "%zu", value);
    append_raw(buf, bufsz, pos, number);
}

static void append_json_bool(char *buf, size_t bufsz, size_t *pos, bool value) {
    append_raw(buf, bufsz, pos, value ? "true" : "false");
}

static void finish_line(char *buf, size_t bufsz, size_t pos) {
    if (bufsz == 0) {
        return;
    }
    if (pos >= bufsz) {
        buf[bufsz - 1] = '\0';
    } else {
        buf[pos] = '\0';
    }
}

static void emit_line_locked(const char *line) {
    if (g_log_sink) {
        g_log_sink(line);
        if (g_log_sink_mode == CBM_LOG_SINK_REPLACE) {
            return;
        }
    }
    (void)fprintf(stderr, "%s\n", line);
}

static void emit_pipeline_phase_line_locked(const char *line) {
    if (g_log_format == CBM_LOG_FORMAT_JSON) {
        emit_line_locked(line);
    } else {
        /* Text phase traces historically bypass every configured sink. Keep
         * standalone CLI/UI behavior byte-identical in text mode. */
        (void)fprintf(stderr, "%s\n", line);
    }
    (void)fflush(stderr);
}

/* This path is used only when the ordinary formatter itself cannot complete.
 * Keep every field bounded and allocation-free so JSON mode never degrades to
 * an unparsable text fallback precisely when diagnostics matter most. */
static void emit_internal_failure_locked(const char *event, const char *code,
                                         const char *original_event, bool has_requested_bytes,
                                         size_t requested_bytes, const char *message,
                                         const char *remediation) {
    if (g_log_format == CBM_LOG_FORMAT_TEXT) {
        /* These three text records predate the JSON mode. Preserve their exact
         * names and evidence fields for standalone consumers. */
        if (strcmp(event, "log.length_overflow") == 0) {
            (void)fprintf(stderr,
                          "level=error msg=log.length_overflow original_event=%s remediation="
                          "reduce_the_diagnostic_field_sizes_and_retry\n",
                          original_event ? original_event : "");
            return;
        }
        if (strcmp(event, "log.allocation_failed") == 0) {
            (void)fprintf(stderr,
                          "level=error msg=log.allocation_failed original_event=%s "
                          "requested_bytes=%zu remediation=free_memory_and_retry\n",
                          original_event ? original_event : "", requested_bytes);
            return;
        }
        if (strcmp(event, "log.format_length_mismatch") == 0) {
            (void)fprintf(stderr,
                          "level=error msg=log.format_length_mismatch original_event=%s "
                          "remediation=inspect_variadic_log_arguments\n",
                          original_event ? original_event : "");
            return;
        }
    }

    char retained_event[CBM_SZ_128];
    size_t retained = 0;
    while (original_event && original_event[retained] != '\0' &&
           retained < sizeof(retained_event) - 1) {
        retained_event[retained] = original_event[retained];
        retained++;
    }
    retained_event[retained] = '\0';
    bool original_event_truncated =
        original_event && original_event[retained] != '\0';

    char line[CBM_SZ_1K];
    size_t pos = 0;
    if (g_log_format == CBM_LOG_FORMAT_JSON) {
        append_raw(line, sizeof(line), &pos, "{\"level\":\"error\",\"event\":");
        append_json_string(line, sizeof(line), &pos, event);
        append_raw(line, sizeof(line), &pos, ",\"code\":");
        append_json_string(line, sizeof(line), &pos, code);
        append_raw(line, sizeof(line), &pos, ",\"original_event\":");
        append_json_string(line, sizeof(line), &pos, retained_event);
        append_raw(line, sizeof(line), &pos, ",\"original_event_truncated\":");
        append_json_bool(line, sizeof(line), &pos, original_event_truncated);
        if (has_requested_bytes) {
            append_raw(line, sizeof(line), &pos, ",\"requested_bytes\":");
            append_size(line, sizeof(line), &pos, requested_bytes);
        }
        append_raw(line, sizeof(line), &pos, ",\"message\":");
        append_json_string(line, sizeof(line), &pos, message);
        append_raw(line, sizeof(line), &pos, ",\"remediation\":");
        append_json_string(line, sizeof(line), &pos, remediation);
        append_char(line, sizeof(line), &pos, '}');
    } else {
        append_raw(line, sizeof(line), &pos, "level=error msg=");
        append_text_atom(line, sizeof(line), &pos, event);
        append_raw(line, sizeof(line), &pos, " code=");
        append_text_atom(line, sizeof(line), &pos, code);
        append_raw(line, sizeof(line), &pos, " original_event=");
        append_text_atom(line, sizeof(line), &pos, retained_event);
        append_raw(line, sizeof(line), &pos, " original_event_truncated=");
        append_raw(line, sizeof(line), &pos, original_event_truncated ? "true" : "false");
        if (has_requested_bytes) {
            append_raw(line, sizeof(line), &pos, " requested_bytes=");
            append_size(line, sizeof(line), &pos, requested_bytes);
        }
        append_raw(line, sizeof(line), &pos, " message=");
        append_text_atom(line, sizeof(line), &pos, message);
        append_raw(line, sizeof(line), &pos, " remediation=");
        append_text_atom(line, sizeof(line), &pos, remediation);
    }
    finish_line(line, sizeof(line), pos);
    emit_line_locked(line);
}

static size_t format_pipeline_phase_trace_line(
    char *line, size_t line_size, const char *boundary, const char *phase, uint64_t pid, int mode,
    bool row_sink_active, bool row_sink_completed, int nodes, int edges, bool memory_valid,
    uint64_t working_set_bytes, uint64_t private_bytes, uint64_t peak_working_set_bytes,
    uint64_t peak_private_bytes) {
    size_t pos = 0;
    if (g_log_format == CBM_LOG_FORMAT_JSON) {
        append_raw(line, line_size, &pos,
                   "{\"level\":\"info\",\"event\":\"pipeline.phase_trace\",\"boundary\":");
        append_json_string(line, line_size, &pos, boundary ? boundary : "");
        append_raw(line, line_size, &pos, ",\"phase\":");
        append_json_string(line, line_size, &pos, phase ? phase : "");
        append_raw(line, line_size, &pos, ",\"pid\":");
        append_u64(line, line_size, &pos, pid);
        append_raw(line, line_size, &pos, ",\"mode\":");
        append_i64(line, line_size, &pos, mode);
        append_raw(line, line_size, &pos, ",\"row_sink_active\":");
        append_json_bool(line, line_size, &pos, row_sink_active);
        append_raw(line, line_size, &pos, ",\"row_sink_completed\":");
        append_json_bool(line, line_size, &pos, row_sink_completed);
        append_raw(line, line_size, &pos, ",\"nodes\":");
        append_i64(line, line_size, &pos, nodes);
        append_raw(line, line_size, &pos, ",\"edges\":");
        append_i64(line, line_size, &pos, edges);
        append_raw(line, line_size, &pos, ",\"memory_valid\":");
        append_json_bool(line, line_size, &pos, memory_valid);
        append_raw(line, line_size, &pos, ",\"working_set_bytes\":");
        append_u64(line, line_size, &pos, working_set_bytes);
        append_raw(line, line_size, &pos, ",\"private_bytes\":");
        append_u64(line, line_size, &pos, private_bytes);
        append_raw(line, line_size, &pos, ",\"peak_working_set_bytes\":");
        append_u64(line, line_size, &pos, peak_working_set_bytes);
        append_raw(line, line_size, &pos, ",\"peak_private_bytes\":");
        append_u64(line, line_size, &pos, peak_private_bytes);
        append_char(line, line_size, &pos, '}');
    } else {
        append_raw(line, line_size, &pos, "ASTRO_CBM_PIPELINE_PHASE_TRACE event=");
        append_raw(line, line_size, &pos, boundary ? boundary : "");
        append_raw(line, line_size, &pos, " phase=");
        append_raw(line, line_size, &pos, phase ? phase : "");
        append_raw(line, line_size, &pos, " pid=");
        append_u64(line, line_size, &pos, pid);
        append_raw(line, line_size, &pos, " mode=");
        append_i64(line, line_size, &pos, mode);
        append_raw(line, line_size, &pos, " row_sink_active=");
        append_i64(line, line_size, &pos, row_sink_active ? 1 : 0);
        append_raw(line, line_size, &pos, " row_sink_completed=");
        append_i64(line, line_size, &pos, row_sink_completed ? 1 : 0);
        append_raw(line, line_size, &pos, " nodes=");
        append_i64(line, line_size, &pos, nodes);
        append_raw(line, line_size, &pos, " edges=");
        append_i64(line, line_size, &pos, edges);
        append_raw(line, line_size, &pos, " memory_valid=");
        append_i64(line, line_size, &pos, memory_valid ? 1 : 0);
        append_raw(line, line_size, &pos, " working_set_bytes=");
        append_u64(line, line_size, &pos, working_set_bytes);
        append_raw(line, line_size, &pos, " private_bytes=");
        append_u64(line, line_size, &pos, private_bytes);
        append_raw(line, line_size, &pos, " peak_working_set_bytes=");
        append_u64(line, line_size, &pos, peak_working_set_bytes);
        append_raw(line, line_size, &pos, " peak_private_bytes=");
        append_u64(line, line_size, &pos, peak_private_bytes);
    }
    finish_line(line, line_size, pos);
    return pos;
}

void cbm_log_pipeline_phase_trace(const char *boundary, const char *phase, uint64_t pid,
                                  int mode, bool row_sink_active, bool row_sink_completed,
                                  int nodes, int edges, bool memory_valid,
                                  uint64_t working_set_bytes, uint64_t private_bytes,
                                  uint64_t peak_working_set_bytes,
                                  uint64_t peak_private_bytes) {
    log_lock();
    char stack_line[CBM_SZ_1K];
    size_t line_len = format_pipeline_phase_trace_line(
        stack_line, sizeof(stack_line), boundary, phase, pid, mode, row_sink_active,
        row_sink_completed, nodes, edges, memory_valid, working_set_bytes, private_bytes,
        peak_working_set_bytes, peak_private_bytes);
    if (line_len == SIZE_MAX) {
        emit_internal_failure_locked(
            "pipeline.phase_trace_failed", "CBM_LOG_LENGTH_OVERFLOW", "pipeline.phase_trace",
            false, 0, "the pipeline phase trace length overflowed size_t",
            "reduce the diagnostic field sizes and retry");
        log_unlock();
        return;
    }
    if (line_len < sizeof(stack_line)) {
        emit_pipeline_phase_line_locked(stack_line);
        log_unlock();
        return;
    }
    char *dynamic_line = malloc(line_len + 1);
    if (!dynamic_line) {
        emit_internal_failure_locked(
            "pipeline.phase_trace_failed", "CBM_LOG_ALLOCATION_FAILED", "pipeline.phase_trace",
            true, line_len + 1, "the pipeline phase trace buffer allocation failed",
            "free memory and retry");
        log_unlock();
        return;
    }
    size_t written = format_pipeline_phase_trace_line(
        dynamic_line, line_len + 1, boundary, phase, pid, mode, row_sink_active,
        row_sink_completed, nodes, edges, memory_valid, working_set_bytes, private_bytes,
        peak_working_set_bytes, peak_private_bytes);
    if (written != line_len) {
        free(dynamic_line);
        emit_internal_failure_locked(
            "pipeline.phase_trace_failed", "CBM_LOG_FORMAT_LENGTH_MISMATCH",
            "pipeline.phase_trace", false, 0,
            "the pipeline phase trace changed between format passes",
            "inspect the diagnostic formatter inputs and retry");
        log_unlock();
        return;
    }
    emit_pipeline_phase_line_locked(dynamic_line);
    free(dynamic_line);
    log_unlock();
}

static size_t format_log_line(char *line_buf, size_t line_size, CBMLogLevel level, const char *msg,
                              va_list args) {
    size_t pos = 0;
    if (g_log_format == CBM_LOG_FORMAT_JSON) {
        append_raw(line_buf, line_size, &pos, "{\"level\":");
        append_json_string(line_buf, line_size, &pos, level_str(level));
        append_raw(line_buf, line_size, &pos, ",\"event\":");
        append_json_string(line_buf, line_size, &pos, msg ? msg : "");
        for (;;) {
            const char *key = va_arg(args, const char *);
            if (!key) {
                break;
            }
            const char *val = va_arg(args, const char *);
            append_char(line_buf, line_size, &pos, ',');
            append_json_string(line_buf, line_size, &pos, key);
            append_char(line_buf, line_size, &pos, ':');
            append_json_string(line_buf, line_size, &pos, val ? val : "");
        }
        append_char(line_buf, line_size, &pos, '}');
    } else {
        append_raw(line_buf, line_size, &pos, "level=");
        append_text_atom(line_buf, line_size, &pos, level_str(level));
        append_raw(line_buf, line_size, &pos, " msg=");
        append_text_atom(line_buf, line_size, &pos, msg ? msg : "");
        for (;;) {
            const char *key = va_arg(args, const char *);
            if (!key) {
                break;
            }
            const char *val = va_arg(args, const char *);
            append_char(line_buf, line_size, &pos, ' ');
            append_text_atom(line_buf, line_size, &pos, key);
            append_char(line_buf, line_size, &pos, '=');
            append_text_atom(line_buf, line_size, &pos, val ? val : "");
        }
    }
    finish_line(line_buf, line_size, pos);
    return pos;
}

void cbm_log(CBMLogLevel level, const char *msg, ...) {
    log_lock();
    if (level < g_log_level) {
        log_unlock();
        return;
    }

    char stack_line[CBM_SZ_4K];
    va_list args;
    va_start(args, msg);
    va_list stack_args;
    va_copy(stack_args, args);
    size_t line_len = format_log_line(stack_line, sizeof(stack_line), level, msg, stack_args);
    va_end(stack_args);
    if (line_len == SIZE_MAX) {
        va_end(args);
        emit_internal_failure_locked(
            "log.length_overflow", "CBM_LOG_LENGTH_OVERFLOW", msg, false, 0,
            "the structured diagnostic length overflowed size_t",
            "reduce the diagnostic field sizes and retry");
        log_unlock();
        return;
    }
    if (line_len < sizeof(stack_line)) {
        va_end(args);
        emit_line_locked(stack_line);
        log_unlock();
        return;
    }
    char *line_buf = malloc(line_len + 1);
    if (!line_buf) {
        va_end(args);
        emit_internal_failure_locked(
            "log.allocation_failed", "CBM_LOG_ALLOCATION_FAILED", msg, true, line_len + 1,
            "the structured diagnostic buffer allocation failed", "free memory and retry");
        log_unlock();
        return;
    }
    size_t written = format_log_line(line_buf, line_len + 1, level, msg, args);
    va_end(args);

    if (written != line_len) {
        free(line_buf);
        emit_internal_failure_locked(
            "log.format_length_mismatch", "CBM_LOG_FORMAT_LENGTH_MISMATCH", msg, false, 0,
            "the structured diagnostic changed between format passes",
            "inspect the variadic log arguments and retry");
        log_unlock();
        return;
    }
    emit_line_locked(line_buf);
    free(line_buf);
    log_unlock();
}

void cbm_log_int(CBMLogLevel level, const char *msg, const char *key, int64_t value) {
    char value_buf[CBM_SZ_32];
    snprintf(value_buf, sizeof(value_buf), "%" PRId64, value);
    cbm_log(level, msg, key ? key : "?", value_buf, NULL);
}

static void copy_path_without_query(const char *path, char *out, size_t outsz) {
    if (!out || outsz == 0) {
        return;
    }
    out[0] = '\0';
    if (!path) {
        return;
    }
    size_t n = 0;
    while (path[n] && path[n] != '?' && path[n] != '#' && n < outsz - 1) {
        out[n] = path[n];
        n++;
    }
    out[n] = '\0';
}

void cbm_log_mcp_request(const char *method, const char *tool_name, bool is_error,
                         int64_t duration_us) {
    char duration_ms[CBM_SZ_32];
    snprintf(duration_ms, sizeof(duration_ms), "%" PRId64, duration_us / 1000);
    if (tool_name && tool_name[0] != '\0') {
        cbm_log(is_error ? CBM_LOG_WARN : CBM_LOG_INFO, "mcp.request", "protocol", "jsonrpc",
                "method", method ? method : "", "tool", tool_name, "status",
                is_error ? "error" : "ok", "duration_ms", duration_ms, NULL);
    } else {
        cbm_log(is_error ? CBM_LOG_WARN : CBM_LOG_INFO, "mcp.request", "protocol", "jsonrpc",
                "method", method ? method : "", "status", is_error ? "error" : "ok", "duration_ms",
                duration_ms, NULL);
    }
}

void cbm_log_http_request(const char *component, const char *method, const char *path, int status,
                          int64_t duration_ms, size_t request_bytes, size_t response_bytes) {
    char safe_path[CBM_SZ_1K];
    char status_buf[CBM_SZ_16];
    char duration_buf[CBM_SZ_32];
    char request_buf[CBM_SZ_32];
    char response_buf[CBM_SZ_32];
    copy_path_without_query(path, safe_path, sizeof(safe_path));
    snprintf(status_buf, sizeof(status_buf), "%d", status);
    snprintf(duration_buf, sizeof(duration_buf), "%" PRId64, duration_ms);
    snprintf(request_buf, sizeof(request_buf), "%zu", request_bytes);
    snprintf(response_buf, sizeof(response_buf), "%zu", response_bytes);

    CBMLogLevel level = CBM_LOG_INFO;
    if (status >= 500) {
        level = CBM_LOG_ERROR;
    } else if (status >= 400) {
        level = CBM_LOG_WARN;
    }

    cbm_log(level, "http.request", "component", component ? component : "", "method",
            method ? method : "", "path", safe_path, "status", status_buf, "duration_ms",
            duration_buf, "request_bytes", request_buf, "response_bytes", response_buf, NULL);
}
