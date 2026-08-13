/*
 * env_store_config.c — Astrolabe-owned store configuration for libcbm (#240/#241).
 *
 * See env_store_config.h for the two defects this repairs and why the repair
 * lives in Astrolabe-owned C rather than in the pinned vendor tree.
 */
#include "env_store_config.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "foundation/constants.h"
#include "foundation/log.h"

/* Standing invariant 4: the store-path capacity is a measurement of CBM's own
 * result buffer, not a constant somebody chose. If upstream resizes it, this
 * translation unit fails to compile rather than silently truncating a path. */
_Static_assert(CBM_ASTRO_STORE_PATH_CAP == CBM_SZ_1K,
               "CBM_ASTRO_STORE_PATH_CAP must equal the CBM_SZ_1K result buffer that "
               "cbm_resolve_cache_dir() and cbm_get_home_dir() publish");

/* Longest environment variable name CBM reads is CBM_UI_MAX_RENDER_NODES (23
 * bytes); 64 leaves headroom without a heap allocation on a refusal path. */
#define CBM_ASTRO_ENV_NAME_CAP 64
/* A remediation names the variable and the two byte counts; 512 holds the
 * longest envelope this file can build with room to spare. */
#define CBM_ASTRO_ENV_TEXT_CAP 512

static atomic_flag g_astro_env_lock = ATOMIC_FLAG_INIT;

static void astro_env_lock(void) {
    while (atomic_flag_test_and_set_explicit(&g_astro_env_lock, memory_order_acquire)) {
        /* Contention is bounded by the handful of store resolves a process
         * performs; a spinlock keeps this TU free of platform mutex deps. */
    }
}

static void astro_env_unlock(void) {
    atomic_flag_clear_explicit(&g_astro_env_lock, memory_order_release);
}

static char g_override[CBM_ASTRO_STORE_PATH_CAP];
static bool g_override_set;

static char g_fault_var[CBM_ASTRO_ENV_NAME_CAP];
static char g_fault_code[CBM_ASTRO_ENV_NAME_CAP];
static char g_fault_message[CBM_ASTRO_ENV_TEXT_CAP];
static char g_fault_remediation[CBM_ASTRO_ENV_TEXT_CAP];
static atomic_int g_faulted;

/* Copy `src` into `dst` (capacity `cap`), reporting truncation instead of
 * hiding it. Every writer below treats a true return as a programming error and
 * refuses; nothing in this file may ever emit a silently shortened string. */
static bool astro_copy_truncated(char *dst, size_t cap, const char *src) {
    int written = snprintf(dst, cap, "%s", src ? src : "");
    if (written < 0 || (size_t)written >= cap) {
        dst[0] = '\0';
        return true;
    }
    return false;
}

/* Store a fault under the lock, once per distinct (code, var) pair: the resolvers
 * are called per operation, and a refusal that repeats on every call is noise, not
 * signal. Returns non-zero when this call is the one that newly published it, so
 * the caller can emit the envelope AFTER releasing the lock. Emission must not
 * happen under the lock: it calls cbm_log_error, and any environment read the log
 * path performs would re-enter this module and deadlock a non-recursive spinlock. */
static int astro_env_store_fault(const char *code, const char *var, const char *message,
                                 const char *remediation) {
    astro_env_lock();
    if (atomic_load_explicit(&g_faulted, memory_order_relaxed) != 0 &&
        strncmp(g_fault_code, code, sizeof(g_fault_code)) == 0 &&
        strncmp(g_fault_var, var, sizeof(g_fault_var)) == 0) {
        astro_env_unlock();
        return 0; /* already published, identical fault */
    }

    if (astro_copy_truncated(g_fault_code, sizeof(g_fault_code), code) ||
        astro_copy_truncated(g_fault_var, sizeof(g_fault_var), var) ||
        astro_copy_truncated(g_fault_message, sizeof(g_fault_message), message) ||
        astro_copy_truncated(g_fault_remediation, sizeof(g_fault_remediation), remediation)) {
        /* The envelope itself did not fit. Refuse with a fixed, always-representable
         * envelope rather than publishing a truncated diagnostic. */
        (void)snprintf(g_fault_code, sizeof(g_fault_code), "%s", "CBM_E_ENV_FAULT_UNREPRESENTABLE");
        (void)snprintf(g_fault_var, sizeof(g_fault_var), "%s", "?");
        (void)snprintf(g_fault_message, sizeof(g_fault_message), "%s",
                       "a store-configuration fault envelope exceeded its own buffer");
        (void)snprintf(g_fault_remediation, sizeof(g_fault_remediation), "%s",
                       "Shorten the environment variable name or store path and retry.");
    }
    atomic_store_explicit(&g_faulted, 1, memory_order_release);
    astro_env_unlock();
    return 1;
}

/* Emit the currently-stored envelope. Called with NO lock held. Reads a stable
 * snapshot of the fault strings under the lock, then logs and prints outside it. */
static void astro_env_emit(void) {
    char code[CBM_ASTRO_ENV_NAME_CAP];
    char var[CBM_ASTRO_ENV_NAME_CAP];
    char message[CBM_ASTRO_ENV_TEXT_CAP];
    char remediation[CBM_ASTRO_ENV_TEXT_CAP];
    astro_env_lock();
    (void)snprintf(code, sizeof(code), "%s", g_fault_code);
    (void)snprintf(var, sizeof(var), "%s", g_fault_var);
    (void)snprintf(message, sizeof(message), "%s", g_fault_message);
    (void)snprintf(remediation, sizeof(remediation), "%s", g_fault_remediation);
    astro_env_unlock();

    cbm_log_error("store.env.fault", "code", code, "var", var, "message", message, "remediation",
                  remediation);
    /* A fail-closed refusal must stay visible even when the host silences the CBM
     * log sink (astrolabe-bridge does exactly that in silent mode). */
    (void)fprintf(stderr, "ERROR[%s]: %s\n  remediation: %s\n", code, message, remediation);
    (void)fflush(stderr);
}

void cbm_astro_env_record_fault(const char *code, const char *var, const char *message,
                                const char *remediation) {
    if (astro_env_store_fault(code ? code : "CBM_E_ENV_FAULT", var ? var : "?",
                              message ? message : "", remediation ? remediation : "")) {
        astro_env_emit();
    }
}

void cbm_astro_env_record_unresolvable_store(void) {
    cbm_astro_env_record_fault(
        "CBM_E_STORE_UNRESOLVABLE", "CBM_CACHE_DIR",
        "no CBM store could be resolved: no explicit override was configured, CBM_CACHE_DIR is "
        "unset, and neither HOME nor USERPROFILE names a directory",
        "Configure the store explicitly with cbm_astro_set_cache_dir(), or set CBM_CACHE_DIR (or "
        "HOME/USERPROFILE) to a writable absolute directory before starting CBM.");
}

void cbm_astro_env_record_truncation(const char *name, size_t needed, size_t capacity) {
    const char *var = name ? name : "?";
    char message[CBM_ASTRO_ENV_TEXT_CAP];
    char remediation[CBM_ASTRO_ENV_TEXT_CAP];

    (void)snprintf(message, sizeof(message),
                   "environment variable %.*s holds %zu bytes but CBM reads it into a %zu-byte "
                   "buffer; a truncated value would resolve a different path than the one "
                   "configured",
                   (int)CBM_ASTRO_ENV_NAME_CAP - 1, var, needed, capacity);
    (void)snprintf(remediation, sizeof(remediation),
                   "Set %.*s to a value shorter than %zu bytes, or configure the CBM store "
                   "explicitly with cbm_astro_set_cache_dir() instead of through the environment.",
                   (int)CBM_ASTRO_ENV_NAME_CAP - 1, var, capacity);

    cbm_astro_env_record_fault("CBM_E_ENV_VALUE_TRUNCATED", var, message, remediation);
}

int cbm_astro_env_faulted_for(const char *name) {
    if (!name || atomic_load_explicit(&g_faulted, memory_order_acquire) == 0) {
        return 0;
    }
    astro_env_lock();
    int matched = (strncmp(g_fault_var, name, sizeof(g_fault_var)) == 0) ? 1 : 0;
    astro_env_unlock();
    return matched;
}

const char *cbm_astro_env_fault_code(void) {
    if (atomic_load_explicit(&g_faulted, memory_order_acquire) == 0) {
        return NULL;
    }
    return g_fault_code;
}

const char *cbm_astro_env_fault_message(void) {
    if (atomic_load_explicit(&g_faulted, memory_order_acquire) == 0) {
        return NULL;
    }
    return g_fault_message;
}

const char *cbm_astro_env_fault_remediation(void) {
    if (atomic_load_explicit(&g_faulted, memory_order_acquire) == 0) {
        return NULL;
    }
    return g_fault_remediation;
}

void cbm_astro_env_fault_clear(void) {
    astro_env_lock();
    g_fault_code[0] = '\0';
    g_fault_var[0] = '\0';
    g_fault_message[0] = '\0';
    g_fault_remediation[0] = '\0';
    atomic_store_explicit(&g_faulted, 0, memory_order_release);
    astro_env_unlock();
}

int cbm_astro_set_cache_dir(const char *path) {
    if (!path) {
        cbm_astro_env_record_fault("CBM_E_CACHE_DIR_NULL", "CBM_CACHE_DIR",
                                   "cbm_astro_set_cache_dir received a NULL store path",
                                   "Pass an absolute store path, or call "
                                   "cbm_astro_clear_cache_dir() to restore the default "
                                   "resolution order.");
        return 1;
    }
    if (path[0] == '\0') {
        cbm_astro_env_record_fault("CBM_E_CACHE_DIR_EMPTY", "CBM_CACHE_DIR",
                                   "cbm_astro_set_cache_dir received an empty store path, which "
                                   "would resolve the store against the process working directory",
                                   "Pass an absolute store path, or call "
                                   "cbm_astro_clear_cache_dir() to restore the default "
                                   "resolution order.");
        return 1;
    }

    size_t length = strlen(path);
    if (length >= CBM_ASTRO_STORE_PATH_CAP) {
        char message[CBM_ASTRO_ENV_TEXT_CAP];
        char remediation[CBM_ASTRO_ENV_TEXT_CAP];
        (void)snprintf(message, sizeof(message),
                       "store path is %zu bytes; CBM publishes resolved store paths from a "
                       "%d-byte buffer and cannot represent it",
                       length, CBM_ASTRO_STORE_PATH_CAP);
        (void)snprintf(remediation, sizeof(remediation),
                       "Point the CBM store at an absolute path shorter than %d bytes.",
                       CBM_ASTRO_STORE_PATH_CAP);
        cbm_astro_env_record_fault("CBM_E_CACHE_DIR_TOO_LONG", "CBM_CACHE_DIR", message,
                                   remediation);
        return 1;
    }

    astro_env_lock();
    bool truncated = astro_copy_truncated(g_override, sizeof(g_override), path);
    g_override_set = !truncated;
    astro_env_unlock();
    if (truncated) {
        /* Unreachable: the length check above already rejected an unrepresentable
         * path. Kept as a fail-closed backstop so no truncated override can ever
         * become the store. */
        cbm_astro_env_record_fault("CBM_E_CACHE_DIR_TOO_LONG", "CBM_CACHE_DIR",
                                   "store path did not fit the override buffer",
                                   "Point the CBM store at a shorter absolute path.");
        return 1;
    }
    return 0;
}

void cbm_astro_clear_cache_dir(void) {
    astro_env_lock();
    g_override[0] = '\0';
    g_override_set = false;
    astro_env_unlock();
}

const char *cbm_astro_cache_dir_override(void) {
    astro_env_lock();
    bool active = g_override_set;
    astro_env_unlock();
    return active ? g_override : NULL;
}
