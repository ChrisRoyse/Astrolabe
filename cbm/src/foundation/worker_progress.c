#include "worker_progress.h"

#include "compat_fs.h"
#include "compat_thread.h"
#include "log.h"
#include "platform.h"
#include "sha256.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define progress_seek _fseeki64
#define progress_tell _ftelli64
typedef __int64 progress_offset_t;
#else
#include <sys/types.h>
#define progress_seek fseeko
#define progress_tell ftello
typedef off_t progress_offset_t;
#endif

enum {
    PROGRESS_OFF_MAGIC = 0,
    PROGRESS_OFF_VERSION = 8,
    PROGRESS_OFF_SIZE = 12,
    PROGRESS_OFF_ATTEMPT = 16,
    PROGRESS_OFF_SEQUENCE = 80,
    PROGRESS_OFF_MONOTONIC_MS = 88,
    PROGRESS_OFF_STAGE_ORDER = 96,
    PROGRESS_OFF_STEP_ORDER = 100,
    PROGRESS_OFF_COMPLETED = 104,
    PROGRESS_OFF_TOTAL = 112,
    PROGRESS_OFF_STEP_COMPLETED = 120,
    PROGRESS_OFF_STEP_TOTAL = 128,
    PROGRESS_OFF_STAGE = 136,
    PROGRESS_OFF_STEP = 168,
    PROGRESS_OFF_PREVIOUS_HASH = 200,
    PROGRESS_OFF_RECORD_HASH = 232,
    PROGRESS_OFF_RESERVED = 264,
    PROGRESS_HASHED_BYTES = PROGRESS_OFF_RECORD_HASH,
    PROGRESS_RESERVED_BYTES = CBM_WORKER_PROGRESS_RECORD_SIZE - PROGRESS_OFF_RESERVED,
    PROGRESS_SCHEMA_VERSION = 1,
};

static const uint8_t PROGRESS_MAGIC[8] = {'A', 'S', 'T', 'R', 'P', 'R', 'G', '1'};

static const char *progress_stage_name(uint32_t stage_order) {
    switch (stage_order) {
    case CBM_WORKER_PROGRESS_STAGE_STARTUP:
        return "startup";
    case CBM_WORKER_PROGRESS_STAGE_DISCOVERY:
        return "discovery";
    case CBM_WORKER_PROGRESS_STAGE_SOURCE_CAPTURE:
        return "source_capture";
    case CBM_WORKER_PROGRESS_STAGE_STRUCTURE:
        return "structure";
    case CBM_WORKER_PROGRESS_STAGE_PARALLEL_EXTRACT:
        return "parallel_extract";
    case CBM_WORKER_PROGRESS_STAGE_COMPILER_PREPROCESS:
        return "compiler_preprocess";
    case CBM_WORKER_PROGRESS_STAGE_REGISTRY:
        return "registry";
    case CBM_WORKER_PROGRESS_STAGE_RESOLVE:
        return "resolve";
    case CBM_WORKER_PROGRESS_STAGE_ENRICH:
        return "enrich";
    case CBM_WORKER_PROGRESS_STAGE_PREDUMP:
        return "predump";
    case CBM_WORKER_PROGRESS_STAGE_PERSIST:
        return "persist";
    case CBM_WORKER_PROGRESS_STAGE_COMPLETE:
        return "complete";
    default:
        return NULL;
    }
}

typedef struct {
    bool present;
    uint64_t sequence;
    uint64_t monotonic_ms;
    uint32_t stage_order;
    uint32_t step_order;
    uint64_t completed;
    uint64_t total;
    uint64_t step_completed;
    uint64_t step_total;
    char stage[CBM_WORKER_PROGRESS_NAME_CAP];
    char step[CBM_WORKER_PROGRESS_NAME_CAP];
    uint8_t record_hash[CBM_SHA256_DIGEST_LEN];
} progress_cursor_t;

typedef struct {
    cbm_mutex_t mutex;
    bool mutex_live;
    FILE *stream;
    char path[1200];
    char attempt[CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN + 1];
    progress_cursor_t cursor;
    uint32_t unit_stage_order;
    char unit_stage[CBM_WORKER_PROGRESS_NAME_CAP];
    uint64_t unit_completed;
    uint64_t unit_total;
    uint64_t unit_last_published_ms;
    atomic_bool active;
    atomic_bool failed;
} progress_writer_t;

static progress_writer_t g_writer = {
    .active = ATOMIC_VAR_INIT(false),
    .failed = ATOMIC_VAR_INIT(false),
};

struct cbm_worker_progress_reader {
    char path[1200];
    char attempt[CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN + 1];
    FILE *stream;
    progress_offset_t consumed;
    progress_cursor_t cursor;
    cbm_sha256_ctx stream_hash;
    char error_code[96];
    char error_detail[512];
};

static void put_u32(uint8_t *bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) {
        bytes[i] = (uint8_t)(value >> (i * 8U));
    }
}

static void put_u64(uint8_t *bytes, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)(value >> (i * 8U));
    }
}

static uint32_t get_u32(const uint8_t *bytes) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; i++) {
        value |= (uint32_t)bytes[i] << (i * 8U);
    }
    return value;
}

static uint64_t get_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) {
        value |= (uint64_t)bytes[i] << (i * 8U);
    }
    return value;
}

static bool lowercase_hex_exact(const char *value, size_t length) {
    if (!value || strlen(value) != length) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool progress_name_valid(const char *name) {
    if (!name || !name[0]) {
        return false;
    }
    size_t length = strlen(name);
    if (length >= CBM_WORKER_PROGRESS_NAME_CAP) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
              c == '-')) {
            return false;
        }
    }
    return true;
}

static bool progress_stage_valid(uint32_t order, const char *stage) {
    const char *expected = progress_stage_name(order);
    return expected && stage && strcmp(expected, stage) == 0;
}

static bool decode_name(const uint8_t *bytes, char out[CBM_WORKER_PROGRESS_NAME_CAP]) {
    size_t nul = 0;
    while (nul < CBM_WORKER_PROGRESS_NAME_CAP && bytes[nul] != 0) {
        nul++;
    }
    if (nul == 0 || nul == CBM_WORKER_PROGRESS_NAME_CAP) {
        return false;
    }
    for (size_t i = nul + 1; i < CBM_WORKER_PROGRESS_NAME_CAP; i++) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    memcpy(out, bytes, nul);
    out[nul] = '\0';
    return progress_name_valid(out);
}

static bool cursor_advances(const progress_cursor_t *previous,
                            const progress_cursor_t *current) {
    if (!previous->present) {
        return true;
    }
    if (current->stage_order < previous->stage_order) {
        return false;
    }
    if (current->stage_order > previous->stage_order) {
        return true;
    }
    if (strcmp(current->stage, previous->stage) != 0 || current->total != previous->total ||
        current->completed < previous->completed) {
        return false;
    }
    if (current->completed > previous->completed) {
        return true;
    }
    if (current->step_order < previous->step_order) {
        return false;
    }
    if (current->step_order > previous->step_order) {
        return true;
    }
    return strcmp(current->step, previous->step) == 0 &&
           current->step_total == previous->step_total &&
           current->step_completed > previous->step_completed;
}

static void reader_fail(cbm_worker_progress_reader_t *reader, const char *code,
                        const char *detail) {
    if (!reader || reader->error_code[0]) {
        return;
    }
    snprintf(reader->error_code, sizeof(reader->error_code), "%s", code ? code : "");
    snprintf(reader->error_detail, sizeof(reader->error_detail), "%s", detail ? detail : "");
    cbm_log_error("index.supervisor.progress_protocol", "code", reader->error_code, "path",
                  reader->path, "attempt", reader->attempt, "message", reader->error_detail,
                  "remediation",
                  "preserve the worker workspace and repair the exact progress producer/consumer "
                  "contract before retrying the unchanged repository");
}

static bool decode_record(const uint8_t record[CBM_WORKER_PROGRESS_RECORD_SIZE],
                          const char *attempt, const progress_cursor_t *previous,
                          progress_cursor_t *decoded, const char **code, char *detail,
                          size_t detail_capacity) {
    memset(decoded, 0, sizeof(*decoded));
    *code = "CBM_INDEX_WORKER_PROGRESS_RECORD_INVALID";
    if (memcmp(record + PROGRESS_OFF_MAGIC, PROGRESS_MAGIC, sizeof(PROGRESS_MAGIC)) != 0 ||
        get_u32(record + PROGRESS_OFF_VERSION) != PROGRESS_SCHEMA_VERSION ||
        get_u32(record + PROGRESS_OFF_SIZE) != CBM_WORKER_PROGRESS_RECORD_SIZE) {
        *code = "CBM_INDEX_WORKER_PROGRESS_SCHEMA_INVALID";
        snprintf(detail, detail_capacity, "record schema magic/version/size is invalid");
        return false;
    }
    if (memcmp(record + PROGRESS_OFF_ATTEMPT, attempt,
               CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN) != 0) {
        *code = "CBM_INDEX_WORKER_PROGRESS_ATTEMPT_MISMATCH";
        snprintf(detail, detail_capacity, "record belongs to a foreign worker attempt");
        return false;
    }
    for (size_t i = 0; i < PROGRESS_RESERVED_BYTES; i++) {
        if (record[PROGRESS_OFF_RESERVED + i] != 0) {
            *code = "CBM_INDEX_WORKER_PROGRESS_RESERVED_INVALID";
            snprintf(detail, detail_capacity, "record reserved bytes are nonzero");
            return false;
        }
    }
    uint8_t hash[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_ctx hash_ctx;
    cbm_sha256_init(&hash_ctx);
    cbm_sha256_update(&hash_ctx, record, PROGRESS_HASHED_BYTES);
    cbm_sha256_final(&hash_ctx, hash);
    if (memcmp(hash, record + PROGRESS_OFF_RECORD_HASH, sizeof(hash)) != 0) {
        *code = "CBM_INDEX_WORKER_PROGRESS_HASH_MISMATCH";
        snprintf(detail, detail_capacity, "record SHA-256 does not match its encoded bytes");
        return false;
    }
    uint8_t zero_hash[CBM_SHA256_DIGEST_LEN] = {0};
    const uint8_t *expected_previous = previous->present ? previous->record_hash : zero_hash;
    if (memcmp(record + PROGRESS_OFF_PREVIOUS_HASH, expected_previous,
               CBM_SHA256_DIGEST_LEN) != 0) {
        *code = "CBM_INDEX_WORKER_PROGRESS_CHAIN_INVALID";
        snprintf(detail, detail_capacity, "record hash chain is discontinuous");
        return false;
    }

    decoded->present = true;
    decoded->sequence = get_u64(record + PROGRESS_OFF_SEQUENCE);
    decoded->monotonic_ms = get_u64(record + PROGRESS_OFF_MONOTONIC_MS);
    decoded->stage_order = get_u32(record + PROGRESS_OFF_STAGE_ORDER);
    decoded->step_order = get_u32(record + PROGRESS_OFF_STEP_ORDER);
    decoded->completed = get_u64(record + PROGRESS_OFF_COMPLETED);
    decoded->total = get_u64(record + PROGRESS_OFF_TOTAL);
    decoded->step_completed = get_u64(record + PROGRESS_OFF_STEP_COMPLETED);
    decoded->step_total = get_u64(record + PROGRESS_OFF_STEP_TOTAL);
    memcpy(decoded->record_hash, record + PROGRESS_OFF_RECORD_HASH, CBM_SHA256_DIGEST_LEN);
    if (!decode_name(record + PROGRESS_OFF_STAGE, decoded->stage) ||
        !decode_name(record + PROGRESS_OFF_STEP, decoded->step)) {
        *code = "CBM_INDEX_WORKER_PROGRESS_NAME_INVALID";
        snprintf(detail, detail_capacity, "stage or step name is malformed");
        return false;
    }
    uint64_t expected_sequence = previous->present ? previous->sequence + 1U : 1U;
    if ((previous->present && previous->sequence == UINT64_MAX) ||
        decoded->sequence != expected_sequence ||
        !progress_stage_valid(decoded->stage_order, decoded->stage) ||
        decoded->step_order == 0 || decoded->total == 0 || decoded->completed > decoded->total ||
        decoded->step_total == 0 || decoded->step_completed > decoded->step_total) {
        *code = "CBM_INDEX_WORKER_PROGRESS_CURSOR_INVALID";
        snprintf(detail, detail_capacity, "record sequence/order/count fields are impossible");
        return false;
    }
    if (!previous->present &&
        (decoded->stage_order != CBM_WORKER_PROGRESS_STAGE_STARTUP || decoded->completed != 1 ||
         decoded->total != 1)) {
        *code = "CBM_INDEX_WORKER_PROGRESS_STARTUP_MISSING";
        snprintf(detail, detail_capacity,
                 "the first record is not the exact completed startup boundary");
        return false;
    }
    if (previous->present && previous->stage_order == CBM_WORKER_PROGRESS_STAGE_COMPLETE) {
        *code = "CBM_INDEX_WORKER_PROGRESS_AFTER_COMPLETE";
        snprintf(detail, detail_capacity, "a record follows the terminal completion boundary");
        return false;
    }
    if (previous->present && decoded->monotonic_ms < previous->monotonic_ms) {
        *code = "CBM_INDEX_WORKER_PROGRESS_CLOCK_REGRESSED";
        snprintf(detail, detail_capacity, "worker monotonic observation regressed");
        return false;
    }
    if (!cursor_advances(previous, decoded)) {
        *code = "CBM_INDEX_WORKER_PROGRESS_CURSOR_REGRESSED";
        snprintf(detail, detail_capacity, "semantic work cursor did not advance monotonically");
        return false;
    }
    return true;
}

static int writer_publish_locked(uint32_t stage_order, const char *stage, uint64_t completed,
                                 uint64_t total, uint32_t step_order, const char *step,
                                 uint64_t step_completed, uint64_t step_total) {
    if (!g_writer.stream || atomic_load_explicit(&g_writer.failed, memory_order_acquire) ||
        (g_writer.cursor.present && g_writer.cursor.sequence == UINT64_MAX) ||
        !progress_name_valid(stage) || !progress_name_valid(step) ||
        !progress_stage_name(stage_order) || strcmp(stage, progress_stage_name(stage_order)) != 0 ||
        step_order == 0 || total == 0 || completed > total || step_total == 0 ||
        step_completed > step_total) {
        return -1;
    }
    uint8_t record[CBM_WORKER_PROGRESS_RECORD_SIZE] = {0};
    memcpy(record + PROGRESS_OFF_MAGIC, PROGRESS_MAGIC, sizeof(PROGRESS_MAGIC));
    put_u32(record + PROGRESS_OFF_VERSION, PROGRESS_SCHEMA_VERSION);
    put_u32(record + PROGRESS_OFF_SIZE, CBM_WORKER_PROGRESS_RECORD_SIZE);
    memcpy(record + PROGRESS_OFF_ATTEMPT, g_writer.attempt,
           CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN);
    put_u64(record + PROGRESS_OFF_SEQUENCE,
            g_writer.cursor.present ? g_writer.cursor.sequence + 1U : 1U);
    put_u64(record + PROGRESS_OFF_MONOTONIC_MS, cbm_now_ms());
    put_u32(record + PROGRESS_OFF_STAGE_ORDER, stage_order);
    put_u32(record + PROGRESS_OFF_STEP_ORDER, step_order);
    put_u64(record + PROGRESS_OFF_COMPLETED, completed);
    put_u64(record + PROGRESS_OFF_TOTAL, total);
    put_u64(record + PROGRESS_OFF_STEP_COMPLETED, step_completed);
    put_u64(record + PROGRESS_OFF_STEP_TOTAL, step_total);
    memcpy(record + PROGRESS_OFF_STAGE, stage, strlen(stage));
    memcpy(record + PROGRESS_OFF_STEP, step, strlen(step));
    if (g_writer.cursor.present) {
        memcpy(record + PROGRESS_OFF_PREVIOUS_HASH, g_writer.cursor.record_hash,
               CBM_SHA256_DIGEST_LEN);
    }
    cbm_sha256_ctx hash_ctx;
    cbm_sha256_init(&hash_ctx);
    cbm_sha256_update(&hash_ctx, record, PROGRESS_HASHED_BYTES);
    cbm_sha256_final(&hash_ctx, record + PROGRESS_OFF_RECORD_HASH);

    progress_cursor_t decoded;
    const char *decode_code = NULL;
    char detail[256];
    if (!decode_record(record, g_writer.attempt, &g_writer.cursor, &decoded, &decode_code, detail,
                       sizeof(detail))) {
        return -1;
    }
    size_t written = fwrite(record, 1, sizeof(record), g_writer.stream);
    if (written != sizeof(record) || fflush(g_writer.stream) != 0) {
        return -1;
    }
    g_writer.cursor = decoded;
    return 0;
}

static void writer_mark_failed(const char *operation) {
    if (atomic_exchange_explicit(&g_writer.failed, true, memory_order_acq_rel)) {
        return;
    }
    cbm_log_error("index.worker.progress_write_failed", "code",
                  "CBM_INDEX_WORKER_PROGRESS_WRITE_FAILED", "operation", operation, "path",
                  g_writer.path, "attempt", g_writer.attempt, "message",
                  "the worker could not publish a validated semantic progress record",
                  "remediation",
                  "preserve the worker workspace, repair the exact file or protocol failure, and "
                  "retry the unchanged repository");
}

/* Clear only ordinary state. Atomics are updated through their API and the
 * mutex object is initialized/destroyed explicitly; byte-zeroing either object
 * after it has entered its lifetime is not a portable reset operation. */
static void writer_clear_ordinary_state(void) {
    g_writer.stream = NULL;
    g_writer.path[0] = '\0';
    g_writer.attempt[0] = '\0';
    memset(&g_writer.cursor, 0, sizeof(g_writer.cursor));
    g_writer.unit_stage_order = 0;
    g_writer.unit_stage[0] = '\0';
    g_writer.unit_completed = 0;
    g_writer.unit_total = 0;
    g_writer.unit_last_published_ms = 0;
}

int cbm_worker_progress_configure(const char *path, const char *attempt) {
    if (!path || !path[0] || strlen(path) >= sizeof(g_writer.path) ||
        !lowercase_hex_exact(attempt, CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN) ||
        atomic_load_explicit(&g_writer.active, memory_order_acquire) || g_writer.mutex_live) {
        cbm_log_error("index.worker.progress_configure_failed", "code",
                      "CBM_INDEX_WORKER_PROGRESS_CONFIG_INVALID", "message",
                      "worker progress path/attempt state is incomplete or already active",
                      "remediation", "pass one fresh absent path and exact lowercase SHA-256 attempt");
        return -1;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(path, &probe_error);
    if (probe != CBM_PATH_PROBE_ABSENT) {
        char native_error[32];
        snprintf(native_error, sizeof(native_error), "%lu", probe_error);
        cbm_log_error("index.worker.progress_configure_failed", "code",
                      probe == CBM_PATH_PROBE_PRESENT
                          ? "CBM_INDEX_WORKER_PROGRESS_PATH_PRESENT"
                          : "CBM_INDEX_WORKER_PROGRESS_PATH_UNREADABLE",
                      "path", path, "native_error", native_error, "message",
                      "worker progress path is not authoritatively absent", "remediation",
                      "preserve the path and start a fresh request-owned worker workspace");
        return -1;
    }
    writer_clear_ordinary_state();
    atomic_store_explicit(&g_writer.active, false, memory_order_release);
    atomic_store_explicit(&g_writer.failed, false, memory_order_release);
    cbm_mutex_init(&g_writer.mutex);
    g_writer.mutex_live = true;
    snprintf(g_writer.path, sizeof(g_writer.path), "%s", path);
    snprintf(g_writer.attempt, sizeof(g_writer.attempt), "%s", attempt);
    g_writer.stream = cbm_fopen(path, "wb");
    if (!g_writer.stream) {
        writer_mark_failed("create_progress_stream");
        cbm_mutex_destroy(&g_writer.mutex);
        g_writer.mutex_live = false;
        writer_clear_ordinary_state();
        atomic_store_explicit(&g_writer.failed, false, memory_order_release);
        return -1;
    }
    atomic_store_explicit(&g_writer.active, true, memory_order_release);
    return 0;
}

void cbm_worker_progress_reset(void) {
    if (!g_writer.mutex_live) {
        writer_clear_ordinary_state();
        atomic_store_explicit(&g_writer.active, false, memory_order_release);
        atomic_store_explicit(&g_writer.failed, false, memory_order_release);
        return;
    }
    atomic_store_explicit(&g_writer.active, false, memory_order_release);
    cbm_mutex_lock(&g_writer.mutex);
    FILE *stream = g_writer.stream;
    g_writer.stream = NULL;
    if (stream) {
        (void)fflush(stream);
        (void)fclose(stream);
    }
    cbm_mutex_unlock(&g_writer.mutex);
    cbm_mutex_destroy(&g_writer.mutex);
    g_writer.mutex_live = false;
    writer_clear_ordinary_state();
    atomic_store_explicit(&g_writer.failed, false, memory_order_release);
}

bool cbm_worker_progress_active(void) {
    return atomic_load_explicit(&g_writer.active, memory_order_acquire);
}

bool cbm_worker_progress_failed(void) {
    return atomic_load_explicit(&g_writer.failed, memory_order_acquire);
}

int cbm_worker_progress_publish(uint32_t stage_order, const char *stage, uint64_t completed,
                                uint64_t total, uint32_t step_order, const char *step,
                                uint64_t step_completed, uint64_t step_total) {
    if (!cbm_worker_progress_active()) {
        return 0;
    }
    cbm_mutex_lock(&g_writer.mutex);
    int rc = writer_publish_locked(stage_order, stage, completed, total, step_order, step,
                                   step_completed, step_total);
    cbm_mutex_unlock(&g_writer.mutex);
    if (rc != 0) {
        writer_mark_failed("append_progress_record");
    }
    return rc;
}

int cbm_worker_progress_advance_unit(uint32_t stage_order, const char *stage, uint64_t total) {
    if (!cbm_worker_progress_active()) {
        return 0;
    }
    cbm_mutex_lock(&g_writer.mutex);
    int rc = 0;
    bool same_stage = g_writer.unit_stage_order == stage_order && stage &&
                      strcmp(g_writer.unit_stage, stage) == 0;
    if (!same_stage) {
        bool resume_existing_stage =
            g_writer.cursor.present && stage &&
            g_writer.cursor.stage_order == stage_order &&
            strcmp(g_writer.cursor.stage, stage) == 0 &&
            g_writer.cursor.total == total;
        if (!progress_stage_valid(stage_order, stage) || total == 0 ||
            (g_writer.cursor.present && stage_order < g_writer.cursor.stage_order) ||
            (g_writer.cursor.present && stage_order == g_writer.cursor.stage_order &&
             !resume_existing_stage)) {
            rc = -1;
        } else {
            g_writer.unit_stage_order = stage_order;
            snprintf(g_writer.unit_stage, sizeof(g_writer.unit_stage), "%s", stage);
            g_writer.unit_completed = resume_existing_stage ? g_writer.cursor.completed : 0;
            g_writer.unit_total = total;
            g_writer.unit_last_published_ms =
                resume_existing_stage ? g_writer.cursor.monotonic_ms : 0;
        }
    } else if (g_writer.unit_total != total) {
        rc = -1;
    }
    if (rc == 0) {
        if (g_writer.unit_completed == UINT64_MAX || g_writer.unit_completed >= total) {
            rc = -1;
        } else {
            g_writer.unit_completed++;
            uint64_t now_ms = cbm_now_ms();
            if (g_writer.unit_last_published_ms != 0 &&
                now_ms < g_writer.unit_last_published_ms) {
                rc = -1;
            }
            bool publish = rc == 0 &&
                           (g_writer.unit_last_published_ms == 0 ||
                            g_writer.unit_completed == total ||
                            now_ms - g_writer.unit_last_published_ms >=
                                CBM_WORKER_PROGRESS_MAX_REPORT_INTERVAL_MS);
            if (publish) {
                rc = writer_publish_locked(stage_order, stage, g_writer.unit_completed, total, 1,
                                           "units", 1, 1);
                if (rc == 0) {
                    g_writer.unit_last_published_ms = now_ms;
                }
            }
        }
    }
    cbm_mutex_unlock(&g_writer.mutex);
    if (rc != 0) {
        writer_mark_failed("advance_progress_unit");
    }
    return rc;
}

int cbm_worker_progress_complete(void) {
    return cbm_worker_progress_publish(CBM_WORKER_PROGRESS_STAGE_COMPLETE, "complete", 1, 1, 1,
                                       "response", 1, 1);
}

cbm_worker_progress_reader_t *cbm_worker_progress_reader_new(const char *path,
                                                             const char *attempt) {
    if (!path || !path[0] || strlen(path) >= 1200 ||
        !lowercase_hex_exact(attempt, CBM_WORKER_PROGRESS_ATTEMPT_HEX_LEN)) {
        return NULL;
    }
    cbm_worker_progress_reader_t *reader = calloc(1, sizeof(*reader));
    if (!reader) {
        return NULL;
    }
    snprintf(reader->path, sizeof(reader->path), "%s", path);
    snprintf(reader->attempt, sizeof(reader->attempt), "%s", attempt);
    cbm_sha256_init(&reader->stream_hash);
    return reader;
}

void cbm_worker_progress_reader_free(cbm_worker_progress_reader_t *reader) {
    if (!reader) {
        return;
    }
    if (reader->stream) {
        (void)fclose(reader->stream);
    }
    free(reader);
}

static bool reader_verify_prefix(cbm_worker_progress_reader_t *reader) {
    /* Terminal verification reopens the named source of truth. Reading only
     * the retained stream handle would miss a namespace replacement that left
     * the old object readable while progress.bin named different bytes. */
    FILE *verification = cbm_fopen(reader->path, "rb");
    if (!verification) {
        return false;
    }
    cbm_sha256_ctx actual_ctx;
    cbm_sha256_init(&actual_ctx);
    uint8_t buffer[4096];
    progress_offset_t remaining = reader->consumed;
    while (remaining > 0) {
        size_t want = remaining > (progress_offset_t)sizeof(buffer) ? sizeof(buffer)
                                                                    : (size_t)remaining;
        size_t got = fread(buffer, 1, want, verification);
        if (got != want) {
            (void)fclose(verification);
            return false;
        }
        cbm_sha256_update(&actual_ctx, buffer, got);
        remaining -= (progress_offset_t)got;
    }
    cbm_sha256_ctx expected_ctx = reader->stream_hash;
    uint8_t actual[CBM_SHA256_DIGEST_LEN];
    uint8_t expected[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&actual_ctx, actual);
    cbm_sha256_final(&expected_ctx, expected);
    int trailing = fgetc(verification);
    bool exact = trailing == EOF && ferror(verification) == 0;
    bool closed = fclose(verification) == 0;
    return exact && closed && memcmp(actual, expected, sizeof(actual)) == 0;
}

cbm_worker_progress_poll_result_t
cbm_worker_progress_reader_poll(cbm_worker_progress_reader_t *reader, bool terminal) {
    if (!reader || reader->error_code[0]) {
        return CBM_WORKER_PROGRESS_POLL_INVALID;
    }
    unsigned long probe_error = 0;
    cbm_path_probe_result_t probe = cbm_path_probe(reader->path, &probe_error);
    if (probe == CBM_PATH_PROBE_ERROR) {
        reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_PATH_UNREADABLE",
                    "the progress path cannot be classified");
        return CBM_WORKER_PROGRESS_POLL_INVALID;
    }
    if (probe == CBM_PATH_PROBE_ABSENT) {
        if (reader->stream || terminal) {
            reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_MISSING",
                        "the required progress stream is absent");
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
        return CBM_WORKER_PROGRESS_POLL_IDLE;
    }
    if (!reader->stream) {
        reader->stream = cbm_fopen(reader->path, "rb");
        if (!reader->stream) {
            reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_OPEN_FAILED",
                        "the present progress stream cannot be opened for a narrow read");
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
    }
    if (progress_seek(reader->stream, 0, SEEK_END) != 0) {
        reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_SIZE_FAILED",
                    "the progress stream size cannot be read");
        return CBM_WORKER_PROGRESS_POLL_INVALID;
    }
    progress_offset_t size = progress_tell(reader->stream);
    if (size < reader->consumed) {
        reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_REWRITTEN",
                    "the append-only progress stream shrank below its consumed prefix");
        return CBM_WORKER_PROGRESS_POLL_INVALID;
    }
    progress_offset_t complete_size =
        size - (size % (progress_offset_t)CBM_WORKER_PROGRESS_RECORD_SIZE);
    if (progress_seek(reader->stream, reader->consumed, SEEK_SET) != 0) {
        reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_SEEK_FAILED",
                    "the next progress record cannot be addressed");
        return CBM_WORKER_PROGRESS_POLL_INVALID;
    }
    bool advanced = false;
    while (reader->consumed < complete_size) {
        uint8_t record[CBM_WORKER_PROGRESS_RECORD_SIZE];
        if (fread(record, 1, sizeof(record), reader->stream) != sizeof(record)) {
            reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_READ_FAILED",
                        "a complete progress record could not be read exactly");
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
        progress_cursor_t decoded;
        const char *decode_code = NULL;
        char detail[256];
        if (!decode_record(record, reader->attempt, &reader->cursor, &decoded, &decode_code, detail,
                           sizeof(detail))) {
            reader_fail(reader, decode_code, detail);
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
        cbm_sha256_update(&reader->stream_hash, record, sizeof(record));
        reader->cursor = decoded;
        reader->consumed += (progress_offset_t)sizeof(record);
        advanced = true;
    }
    if (terminal) {
        if (size == 0 || size != reader->consumed) {
            reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_TRUNCATED",
                        "the terminal progress stream has an incomplete record tail");
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
        if (!reader_verify_prefix(reader)) {
            reader_fail(reader, "CBM_INDEX_WORKER_PROGRESS_REWRITTEN",
                        "the consumed progress prefix changed before terminal readback");
            return CBM_WORKER_PROGRESS_POLL_INVALID;
        }
    }
    return advanced ? CBM_WORKER_PROGRESS_POLL_ADVANCED : CBM_WORKER_PROGRESS_POLL_IDLE;
}

const char *cbm_worker_progress_reader_error_code(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->error_code[0] ? reader->error_code : NULL;
}

const char *cbm_worker_progress_reader_error_detail(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->error_detail[0] ? reader->error_detail : NULL;
}

uint64_t cbm_worker_progress_reader_record_count(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present ? reader->cursor.sequence : 0;
}

uint32_t cbm_worker_progress_reader_stage_order(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present ? reader->cursor.stage_order : 0;
}

uint64_t cbm_worker_progress_reader_completed(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present ? reader->cursor.completed : 0;
}

uint64_t cbm_worker_progress_reader_total(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present ? reader->cursor.total : 0;
}

const char *cbm_worker_progress_reader_stage(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present ? reader->cursor.stage : NULL;
}

bool cbm_worker_progress_reader_complete(const cbm_worker_progress_reader_t *reader) {
    return reader && reader->cursor.present &&
           reader->cursor.stage_order == CBM_WORKER_PROGRESS_STAGE_COMPLETE &&
           strcmp(reader->cursor.stage, "complete") == 0 && reader->cursor.completed == 1 &&
           reader->cursor.total == 1;
}
