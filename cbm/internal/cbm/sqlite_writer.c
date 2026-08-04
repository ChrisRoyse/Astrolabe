// sqlite_writer.c — Direct SQLite page writer.
// Constructs a valid .db file from sorted in-memory data without using
// the SQL parser, INSERT statements, or B-tree rebalancing.
//
// SQLite file format reference: https://www.sqlite.org/fileformat2.html
//
// Key invariants:
//   - Page size: 65536 bytes
//   - Page 1 has a 100-byte database header before the B-tree header
//   - Leaf table B-tree pages: flag 0x0D
//   - Interior table B-tree pages: flag 0x05
//   - Leaf index B-tree pages: flag 0x0A
//   - Interior index B-tree pages: flag 0x02
//   - Records: header (varint count + serial types) + body (column values)
//   - Varints: 1-9 bytes, big-endian, MSB continuation

#include "sqlite_writer.h"
#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/compat_thread.h"
#include "foundation/log.h"
#include "foundation/profile.h"
#include "foundation/schema_version.h"
#include "foundation/sha256.h"
#include "foundation/win_utf8.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <io.h>
#include <limits.h>
#include <stddef.h> // NULL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#define CBM_PAGE_SIZE 65536

/* SQLite reserves the page containing the 1 GiB file offset (the "pending byte"
 * used for file locking on Windows). This page MUST be skipped during allocation
 * otherwise integrity_check reports "2nd reference to page N" because it marks
 * this page as referenced before walking any tree.
 *
 * PENDING_BYTE = 0x40000000 = 1073741824 (1 GiB)
 * PENDING_BYTE_PAGE = (PENDING_BYTE / page_size) + 1
 *   64KB pages → page 16385
 *   32KB pages → page 32769
 *   16KB pages → page 65537
 */
#define SQLITE_MAX_PAGE_SIZE 65536
#define SQLITE_MAX_PAGE_NUMBER (UINT32_MAX - 1u)
#define CBM_PENDING_BYTE (0x40000000u)
#define CBM_PENDING_BYTE_PAGE ((CBM_PENDING_BYTE / CBM_PAGE_SIZE) + 1)

#define SCHEMA_FORMAT 4
#define FILE_FORMAT 1
#define SQLITE_VERSION 3046000 // 3.46.0

// Varint encoding constants.
#define VARINT_MASK 0x7f
#define VARINT_CONTINUE 0x80
#define BYTE_MASK 0xff

enum {
    VARINT_SHIFT = 7,
    VARINT_BUF_SIZE = 10,
    VARINT_MIN_LEN = 1,
    SERIAL_INT8 = 1,
    SERIAL_INT16 = 2,
    SERIAL_INT24 = 3,
    SERIAL_INT32 = 4,
    SERIAL_INT48 = 5,
    SERIAL_INT64 = 6,
    SERIAL_FLOAT64 = 7,
    SERIAL_CONST_ZERO = 8,
    SERIAL_CONST_ONE = 9,
    SERIAL_SIZE_INT8 = 1,
    SERIAL_SIZE_INT16 = 2,
    SERIAL_SIZE_INT24 = 3,
    SERIAL_SIZE_INT32 = 4,
    SERIAL_SIZE_INT48 = 6,
    SERIAL_SIZE_INT64 = 8,
    BTREE_HEADER_SIZE = 8,
    BTREE_INTERIOR_HDR = 12,
    BTREE_PTR_SIZE = 4,
    CELL_PTR_SIZE = 2,
    INITIAL_PAGE_CAP = 4096,
    INITIAL_LEAF_CAP = 256,
    INITIAL_PARENT_CAP = 64,
    GROWTH_FACTOR = 2,
    VARINT_MAX_BYTES = 9,
    INT64_BYTES = 8,
    SORT_THRESHOLD = 20,
    MAX_NAME_LEN = 64,
    HASH_INIT = 5381,
    HASH_MULT = 33,
    HDR_FREEBLOCK_OFF = 1,
    HDR_CELLCOUNT_OFF = 3,
    HDR_CONTENT_OFF = 5,
    HDR_FRAGBYTES_OFF = 7,
    HDR_RIGHTCHILD_OFF = 8,
    INTERIOR_TABLE_FLAG = 0x05,
    INTERIOR_INDEX_FLAG = 0x02,
    NEWLINE_BYTE = 0x0A,
    NODE_SORT_THREADS = 5,
    EDGE_SORT_THREADS = 7,
    TOTAL_SORT_THREADS = 12,
    ERR_SORT_FAILED = -4,
    ERR_WRITE_FAILED = -3,
    ERR_MASTER_OVERFLOW = -2,
    MAX_EMBED_FRACTION = 64,
    MIN_EMBED_FRACTION = 32,
    LEAF_PAYLOAD_FRACTION = 32,
    INTERIOR_CELL_BUF = 20,
    FIRST_ROWID = 1,
    FIRST_DATA_PAGE = 2,
    NSORT_NAME = 1,
    NSORT_FILE = 2,
    NSORT_QN = 3,
    NSORT_ATOM = 4,
    ESORT_TARGET = 1,
    ESORT_TYPE = 2,
    ESORT_PROJ_TGT_TYPE = 3,
    ESORT_PROJ_SRC_TYPE = 4,
    ESORT_URL_PATH = 5,
    ESORT_SRC_TGT_TYPE = 6,
    SQLITE_HEADER_SIZE = 100,
    SHIFT_8 = 8,
    SHIFT_16 = 16,
    SHIFT_24 = 24,
};
// SQLite text serial type offset: serial_type = len*2 + TEXT_SERIAL_BASE.
#define TEXT_SERIAL_BASE 13

// SQLite blob serial type offset: serial_type = len*2 + BLOB_SERIAL_BASE.
#define BLOB_SERIAL_BASE 12
#define BLOB_SERIAL_MUL 2 /* serial_type = len * BLOB_SERIAL_MUL + BLOB_SERIAL_BASE */

// SQLite integer storage range limits.
#define INT8_MAX_VAL 127
#define INT16_MAX_VAL 32767
#define INT24_MIN_VAL (-8388608)
#define INT24_MAX_VAL 8388607
#define INT32_MIN_VAL (-2147483648LL)
#define INT32_MAX_VAL 2147483647LL
#define INT48_MIN_VAL (-140737488355328LL)
#define INT48_MAX_VAL 140737488355327LL

// SQLite B-tree page type flags.
#define BTREE_LEAF_TABLE 0x0D
#define BTREE_INTERIOR_TABLE 0x05
#define BTREE_LEAF_INDEX 0x0A
#define BTREE_INTERIOR_INDEX 0x02

// SQLite 100-byte database header field offsets.
#define HDR_OFF_CBM_PAGE_SIZE 16
#define HDR_OFF_WRITE_VERSION 18
#define HDR_OFF_READ_VERSION 19
#define HDR_OFF_RESERVED 20
#define HDR_OFF_MAX_EMBED_FRAC 21
#define HDR_OFF_MIN_EMBED_FRAC 22
#define HDR_OFF_LEAF_FRAC 23
#define HDR_OFF_FILE_CHANGE 24
#define HDR_OFF_DB_SIZE 28
#define HDR_OFF_FREELIST_TRUNK 32
#define HDR_OFF_FREELIST_COUNT 36
#define HDR_OFF_SCHEMA_COOKIE 40
#define HDR_OFF_SCHEMA_FORMAT 44
#define HDR_OFF_DEFAULT_CACHE 48
#define HDR_OFF_AUTOVAC_TOP 52
#define HDR_OFF_TEXT_ENCODING 56
#define HDR_OFF_USER_VERSION 60
#define HDR_OFF_INCR_VACUUM 64
#define HDR_OFF_APP_ID 68
#define HDR_OFF_VERSION_VALID 92
#define HDR_OFF_SQLITE_VERSION 96

typedef struct {
    FILE *fp;
    const char *path;
    const char *failed_operation;
    const char *native_error_kind;
    unsigned long native_error;
    bool stage_created;
    bool failed;
} WriterIo;

typedef int64_t WriterOffset;

static void writer_io_record_failure(WriterIo *io, const char *operation,
                                     const char *native_error_kind, unsigned long native_error) {
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = native_error_kind;
    io->native_error = native_error;

    char native_error_buf[32];
    (void)snprintf(native_error_buf, sizeof(native_error_buf), "%lu", native_error);
    cbm_log_error("sqlite_writer.io_failed", "code", "CBM_SQLITE_WRITER_IO_FAILED", "operation",
                  operation, "path", io->path ? io->path : "", "native_error_kind",
                  native_error_kind, "native_error", native_error_buf, "message",
                  "the direct SQLite writer could not durably construct the complete staging file",
                  "remediation",
                  "resolve the reported filesystem failure; preserve the prior live database and "
                  "retry indexing");
}

static void writer_io_record_errno(WriterIo *io, const char *operation) {
    int saved = errno;
    writer_io_record_failure(io, operation, "errno", (unsigned long)(saved ? saved : EIO));
}

static void writer_io_record_seek_errno(WriterIo *io, WriterOffset offset, int origin) {
    int saved = errno;
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = "seek";
    io->native_error_kind = "errno";
    io->native_error = (unsigned long)(saved ? saved : EIO);

    char native_error_buf[32];
    char offset_buf[32];
    char origin_buf[32];
    (void)snprintf(native_error_buf, sizeof(native_error_buf), "%lu", io->native_error);
    (void)snprintf(offset_buf, sizeof(offset_buf), "%" PRId64, offset);
    (void)snprintf(origin_buf, sizeof(origin_buf), "%d", origin);
    cbm_log_error("sqlite_writer.io_failed", "code", "CBM_SQLITE_WRITER_IO_FAILED", "operation",
                  "seek", "path", io->path ? io->path : "", "native_error_kind", "errno",
                  "native_error", native_error_buf, "offset_bytes", offset_buf, "origin",
                  origin_buf, "message",
                  "the direct SQLite writer could not durably construct the complete staging file",
                  "remediation",
                  "resolve the reported filesystem failure; preserve the prior live database and "
                  "retry indexing");
}

static void writer_record_offset_failure(WriterIo *io, const char *operation, uint32_t page_num,
                                         const char *detail) {
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = "offset_contract";
    io->native_error = ERROR_ARITHMETIC_OVERFLOW;

    char page_num_buf[32];
    char max_page_num_buf[32];
    char page_size_buf[32];
    (void)snprintf(page_num_buf, sizeof(page_num_buf), "%" PRIu32, page_num);
    (void)snprintf(max_page_num_buf, sizeof(max_page_num_buf), "%" PRIu32,
                   (uint32_t)SQLITE_MAX_PAGE_NUMBER);
    (void)snprintf(page_size_buf, sizeof(page_size_buf), "%u", (unsigned int)CBM_PAGE_SIZE);
    cbm_log_error("sqlite_writer.offset_invalid", "code", "CBM_SQLITE_WRITER_OFFSET_INVALID",
                  "operation", operation, "path", io->path ? io->path : "", "page_num",
                  page_num_buf, "max_page_num", max_page_num_buf, "page_size", page_size_buf,
                  "detail", detail, "message",
                  "the direct SQLite writer rejected an unrepresentable page position before I/O",
                  "remediation",
                  "preserve the source corpus and report the exact page position; no database was "
                  "published");
}

/* Allocate exactly one SQLite page number through the format-wide page-number
 * contract. Every page kind must use this allocator: at 64 KiB/page the page
 * containing SQLite's 1 GiB lock byte is page 16385, and the SQLite core marks
 * that page reserved before traversing any B-tree. Allowing even an overflow
 * chain to consume it therefore creates a physically corrupt database.
 *
 * next_page may advance to UINT32_MAX after allocating SQLite's final legal
 * page (UINT32_MAX - 1). A later allocation fails closed before arithmetic can
 * wrap or any I/O occurs. */
static bool writer_allocate_page(WriterIo *io, uint32_t *next_page, const char *operation,
                                 uint32_t *out_page) {
    if (!next_page || !out_page) {
        writer_record_offset_failure(io, operation, next_page ? *next_page : 0,
                                     "page allocator pointer is NULL");
        return false;
    }

    uint32_t page_num = *next_page;
    if (page_num == CBM_PENDING_BYTE_PAGE) {
        page_num++;
    }
    if (page_num == 0 || page_num > SQLITE_MAX_PAGE_NUMBER) {
        writer_record_offset_failure(io, operation, page_num,
                                     "no legal SQLite page number remains for allocation");
        return false;
    }

    *out_page = page_num;
    *next_page = page_num + SKIP_ONE;
    return true;
}

static void writer_record_allocation_failure(WriterIo *io, const char *operation,
                                             size_t requested_bytes) {
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = "allocation_bytes";
    io->native_error = requested_bytes > ULONG_MAX ? ULONG_MAX : (unsigned long)requested_bytes;

    char requested_buf[32];
    (void)snprintf(requested_buf, sizeof(requested_buf), "%zu", requested_bytes);
    cbm_log_error("sqlite_writer.allocation_failed", "code", "CBM_SQLITE_WRITER_ALLOC_FAILED",
                  "operation", operation, "path", io->path ? io->path : "", "requested_bytes",
                  requested_buf, "message",
                  "the direct SQLite writer could not allocate the complete record or page state",
                  "remediation", "free memory or reduce repository size, then retry indexing");
}

static void writer_record_cell_failure(WriterIo *io, const char *operation, size_t cell_bytes) {
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = "cell_bytes";
    io->native_error = cell_bytes > ULONG_MAX ? ULONG_MAX : (unsigned long)cell_bytes;

    char cell_buf[32];
    (void)snprintf(cell_buf, sizeof(cell_buf), "%zu", cell_bytes);
    cbm_log_error("sqlite_writer.cell_invalid", "code", "CBM_SQLITE_WRITER_CELL_INVALID",
                  "operation", operation, "path", io->path ? io->path : "", "cell_bytes", cell_buf,
                  "message",
                  "the direct SQLite writer produced a cell that violates the SQLite page format",
                  "remediation",
                  "preserve the source corpus and report the exact cell size and operation; no "
                  "database was published");
}

static void writer_record_thread_failure(WriterIo *io, const char *operation,
                                         const cbm_thread_t *thread) {
    if (!io || io->failed) {
        return;
    }
    const char *domain = "unknown";
    unsigned long code = ERROR_GEN_FAILURE;
    if (thread) {
        code = thread->error_code;
        if (thread->error_domain == CBM_THREAD_ERROR_ERRNO) {
            domain = "errno";
        } else if (thread->error_domain == CBM_THREAD_ERROR_WIN32) {
            domain = "win32";
        } else if (thread->error_domain == CBM_THREAD_ERROR_PTHREAD) {
            domain = "pthread";
        }
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = domain;
    io->native_error = code;

    char code_buf[32];
    (void)snprintf(code_buf, sizeof(code_buf), "%lu", code);
    cbm_log_error("sqlite_writer.thread_failed", "code", "CBM_SQLITE_WRITER_THREAD_FAILED",
                  "operation", operation, "path", io->path ? io->path : "", "native_error_kind",
                  domain, "native_error", code_buf, "message",
                  "the direct SQLite writer could not complete its index sort workers",
                  "remediation",
                  "resolve the reported process or thread resource failure, then retry indexing");
}

static void writer_record_input_failure(WriterIo *io, const char *operation, const char *detail) {
    if (!io || io->failed) {
        return;
    }
    io->failed = true;
    io->failed_operation = operation;
    io->native_error_kind = "input_contract";
    io->native_error = ERROR_INVALID_PARAMETER;

    cbm_log_error("sqlite_writer.input_invalid", "code", "CBM_SQLITE_WRITER_INPUT_INVALID",
                  "operation", operation, "path", io->path ? io->path : "", "detail",
                  detail ? detail : "invalid direct-writer input", "message",
                  "the direct SQLite writer rejected an inconsistent or invalid input contract",
                  "remediation",
                  "supply non-negative counts, non-NULL positive-count arrays, and the exact "
                  "streamed node identity sequence at finalize; no database was published");
}

static bool writer_io_open_create_new(WriterIo *io) {
    wchar_t *wide_path = cbm_utf8_to_wide_path(io->path);
    if (!wide_path) {
        DWORD error = GetLastError();
        writer_io_record_failure(io, "widen_path", "win32",
                                 (unsigned long)(error ? error : ERROR_NO_UNICODE_TRANSLATION));
        return false;
    }
    HANDLE handle = CreateFileW(wide_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE) {
        writer_io_record_failure(io, "create_new", "win32", (unsigned long)GetLastError());
        return false;
    }
    io->stage_created = true;

    errno = 0;
    int fd = _open_osfhandle((intptr_t)handle, _O_WRONLY | _O_BINARY | _O_NOINHERIT);
    if (fd < 0) {
        int saved = errno;
        (void)CloseHandle(handle);
        errno = saved;
        writer_io_record_errno(io, "open_os_handle");
        return false;
    }

    errno = 0;
    io->fp = _fdopen(fd, "wb");
    if (!io->fp) {
        int saved = errno;
        (void)_close(fd);
        errno = saved;
        writer_io_record_errno(io, "open_stream");
        return false;
    }
    return true;
}

static bool writer_io_seek(WriterIo *io, WriterOffset offset, int origin) {
    if (!io || !io->fp || io->failed) {
        return false;
    }
    errno = 0;
    if (_fseeki64(io->fp, offset, origin) != 0) {
        writer_io_record_seek_errno(io, offset, origin);
        return false;
    }
    return true;
}

static bool writer_page_offset(WriterIo *io, uint32_t page_num, WriterOffset *out_offset) {
    if (!out_offset) {
        writer_record_offset_failure(io, "page_offset", page_num, "output pointer is NULL");
        return false;
    }
    if (page_num == 0) {
        writer_record_offset_failure(io, "page_offset", page_num,
                                     "SQLite page numbers are one-based");
        return false;
    }
    if (page_num > SQLITE_MAX_PAGE_NUMBER) {
        writer_record_offset_failure(io, "page_offset", page_num,
                                     "page number exceeds the SQLite file-format maximum");
        return false;
    }
    uint64_t page_index = (uint64_t)page_num - SKIP_ONE;
    if (page_index > (uint64_t)INT64_MAX / CBM_PAGE_SIZE) {
        writer_record_offset_failure(io, "page_offset", page_num,
                                     "page byte offset exceeds the signed 64-bit stream domain");
        return false;
    }
    *out_offset = (WriterOffset)(page_index * CBM_PAGE_SIZE);
    return true;
}

static bool writer_io_seek_page(WriterIo *io, uint32_t page_num) {
    WriterOffset offset = 0;
    return writer_page_offset(io, page_num, &offset) && writer_io_seek(io, offset, SEEK_SET);
}

static bool writer_expected_file_size(WriterIo *io, uint32_t next_page, WriterOffset *out_size) {
    if (!out_size) {
        writer_record_offset_failure(io, "expected_file_size", next_page, "output pointer is NULL");
        return false;
    }
    if (next_page == 0) {
        writer_record_offset_failure(io, "expected_file_size", next_page,
                                     "next page wrapped below the one-based page domain");
        return false;
    }
    uint64_t page_count = (uint64_t)next_page - SKIP_ONE;
    if (page_count > (uint64_t)SQLITE_MAX_PAGE_NUMBER ||
        page_count > (uint64_t)INT64_MAX / CBM_PAGE_SIZE) {
        writer_record_offset_failure(io, "expected_file_size", next_page,
                                     "database size exceeds the SQLite or stream offset domain");
        return false;
    }
    *out_size = (WriterOffset)(page_count * CBM_PAGE_SIZE);
    return true;
}

static bool writer_io_write(WriterIo *io, const void *data, size_t size) {
    if (!io || !io->fp || io->failed) {
        return false;
    }
    errno = 0;
    if (fwrite(data, SKIP_ONE, size, io->fp) != size) {
        writer_io_record_errno(io, "write");
        return false;
    }
    return true;
}

static WriterOffset writer_io_tell(WriterIo *io) {
    if (!io || !io->fp || io->failed) {
        return CBM_NOT_FOUND;
    }
    errno = 0;
    WriterOffset position = _ftelli64(io->fp);
    if (position < 0) {
        writer_io_record_errno(io, "tell");
    }
    return position;
}

/* The writer runs only on native Windows until the port phase. A successful
 * finalization means stdio is flushed, the underlying Win32 handle is flushed,
 * and fclose has also succeeded. Every step is attempted and checked; the first
 * exact native failure remains authoritative. */
static int writer_io_close(WriterIo *io, bool require_durable_sync) {
    if (!io || !io->fp) {
        return ERR_WRITE_FAILED;
    }

    if (require_durable_sync) {
        errno = 0;
        if (fflush(io->fp) != 0) {
            writer_io_record_errno(io, "flush");
        }

        errno = 0;
        int fd = _fileno(io->fp);
        if (fd < 0) {
            writer_io_record_errno(io, "fileno");
        } else {
            intptr_t raw_handle = _get_osfhandle(fd);
            if (raw_handle == (intptr_t)CBM_NOT_FOUND) {
                writer_io_record_errno(io, "os_handle");
            } else if (!FlushFileBuffers((HANDLE)raw_handle)) {
                writer_io_record_failure(io, "sync", "win32", (unsigned long)GetLastError());
            }
        }
    }

    errno = 0;
    if (fclose(io->fp) != 0) {
        writer_io_record_errno(io, "close");
    }
    io->fp = NULL;
    return io->failed ? ERR_WRITE_FAILED : 0;
}

static int writer_io_finish(WriterIo *io, int result, bool require_durable_sync) {
    int close_result = writer_io_close(io, require_durable_sync && result == 0);
    return close_result != 0 ? close_result : result;
}

static void writer_remove_failed_stage(const char *path) {
    errno = 0;
    if (cbm_unlink(path) == 0 || errno == ENOENT) {
        return;
    }
    char native_error[32];
    (void)snprintf(native_error, sizeof(native_error), "%d", errno ? errno : EIO);
    cbm_log_error("sqlite_writer.cleanup_failed", "code", "CBM_SQLITE_WRITER_PARTIAL_REMOVE_FAILED",
                  "path", path, "native_error_kind", "errno", "native_error", native_error,
                  "message", "the failed direct-writer staging file could not be removed",
                  "remediation",
                  "preserve the path, resolve the reported filesystem failure, and retry");
}

// --- Varint encoding ---

static int put_varint(uint8_t *buf, int64_t value) {
    uint64_t v = (uint64_t)value;
    if (v <= VARINT_MASK) {
        buf[0] = (uint8_t)v;
        return SERIAL_SIZE_INT8;
    }
    // Encode in big-endian with MSB continuation bits
    uint8_t tmp[VARINT_BUF_SIZE];
    int n = 0;
    while (v > VARINT_MASK) {
        tmp[n++] = (uint8_t)(v & VARINT_MASK);
        v >>= VARINT_SHIFT;
    }
    tmp[n++] = (uint8_t)v;
    // Reverse into output with continuation bits
    for (int i = 0; i < n; i++) {
        buf[i] = tmp[n - SKIP_ONE - i];
        if (i < n - SKIP_ONE) {
            buf[i] |= VARINT_CONTINUE;
        }
    }
    return n;
}

static int varint_len(int64_t value) {
    uint64_t v = (uint64_t)value;
    int n = VARINT_MIN_LEN;
    while (v > VARINT_MASK) {
        v >>= VARINT_SHIFT;
        n++;
    }
    return n;
}

// SQLite serial type for a TEXT value
static int64_t text_serial_type(int len) {
    return (len * PAIR_LEN) + TEXT_SERIAL_BASE;
}

// SQLite serial type for an integer value
static int64_t int_serial_type(int64_t val) {
    if (val == 0) {
        return SERIAL_CONST_ZERO;
    }
    if (val == SERIAL_INT8) {
        return SERIAL_CONST_ONE;
    }
    if (val >= -INT8_MAX_VAL - SKIP_ONE && val <= INT8_MAX_VAL) {
        return SERIAL_SIZE_INT8;
    }
    if (val >= -INT16_MAX_VAL - SKIP_ONE && val <= INT16_MAX_VAL) {
        return SERIAL_SIZE_INT16;
    }
    if (val >= INT24_MIN_VAL && val <= INT24_MAX_VAL) {
        return SERIAL_SIZE_INT24;
    }
    if (val >= INT32_MIN_VAL && val <= INT32_MAX_VAL) {
        return SERIAL_SIZE_INT32;
    }
    if (val >= INT48_MIN_VAL && val <= INT48_MAX_VAL) {
        return SERIAL_SIZE_INT48;
    }
    return SERIAL_SIZE_INT64;
}

// Bytes needed to store an integer of given serial type
static int int_storage_bytes(int serial_type) {
    switch (serial_type) {
    case 0:
        return 0; // NULL
    case SERIAL_INT8:
        return SERIAL_SIZE_INT8;
    case SERIAL_INT16:
        return SERIAL_SIZE_INT16;
    case SERIAL_INT24:
        return SERIAL_SIZE_INT24;
    case SERIAL_INT32:
        return SERIAL_SIZE_INT32;
    case SERIAL_INT48:
        return SERIAL_SIZE_INT48;
    case SERIAL_INT64:
        return SERIAL_SIZE_INT64;
    case SERIAL_CONST_ZERO: // integer 0
    case SERIAL_CONST_ONE:  // integer 1
    default:
        return 0;
    }
}

// Write integer in big-endian for given byte count
static void put_int_be(uint8_t *buf, int64_t val, int nbytes) {
    for (int i = nbytes - SKIP_ONE; i >= 0; i--) {
        buf[i] = (uint8_t)(val & BYTE_MASK);
        val >>= SHIFT_8;
    }
}

// Write a 2-byte big-endian value
static void put_u16(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val >> SHIFT_8);
    buf[SKIP_ONE] = (uint8_t)(val & BYTE_MASK);
}

// Write a 4-byte big-endian value
static void put_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> SHIFT_24);
    buf[SKIP_ONE] = (uint8_t)(val >> SHIFT_16);
    buf[PAIR_LEN] = (uint8_t)(val >> SHIFT_8);
    buf[SERIAL_SIZE_INT24] = (uint8_t)(val & BYTE_MASK);
}

// --- Dynamic buffer ---

typedef struct {
    uint8_t *data;
    int len;
    int cap;
} DynBuf;

static void dynbuf_init(DynBuf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static bool dynbuf_ensure(DynBuf *b, int needed) {
    if (needed < 0 || b->len < 0 || b->cap < 0 || needed > INT_MAX - b->len) {
        return false;
    }
    if (b->len + needed <= b->cap) {
        return true;
    }
    int required = b->len + needed;
    int newcap = b->cap == 0 ? INITIAL_PAGE_CAP : b->cap;
    while (newcap < required) {
        if (newcap > INT_MAX / GROWTH_FACTOR) {
            newcap = required;
            break;
        }
        newcap *= GROWTH_FACTOR;
    }
    uint8_t *p = (uint8_t *)realloc(b->data, (size_t)newcap);
    if (!p) {
        (void)fprintf(stderr, "cbm_write_db: dynbuf realloc failed size=%d\n", newcap);
        return false;
    }
    b->data = p;
    b->cap = newcap;
    return true;
}

static bool dynbuf_append(DynBuf *b, const void *data, int len) {
    if (len <= 0) {
        return true;
    }
    if (!data) {
        return false;
    }
    if (!dynbuf_ensure(b, len)) {
        return false;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return true;
}

static void dynbuf_free(DynBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

// --- Record builder ---
// Builds a SQLite record: header (header_len varint + serial types) + body (values)

typedef struct {
    DynBuf header; // serial type varints
    DynBuf body;   // column values
    WriterIo *io;
    const char *operation;
    bool failed;
} RecordBuilder;

static void rec_init(RecordBuilder *r, WriterIo *io, const char *operation) {
    dynbuf_init(&r->header);
    dynbuf_init(&r->body);
    r->io = io;
    r->operation = operation;
    r->failed = false;
}

static void rec_free(RecordBuilder *r) {
    dynbuf_free(&r->header);
    dynbuf_free(&r->body);
}

static void rec_add_null(RecordBuilder *r) {
    uint8_t v[SKIP_ONE] = {0};
    if (!dynbuf_append(&r->header, v, SKIP_ONE)) {
        r->failed = true;
        writer_record_allocation_failure(r->io, r->operation, SKIP_ONE);
    }
}

static void rec_add_int(RecordBuilder *r, int64_t val) {
    int64_t st = int_serial_type(val);
    uint8_t vbuf[VARINT_MAX_BYTES];
    int vlen = put_varint(vbuf, st);
    if (!dynbuf_append(&r->header, vbuf, vlen)) {
        r->failed = true;
        writer_record_allocation_failure(r->io, r->operation, (size_t)vlen);
    }

    int nbytes = int_storage_bytes((int)st);
    if (nbytes > 0) {
        uint8_t ibuf[INT64_BYTES];
        put_int_be(ibuf, val, nbytes);
        if (!dynbuf_append(&r->body, ibuf, nbytes)) {
            r->failed = true;
            writer_record_allocation_failure(r->io, r->operation, (size_t)nbytes);
        }
    }
}

static void rec_add_text(RecordBuilder *r, const char *s) {
    size_t text_len = s ? strlen(s) : 0;
    if (text_len > INT_MAX) {
        r->failed = true;
        writer_record_cell_failure(r->io, r->operation, text_len);
        return;
    }
    int slen = (int)text_len;
    int64_t st = text_serial_type(slen);
    uint8_t vbuf[VARINT_MAX_BYTES];
    int vlen = put_varint(vbuf, st);
    if (!dynbuf_append(&r->header, vbuf, vlen)) {
        r->failed = true;
        writer_record_allocation_failure(r->io, r->operation, (size_t)vlen);
    }
    if (slen > 0) {
        if (!dynbuf_append(&r->body, s, slen)) {
            r->failed = true;
            writer_record_allocation_failure(r->io, r->operation, (size_t)slen);
        }
    }
}

static void rec_add_blob(RecordBuilder *r, const uint8_t *data, int len) {
    if (len < 0 || (len > 0 && !data)) {
        r->failed = true;
        writer_record_cell_failure(r->io, r->operation, len < 0 ? SIZE_MAX : (size_t)len);
        return;
    }
    int64_t st = ((int64_t)len * BLOB_SERIAL_MUL) + BLOB_SERIAL_BASE;
    uint8_t vbuf[VARINT_MAX_BYTES];
    int vlen = put_varint(vbuf, st);
    if (!dynbuf_append(&r->header, vbuf, vlen)) {
        r->failed = true;
        writer_record_allocation_failure(r->io, r->operation, (size_t)vlen);
    }
    if (len > 0) {
        if (!dynbuf_append(&r->body, data, len)) {
            r->failed = true;
            writer_record_allocation_failure(r->io, r->operation, (size_t)len);
        }
    }
}

// Finalize: returns the complete record bytes (header_len + header + body).
// Caller must free the returned buffer.
static uint8_t *rec_finalize(RecordBuilder *r, int *out_len) {
    *out_len = 0;
    if (r->failed) {
        return NULL;
    }
    int header_content_len = r->header.len;
    int header_len_varint_len = varint_len(header_content_len + varint_len(header_content_len));
    // The header size varint includes itself, so we may need to iterate
    int total_header = header_len_varint_len + header_content_len;
    // Check if the header_len varint changes size when it includes itself
    int recalc = varint_len(total_header);
    if (recalc != header_len_varint_len) {
        header_len_varint_len = recalc;
        total_header = header_len_varint_len + header_content_len;
    }

    size_t total_size = (size_t)total_header + (size_t)r->body.len;
    if (total_size > INT_MAX) {
        r->failed = true;
        writer_record_cell_failure(r->io, r->operation, total_size);
        return NULL;
    }
    int total = (int)total_size;
    uint8_t *buf = (uint8_t *)malloc(total_size);
    if (!buf) {
        writer_record_allocation_failure(r->io, r->operation, total_size);
        return NULL;
    }
    int pos = put_varint(buf, total_header);
    memcpy(buf + pos, r->header.data, header_content_len);
    pos += header_content_len;
    memcpy(buf + pos, r->body.data, r->body.len);
    *out_len = total;
    return buf;
}

// --- Page builder ---
// Accumulates cells (records) into B-tree leaf pages.

typedef struct {
    uint32_t page_num; // page number of this page (1-based)
    int64_t max_key;   // max rowid on this page (table B-trees)
    uint8_t *sep_cell; // separator cell content for index interior pages (owned, NULL for table)
    int sep_cell_len;
} PageRef;

typedef struct {
    WriterIo *io;
    uint32_t next_page; // next page number to allocate
    int page1_offset;   // 100 for page 1, 0 for others
    bool is_index;      // true for index B-trees

    // Current leaf page being built
    uint8_t page[CBM_PAGE_SIZE];
    int cell_count;
    int content_offset; // where cell content starts (grows down from page end)
    int ptr_offset;     // where cell pointers are written (grows up from header)

    // Completed leaf pages for building interior nodes
    PageRef *leaves;
    int leaf_count;
    int leaf_cap;
} PageBuilder;

static void pb_init(PageBuilder *pb, WriterIo *io, uint32_t start_page, bool is_index) {
    pb->io = io;
    pb->next_page = start_page;
    pb->is_index = is_index;
    pb->cell_count = 0;
    pb->content_offset = CBM_PAGE_SIZE;
    pb->page1_offset = (start_page == SKIP_ONE) ? SQLITE_HEADER_SIZE : 0;
    // Header: flag(1) + freeblock(2) + cell_count(2) + content_start(2) + fragmented(1) = 8
    pb->ptr_offset = pb->page1_offset + BTREE_HEADER_SIZE;
    memset(pb->page, 0, CBM_PAGE_SIZE);
    pb->leaves = NULL;
    pb->leaf_count = 0;
    pb->leaf_cap = 0;
}

static void pb_free(PageBuilder *pb) {
    if (pb->leaves) {
        for (int i = 0; i < pb->leaf_count; i++) {
            free(pb->leaves[i].sep_cell);
        }
        free(pb->leaves);
    }
}

// Flush current leaf page to file
static void pb_flush_leaf(PageBuilder *pb) {
    if (pb->cell_count == 0) {
        return;
    }

    int hdr = pb->page1_offset;
    // Write leaf page header
    pb->page[hdr + 0] = pb->is_index ? BTREE_LEAF_INDEX : BTREE_LEAF_TABLE; // leaf flag
    put_u16(pb->page + hdr + HDR_FREEBLOCK_OFF, 0);                         // first freeblock
    put_u16(pb->page + hdr + HDR_CELLCOUNT_OFF, (uint16_t)pb->cell_count);
    put_u16(pb->page + hdr + HDR_CONTENT_OFF, (uint16_t)pb->content_offset);
    pb->page[hdr + HDR_FRAGBYTES_OFF] = 0; // fragmented free bytes

    // Write page to file through the format-wide page allocator.
    uint32_t page_num = 0;
    if (!writer_allocate_page(pb->io, &pb->next_page, "allocate_leaf_page", &page_num)) {
        return;
    }
    if (!writer_io_seek_page(pb->io, page_num) ||
        !writer_io_write(pb->io, pb->page, CBM_PAGE_SIZE)) {
        return;
    }

    // Record this leaf for interior page building
    if (pb->leaf_count >= pb->leaf_cap) {
        int old_cap = pb->leaf_cap;
        if (old_cap > INT_MAX / GROWTH_FACTOR) {
            writer_record_allocation_failure(pb->io, "grow_leaf_references", SIZE_MAX);
            return;
        }
        int new_cap = old_cap == 0 ? INITIAL_LEAF_CAP : old_cap * GROWTH_FACTOR;
        size_t requested = (size_t)new_cap * sizeof(PageRef);
        void *tmp = realloc(pb->leaves, requested);
        if (!tmp) {
            writer_record_allocation_failure(pb->io, "grow_leaf_references", requested);
            return;
        }
        pb->leaves = (PageRef *)tmp;
        pb->leaf_cap = new_cap;
        /* Zero-init new slots */
        memset(&pb->leaves[old_cap], 0, ((size_t)pb->leaf_cap - (size_t)old_cap) * sizeof(PageRef));
    }
    pb->leaves[pb->leaf_count].page_num = page_num;
    // max_key is set by caller before flush
    pb->leaf_count++;

    // Reset for next page
    pb->cell_count = 0;
    pb->content_offset = CBM_PAGE_SIZE;
    pb->page1_offset = 0;               // only page 1 has the 100-byte header
    pb->ptr_offset = BTREE_HEADER_SIZE; // standard B-tree header size for non-page-1
    memset(pb->page, 0, CBM_PAGE_SIZE);
}

// Check if a cell of given size fits in the current page
static bool pb_cell_fits(PageBuilder *pb, int cell_len) {
    // Cell pointer (2 bytes) + cell content
    int available = pb->content_offset - pb->ptr_offset - CELL_PTR_SIZE;
    return cell_len <= available;
}

// Add a cell to the current leaf page.
// For table leaves: varint(payload_len) + varint(rowid) + payload
// For index leaves: varint(payload_len) + payload
static void pb_add_cell(PageBuilder *pb, const uint8_t *cell, int cell_len) {
    // Write cell content (grows down)
    pb->content_offset -= cell_len;
    memcpy(pb->page + pb->content_offset, cell, cell_len);

    // Write cell pointer (grows up)
    put_u16(pb->page + pb->ptr_offset, (uint16_t)pb->content_offset);
    pb->ptr_offset += CELL_PTR_SIZE;
    pb->cell_count++;
}

// Build interior pages from child page references.
// Returns the root page number.
//
// SQLite interior page structure:
//   - Header has right-child pointer (the last child page)
//   - Each cell contains: child_page(4) + key
//   - For N children, there are N-1 cells (children[0..N-2] get cells,
//     children[N-1] becomes the right-child in the header)
//   - Cell[j] = {left_child: children[j].page, key: children[j].max_key/sep_cell}
//   - Lookup: X ≤ K0 → cell[0].left_child, K0 < X ≤ K1 → cell[1].left_child, etc.
//   - Table keys: varint(rowid)
//   - Index keys: varint(payload_len) + payload (full index record)
// Build an interior cell for a child PageRef. Returns cell length.
// For table B-trees: child_page(4) + varint(rowid).
// For index B-trees: child_page(4) + separator_cell.
// cell_buf must be at least 20 bytes for table cells.
// For index cells, returns malloc'd data via *out_heap (caller frees).
static int build_interior_cell(WriterIo *io, const PageRef *child, bool is_index, uint8_t *cell_buf,
                               uint8_t **out_heap) {
    *out_heap = NULL;
    if (!is_index) {
        put_u32(cell_buf, child->page_num);
        return BTREE_PTR_SIZE + put_varint(cell_buf + BTREE_PTR_SIZE, child->max_key);
    }
    int clen = BTREE_PTR_SIZE + child->sep_cell_len;
    uint8_t *data = (uint8_t *)malloc(clen);
    if (!data) {
        writer_record_allocation_failure(io, "build_interior_cell", (size_t)clen);
        return CBM_NOT_FOUND;
    }
    put_u32(data, child->page_num);
    memcpy(data + 4, child->sep_cell, child->sep_cell_len);
    *out_heap = data;
    return clen;
}

// Write a completed interior page to disk and record it as a parent.
// Returns updated parent_count, or -1 on allocation failure.
static int write_interior_page(PageBuilder *pb, uint8_t *page, int cell_count, int content_offset,
                               uint32_t right_child_page, const PageRef *children,
                               int right_child_idx, bool is_index, PageRef **parents,
                               int parent_count, int *parent_cap) {
    uint32_t pnum = 0;
    if (!writer_allocate_page(pb->io, &pb->next_page, "allocate_interior_page", &pnum)) {
        return CBM_NOT_FOUND;
    }
    page[0] = is_index ? INTERIOR_INDEX_FLAG : INTERIOR_TABLE_FLAG;
    put_u16(page + HDR_FREEBLOCK_OFF, 0);
    put_u16(page + HDR_CELLCOUNT_OFF, (uint16_t)cell_count);
    put_u16(page + HDR_CONTENT_OFF, (uint16_t)content_offset);
    page[HDR_FRAGBYTES_OFF] = 0;
    put_u32(page + HDR_RIGHTCHILD_OFF, right_child_page);

    if (!writer_io_seek_page(pb->io, pnum) || !writer_io_write(pb->io, page, CBM_PAGE_SIZE)) {
        return CBM_NOT_FOUND;
    }

    if (parent_count >= *parent_cap) {
        int old_pcap = *parent_cap;
        if (old_pcap > INT_MAX / GROWTH_FACTOR) {
            writer_record_allocation_failure(pb->io, "grow_parent_references", SIZE_MAX);
            return CBM_NOT_FOUND;
        }
        int new_cap = old_pcap == 0 ? INITIAL_PARENT_CAP : old_pcap * GROWTH_FACTOR;
        size_t requested = (size_t)new_cap * sizeof(PageRef);
        PageRef *tmp = (PageRef *)realloc(*parents, requested);
        if (!tmp) {
            writer_record_allocation_failure(pb->io, "grow_parent_references", requested);
            return CBM_NOT_FOUND;
        }
        *parents = tmp;
        *parent_cap = new_cap;
        memset(&(*parents)[old_pcap], 0,
               ((size_t)*parent_cap - (size_t)old_pcap) * sizeof(PageRef));
    }
    (*parents)[parent_count].page_num = pnum;
    (*parents)[parent_count].max_key = children[right_child_idx].max_key;
    if (is_index && children[right_child_idx].sep_cell) {
        int slen = children[right_child_idx].sep_cell_len;
        (*parents)[parent_count].sep_cell = (uint8_t *)malloc(slen);
        if (!(*parents)[parent_count].sep_cell) {
            writer_record_allocation_failure(pb->io, "copy_parent_separator", (size_t)slen);
            return CBM_NOT_FOUND;
        }
        memcpy((*parents)[parent_count].sep_cell, children[right_child_idx].sep_cell, slen);
        (*parents)[parent_count].sep_cell_len = slen;
    } else {
        (*parents)[parent_count].sep_cell = NULL;
        (*parents)[parent_count].sep_cell_len = 0;
    }
    return parent_count + SKIP_ONE;
}

// Free a PageRef array (sep_cell allocations), unless it's the original leaves.
static void free_children(PageRef *children, int child_count, const PageRef *leaves) {
    if (children != leaves) {
        for (int j = 0; j < child_count; j++) {
            free(children[j].sep_cell);
        }
        free(children);
    }
}

// Fill an interior page with cells from children[*idx..child_count-2].
// Updates cell_count, content_offset, ptr_offset, and *idx.
static bool fill_interior_page(PageBuilder *pb, uint8_t *page, const PageRef *children,
                               int child_count, bool is_index, int *idx, int *cell_count,
                               int *content_offset, int *ptr_offset) {
    while (*idx < child_count - SKIP_ONE) {
        uint8_t tbuf[INTERIOR_CELL_BUF];
        uint8_t *heap_cell = NULL;
        int clen = build_interior_cell(pb->io, &children[*idx], is_index, tbuf, &heap_cell);
        if (clen < 0) {
            return false;
        }
        uint8_t *cell_data = heap_cell ? heap_cell : tbuf;

        int available = *content_offset - *ptr_offset - CELL_PTR_SIZE;
        if (clen > available) {
            free(heap_cell);
            if (*cell_count > 0) {
                return true;
            }
            writer_record_cell_failure(pb->io, "interior_cell_does_not_fit", (size_t)clen);
            return false;
        }

        *content_offset -= clen;
        memcpy(page + *content_offset, cell_data, clen);
        put_u16(page + *ptr_offset, (uint16_t)*content_offset);
        *ptr_offset += CELL_PTR_SIZE;
        (*cell_count)++;
        free(heap_cell);
        (*idx)++;
    }
    return true;
}

static uint32_t pb_build_interior(PageBuilder *pb, bool is_index) {
    if (!pb->leaves) {
        return 0;
    }
    if (pb->leaf_count <= SKIP_ONE) {
        return pb->leaves[0].page_num;
    }

    PageRef *children = pb->leaves;
    int child_count = pb->leaf_count;

    while (child_count > SKIP_ONE && children) {
        PageRef *parents = NULL;
        int parent_count = 0;
        int parent_cap = 0;
        bool level_failed = false;

        int i = 0;
        while (i < child_count) {
            uint8_t page[CBM_PAGE_SIZE];
            memset(page, 0, CBM_PAGE_SIZE);
            int cell_count = 0;
            int content_offset = CBM_PAGE_SIZE;
            int ptr_offset = BTREE_INTERIOR_HDR;

            if (!fill_interior_page(pb, page, children, child_count, is_index, &i, &cell_count,
                                    &content_offset, &ptr_offset)) {
                level_failed = true;
                break;
            }

            int right_child_idx = (i < child_count - SKIP_ONE) ? i : child_count - SKIP_ONE;
            uint32_t right_child_page = 0;
            if (right_child_idx >= 0 && right_child_idx < child_count) {
                right_child_page = children[right_child_idx].page_num;
            }
            if (i < child_count - SKIP_ONE) {
                i++;
            } else {
                i = child_count;
            }

            int updated_count = write_interior_page(pb, page, cell_count, content_offset,
                                                    right_child_page, children, right_child_idx,
                                                    is_index, &parents, parent_count, &parent_cap);
            if (updated_count < 0) {
                level_failed = true;
                break;
            }
            parent_count = updated_count;
        }

        if (level_failed) {
            free_children(children, child_count, pb->leaves);
            free_children(parents, parent_count, pb->leaves);
            return 0;
        }
        free_children(children, child_count, pb->leaves);
        children = parents;
        child_count = parent_count;
    }

    uint32_t root = children ? children[0].page_num : 0;
    free_children(children, child_count, pb->leaves);
    return root;
}

// --- Table record builders ---

// Build a nodes table record: (id, project, label, name, qualified_name, file_path, start_line,
// end_line, properties)
static uint8_t *build_node_record(WriterIo *io, const CBMDumpNode *n, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_node_record");

    rec_add_int(&r, n->id);
    rec_add_text(&r, n->project);
    rec_add_text(&r, n->label);
    rec_add_text(&r, n->name);
    rec_add_text(&r, n->qualified_name);
    rec_add_text(&r, n->file_path ? n->file_path : "");
    rec_add_int(&r, n->start_line);
    rec_add_int(&r, n->end_line);
    rec_add_text(&r, n->properties ? n->properties : "{}");
    rec_add_text(&r, n->atom_id);
    rec_add_int(&r, n->source_present ? 1 : 0);
    if (n->source_present) {
        rec_add_blob(&r, n->source_bytes, (int)n->source_len);
    } else {
        rec_add_null(&r);
    }
    rec_add_text(&r, n->source_sha256 ? n->source_sha256 : "");
    rec_add_int(&r, (int64_t)n->start_byte);
    rec_add_int(&r, (int64_t)n->end_byte);

    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// Build an edges table record: (id, project, source_id, target_id, type, properties)
// url_path_gen and local_name_gen are VIRTUAL generated columns — NOT stored in the record.
static uint8_t *build_edge_record(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_edge_record");

    rec_add_int(&r, e->id);
    rec_add_text(&r, e->project);
    rec_add_int(&r, e->source_id);
    rec_add_int(&r, e->target_id);
    rec_add_text(&r, e->type);
    rec_add_text(&r, e->properties ? e->properties : "{}");

    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// Build a node_vectors table record: (node_id, project, vector)
// Includes node_id in the record body (same pattern as build_node_record).
static uint8_t *build_vector_record(WriterIo *io, const CBMDumpVector *v, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_vector_record");

    rec_add_int(&r, v->node_id);
    rec_add_text(&r, v->project);
    rec_add_blob(&r, v->vector, v->vector_len);

    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// Build a token_vectors table record: (id, project, token, vector, idf)
static uint8_t *build_token_vec_record(WriterIo *io, const CBMDumpTokenVec *tv, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_token_vector_record");

    rec_add_int(&r, tv->id);
    rec_add_text(&r, tv->project);
    rec_add_text(&r, tv->token);
    rec_add_blob(&r, tv->vector, tv->vector_len);
    /* Store IDF as integer × 1000 for fixed-point (avoid float in record) */
    enum { IDF_FIXED_POINT_SCALE = 1000 };
    rec_add_int(&r, (int64_t)(tv->idf * IDF_FIXED_POINT_SCALE));

    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// Build a projects table record: (name, indexed_at, root_path)
static uint8_t *build_project_record(WriterIo *io, const char *name, const char *indexed_at,
                                     const char *root_path, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_project_record");

    rec_add_text(&r, name);
    rec_add_text(&r, indexed_at);
    rec_add_text(&r, root_path);

    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// --- Table cell builder ---
// Table leaf cell: varint(payload_len) + varint(rowid) + payload

static uint8_t *build_table_cell(WriterIo *io, int64_t rowid, const uint8_t *payload,
                                 int payload_len, int *out_cell_len) {
    int rl = varint_len(payload_len);
    int kl = varint_len(rowid);
    int total = rl + kl + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_table_cell", (size_t)total);
        return NULL;
    }
    int pos = 0;
    pos += put_varint(cell + pos, payload_len);
    pos += put_varint(cell + pos, rowid);
    memcpy(cell + pos, payload, payload_len);
    *out_cell_len = pos + payload_len;
    return cell;
}

// Build a table leaf cell with overflow: stores only the first local_len bytes of
// payload inline, followed by a 4-byte overflow page number.
// total_payload_len is the FULL original payload length (written as the payload-size
// varint so SQLite knows the real record size).
static uint8_t *build_table_cell_overflow(WriterIo *io, int64_t rowid, const uint8_t *payload,
                                          int total_payload_len, int local_len,
                                          uint32_t overflow_page, int *out_cell_len) {
    int rl = varint_len(total_payload_len);
    int kl = varint_len(rowid);
    // cell = varint(total_payload_len) + varint(rowid) + payload[0..local_len) + uint32(overflow)
    int total = rl + kl + local_len + BTREE_PTR_SIZE;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_overflow_table_cell", (size_t)total);
        return NULL;
    }
    int pos = 0;
    pos += put_varint(cell + pos, total_payload_len);
    pos += put_varint(cell + pos, rowid);
    memcpy(cell + pos, payload, local_len);
    pos += local_len;
    put_u32(cell + pos, overflow_page);
    pos += BTREE_PTR_SIZE;
    *out_cell_len = pos;
    return cell;
}

// --- Overflow page writer ---
// Writes overflow pages for payload bytes that exceed local storage.
// Returns the first overflow page number (embedded in the leaf cell).
// Each overflow page: 4-byte next-page pointer + up to (CBM_PAGE_SIZE-4) bytes of data.
static uint32_t write_overflow_pages(WriterIo *io, uint32_t *next_page, const uint8_t *data,
                                     int data_len) {
    int per_page = CBM_PAGE_SIZE - BTREE_PTR_SIZE;
    uint32_t first_page = 0;
    uint32_t previous_page = 0;

    int offset = 0;
    while (offset < data_len) {
        uint32_t pnum = 0;
        if (!writer_allocate_page(io, next_page, "allocate_overflow_page", &pnum)) {
            return 0;
        }
        if (first_page == 0) {
            first_page = pnum;
        }

        // Backpatch previous overflow page's next-page pointer
        if (previous_page != 0) {
            uint8_t ptr[BTREE_PTR_SIZE];
            put_u32(ptr, pnum);
            if (!writer_io_seek_page(io, previous_page) ||
                !writer_io_write(io, ptr, BTREE_PTR_SIZE)) {
                return 0;
            }
        }

        int chunk = data_len - offset;
        if (chunk > per_page) {
            chunk = per_page;
        }

        uint8_t page[CBM_PAGE_SIZE];
        memset(page, 0, CBM_PAGE_SIZE);
        put_u32(page, 0); // next-page pointer — 0 for now, backpatched on next iteration
        memcpy(page + BTREE_PTR_SIZE, data + offset, chunk);

        previous_page = pnum;
        if (!writer_io_seek_page(io, pnum) || !writer_io_write(io, page, CBM_PAGE_SIZE)) {
            return 0;
        }

        offset += chunk;
    }
    return first_page;
}

// --- Index record builders ---

// Build an index entry for a 2-column TEXT index (project, col) + rowid.
// Index records: varint(payload_len) + payload(record of indexed cols + rowid)
static uint8_t *build_index_entry_2text_rowid(WriterIo *io, const char *col1, const char *col2,
                                              int64_t rowid, int *out_len) {
    // Build the record portion: (col1, col2, rowid)
    RecordBuilder r;
    rec_init(&r, io, "build_index_2text_record");
    rec_add_text(&r, col1);
    rec_add_text(&r, col2);
    rec_add_int(&r, rowid);
    int payload_len = 0;
    uint8_t *payload = rec_finalize(&r, &payload_len);
    rec_free(&r);
    if (!payload) {
        *out_len = 0;
        return NULL;
    }

    // Index cell: varint(payload_len) + payload
    int vl = varint_len(payload_len);
    int total = vl + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_index_2text_cell", (size_t)total);
        free(payload);
        *out_len = 0;
        return NULL;
    }
    int pos = put_varint(cell, payload_len);
    memcpy(cell + pos, payload, payload_len);
    free(payload);
    *out_len = total;
    return cell;
}

// Build index entry for (int64, text) + rowid (e.g., idx_edges_source)
static uint8_t *build_index_entry_int_text_rowid(WriterIo *io, int64_t val, const char *text,
                                                 int64_t rowid, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_index_int_text_record");
    rec_add_int(&r, val);
    rec_add_text(&r, text);
    rec_add_int(&r, rowid);
    int payload_len = 0;
    uint8_t *payload = rec_finalize(&r, &payload_len);
    rec_free(&r);
    if (!payload) {
        *out_len = 0;
        return NULL;
    }

    int vl = varint_len(payload_len);
    int total = vl + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_index_int_text_cell", (size_t)total);
        free(payload);
        *out_len = 0;
        return NULL;
    }
    int pos = put_varint(cell, payload_len);
    memcpy(cell + pos, payload, payload_len);
    free(payload);
    *out_len = total;
    return cell;
}

// Build index entry for (text, int64, text) + rowid (e.g., idx_edges_target_type)
static uint8_t *build_index_entry_text_int_text_rowid(WriterIo *io, const char *t1, int64_t val,
                                                      const char *t2, int64_t rowid, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_index_text_int_text_record");
    rec_add_text(&r, t1);
    rec_add_int(&r, val);
    rec_add_text(&r, t2);
    rec_add_int(&r, rowid);
    int payload_len = 0;
    uint8_t *payload = rec_finalize(&r, &payload_len);
    rec_free(&r);
    if (!payload) {
        *out_len = 0;
        return NULL;
    }

    int vl = varint_len(payload_len);
    int total = vl + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_index_text_int_text_cell", (size_t)total);
        free(payload);
        *out_len = 0;
        return NULL;
    }
    int pos = put_varint(cell, payload_len);
    memcpy(cell + pos, payload, payload_len);
    free(payload);
    *out_len = total;
    return cell;
}

// Build UNIQUE index entry for (int64, int64, text, text) + rowid — edges
// unique(source_id, target_id, type, local_name_gen) (#768).
static uint8_t *build_index_entry_unique_2int_2text_rowid(WriterIo *io, int64_t v1, int64_t v2,
                                                          const char *text, const char *text2,
                                                          int64_t rowid, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_unique_index_record");
    rec_add_int(&r, v1);
    rec_add_int(&r, v2);
    rec_add_text(&r, text);
    rec_add_text(&r, text2);
    rec_add_int(&r, rowid);
    int payload_len = 0;
    uint8_t *payload = rec_finalize(&r, &payload_len);
    rec_free(&r);
    if (!payload) {
        *out_len = 0;
        return NULL;
    }

    int vlen = varint_len(payload_len);
    int total = vlen + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_unique_index_cell", (size_t)total);
        free(payload);
        *out_len = 0;
        return NULL;
    }
    int pos = put_varint(cell, payload_len);
    memcpy(cell + pos, payload, payload_len);
    free(payload);
    *out_len = total;
    return cell;
}

// --- Write a table B-tree from records ---

// Ensure leaves array has capacity for one more entry.
// Returns false on allocation failure.
static bool pb_ensure_leaf_cap(PageBuilder *pb) {
    if (pb->leaf_count < pb->leaf_cap) {
        return true;
    }
    if (pb->leaf_cap > INT_MAX / GROWTH_FACTOR) {
        writer_record_allocation_failure(pb->io, "grow_leaf_references", SIZE_MAX);
        return false;
    }
    int new_cap = pb->leaf_cap == 0 ? INITIAL_LEAF_CAP : pb->leaf_cap * GROWTH_FACTOR;
    size_t requested = (size_t)new_cap * sizeof(PageRef);
    void *tmp = realloc(pb->leaves, requested);
    if (!tmp) {
        writer_record_allocation_failure(pb->io, "grow_leaf_references", requested);
        return false;
    }
    pb->leaves = (PageRef *)tmp;
    pb->leaf_cap = new_cap;
    return true;
}

// SQLite overflow thresholds for leaf table B-tree pages (PAGE_SIZE=65536, reserved=0):
//   usable    = PAGE_SIZE = 65536
//   max_local = usable - 35 = 65501
//   min_local = (usable - 12) * 32 / 255 - 23 = 8199  (C integer arithmetic, same as SQLite)
#define TABLE_OVERFLOW_MAX_LOCAL 65501

// SQLite index B-tree local-payload thresholds for PAGE_SIZE=65536, reserved=0:
//   X (max local) = ((U-12)*64/255) - 23 = 16422
//   M (min local) = ((U-12)*32/255) - 23 = 8199
// An index cell whose payload exceeds X MUST spill to overflow pages; storing
// it fully inline makes SQLite read key bytes as an overflow page number
// (integrity_check: "invalid page number", name lookups silently miss — seen
// on elasticsearch's very long Section names in idx_nodes_name).
#define INDEX_OVERFLOW_MAX_LOCAL 16422
#define INDEX_OVERFLOW_MIN_LOCAL 8199

// Read a SQLite varint (1-9 bytes). Returns bytes consumed.
static int get_varint(const uint8_t *buf, uint64_t *out) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 7) | (uint64_t)(buf[i] & 0x7f);
        if ((buf[i] & 0x80) == 0) {
            *out = v;
            return i + 1;
        }
    }
    v = (v << 8) | (uint64_t)buf[8];
    *out = v;
    return 9;
}

// If an index cell's payload exceeds X, rewrite it to spill the tail to
// overflow pages: varint(payload_len) + payload[0..local) + u32(first_ovfl).
// Returns the (possibly new, malloc'd) cell; frees the original when replaced.
static uint8_t *overflowize_index_cell(WriterIo *io, uint32_t *next_page, uint8_t *cell,
                                       int *cell_len) {
    uint64_t plen = 0;
    int vlen = get_varint(cell, &plen);
    if ((int64_t)plen <= INDEX_OVERFLOW_MAX_LOCAL) {
        return cell;
    }
    int64_t per_ovfl = (int64_t)CBM_PAGE_SIZE - BTREE_PTR_SIZE;
    int64_t k = INDEX_OVERFLOW_MIN_LOCAL + (((int64_t)plen - INDEX_OVERFLOW_MIN_LOCAL) % per_ovfl);
    int local = (k <= INDEX_OVERFLOW_MAX_LOCAL) ? (int)k : INDEX_OVERFLOW_MIN_LOCAL;
    uint32_t first_ovfl =
        write_overflow_pages(io, next_page, cell + vlen + local, (int)plen - local);
    if (first_ovfl == 0) {
        return NULL;
    }
    int nlen = vlen + local + BTREE_PTR_SIZE;
    uint8_t *data = (uint8_t *)malloc((size_t)nlen);
    if (!data) {
        writer_record_allocation_failure(io, "overflow_index_cell", (size_t)nlen);
        return NULL;
    }
    memcpy(data, cell, (size_t)(vlen + local));
    put_u32(data + vlen + local, first_ovfl);
    free(cell);
    *cell_len = nlen;
    return data;
}
#define TABLE_OVERFLOW_MIN_LOCAL 8199

// Add a table cell to the PageBuilder, flushing leaf pages as needed.
// If the payload exceeds max_local, overflow pages are written and only the
// local portion plus a 4-byte overflow page pointer is stored in the leaf cell.
static void pb_add_table_cell_with_flush(PageBuilder *pb, int64_t rowid, const uint8_t *payload,
                                         int payload_len, int64_t prev_rowid) {
    int cell_len = 0;
    uint8_t *cell = NULL;

    if (payload_len > TABLE_OVERFLOW_MAX_LOCAL) {
        // Compute local_len per SQLite spec for leaf table cells.
        int ovfl_page_data = CBM_PAGE_SIZE - BTREE_PTR_SIZE;
        int remainder = (payload_len - TABLE_OVERFLOW_MIN_LOCAL) % ovfl_page_data;
        int local_len = TABLE_OVERFLOW_MIN_LOCAL + remainder;
        if (local_len > TABLE_OVERFLOW_MAX_LOCAL) {
            local_len = TABLE_OVERFLOW_MIN_LOCAL;
        }

        // Write overflow pages for the bytes that don't fit locally.
        uint32_t overflow_page = write_overflow_pages(pb->io, &pb->next_page, payload + local_len,
                                                      payload_len - local_len);
        if (overflow_page == 0) {
            return; // overflow write failed
        }

        cell = build_table_cell_overflow(pb->io, rowid, payload, payload_len, local_len,
                                         overflow_page, &cell_len);
    } else {
        cell = build_table_cell(pb->io, rowid, payload, payload_len, &cell_len);
    }

    if (!cell) {
        return;
    }

    if (!pb_cell_fits(pb, cell_len) && pb->cell_count > 0) {
        if (!pb_ensure_leaf_cap(pb)) {
            free(cell);
            return;
        }
        pb->leaves[pb->leaf_count].max_key = prev_rowid;
        pb->leaves[pb->leaf_count].sep_cell = NULL;
        pb->leaves[pb->leaf_count].sep_cell_len = 0;
        pb_flush_leaf(pb);
        if (pb->io->failed) {
            free(cell);
            return;
        }
    }

    pb_add_cell(pb, cell, cell_len);
    free(cell);
}

// Finalize a table PageBuilder: flush last leaf and build interior pages.
static uint32_t pb_finalize_table(PageBuilder *pb, uint32_t *next_page, int64_t last_rowid) {
    if (pb->cell_count > 0) {
        pb_ensure_leaf_cap(pb);
        if (!pb->leaves) {
            pb_free(pb);
            return 0;
        }
        pb->leaves[pb->leaf_count].max_key = last_rowid;
        pb->leaves[pb->leaf_count].sep_cell = NULL;
        pb->leaves[pb->leaf_count].sep_cell_len = 0;
        pb_flush_leaf(pb);
        if (pb->io->failed) {
            pb_free(pb);
            return 0;
        }
    }

    *next_page = pb->next_page;
    uint32_t root;
    if (pb->leaf_count == SKIP_ONE) {
        root = pb->leaves[0].page_num;
    } else if (pb->leaf_count > SKIP_ONE) {
        root = pb_build_interior(pb, false);
        *next_page = pb->next_page;
    } else {
        root = 0; // shouldn't happen when count > 0
    }
    pb_free(pb);
    return root;
}

// Write leaf pages for a table, returns root page.
// rowids must be sequential starting from 1 (or single-row PK text).
static uint32_t write_table_btree(WriterIo *io, uint32_t *next_page, const uint8_t **records,
                                  const int *record_lens, const int64_t *rowids, int count,
                                  bool first_is_page1) {
    if (count == 0) {
        // Empty table: write a single empty leaf page
        uint32_t pnum = 0;
        if (!writer_allocate_page(io, next_page, "allocate_empty_table_page", &pnum)) {
            return 0;
        }
        uint8_t page[CBM_PAGE_SIZE];
        memset(page, 0, CBM_PAGE_SIZE);
        int hdr = first_is_page1 ? SQLITE_HEADER_SIZE : 0;
        page[hdr] = BTREE_LEAF_TABLE;                                   // leaf table
        put_u16(page + hdr + HDR_FREEBLOCK_OFF, 0);                     // no freeblocks
        put_u16(page + hdr + HDR_CELLCOUNT_OFF, 0);                     // 0 cells
        put_u16(page + hdr + HDR_CONTENT_OFF, (uint16_t)CBM_PAGE_SIZE); // content at end of page
        page[hdr + HDR_FRAGBYTES_OFF] = 0;                              // 0 fragmented bytes
        if (!writer_io_seek_page(io, pnum) || !writer_io_write(io, page, CBM_PAGE_SIZE)) {
            return 0;
        }
        return pnum;
    }

    PageBuilder pb;
    pb_init(&pb, io, *next_page, false);
    pb.page1_offset = first_is_page1 ? SQLITE_HEADER_SIZE : 0;
    pb.ptr_offset = pb.page1_offset + BTREE_HEADER_SIZE;

    for (int i = 0; i < count; i++) {
        pb_add_table_cell_with_flush(&pb, rowids[i], records[i], record_lens[i],
                                     i > 0 ? rowids[i - SKIP_ONE] : 0);
        if (io->failed) {
            pb_free(&pb);
            return 0;
        }
    }

    return pb_finalize_table(&pb, next_page, rowids[count - SKIP_ONE]);
}

// Promote the last cell from current page to separator, un-add it, and flush.
static bool pb_promote_and_flush(PageBuilder *pb, uint8_t **cells, int *cell_lens, int prev_idx) {
    if (!pb_ensure_leaf_cap(pb)) {
        return false;
    }
    pb->leaves[pb->leaf_count].max_key = 0;
    pb->leaves[pb->leaf_count].sep_cell = (uint8_t *)malloc(cell_lens[prev_idx]);
    if (!pb->leaves[pb->leaf_count].sep_cell) {
        writer_record_allocation_failure(pb->io, "copy_index_separator",
                                         (size_t)cell_lens[prev_idx]);
        return false;
    }
    memcpy(pb->leaves[pb->leaf_count].sep_cell, cells[prev_idx], cell_lens[prev_idx]);
    pb->leaves[pb->leaf_count].sep_cell_len = cell_lens[prev_idx];

    // Un-add the last cell — it's promoted to the interior separator.
    // SQLite index B-tree interior cells are counted by integrity_check,
    // so this cell exists in the interior page instead of the leaf.
    pb->cell_count--;
    pb->content_offset += cell_lens[prev_idx];
    pb->ptr_offset -= CELL_PTR_SIZE;

    pb_flush_leaf(pb);
    return !pb->io->failed;
}

// Write an empty index leaf page.
static uint32_t write_empty_index_leaf(WriterIo *io, uint32_t *next_page) {
    uint32_t pnum = 0;
    if (!writer_allocate_page(io, next_page, "allocate_empty_index_page", &pnum)) {
        return 0;
    }
    uint8_t page[CBM_PAGE_SIZE];
    memset(page, 0, CBM_PAGE_SIZE);
    page[0] = NEWLINE_BYTE;
    put_u16(page + HDR_FREEBLOCK_OFF, 0);
    put_u16(page + HDR_CELLCOUNT_OFF, 0);
    put_u16(page + HDR_CONTENT_OFF, (uint16_t)CBM_PAGE_SIZE);
    page[HDR_FRAGBYTES_OFF] = 0;
    if (!writer_io_seek_page(io, pnum) || !writer_io_write(io, page, CBM_PAGE_SIZE)) {
        return 0;
    }
    return pnum;
}

// Write leaf pages for an index, returns root page.
static uint32_t write_index_btree(WriterIo *io, uint32_t *next_page, uint8_t **cells,
                                  int *cell_lens, int count) {
    if (count == 0) {
        return write_empty_index_leaf(io, next_page);
    }

    /* Spill oversized index payloads to overflow pages BEFORE page building so
     * every cell added below is within the local-payload limit (see
     * INDEX_OVERFLOW_MAX_LOCAL). Overflow pages are allocated from *next_page
     * ahead of the leaf pages, which is fine — page order is arbitrary. */
    for (int i = 0; i < count; i++) {
        uint8_t *converted = overflowize_index_cell(io, next_page, cells[i], &cell_lens[i]);
        if (!converted || io->failed) {
            return 0;
        }
        cells[i] = converted;
    }

    PageBuilder pb;
    pb_init(&pb, io, *next_page, true);

    for (int i = 0; i < count; i++) {
        if (!pb_cell_fits(&pb, cell_lens[i])) {
            if (pb.cell_count > 0) {
                if (!pb_promote_and_flush(&pb, cells, cell_lens, i - SKIP_ONE)) {
                    pb_free(&pb);
                    return 0;
                }
            }
            // After overflow conversion every index cell must fit an empty leaf.
            // Anything else is a format invariant violation, never a skippable row.
            if (!pb_cell_fits(&pb, cell_lens[i])) {
                writer_record_cell_failure(io, "index_cell_does_not_fit", (size_t)cell_lens[i]);
                pb_free(&pb);
                return 0;
            }
        }
        pb_add_cell(&pb, cells[i], cell_lens[i]);
    }

    if (pb.cell_count > 0) {
        if (!pb_ensure_leaf_cap(&pb)) {
            pb_free(&pb);
            return 0;
        }
        pb.leaves[pb.leaf_count].max_key = 0;
        int last = count - SKIP_ONE;
        pb.leaves[pb.leaf_count].sep_cell = (uint8_t *)malloc(cell_lens[last]);
        if (!pb.leaves[pb.leaf_count].sep_cell) {
            writer_record_allocation_failure(io, "copy_final_index_separator",
                                             (size_t)cell_lens[last]);
            pb_free(&pb);
            return 0;
        }
        memcpy(pb.leaves[pb.leaf_count].sep_cell, cells[last], cell_lens[last]);
        pb.leaves[pb.leaf_count].sep_cell_len = cell_lens[last];
        pb_flush_leaf(&pb);
        if (io->failed) {
            pb_free(&pb);
            return 0;
        }
    }

    *next_page = pb.next_page;

    uint32_t root;
    if (!pb.leaves) {
        root = 0;
    } else if (pb.leaf_count == SKIP_ONE) {
        root = pb.leaves[0].page_num;
    } else {
        root = pb_build_interior(&pb, true);
        *next_page = pb.next_page;
    }

    pb_free(&pb);
    return root;
}

// --- sqlite_master entries ---

typedef struct {
    const char *type;     // "table" or "index"
    const char *name;     // table/index name
    const char *tbl_name; // table name
    uint32_t rootpage;    // root page number
    const char *sql;      // CREATE statement
} MasterEntry;

static uint8_t *build_master_record(WriterIo *io, const MasterEntry *e, int *out_len) {
    RecordBuilder r;
    rec_init(&r, io, "build_master_record");
    rec_add_text(&r, e->type);
    rec_add_text(&r, e->name);
    rec_add_text(&r, e->tbl_name);
    rec_add_int(&r, (int64_t)e->rootpage);
    if (e->sql) {
        rec_add_text(&r, e->sql);
    } else {
        rec_add_null(&r);
    }
    uint8_t *data = rec_finalize(&r, out_len);
    rec_free(&r);
    return data;
}

// --- transaction-local qsort_s comparators for parallel index sorting ---

static inline int cmp_i64(int64_t a, int64_t b) {
    return (a > b) - (a < b);
}

static inline const char *safe_str(const char *s) {
    return s ? s : "";
}

// Allocate permutation array [0, 1, ..., n-1], sort with comparator.
// Returns NULL on allocation failure.
typedef int(__cdecl *sort_compare_fn)(void *, const void *, const void *);

static int *make_sorted_perm(int n, sort_compare_fn cmp, const void *context) {
    int *perm = (int *)malloc(n * sizeof(int));
    if (!perm) {
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        perm[i] = i;
    }
    qsort_s(perm, (size_t)n, sizeof(int), cmp, (void *)context);
    return perm;
}

// --- Node index comparators (project is same for all, skip it) ---

static int __cdecl cmp_node_by_label(void *context, const void *a, const void *b) {
    const CBMDumpNode *nodes = (const CBMDumpNode *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(nodes[ia].label), safe_str(nodes[ib].label));
    if (c) {
        return c;
    }
    return cmp_i64(nodes[ia].id, nodes[ib].id);
}

static int __cdecl cmp_node_by_name(void *context, const void *a, const void *b) {
    const CBMDumpNode *nodes = (const CBMDumpNode *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(nodes[ia].name), safe_str(nodes[ib].name));
    if (c) {
        return c;
    }
    return cmp_i64(nodes[ia].id, nodes[ib].id);
}

static int __cdecl cmp_node_by_file(void *context, const void *a, const void *b) {
    const CBMDumpNode *nodes = (const CBMDumpNode *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(nodes[ia].file_path), safe_str(nodes[ib].file_path));
    if (c) {
        return c;
    }
    return cmp_i64(nodes[ia].id, nodes[ib].id);
}

static int __cdecl cmp_node_by_qn(void *context, const void *a, const void *b) {
    const CBMDumpNode *nodes = (const CBMDumpNode *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(nodes[ia].qualified_name), safe_str(nodes[ib].qualified_name));
    if (c) {
        return c;
    }
    return cmp_i64(nodes[ia].id, nodes[ib].id);
}

static int __cdecl cmp_node_by_atom(void *context, const void *a, const void *b) {
    const CBMDumpNode *nodes = (const CBMDumpNode *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(nodes[ia].atom_id), safe_str(nodes[ib].atom_id));
    return c ? c : cmp_i64(nodes[ia].id, nodes[ib].id);
}

// --- Edge index comparators ---

// idx_edges_source: (source_id, type) + rowid
static int __cdecl cmp_edge_by_source_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = cmp_i64(edges[ia].source_id, edges[ib].source_id);
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// idx_edges_target: (target_id, type) + rowid
static int __cdecl cmp_edge_by_target_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = cmp_i64(edges[ia].target_id, edges[ib].target_id);
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// idx_edges_type: (project, type) + rowid
static int __cdecl cmp_edge_by_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// idx_edges_target_type: (project, target_id, type) + rowid
static int __cdecl cmp_edge_by_proj_target_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = cmp_i64(edges[ia].target_id, edges[ib].target_id);
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// idx_edges_source_type: (project, source_id, type) + rowid
static int __cdecl cmp_edge_by_proj_source_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = cmp_i64(edges[ia].source_id, edges[ib].source_id);
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// idx_edges_url_path: (project, url_path_gen) + rowid — NULL sorts first
static int __cdecl cmp_edge_by_url_path(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    const char *ua = edges[ia].url_path;
    const char *ub = edges[ib].url_path;
    bool na = (!ua || ua[0] == '\0');
    bool nb = (!ub || ub[0] == '\0');
    if (na && nb) {
        return cmp_i64(edges[ia].id, edges[ib].id);
    }
    if (na) {
        return CBM_NOT_FOUND;
    }
    if (nb) {
        return SERIAL_SIZE_INT8;
    }
    int c = strcmp(ua, ub);
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// autoindex_edges_1: UNIQUE(source_id, target_id, type, local_name_gen) + rowid (#768)
static int __cdecl cmp_edge_by_src_tgt_type(void *context, const void *a, const void *b) {
    const CBMDumpEdge *edges = (const CBMDumpEdge *)context;
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    int c = cmp_i64(edges[ia].source_id, edges[ib].source_id);
    if (c) {
        return c;
    }
    c = cmp_i64(edges[ia].target_id, edges[ib].target_id);
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].type), safe_str(edges[ib].type));
    if (c) {
        return c;
    }
    c = strcmp(safe_str(edges[ia].local_name), safe_str(edges[ib].local_name));
    if (c) {
        return c;
    }
    return cmp_i64(edges[ia].id, edges[ib].id);
}

// --- Parallel sort support ---

typedef struct {
    int count;
    sort_compare_fn cmp;
    const void *context;
    int *perm; // output: sorted permutation array, caller frees
} SortJob;

static void *sort_worker(void *arg) {
    SortJob *j = (SortJob *)arg;
    j->perm = make_sorted_perm(j->count, j->cmp, j->context);
    return NULL;
}

/* Edge index cell builder callback: builds one index cell from an edge. */
typedef uint8_t *(*edge_cell_fn)(WriterIo *io, const CBMDumpEdge *e, int *out_len);

static uint8_t *ecell_source(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_int_text_rowid(io, e->source_id, e->type, e->id, out_len);
}
static uint8_t *ecell_target(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_int_text_rowid(io, e->target_id, e->type, e->id, out_len);
}
static uint8_t *ecell_type(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_2text_rowid(io, e->project, e->type, e->id, out_len);
}
static uint8_t *ecell_proj_target_type(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_text_int_text_rowid(io, e->project, e->target_id, e->type, e->id,
                                                 out_len);
}
static uint8_t *ecell_proj_source_type(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_text_int_text_rowid(io, e->project, e->source_id, e->type, e->id,
                                                 out_len);
}
static uint8_t *ecell_src_tgt_type(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    return build_index_entry_unique_2int_2text_rowid(io, e->source_id, e->target_id, e->type,
                                                     safe_str(e->local_name), e->id, out_len);
}
static uint8_t *ecell_url_path(WriterIo *io, const CBMDumpEdge *e, int *out_len) {
    const char *url = (e->url_path && e->url_path[0] != '\0') ? e->url_path : NULL;
    RecordBuilder r;
    rec_init(&r, io, "build_url_path_index_record");
    rec_add_text(&r, e->project);
    if (url) {
        rec_add_text(&r, url);
    } else {
        rec_add_null(&r);
    }
    rec_add_int(&r, e->id);
    int payload_len = 0;
    uint8_t *payload = rec_finalize(&r, &payload_len);
    rec_free(&r);
    if (!payload) {
        *out_len = 0;
        return NULL;
    }
    int vlen = varint_len(payload_len);
    int total = vlen + payload_len;
    uint8_t *cell = (uint8_t *)malloc(total);
    if (!cell) {
        writer_record_allocation_failure(io, "build_url_path_index_cell", (size_t)total);
        free(payload);
        *out_len = 0;
        return NULL;
    }
    int pos = put_varint(cell, payload_len);
    memcpy(cell + pos, payload, payload_len);
    free(payload);
    *out_len = total;
    return cell;
}

/* Build an edge index from a pre-sorted permutation using a cell builder callback. */
static uint32_t build_edge_index_sorted(WriterIo *io, uint32_t *next_page, CBMDumpEdge *edges,
                                        int edge_count, int *perm, edge_cell_fn cell_fn) {
    if (edge_count <= 0) {
        return write_index_btree(io, next_page, NULL, NULL, 0);
    }
    if (!perm) {
        writer_record_allocation_failure(io, "sort_edge_index", (size_t)edge_count * sizeof(int));
        return 0;
    }
    uint8_t **idx_cells = (uint8_t **)malloc(edge_count * sizeof(uint8_t *));
    int *idx_lens = (int *)malloc(edge_count * sizeof(int));
    if (!idx_cells || !idx_lens) {
        writer_record_allocation_failure(io, "allocate_edge_index_cells",
                                         (size_t)edge_count * (sizeof(uint8_t *) + sizeof(int)));
        free(perm);
        free(idx_cells);
        free(idx_lens);
        return 0;
    }
    for (int i = 0; i < edge_count; i++) {
        int si = perm[i];
        idx_cells[i] = cell_fn(io, &edges[si], &idx_lens[i]);
        if (!idx_cells[i]) {
            for (int j = 0; j < i; j++) {
                free(idx_cells[j]);
            }
            free(idx_cells);
            free(idx_lens);
            free(perm);
            return 0;
        }
    }
    free(perm);
    uint32_t root = write_index_btree(io, next_page, idx_cells, idx_lens, edge_count);
    for (int i = 0; i < edge_count; i++) {
        free(idx_cells[i]);
    }
    free(idx_cells);
    free(idx_lens);
    return root;
}

/* Node column getter for index building. */
typedef const char *(*node_col_fn)(const CBMDumpNode *n);
static const char *ncol_label(const CBMDumpNode *n) {
    return n->label;
}
static const char *ncol_name(const CBMDumpNode *n) {
    return n->name;
}
static const char *ncol_file(const CBMDumpNode *n) {
    return n->file_path ? n->file_path : "";
}
static const char *ncol_qn(const CBMDumpNode *n) {
    return n->qualified_name;
}
static const char *ncol_atom(const CBMDumpNode *n) {
    return n->atom_id;
}

/* Build a 2-text node index from a pre-sorted permutation. Returns root page or 0. */
static uint32_t build_node_index_sorted(WriterIo *io, uint32_t *next_page, CBMDumpNode *nodes,
                                        int node_count, int *perm, node_col_fn col_fn) {
    if (node_count <= 0) {
        return write_index_btree(io, next_page, NULL, NULL, 0);
    }
    if (!perm) {
        writer_record_allocation_failure(io, "sort_node_index", (size_t)node_count * sizeof(int));
        return 0;
    }
    uint8_t **idx_cells = (uint8_t **)malloc(node_count * sizeof(uint8_t *));
    int *idx_lens = (int *)malloc(node_count * sizeof(int));
    if (!idx_cells || !idx_lens) {
        writer_record_allocation_failure(io, "allocate_node_index_cells",
                                         (size_t)node_count * (sizeof(uint8_t *) + sizeof(int)));
        free(perm);
        free(idx_cells);
        free(idx_lens);
        return 0;
    }
    for (int i = 0; i < node_count; i++) {
        int si = perm[i];
        idx_cells[i] = build_index_entry_2text_rowid(io, nodes[si].project, col_fn(&nodes[si]),
                                                     nodes[si].id, &idx_lens[i]);
        if (!idx_cells[i]) {
            for (int j = 0; j < i; j++) {
                free(idx_cells[j]);
            }
            free(idx_cells);
            free(idx_lens);
            free(perm);
            return 0;
        }
    }
    free(perm);
    uint32_t root = write_index_btree(io, next_page, idx_cells, idx_lens, node_count);
    for (int i = 0; i < node_count; i++) {
        free(idx_cells[i]);
    }
    free(idx_cells);
    free(idx_lens);
    return root;
}

// --- Main entry point ---

/* Write context passed to sub-phases of cbm_write_db. */
typedef struct {
    WriterIo *io;
    uint32_t next_page;
    const char *project;
    const char *root_path;
    const char *indexed_at;
    CBMDumpNode *nodes;
    int node_count;
    CBMDumpEdge *edges;
    int edge_count;
    CBMDumpVector *vectors;
    int vector_count;
    CBMDumpTokenVec *token_vecs;
    int token_vec_count;
} write_db_ctx_t;

/* Callback type for building a record from an item at index i. */
typedef uint8_t *(*build_record_fn)(WriterIo *io, const void *items, int i, int *out_len);
typedef int64_t (*get_rowid_fn)(const void *items, int i);

/* Write a streaming B-tree table from count items, or an empty table if count == 0. */
static int write_one_table(write_db_ctx_t *w, uint32_t *root, const void *items, int count,
                           build_record_fn build_rec, get_rowid_fn get_id) {
    if (count <= 0 || !items) {
        *root = write_table_btree(w->io, &w->next_page, NULL, NULL, NULL, 0, false);
        return *root == 0 || w->io->failed ? ERR_WRITE_FAILED : 0;
    }
    PageBuilder pb;
    pb_init(&pb, w->io, w->next_page, false);
    for (int i = 0; i < count; i++) {
        int rec_len;
        uint8_t *rec = build_rec(w->io, items, i, &rec_len);
        if (!rec) {
            pb_free(&pb);
            return ERR_WRITE_FAILED;
        }
        int64_t rowid = get_id(items, i);
        int64_t prev_id = i > 0 ? get_id(items, i - SKIP_ONE) : 0;
        pb_add_table_cell_with_flush(&pb, rowid, rec, rec_len, prev_id);
        free(rec);
        if (w->io->failed) {
            pb_free(&pb);
            return ERR_WRITE_FAILED;
        }
    }
    *root = pb_finalize_table(&pb, &w->next_page, get_id(items, count - SKIP_ONE));
    return *root == 0 || w->io->failed ? ERR_WRITE_FAILED : 0;
}

/* Adapter functions for write_one_table (nodes are written via the streaming
 * PageBuilder in cbm_writer_append_nodes, so no node adapter is needed here). */
static uint8_t *adapt_build_edge(WriterIo *io, const void *items, int i, int *out_len) {
    return build_edge_record(io, &((const CBMDumpEdge *)items)[i], out_len);
}
static int64_t adapt_edge_id(const void *items, int i) {
    return ((const CBMDumpEdge *)items)[i].id;
}
static uint8_t *adapt_build_vector(WriterIo *io, const void *items, int i, int *out_len) {
    return build_vector_record(io, &((const CBMDumpVector *)items)[i], out_len);
}
static int64_t adapt_vector_id(const void *items, int i) {
    return ((const CBMDumpVector *)items)[i].node_id;
}
static uint8_t *adapt_build_token_vec(WriterIo *io, const void *items, int i, int *out_len) {
    return build_token_vec_record(io, &((const CBMDumpTokenVec *)items)[i], out_len);
}
static int64_t adapt_token_vec_id(const void *items, int i) {
    return ((const CBMDumpTokenVec *)items)[i].id;
}

/* Phase 2: Write metadata tables (projects, file_hashes, summaries, sqlite_sequence). */
static int write_metadata_tables(write_db_ctx_t *w, uint32_t *projects_root,
                                 uint32_t *file_hashes_root, uint32_t *summaries_root,
                                 uint32_t *sqlite_seq_root) {
    int proj_rec_len = 0;
    uint8_t *proj_rec =
        build_project_record(w->io, w->project, w->indexed_at, w->root_path, &proj_rec_len);
    if (!proj_rec) {
        return ERR_WRITE_FAILED;
    }
    const uint8_t *proj_recs[] = {proj_rec};
    int proj_lens[] = {proj_rec_len};
    int64_t proj_rowids[] = {FIRST_ROWID};
    *projects_root =
        write_table_btree(w->io, &w->next_page, proj_recs, proj_lens, proj_rowids, SKIP_ONE, false);
    free(proj_rec);

    *file_hashes_root = write_table_btree(w->io, &w->next_page, NULL, NULL, NULL, 0, false);
    *summaries_root = write_table_btree(w->io, &w->next_page, NULL, NULL, NULL, 0, false);

    RecordBuilder r1;
    RecordBuilder r2;
    rec_init(&r1, w->io, "build_sqlite_sequence_nodes");
    rec_add_text(&r1, "nodes");
    rec_add_int(&r1, w->node_count > 0 ? w->nodes[w->node_count - SKIP_ONE].id : 0);
    int seq1_len;
    uint8_t *seq1 = rec_finalize(&r1, &seq1_len);
    rec_free(&r1);

    rec_init(&r2, w->io, "build_sqlite_sequence_edges");
    rec_add_text(&r2, "edges");
    rec_add_int(&r2, w->edge_count > 0 ? w->edges[w->edge_count - SKIP_ONE].id : 0);
    int seq2_len;
    uint8_t *seq2 = rec_finalize(&r2, &seq2_len);
    rec_free(&r2);
    if (!seq1 || !seq2) {
        free(seq1);
        free(seq2);
        return ERR_WRITE_FAILED;
    }

    const uint8_t *seq_recs[] = {seq1, seq2};
    int seq_lens[] = {seq1_len, seq2_len};
    int64_t seq_rowids[] = {FIRST_ROWID, FIRST_DATA_PAGE};
    *sqlite_seq_root =
        write_table_btree(w->io, &w->next_page, seq_recs, seq_lens, seq_rowids, PAIR_LEN, false);
    free(seq1);
    free(seq2);
    if (w->io->failed || !*projects_root || !*file_hashes_root || !*summaries_root ||
        !*sqlite_seq_root) {
        return ERR_WRITE_FAILED;
    }
    return 0;
}

/* Write the SQLite file header on page 1 with master entries. */
static void write_sqlite_file_header(uint8_t *page1, uint32_t total_pages) {
    memcpy(page1, "SQLite format 3\000", 16);
    put_u16(page1 + HDR_OFF_CBM_PAGE_SIZE,
            CBM_PAGE_SIZE == SQLITE_MAX_PAGE_SIZE ? (uint16_t)SKIP_ONE : (uint16_t)CBM_PAGE_SIZE);
    page1[HDR_OFF_WRITE_VERSION] = FILE_FORMAT;
    page1[HDR_OFF_READ_VERSION] = FILE_FORMAT;
    page1[HDR_OFF_RESERVED] = 0;
    page1[HDR_OFF_MAX_EMBED_FRAC] = MAX_EMBED_FRACTION;
    page1[HDR_OFF_MIN_EMBED_FRAC] = MIN_EMBED_FRACTION;
    page1[HDR_OFF_LEAF_FRAC] = LEAF_PAYLOAD_FRACTION;
    put_u32(page1 + HDR_OFF_FILE_CHANGE, SKIP_ONE);
    put_u32(page1 + HDR_OFF_DB_SIZE, total_pages);
    put_u32(page1 + HDR_OFF_FREELIST_TRUNK, 0);
    put_u32(page1 + HDR_OFF_FREELIST_COUNT, 0);
    put_u32(page1 + HDR_OFF_SCHEMA_COOKIE, SKIP_ONE);
    put_u32(page1 + HDR_OFF_SCHEMA_FORMAT, SCHEMA_FORMAT);
    put_u32(page1 + HDR_OFF_DEFAULT_CACHE, 0);
    put_u32(page1 + HDR_OFF_AUTOVAC_TOP, 0);
    put_u32(page1 + HDR_OFF_TEXT_ENCODING, SKIP_ONE);
    put_u32(page1 + HDR_OFF_USER_VERSION, CBM_GRAPH_SCHEMA_VERSION);
    put_u32(page1 + HDR_OFF_INCR_VACUUM, 0);
    put_u32(page1 + HDR_OFF_APP_ID, 0);
    put_u32(page1 + HDR_OFF_VERSION_VALID, SKIP_ONE);
    put_u32(page1 + HDR_OFF_SQLITE_VERSION, SQLITE_VERSION);
}

/* Build master records, write page 1 B-tree + file header. */
static int write_master_page1(WriterIo *io, MasterEntry *master, int master_count,
                              uint32_t next_page) {
    if (master_count <= 0) {
        writer_record_cell_failure(io, "master_entry_count", 0);
        return ERR_MASTER_OVERFLOW;
    }
    size_t records_bytes = (size_t)master_count * sizeof(uint8_t *);
    size_t lens_bytes = (size_t)master_count * sizeof(int);
    size_t rowids_bytes = (size_t)master_count * sizeof(int64_t);
    const uint8_t **master_records =
        (const uint8_t **)calloc((size_t)master_count, sizeof(uint8_t *));
    int *master_lens = (int *)malloc(lens_bytes);
    int64_t *master_rowids = (int64_t *)malloc(rowids_bytes);
    if (!master_records || !master_lens || !master_rowids) {
        writer_record_allocation_failure(io, "allocate_master_records",
                                         records_bytes + lens_bytes + rowids_bytes);
        free(master_records);
        free(master_lens);
        free(master_rowids);
        return ERR_WRITE_FAILED;
    }
    for (int i = 0; i < master_count; i++) {
        master_rowids[i] = i + SKIP_ONE;
        master_records[i] = build_master_record(io, &master[i], &master_lens[i]);
        if (!master_records[i]) {
            for (int j = 0; j < i; j++) {
                free((void *)master_records[j]);
            }
            free(master_records);
            free(master_lens);
            free(master_rowids);
            return ERR_WRITE_FAILED;
        }
    }

    uint8_t page1[CBM_PAGE_SIZE];
    memset(page1, 0, CBM_PAGE_SIZE);
    int hdr = SQLITE_HEADER_SIZE;
    page1[hdr] = BTREE_LEAF_TABLE;
    int content_off = CBM_PAGE_SIZE;
    int ptr_off = hdr + BTREE_HEADER_SIZE;
    int mcell_count = 0;

    for (int i = 0; i < master_count; i++) {
        int cell_len = 0;
        uint8_t *cell =
            build_table_cell(io, master_rowids[i], master_records[i], master_lens[i], &cell_len);
        int available = content_off - ptr_off - CELL_PTR_SIZE;
        if (!cell || cell_len > available) {
            bool allocation_failed = cell == NULL;
            if (cell && cell_len > available) {
                writer_record_cell_failure(io, "master_cell_does_not_fit", (size_t)cell_len);
            }
            free(cell);
            for (int j = 0; j < master_count; j++) {
                free((void *)master_records[j]);
            }
            free(master_records);
            free(master_lens);
            free(master_rowids);
            return allocation_failed ? ERR_WRITE_FAILED : ERR_MASTER_OVERFLOW;
        }
        content_off -= cell_len;
        memcpy(page1 + content_off, cell, cell_len);
        put_u16(page1 + ptr_off, (uint16_t)content_off);
        ptr_off += CELL_PTR_SIZE;
        mcell_count++;
        free(cell);
    }

    put_u16(page1 + hdr + HDR_FREEBLOCK_OFF, 0);
    put_u16(page1 + hdr + HDR_CELLCOUNT_OFF, (uint16_t)mcell_count);
    put_u16(page1 + hdr + HDR_CONTENT_OFF, (uint16_t)content_off);
    page1[hdr + HDR_FRAGBYTES_OFF] = 0;

    write_sqlite_file_header(page1, next_page - SKIP_ONE);

    if (!writer_io_seek(io, 0, SEEK_SET) || !writer_io_write(io, page1, CBM_PAGE_SIZE)) {
        for (int i = 0; i < master_count; i++) {
            free((void *)master_records[i]);
        }
        free(master_records);
        free(master_lens);
        free(master_rowids);
        return ERR_WRITE_FAILED;
    }

    for (int i = 0; i < master_count; i++) {
        free((void *)master_records[i]);
    }
    free(master_records);
    free(master_lens);
    free(master_rowids);
    return 0;
}

/* Pad file to exact page boundary. */
static int pad_file_to_page_boundary(WriterIo *io, uint32_t next_page) {
    if (!writer_io_seek(io, 0, SEEK_END)) {
        return ERR_WRITE_FAILED;
    }
    WriterOffset file_size = writer_io_tell(io);
    if (file_size < 0) {
        return ERR_WRITE_FAILED;
    }
    WriterOffset expected_size = 0;
    if (!writer_expected_file_size(io, next_page, &expected_size)) {
        return ERR_WRITE_FAILED;
    }
    if (file_size < expected_size) {
        uint8_t zero = 0;
        if (!writer_io_seek(io, expected_size - SKIP_ONE, SEEK_SET) ||
            !writer_io_write(io, &zero, SKIP_ONE)) {
            return ERR_WRITE_FAILED;
        }
    }
    return 0;
}

/* Build all 4 node index B-trees. Returns 0 on success, ERR_SORT_FAILED on failure. */
static int build_node_indexes(WriterIo *io, uint32_t *next_page, CBMDumpNode *nodes, int node_count,
                              SortJob *nsorts, uint32_t *label_root, uint32_t *name_root,
                              uint32_t *file_root, uint32_t *qn_root, uint32_t *atom_root) {
    *label_root =
        build_node_index_sorted(io, next_page, nodes, node_count, nsorts[0].perm, ncol_label);
    *name_root = build_node_index_sorted(io, next_page, nodes, node_count, nsorts[NSORT_NAME].perm,
                                         ncol_name);
    *file_root = build_node_index_sorted(io, next_page, nodes, node_count, nsorts[NSORT_FILE].perm,
                                         ncol_file);
    *qn_root =
        build_node_index_sorted(io, next_page, nodes, node_count, nsorts[NSORT_QN].perm, ncol_qn);
    *atom_root = build_node_index_sorted(io, next_page, nodes, node_count, nsorts[NSORT_ATOM].perm,
                                         ncol_atom);
    if (node_count > 0 &&
        (!*label_root || !*name_root || !*file_root || !*qn_root || !*atom_root || io->failed)) {
        return ERR_SORT_FAILED;
    }
    return 0;
}

/* Build all 7 edge index B-trees. Returns 0 on success, ERR_SORT_FAILED on failure. */
static int build_edge_indexes(WriterIo *io, uint32_t *next_page, CBMDumpEdge *edges, int edge_count,
                              SortJob *esorts, uint32_t *source_root, uint32_t *target_root,
                              uint32_t *type_root, uint32_t *tgt_type_root, uint32_t *src_type_root,
                              uint32_t *url_path_root, uint32_t *auto_root) {
    *source_root =
        build_edge_index_sorted(io, next_page, edges, edge_count, esorts[0].perm, ecell_source);
    *target_root = build_edge_index_sorted(io, next_page, edges, edge_count,
                                           esorts[ESORT_TARGET].perm, ecell_target);
    *type_root = build_edge_index_sorted(io, next_page, edges, edge_count, esorts[ESORT_TYPE].perm,
                                         ecell_type);
    *tgt_type_root = build_edge_index_sorted(
        io, next_page, edges, edge_count, esorts[ESORT_PROJ_TGT_TYPE].perm, ecell_proj_target_type);
    *src_type_root = build_edge_index_sorted(
        io, next_page, edges, edge_count, esorts[ESORT_PROJ_SRC_TYPE].perm, ecell_proj_source_type);
    *url_path_root = build_edge_index_sorted(io, next_page, edges, edge_count,
                                             esorts[ESORT_URL_PATH].perm, ecell_url_path);
    *auto_root = build_edge_index_sorted(io, next_page, edges, edge_count,
                                         esorts[ESORT_SRC_TGT_TYPE].perm, ecell_src_tgt_type);
    if (edge_count > 0 && (!*source_root || !*target_root || !*type_root || !*tgt_type_root ||
                           !*src_type_root || !*url_path_root || !*auto_root || io->failed)) {
        return ERR_SORT_FAILED;
    }
    return 0;
}

/* Launch parallel sort threads for all index permutations. */
static int parallel_sort_indexes(WriterIo *io, SortJob *nsorts, int n_node, SortJob *esorts,
                                 int n_edge) {
    cbm_thread_t st[TOTAL_SORT_THREADS];
    int nt = 0;
    for (int i = 0; i < n_node; i++) {
        if (nsorts[i].count > 0) {
            if (cbm_thread_create(&st[nt], 0, sort_worker, &nsorts[i]) != 0) {
                writer_record_thread_failure(io, "create_node_sort_thread", &st[nt]);
                break;
            }
            nt++;
        }
    }
    if (!io->failed) {
        for (int i = 0; i < n_edge; i++) {
            if (esorts[i].count > 0) {
                if (cbm_thread_create(&st[nt], 0, sort_worker, &esorts[i]) != 0) {
                    writer_record_thread_failure(io, "create_edge_sort_thread", &st[nt]);
                    break;
                }
                nt++;
            }
        }
    }
    for (int i = 0; i < nt; i++) {
        if (cbm_thread_join(&st[i]) != 0) {
            writer_record_thread_failure(io, "join_sort_thread", &st[i]);
        }
    }
    return io->failed ? ERR_SORT_FAILED : 0;
}

static void free_sort_permutations(SortJob *jobs, int count) {
    for (int i = 0; i < count; i++) {
        free(jobs[i].perm);
        jobs[i].perm = NULL;
    }
}

/* Write everything after the nodes table: the edges/vectors/token_vectors data
 * tables, metadata tables, all indexes, and the sqlite_master page-1 + file
 * header. `nodes_root` is the root of the already-written nodes table. Closes
 * w->io before returning (success or error). */
static int write_db_after_nodes(write_db_ctx_t *w, uint32_t nodes_root) {
    WriterIo *io = w->io;
    CBMDumpNode *nodes = w->nodes;
    int node_count = w->node_count;
    CBMDumpEdge *edges = w->edges;
    int edge_count = w->edge_count;

    // Phase 1 (cont.): remaining data tables (edge + vector + token_vector records)
    CBM_PROF_START(t_data);
    uint32_t edges_root;
    uint32_t vectors_root;
    uint32_t token_vecs_root;
    int rc =
        write_one_table(w, &edges_root, w->edges, w->edge_count, adapt_build_edge, adapt_edge_id);
    if (rc != 0) {
        return writer_io_finish(io, rc, false);
    }
    rc = write_one_table(w, &vectors_root, w->vectors, w->vector_count, adapt_build_vector,
                         adapt_vector_id);
    if (rc != 0) {
        return writer_io_finish(io, rc, false);
    }
    rc = write_one_table(w, &token_vecs_root, w->token_vecs, w->token_vec_count,
                         adapt_build_token_vec, adapt_token_vec_id);
    if (rc != 0) {
        return writer_io_finish(io, rc, false);
    }
    CBM_PROF_END_N("write_db", "1_data_tables", t_data, node_count + edge_count);

    // Phase 2: Metadata tables (projects, file_hashes, summaries, sqlite_sequence)
    CBM_PROF_START(t_meta);
    uint32_t projects_root;
    uint32_t file_hashes_root;
    uint32_t summaries_root;
    uint32_t sqlite_seq_root;
    rc = write_metadata_tables(w, &projects_root, &file_hashes_root, &summaries_root,
                               &sqlite_seq_root);
    if (rc != 0) {
        return writer_io_finish(io, rc, false);
    }
    uint32_t next_page = w->next_page;
    CBM_PROF_END("write_db", "2_metadata_tables", t_meta);

    // --- Build indexes (all sorted by key columns before writing) ---

    // Parallel sort: all 11 index permutations sorted simultaneously.
    // Sorting is O(N log N) per index — the dominant CPU cost in index building.
    // Cell building + B-tree writing remains serial (sequential page allocation).
    SortJob nsorts[] = {
        {node_count, cmp_node_by_label, nodes, NULL}, {node_count, cmp_node_by_name, nodes, NULL},
        {node_count, cmp_node_by_file, nodes, NULL},  {node_count, cmp_node_by_qn, nodes, NULL},
        {node_count, cmp_node_by_atom, nodes, NULL},
    };
    SortJob esorts[] = {
        {edge_count, cmp_edge_by_source_type, edges, NULL},
        {edge_count, cmp_edge_by_target_type, edges, NULL},
        {edge_count, cmp_edge_by_type, edges, NULL},
        {edge_count, cmp_edge_by_proj_target_type, edges, NULL},
        {edge_count, cmp_edge_by_proj_source_type, edges, NULL},
        {edge_count, cmp_edge_by_url_path, edges, NULL},
        {edge_count, cmp_edge_by_src_tgt_type, edges, NULL},
    };

    CBM_PROF_START(t_sort);
    int sort_rc = parallel_sort_indexes(io, nsorts, NODE_SORT_THREADS, esorts, EDGE_SORT_THREADS);
    CBM_PROF_END_N("write_db", "3_parallel_sort_indexes", t_sort, node_count + edge_count);
    if (sort_rc != 0) {
        free_sort_permutations(nsorts, NODE_SORT_THREADS);
        free_sort_permutations(esorts, EDGE_SORT_THREADS);
        return writer_io_finish(io, sort_rc, false);
    }

    /* Phase 4-5: Build node + edge index B-trees */
    CBM_PROF_START(t_node_idx);
    uint32_t idx_nodes_label_root;
    uint32_t idx_nodes_name_root;
    uint32_t idx_nodes_file_root;
    uint32_t idx_nodes_qn_root;
    uint32_t autoindex_nodes_root;
    int nrc = build_node_indexes(io, &next_page, nodes, node_count, nsorts, &idx_nodes_label_root,
                                 &idx_nodes_name_root, &idx_nodes_file_root, &idx_nodes_qn_root,
                                 &autoindex_nodes_root);
    for (int i = 0; i < NODE_SORT_THREADS; i++) {
        nsorts[i].perm = NULL;
    }
    CBM_PROF_END_N("write_db", "4_node_indexes_seq", t_node_idx, node_count * NODE_SORT_THREADS);
    if (nrc != 0) {
        free_sort_permutations(esorts, EDGE_SORT_THREADS);
        return writer_io_finish(io, nrc, false);
    }

    CBM_PROF_START(t_edge_idx);
    uint32_t idx_edges_source_root;
    uint32_t idx_edges_target_root;
    uint32_t idx_edges_type_root;
    uint32_t idx_edges_target_type_root;
    uint32_t idx_edges_source_type_root;
    uint32_t idx_edges_url_path_root;
    uint32_t autoindex_edges_root;
    int erc = build_edge_indexes(io, &next_page, edges, edge_count, esorts, &idx_edges_source_root,
                                 &idx_edges_target_root, &idx_edges_type_root,
                                 &idx_edges_target_type_root, &idx_edges_source_type_root,
                                 &idx_edges_url_path_root, &autoindex_edges_root);
    for (int i = 0; i < EDGE_SORT_THREADS; i++) {
        esorts[i].perm = NULL;
    }
    CBM_PROF_END_N("write_db", "5_edge_indexes_seq", t_edge_idx, edge_count * EDGE_SORT_THREADS);
    if (erc != 0) {
        return writer_io_finish(io, erc, false);
    }

    // Autoindex for projects(name TEXT PK) — single text column
    uint32_t autoindex_projects_root;
    {
        // 1 row: project name
        RecordBuilder r;
        rec_init(&r, io, "build_projects_autoindex_record");
        rec_add_text(&r, w->project);
        rec_add_int(&r, FIRST_ROWID); /* rowid */
        int plen = 0;
        uint8_t *payload = rec_finalize(&r, &plen);
        rec_free(&r);
        if (!payload) {
            return writer_io_finish(io, ERR_WRITE_FAILED, false);
        }
        int vl = varint_len(plen);
        int total = vl + plen;
        uint8_t *cell = (uint8_t *)malloc(total);
        if (!cell) {
            writer_record_allocation_failure(io, "build_projects_autoindex_cell", (size_t)total);
            free(payload);
            return writer_io_finish(io, ERR_WRITE_FAILED, false);
        }
        int pos = put_varint(cell, plen);
        memcpy(cell + pos, payload, plen);
        free(payload);
        uint8_t *cells_arr[] = {cell};
        int lens_arr[] = {total};
        autoindex_projects_root = write_index_btree(io, &next_page, cells_arr, lens_arr, SKIP_ONE);
        free(cell);
    }

    // Autoindex for file_hashes(project, rel_path PK) — empty (0 rows)
    uint32_t autoindex_file_hashes_root = write_index_btree(io, &next_page, NULL, NULL, 0);

    // Autoindex for project_summaries(project TEXT PK) — empty (0 rows)
    uint32_t autoindex_summaries_root = write_index_btree(io, &next_page, NULL, NULL, 0);
    if (io->failed || !autoindex_projects_root || !autoindex_file_hashes_root ||
        !autoindex_summaries_root) {
        return writer_io_finish(io, ERR_WRITE_FAILED, false);
    }

    // --- sqlite_master table (page 1) ---
    // This must be written last because it references root pages of all other tables/indexes.

    // CRITICAL: sqlite_master entries must follow standard SQLite ordering:
    // table → autoindex → user indexes → next table → autoindex → user indexes → ...
    // SQLite's schema loader expects autoindexes immediately after their table.
    // Mis-ordering causes rootpage mapping corruption in the schema cache.
    MasterEntry master[] = {
        {"table", "projects", "projects", projects_root,
         "CREATE TABLE projects (\n\t\tname TEXT PRIMARY KEY,\n\t\tindexed_at TEXT NOT "
         "NULL,\n\t\troot_path TEXT NOT NULL\n\t)"},
        {"index", "sqlite_autoindex_projects_1", "projects", autoindex_projects_root, NULL},
        {"table", "file_hashes", "file_hashes", file_hashes_root,
         "CREATE TABLE file_hashes (\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON "
         "DELETE CASCADE,\n\t\trel_path TEXT NOT NULL,\n\t\tsha256 TEXT NOT NULL,\n\t\tmtime_ns "
         "INTEGER NOT NULL DEFAULT 0,\n\t\tsize INTEGER NOT NULL DEFAULT 0,\n\t\tPRIMARY KEY "
         "(project, rel_path)\n\t)"},
        {"index", "sqlite_autoindex_file_hashes_1", "file_hashes", autoindex_file_hashes_root,
         NULL},
        {"table", "nodes", "nodes", nodes_root,
         "CREATE TABLE nodes (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT "
         "NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tlabel TEXT NOT NULL,\n\t\tname "
         "TEXT NOT NULL,\n\t\tqualified_name TEXT NOT NULL,\n\t\tfile_path TEXT DEFAULT "
         "'',\n\t\tstart_line INTEGER DEFAULT 0,\n\t\tend_line INTEGER DEFAULT 0,\n\t\tproperties "
         "TEXT DEFAULT '{}',\n\t\tatom_id TEXT NOT NULL,\n\t\tsource_present INTEGER NOT NULL "
         "CHECK(source_present IN (0,1)),\n\t\tsource_bytes BLOB,\n\t\tsource_sha256 TEXT NOT NULL "
         "DEFAULT '',\n\t\tstart_byte INTEGER NOT NULL DEFAULT 0,\n\t\tend_byte INTEGER NOT NULL "
         "DEFAULT 0,\n\t\tCHECK((source_present = 0 AND source_bytes IS NULL AND source_sha256 = "
         "'' "
         "AND start_byte = 0 AND end_byte = 0) OR (source_present = 1 AND source_bytes IS NOT NULL "
         "AND length(source_sha256) = 64 AND end_byte >= start_byte AND length(source_bytes) = "
         "end_byte - start_byte)),\n\t\tUNIQUE(project, atom_id)\n\t)"},
        {"index", "sqlite_autoindex_nodes_1", "nodes", autoindex_nodes_root, NULL},
        {"index", "idx_nodes_label", "nodes", idx_nodes_label_root,
         "CREATE INDEX idx_nodes_label ON nodes(project, label)"},
        {"index", "idx_nodes_name", "nodes", idx_nodes_name_root,
         "CREATE INDEX idx_nodes_name ON nodes(project, name)"},
        {"index", "idx_nodes_file", "nodes", idx_nodes_file_root,
         "CREATE INDEX idx_nodes_file ON nodes(project, file_path)"},
        {"index", "idx_nodes_qn", "nodes", idx_nodes_qn_root,
         "CREATE INDEX idx_nodes_qn ON nodes(project, qualified_name)"},
        // local_name_gen + widened UNIQUE (#768): must stay semantically
        // identical to init_schema in src/store/store.c, and the hand-built
        // sqlite_autoindex_edges_1 (cmp_edge_by_src_tgt_type +
        // ecell_src_tgt_type) must produce exactly the values SQLite computes
        // for local_name_gen, or integrity_check fails on the dumped DB.
        {"table", "edges", "edges", edges_root,
         "CREATE TABLE edges (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT "
         "NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tsource_id INTEGER NOT NULL "
         "REFERENCES nodes(id) ON DELETE CASCADE,\n\t\ttarget_id INTEGER NOT NULL REFERENCES "
         "nodes(id) ON DELETE CASCADE,\n\t\ttype TEXT NOT NULL,\n\t\tproperties TEXT DEFAULT "
         "'{}',\n\t\turl_path_gen TEXT GENERATED ALWAYS AS "
         "(json_extract(properties,'$.url_path')),\n\t\tlocal_name_gen TEXT GENERATED ALWAYS AS "
         "(CASE WHEN type='IMPORTS' THEN coalesce(json_extract(properties,'$.local_name'),'') "
         "ELSE '' END),\n\t\tUNIQUE(source_id, target_id, type, local_name_gen)\n\t)"},
        {"index", "sqlite_autoindex_edges_1", "edges", autoindex_edges_root, NULL},
        {"index", "idx_edges_source", "edges", idx_edges_source_root,
         "CREATE INDEX idx_edges_source ON edges(source_id, type)"},
        {"index", "idx_edges_target", "edges", idx_edges_target_root,
         "CREATE INDEX idx_edges_target ON edges(target_id, type)"},
        {"index", "idx_edges_type", "edges", idx_edges_type_root,
         "CREATE INDEX idx_edges_type ON edges(project, type)"},
        {"index", "idx_edges_target_type", "edges", idx_edges_target_type_root,
         "CREATE INDEX idx_edges_target_type ON edges(project, target_id, type)"},
        {"index", "idx_edges_source_type", "edges", idx_edges_source_type_root,
         "CREATE INDEX idx_edges_source_type ON edges(project, source_id, type)"},
        {"index", "idx_edges_url_path", "edges", idx_edges_url_path_root,
         "CREATE INDEX idx_edges_url_path ON edges(project, url_path_gen)"},
        {"table", "project_summaries", "project_summaries", summaries_root,
         "CREATE TABLE project_summaries (\n\t\t\tproject TEXT PRIMARY KEY,\n\t\t\tsummary TEXT "
         "NOT NULL,\n\t\t\tsource_hash TEXT NOT NULL,\n\t\t\tcreated_at TEXT NOT "
         "NULL,\n\t\t\tupdated_at TEXT NOT NULL\n\t\t)"},
        {"index", "sqlite_autoindex_project_summaries_1", "project_summaries",
         autoindex_summaries_root, NULL},
        {"table", "node_vectors", "node_vectors", vectors_root,
         "CREATE TABLE node_vectors (\n\t\tnode_id INTEGER PRIMARY KEY,\n\t\tproject TEXT NOT "
         "NULL,\n\t\tvector BLOB NOT NULL\n\t)"},
        {"table", "token_vectors", "token_vectors", token_vecs_root,
         "CREATE TABLE token_vectors (\n\t\tid INTEGER PRIMARY KEY,\n\t\tproject "
         "TEXT NOT NULL,\n\t\ttoken TEXT NOT NULL,\n\t\tvector BLOB NOT NULL,\n\t\tidf INTEGER "
         "NOT NULL\n\t)"},
        {"table", "sqlite_sequence", "sqlite_sequence", sqlite_seq_root,
         "CREATE TABLE sqlite_sequence(name,seq)"},
    };

    int master_count = sizeof(master) / sizeof(master[0]);
    int rc2 = write_master_page1(io, master, master_count, next_page);
    if (rc2 != 0) {
        return writer_io_finish(io, rc2, false);
    }
    int pad_rc = pad_file_to_page_boundary(io, next_page);
    return writer_io_finish(io, pad_rc, true);
}

// --- Streaming writer (incremental bulk node-table append) ---

struct cbm_db_writer {
    WriterIo io;
    char *path_owned;
    write_db_ctx_t wc;    // I/O state + next_page carried across calls; arrays filled at finalize
    PageBuilder nodes_pb; // persistent nodes-table builder (leaves flush as they fill)
    int64_t last_node_rowid; // last appended node id (prev_rowid for the next cell)
    int64_t node_rows_written;
    cbm_sha256_ctx node_identity_hash; // index-relevant identity transcript persisted at append
    int err;                           // sticky error
};

static void writer_hash_u64(cbm_sha256_ctx *hash, uint64_t value) {
    uint8_t bytes[INT64_BYTES];
    for (int i = INT64_BYTES - SKIP_ONE; i >= 0; i--) {
        bytes[i] = (uint8_t)(value & BYTE_MASK);
        value >>= SHIFT_8;
    }
    cbm_sha256_update(hash, bytes, sizeof(bytes));
}

static void writer_hash_text(cbm_sha256_ctx *hash, const char *text) {
    const char *value = text ? text : "";
    size_t len = strlen(value);
    writer_hash_u64(hash, (uint64_t)len);
    if (len > 0) {
        cbm_sha256_update(hash, value, len);
    }
}

static void writer_hash_node_identity(cbm_sha256_ctx *hash, const CBMDumpNode *node) {
    writer_hash_u64(hash, (uint64_t)node->id);
    writer_hash_text(hash, node->project);
    writer_hash_text(hash, node->label);
    writer_hash_text(hash, node->name);
    writer_hash_text(hash, node->file_path);
    writer_hash_text(hash, node->qualified_name);
    writer_hash_text(hash, node->atom_id);
}

static bool writer_validate_array(WriterIo *io, const void *array, int count,
                                  const char *operation) {
    if (count < 0) {
        writer_record_input_failure(io, operation, "record count is negative");
        return false;
    }
    if (count > 0 && !array) {
        writer_record_input_failure(io, operation, "positive record count has a NULL array");
        return false;
    }
    return true;
}

static bool writer_validate_finalize_inputs(cbm_db_writer_t *w, const CBMDumpNode *nodes,
                                            int node_count, const CBMDumpEdge *edges,
                                            int edge_count, const CBMDumpVector *vectors,
                                            int vector_count, const CBMDumpTokenVec *token_vecs,
                                            int token_vec_count) {
    if (!writer_validate_array(&w->io, nodes, node_count, "validate_nodes_array") ||
        !writer_validate_array(&w->io, edges, edge_count, "validate_edges_array") ||
        !writer_validate_array(&w->io, vectors, vector_count, "validate_vectors_array") ||
        !writer_validate_array(&w->io, token_vecs, token_vec_count,
                               "validate_token_vectors_array")) {
        return false;
    }
    if (w->node_rows_written != node_count) {
        writer_record_input_failure(&w->io, "validate_streamed_node_count",
                                    "streamed node count does not match finalize node count");
        return false;
    }

    cbm_sha256_ctx finalized_hash;
    cbm_sha256_init(&finalized_hash);
    for (int i = 0; i < node_count; i++) {
        writer_hash_node_identity(&finalized_hash, &nodes[i]);
    }
    uint8_t finalized_digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&finalized_hash, finalized_digest);

    cbm_sha256_ctx streamed_hash = w->node_identity_hash;
    uint8_t streamed_digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&streamed_hash, streamed_digest);
    if (memcmp(streamed_digest, finalized_digest, sizeof(streamed_digest)) != 0) {
        writer_record_input_failure(&w->io, "validate_streamed_node_identity",
                                    "streamed node identities do not match finalize inputs");
        return false;
    }
    return true;
}

cbm_db_writer_t *cbm_writer_open(const char *path) {
    if (!path || path[0] == '\0') {
        cbm_log_error("sqlite_writer.open_failed", "code", "CBM_SQLITE_WRITER_PATH_INVALID",
                      "message", "the direct writer staging path is empty", "remediation",
                      "supply a non-empty unique staging path under the configured store root");
        return NULL;
    }
    cbm_db_writer_t *w = (cbm_db_writer_t *)calloc(CBM_ALLOC_ONE, sizeof(*w));
    if (!w) {
        cbm_log_error("sqlite_writer.open_failed", "code", "CBM_SQLITE_WRITER_ALLOC_FAILED",
                      "message", "the direct writer state could not be allocated", "remediation",
                      "free memory or reduce repository size, then retry indexing");
        return NULL;
    }
    size_t path_len = strlen(path);
    w->path_owned = (char *)malloc(path_len + SKIP_ONE);
    if (!w->path_owned) {
        cbm_log_error("sqlite_writer.open_failed", "code", "CBM_SQLITE_WRITER_ALLOC_FAILED",
                      "message", "the direct writer staging identity could not be retained",
                      "remediation", "free memory or reduce repository size, then retry indexing");
        free(w);
        return NULL;
    }
    memcpy(w->path_owned, path, path_len + SKIP_ONE);
    w->io.path = w->path_owned;

    /* #412/#676: widen long paths, but create the transaction-owned staging
     * file exclusively. A stale or concurrent identity is an exact collision,
     * never permission to truncate an existing file. */
    if (!writer_io_open_create_new(&w->io)) {
        if (w->io.stage_created) {
            writer_remove_failed_stage(w->path_owned);
        }
        free(w->path_owned);
        free(w);
        return NULL;
    }
    w->wc.io = &w->io;
    w->wc.next_page = FIRST_DATA_PAGE;
    cbm_sha256_init(&w->node_identity_hash);
    /* Nodes are never page 1 (page 1 is sqlite_master, written at finalize). */
    pb_init(&w->nodes_pb, &w->io, FIRST_DATA_PAGE, false);
    return w;
}

int cbm_writer_append_nodes(cbm_db_writer_t *w, const CBMDumpNode *nodes, int count) {
    if (!w) {
        return CBM_NOT_FOUND;
    }
    if (w->err) {
        return w->err;
    }
    if (!writer_validate_array(&w->io, nodes, count, "append_nodes_array")) {
        w->err = ERR_WRITE_FAILED;
        return w->err;
    }
    if ((int64_t)count > INT_MAX - w->node_rows_written) {
        writer_record_input_failure(&w->io, "append_nodes_count",
                                    "streamed node count exceeds the finalize API range");
        w->err = ERR_WRITE_FAILED;
        return w->err;
    }
    for (int i = 0; i < count; i++) {
        int64_t expected_id = w->node_rows_written + FIRST_ROWID;
        if (nodes[i].id != expected_id) {
            writer_record_input_failure(&w->io, "append_node_identity",
                                        "node ids must be ascending and contiguous from one");
            w->err = ERR_WRITE_FAILED;
            return w->err;
        }
        int rec_len;
        uint8_t *rec = build_node_record(&w->io, &nodes[i], &rec_len);
        if (!rec) {
            w->err = ERR_WRITE_FAILED;
            return w->err;
        }
        /* prev_rowid is the previous node's id (0 for the very first), matching
         * the one-shot write_one_table loop — so output is byte-identical. */
        pb_add_table_cell_with_flush(&w->nodes_pb, nodes[i].id, rec, rec_len, w->last_node_rowid);
        free(rec);
        if (w->io.failed) {
            w->err = ERR_WRITE_FAILED;
            return w->err;
        }
        w->last_node_rowid = nodes[i].id;
        w->node_rows_written++;
        writer_hash_node_identity(&w->node_identity_hash, &nodes[i]);
    }
    return 0;
}

int cbm_writer_finalize(cbm_db_writer_t *w, const char *project, const char *root_path,
                        const char *indexed_at, CBMDumpNode *nodes, int node_count,
                        CBMDumpEdge *edges, int edge_count, CBMDumpVector *vectors,
                        int vector_count, CBMDumpTokenVec *token_vecs, int token_vec_count) {
    if (!w) {
        return CBM_NOT_FOUND;
    }
    int err = w->err;
    uint32_t nodes_root = 0;
    if (err == 0 &&
        !writer_validate_finalize_inputs(w, nodes, node_count, edges, edge_count, vectors,
                                         vector_count, token_vecs, token_vec_count)) {
        err = ERR_WRITE_FAILED;
    }
    if (err == 0) {
        if (w->node_rows_written == 0) {
            pb_free(&w->nodes_pb);
            nodes_root = write_table_btree(&w->io, &w->wc.next_page, NULL, NULL, NULL, 0, false);
        } else {
            nodes_root = pb_finalize_table(&w->nodes_pb, &w->wc.next_page, w->last_node_rowid);
        }
        if (nodes_root == 0 || w->io.failed) {
            err = ERR_WRITE_FAILED;
        }
    } else {
        pb_free(&w->nodes_pb);
    }
    w->wc.project = project;
    w->wc.root_path = root_path;
    w->wc.indexed_at = indexed_at;
    w->wc.nodes = nodes;
    w->wc.node_count = node_count;
    w->wc.edges = edges;
    w->wc.edge_count = edge_count;
    w->wc.vectors = vectors;
    w->wc.vector_count = vector_count;
    w->wc.token_vecs = token_vecs;
    w->wc.token_vec_count = token_vec_count;

    int result;
    if (err != 0) {
        result = writer_io_finish(&w->io, err, false);
    } else {
        result = write_db_after_nodes(&w->wc, nodes_root);
    }
    if (result != 0) {
        writer_remove_failed_stage(w->path_owned);
    }
    free(w->path_owned);
    free(w);
    return result;
}

int cbm_write_db(const char *path, const char *project, const char *root_path,
                 const char *indexed_at, CBMDumpNode *nodes, int node_count, CBMDumpEdge *edges,
                 int edge_count, CBMDumpVector *vectors, int vector_count,
                 CBMDumpTokenVec *token_vecs, int token_vec_count) {
    /* One-shot = open + append all nodes in a single batch + finalize.
     * Produces byte-identical output to the former monolithic writer. */
    cbm_db_writer_t *w = cbm_writer_open(path);
    if (!w) {
        return CBM_NOT_FOUND;
    }
    (void)cbm_writer_append_nodes(w, nodes,
                                  node_count); /* error recorded in w, handled by finalize */
    return cbm_writer_finalize(w, project, root_path, indexed_at, nodes, node_count, edges,
                               edge_count, vectors, vector_count, token_vecs, token_vec_count);
}
