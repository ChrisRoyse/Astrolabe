/*
 * store.c — SQLite graph store implementation.
 *
 * Implements the opaque cbm_store_t handle with prepared statement caching,
 * schema initialization, and all CRUD operations for nodes, edges, projects,
 * file hashes, search, BFS traversal, and schema introspection.
 */

// for ISO timestamp

#include <stdint.h>
#include "foundation/constants.h"

#include <math.h>

enum {
    ST_COL_1 = 1,
    ST_COL_2 = 2,
    ST_COL_3 = 3,
    ST_COL_4 = 4,
    ST_COL_5 = 5,
    ST_COL_6 = 6,
    ST_COL_7 = 7,
    ST_COL_8 = 8,
    ST_COL_9 = 9,
    ST_FOUND = -1,
    ST_BUF_16 = 16,
    ST_BUF_64 = 64,
    ST_GROWTH = 2,
    ST_MAX_DEGREE = 8192,
    ST_HALF_SEC = 500000,
    ST_RETRY_WAIT_US = 1000,
    ST_INIT_CAP_8 = 8,
    ST_INIT_CAP_16 = 16,
    ST_SQL_BUF = 8192,
    ST_QN_MAX_DOTS = 5,
    ST_QN_MIN_DOTS = 3,
    ST_IN_CLAUSE_MARGIN = 4,
    ST_GLOB_MIN_LEN = 3,
    ST_GLOB_SKIP = 2,
    ST_MAX_LANG = 10,
    ST_SEARCH_MAX_BINDS = 32, /* increased: LIKE pre-filter adds binds per pattern */
    ST_LIKE_POOL_MAX = 12,    /* max malloc'd LIKE strings alive during one search */
    ST_LIKE_HINT_MAX = 2,     /* max LIKE hints extracted per regex pattern */
    ST_MAX_PKGS = 64,
    ST_INIT_CAP_4 = 4,
    ST_HEADER_PREFIX = 3,
    ST_MIN_INDEGREE = 3,
    ST_MAX_PATH_DEPTH = 3,
    ST_MAX_ITERATIONS = 10,
    ST_MAX_SECTIONS = 16,
    ST_METHOD_PROP_LEN = 8,
    ST_PATH_PROP_LEN = 6,
    ST_HANDLER_PROP_LEN = 9,
    CBM_STORE_SCHEMA_VERSION = 3,
};

#define SLEN(s) (sizeof(s) - 1)
#include "store/store.h"
#include "foundation/platform.h"
#include "foundation/dyn_array.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h" /* cbm_unlink / cbm_rename_replace — #415 long-path-safe dump swap */
#include "foundation/log.h"
#include "foundation/sha256.h"
#include "foundation/compat_regex.h"
#include "foundation/str_util.h"

#ifdef _WIN32
#include "foundation/win_utf8.h"
#endif

#define XXH_INLINE_ALL
#include "xxhash/xxhash.h"

#include <sqlite3.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ST_NODE_SELECT_COLUMNS                                                                \
    "id, project, label, name, qualified_name, file_path, start_line, end_line, properties, " \
    "atom_id, source_present, source_bytes, source_sha256, start_byte, end_byte"
#define ST_NODE_SELECT_COLUMNS_N                                                                  \
    "n.id, n.project, n.label, n.name, n.qualified_name, n.file_path, n.start_line, n.end_line, " \
    "n.properties, n.atom_id, n.source_present, n.source_bytes, n.source_sha256, n.start_byte, "  \
    "n.end_byte"

enum {
    ST_NODE_COL_ATOM_ID = 9,
    ST_NODE_COL_SOURCE_PRESENT = 10,
    ST_NODE_COL_SOURCE_BYTES = 11,
    ST_NODE_COL_SOURCE_SHA256 = 12,
    ST_NODE_COL_START_BYTE = 13,
    ST_NODE_COL_END_BYTE = 14,
    ST_NODE_COL_COUNT = 15,
};

/* ── SQLite bind helpers ───────────────────────────────────────── */

/* Isolate the int-to-ptr cast that SQLITE_TRANSIENT expands to.
   A union type-pun avoids the performance-no-int-to-ptr diagnostic. */
static sqlite3_destructor_type make_transient(void) {
    union {
        uintptr_t i;
        sqlite3_destructor_type fn;
    } u;
    u.i = (uintptr_t)CBM_NOT_FOUND;
    return u.fn;
}
#define BIND_TRANSIENT (make_transient())

static int bind_text(sqlite3_stmt *s, int col, const char *v) {
    return sqlite3_bind_text(s, col, v, CBM_NOT_FOUND, BIND_TRANSIENT);
}

/* U+FFFD encodes as three bytes, the largest expansion of any single input byte
 * under cbm_utf8_sanitize; a sanitized copy is therefore at most 3x the input. */
enum { STORE_UTF8_REPLACEMENT_LEN = 3 };

/* Bind a parser-derived text value after enforcing the UTF-8 write contract
 * (#503): any non-UTF-8 byte in an identifier or path is replaced with U+FFFD
 * (via cbm_utf8_sanitize) so the persisted `nodes`/`edges`/`projects`/
 * `file_hashes`/`project_summaries` text columns are always valid UTF-8. This
 * matches the guarantee cbm_json_escape already gives the JSON `properties`
 * columns (#493); together they close every text column the Rust vault importer
 * reads as a fail-closed `String`, so one bad byte can no longer make it refuse
 * the whole repository. A NULL binds the empty string. The sanitized copy is
 * bound transiently (SQLite copies it immediately), so the scratch buffer is
 * freed as soon as the bind returns. */
static int bind_text_utf8(sqlite3_stmt *s, int col, const char *v) {
    if (!v) {
        return sqlite3_bind_text(s, col, "", 0, BIND_TRANSIENT);
    }
    size_t len = strlen(v);
    size_t cap = len * STORE_UTF8_REPLACEMENT_LEN + SKIP_ONE;
    char *tmp = malloc(cap);
    if (!tmp) {
        return SQLITE_NOMEM;
    }
    cbm_utf8_sanitize(tmp, (int)cap, v);
    int rc = sqlite3_bind_text(s, col, tmp, CBM_NOT_FOUND, BIND_TRANSIENT);
    free(tmp);
    return rc;
}

/* ── Internal store structure ───────────────────────────────────── */

struct cbm_store {
    sqlite3 *db;
    const char *db_path; /* heap-allocated, or NULL for :memory: */
    char errbuf[CBM_SZ_512];

    /* Prepared statements (lazily initialized, cached for lifetime) */
    sqlite3_stmt *stmt_upsert_node;
    sqlite3_stmt *stmt_find_node_by_id;
    sqlite3_stmt *stmt_find_node_by_atom_id;
    sqlite3_stmt *stmt_find_node_by_qn;
    sqlite3_stmt *stmt_find_node_by_qn_any; /* QN lookup without project filter */
    sqlite3_stmt *stmt_find_nodes_by_name;
    sqlite3_stmt *stmt_find_nodes_by_name_any; /* name lookup without project filter */
    sqlite3_stmt *stmt_find_nodes_by_label;
    sqlite3_stmt *stmt_find_nodes_by_file;
    sqlite3_stmt *stmt_count_nodes;
    sqlite3_stmt *stmt_delete_nodes_by_project;
    sqlite3_stmt *stmt_delete_nodes_by_file;
    sqlite3_stmt *stmt_delete_nodes_by_label;

    sqlite3_stmt *stmt_insert_edge;
    sqlite3_stmt *stmt_find_edges_by_source;
    sqlite3_stmt *stmt_find_edges_by_target;
    sqlite3_stmt *stmt_find_edges_by_source_type;
    sqlite3_stmt *stmt_find_edges_by_target_type;
    sqlite3_stmt *stmt_find_edges_by_type;
    sqlite3_stmt *stmt_count_edges;
    sqlite3_stmt *stmt_count_edges_by_type;
    sqlite3_stmt *stmt_delete_edges_by_project;
    sqlite3_stmt *stmt_delete_edges_by_type;

    sqlite3_stmt *stmt_upsert_project;
    sqlite3_stmt *stmt_get_project;
    sqlite3_stmt *stmt_list_projects;
    sqlite3_stmt *stmt_delete_project;

    sqlite3_stmt *stmt_upsert_file_hash;
    sqlite3_stmt *stmt_get_file_hashes;
    sqlite3_stmt *stmt_delete_file_hash;
    sqlite3_stmt *stmt_delete_file_hashes;
};

/* ── Helpers ────────────────────────────────────────────────────── */

static void store_set_error(cbm_store_t *s, const char *msg) {
    snprintf(s->errbuf, sizeof(s->errbuf), "%s", msg);
}

static void store_set_error_sqlite(cbm_store_t *s, const char *prefix) {
    snprintf(s->errbuf, sizeof(s->errbuf), "%s: %s", prefix, sqlite3_errmsg(s->db));
}

/* Grow an authoritative store result without changing either the pointer or
 * capacity on arithmetic/allocation failure. Every caller must propagate the
 * returned status and discard its in-progress result; returning a shorter row
 * set as success would make SQLite corruption and OOM indistinguishable from a
 * legitimate query result. */
static int store_array_reserve(cbm_store_t *s, void **items, int *capacity, int required,
                               size_t item_size, const char *operation) {
    if (cbm_da_ensure_capacity(items, capacity, required, item_size)) {
        return CBM_STORE_OK;
    }
    char required_buf[CBM_SZ_32];
    char item_size_buf[CBM_SZ_32];
    snprintf(required_buf, sizeof(required_buf), "%d", required);
    snprintf(item_size_buf, sizeof(item_size_buf), "%zu", item_size);
    snprintf(s->errbuf, sizeof(s->errbuf), "%s: result allocation failed for %d items of %zu bytes",
             operation, required, item_size);
    cbm_log_error("store.result_allocation", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED",
                  "operation", operation, "required_items", required_buf, "item_size",
                  item_size_buf, "message", s->errbuf, "remediation",
                  "free memory or narrow the query, then retry; no partial result was returned");
    return CBM_STORE_ERR;
}

static int exec_sql(cbm_store_t *s, const char *sql) {
    if (!s || !s->db) {
        return CBM_STORE_ERR;
    }
    char *err = NULL;
    int rc = sqlite3_exec(s->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        snprintf(s->errbuf, sizeof(s->errbuf), "exec: %s", err ? err : "unknown");
        sqlite3_free(err);
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* Safe string: returns "" if NULL. */
static const char *safe_str(const char *s) {
    return s ? s : "";
}

/* Safe properties: returns "{}" if NULL. */
static const char *safe_props(const char *s) {
    return (s && s[0]) ? s : "{}";
}

static bool is_canonical_atom_id(const char *value) {
    if (!value || strlen(value) != 64) {
        return false;
    }
    for (size_t i = 0; i < 64; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

/* Duplicate a string onto the heap. */
static char *heap_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *d = malloc(len + SKIP_ONE);
    if (d) {
        memcpy(d, s, len + SKIP_ONE);
    }
    return d;
}

/* Prepare a statement (cached). If already prepared, reset+clear. */
static sqlite3_stmt *prepare_cached(cbm_store_t *s, sqlite3_stmt **slot, const char *sql) {
    if (!s || !s->db) {
        return NULL;
    }
    if (*slot) {
        sqlite3_reset(*slot);
        sqlite3_clear_bindings(*slot);
        return *slot;
    }
    int rc = sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, slot, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "prepare");
        return NULL;
    }
    return *slot;
}

/* Get ISO-8601 timestamp. */
static void iso_now(char *buf, size_t sz) {
    time_t t = time(NULL);
    struct tm tm;
    cbm_gmtime_r(&t, &tm);
    (void)strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ",
                   &tm); // cert-err33-c: strftime only fails if buffer is too small — 21-byte ISO
                         // timestamp always fits in caller-provided buffers
}

/* ── Schema ─────────────────────────────────────────────────────── */

static int read_user_version(cbm_store_t *s, int *out) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "PRAGMA user_version;", CBM_NOT_FOUND, &stmt, NULL) !=
        SQLITE_OK) {
        return CBM_STORE_ERR;
    }
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    *out = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return CBM_STORE_OK;
}

static int validate_node_identity_index(cbm_store_t *s) {
    sqlite3_stmt *indexes = NULL;
    if (sqlite3_prepare_v2(s->db,
                           "SELECT name FROM pragma_index_list('nodes') WHERE \"unique\"=1 "
                           "ORDER BY name;",
                           CBM_NOT_FOUND, &indexes, NULL) != SQLITE_OK) {
        return CBM_STORE_ERR;
    }
    bool atom_unique = false;
    bool collapsed_qn_unique = false;
    while (sqlite3_step(indexes) == SQLITE_ROW) {
        const char *index_name = (const char *)sqlite3_column_text(indexes, 0);
        sqlite3_stmt *columns = NULL;
        if (sqlite3_prepare_v2(s->db, "SELECT name FROM pragma_index_info(?1) ORDER BY seqno;",
                               CBM_NOT_FOUND, &columns, NULL) != SQLITE_OK) {
            sqlite3_finalize(indexes);
            return CBM_STORE_ERR;
        }
        bind_text(columns, SKIP_ONE, index_name);
        const char *first = NULL;
        const char *second = NULL;
        int count = 0;
        while (sqlite3_step(columns) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(columns, 0);
            if (count == 0) {
                first = heap_strdup(name);
            } else if (count == 1) {
                second = heap_strdup(name);
            }
            count++;
        }
        sqlite3_finalize(columns);
        if (count == 2 && first && second && strcmp(first, "project") == 0) {
            atom_unique = atom_unique || strcmp(second, "atom_id") == 0;
            collapsed_qn_unique = collapsed_qn_unique || strcmp(second, "qualified_name") == 0;
        }
        free((void *)first);
        free((void *)second);
    }
    sqlite3_finalize(indexes);
    if (!atom_unique || collapsed_qn_unique) {
        cbm_log_error(
            "store.schema_identity_refused", "code", "CBM_ATOM_SCHEMA_REBUILD_REQUIRED", "message",
            "nodes identity indexes do not enforce unique(project, atom_id) with non-unique "
            "qualified_name",
            "remediation", "delete the collapsed legacy store and rebuild it from source");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

static int init_schema(cbm_store_t *s) {
    int initial_user_version = 0;
    if (read_user_version(s, &initial_user_version) != CBM_STORE_OK ||
        (initial_user_version != 0 && initial_user_version != CBM_STORE_SCHEMA_VERSION)) {
        cbm_log_error("store.schema_version_refused", "code", "CBM_SCHEMA_VERSION_UNSUPPORTED",
                      "message", "SQLite user_version is not the exact stable-atom schema",
                      "remediation", "rebuild from source with this Astrolabe version");
        return CBM_STORE_ERR;
    }
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS projects ("
        "  name TEXT PRIMARY KEY,"
        "  indexed_at TEXT NOT NULL,"
        "  root_path TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS file_hashes ("
        "  project TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,"
        "  rel_path TEXT NOT NULL,"
        "  sha256 TEXT NOT NULL,"
        "  mtime_ns INTEGER NOT NULL DEFAULT 0,"
        "  size INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (project, rel_path)"
        ");"
        "CREATE TABLE IF NOT EXISTS nodes ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,"
        "  label TEXT NOT NULL,"
        "  name TEXT NOT NULL,"
        "  qualified_name TEXT NOT NULL,"
        "  file_path TEXT DEFAULT '',"
        "  start_line INTEGER DEFAULT 0,"
        "  end_line INTEGER DEFAULT 0,"
        "  properties TEXT DEFAULT '{}',"
        "  atom_id TEXT NOT NULL,"
        "  source_present INTEGER NOT NULL CHECK(source_present IN (0,1)),"
        "  source_bytes BLOB,"
        "  source_sha256 TEXT NOT NULL DEFAULT '',"
        "  start_byte INTEGER NOT NULL DEFAULT 0,"
        "  end_byte INTEGER NOT NULL DEFAULT 0,"
        "  CHECK((source_present = 0 AND source_bytes IS NULL AND source_sha256 = '' AND "
        "    start_byte = 0 AND end_byte = 0) OR (source_present = 1 AND source_bytes IS NOT NULL "
        "    AND length(source_sha256) = 64 AND end_byte >= start_byte AND "
        "    length(source_bytes) = end_byte - start_byte)),"
        "  UNIQUE(project, atom_id)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_nodes_qn ON nodes(project, qualified_name);"
        /* local_name_gen (#768): IMPORTS edges carry one imported symbol's
         * local_name each, so uniqueness must discriminate on it — two named
         * imports from the same specifier are distinct edges. Non-IMPORTS
         * edges get '' (NOT NULL: NULLs never conflict in a UNIQUE index,
         * which would break their dedup entirely). Mirrors the graph-buffer
         * dedup key (make_edge_key) and the raw dump writer's DDL + hand-
         * built sqlite_autoindex_edges_1 (internal/cbm/sqlite_writer.c) —
         * keep all three in sync. */
        "CREATE TABLE IF NOT EXISTS edges ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  project TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,"
        "  source_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,"
        "  target_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,"
        "  type TEXT NOT NULL,"
        "  properties TEXT DEFAULT '{}',"
        "  url_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),"
        "  local_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS'"
        "    THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),"
        "  UNIQUE(source_id, target_id, type, local_name_gen)"
        ");"
        "CREATE TABLE IF NOT EXISTS project_summaries ("
        "  project TEXT PRIMARY KEY,"
        "  summary TEXT NOT NULL,"
        "  source_hash TEXT NOT NULL,"
        "  created_at TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL"
        ");";

    int rc = exec_sql(s, ddl);
    if (rc != CBM_STORE_OK) {
        return rc;
    }

    {
        sqlite3_stmt *probe = NULL;
        if (sqlite3_prepare_v2(s->db,
                               "SELECT atom_id, source_present, source_bytes, source_sha256, "
                               "start_byte, end_byte FROM nodes LIMIT 0;",
                               CBM_NOT_FOUND, &probe, NULL) != SQLITE_OK) {
            cbm_log_warn("store.schema", "result", "incompatible", "missing",
                         "nodes exact-source columns");
            return CBM_STORE_ERR;
        }
        sqlite3_finalize(probe);
    }
    if (validate_node_identity_index(s) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }

    /* Schema-compat probe (#768): DBs created before the local_name_gen
     * discriminator still enforce UNIQUE(source_id,target_id,type) and lack
     * the column — the widened upsert in cbm_store_insert_edge can neither
     * prepare nor let two named imports coexist against them. SQLite cannot
     * ALTER a table-level UNIQUE constraint in place, so fail the open:
     * callers already treat an unopenable DB as incompatible (a full index
     * deletes + rebuilds it, artifact import refuses and falls back to a
     * reindex). Read-only query opens skip init_schema and keep working. */
    {
        sqlite3_stmt *probe = NULL;
        if (sqlite3_prepare_v2(s->db, "SELECT local_name_gen FROM edges LIMIT 0;", CBM_NOT_FOUND,
                               &probe, NULL) != SQLITE_OK) {
            cbm_log_warn("store.schema", "result", "incompatible", "missing",
                         "edges.local_name_gen");
            return CBM_STORE_ERR;
        }
        sqlite3_finalize(probe);
    }

    /* FTS5 contentless virtual table for BM25 full-text search.
     * Contentless (content='') means FTS5 stores only the inverted index,
     * not a copy of the source text — required for camelCase tokenization
     * because we feed it `cbm_camel_split(name)` at insert time but want
     * queries to match against the split tokens, not the original.
     * FTS is part of the persisted query contract. A missing FTS5 runtime or
     * malformed virtual-table definition is a store-open failure, never a
     * permission to publish a graph that cannot serve its advertised search. */
    {
        char *fts_err = NULL;
        int fts_rc = sqlite3_exec(s->db,
                                  "CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5("
                                  "  name, qualified_name, label, file_path,"
                                  "  content='',"
                                  "  tokenize='unicode61 remove_diacritics 2'"
                                  ");",
                                  NULL, NULL, &fts_err);
        if (fts_rc != SQLITE_OK) {
            cbm_log_error("store.fts_schema_failed", "code", "CBM_FTS_SCHEMA_FAILED",
                          "sqlite_error", fts_err ? fts_err : sqlite3_errmsg(s->db), "remediation",
                          "restore the required SQLite FTS5 runtime and rebuild the store", NULL);
            if (fts_err) {
                sqlite3_free(fts_err);
            }
            return CBM_STORE_ERR;
        }
        if (fts_err) {
            sqlite3_free(fts_err);
        }
    }
    if (exec_sql(s, "PRAGMA user_version = 3;") != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    int final_user_version = 0;
    if (read_user_version(s, &final_user_version) != CBM_STORE_OK ||
        final_user_version != CBM_STORE_SCHEMA_VERSION) {
        cbm_log_error("store.schema_version_readback_failed", "code",
                      "CBM_SCHEMA_VERSION_READBACK_FAILED", "message",
                      "SQLite did not persist the stable-atom schema version", "remediation",
                      "repair the store path or filesystem and rebuild from source");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

static int create_user_indexes(cbm_store_t *s) {
    const char *sql =
        "CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(project, label);"
        "CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(project, name);"
        "CREATE INDEX IF NOT EXISTS idx_nodes_file ON nodes(project, file_path);"
        "CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id, type);"
        "CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id, type);"
        "CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(project, type);"
        "CREATE INDEX IF NOT EXISTS idx_edges_target_type ON edges(project, target_id, type);"
        "CREATE INDEX IF NOT EXISTS idx_edges_source_type ON edges(project, source_id, type);"
        "CREATE INDEX IF NOT EXISTS idx_edges_url_path ON edges(project, url_path_gen);";
    /* NOTE: a partial expression index on json_extract(properties,'$.is_entry_point')
     * was tried for arch_entry_points and REVERTED: json_extract in an index WHERE
     * aborts CREATE INDEX (and thus store open) on any row whose properties JSON is
     * malformed — and pre-fix databases contain such rows (see
     * pipeline_def_props_valid_json_when_oversized). Revisit only with a
     * json_valid()-guarded expression once legacy DBs have aged out. */
    return exec_sql(s, sql);
}

int64_t cbm_store_resolve_mmap_size(void) {
    enum { MMAP_DEFAULT = 67108864, BASE_10 = 10 }; /* default 64 MB; decimal radix */
    char buf[ST_BUF_64];
    int env_status = cbm_read_env("CBM_SQLITE_MMAP_SIZE", buf, sizeof(buf));
    if (env_status == 0) {
        return (int64_t)MMAP_DEFAULT;
    }
    if (env_status < 0) {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(buf, &end, BASE_10);
    if (buf[0] == '\0' || end == buf || *end != '\0' || errno == ERANGE || parsed < 0) {
        return -1;
    }
    return (int64_t)parsed;
}

static int configure_mmap_size(cbm_store_t *s) {
    int64_t requested = cbm_store_resolve_mmap_size();
    if (requested < 0) {
        store_set_error(s, "CBM_SQLITE_MMAP_SIZE must be an exact non-negative base-10 integer");
        cbm_log_error("store.configure_mmap", "code", "CBM_STORE_MMAP_CONFIG_INVALID", "message",
                      s->errbuf, "remediation",
                      "unset CBM_SQLITE_MMAP_SIZE to use the default, or provide an exact "
                      "non-negative integer");
        return CBM_STORE_ERR;
    }

    char sql[ST_BUF_64];
    int sql_len = snprintf(sql, sizeof(sql), "PRAGMA mmap_size = %lld;", (long long)requested);
    if (sql_len < 0 || (size_t)sql_len >= sizeof(sql)) {
        store_set_error(s, "CBM_SQLITE_MMAP_SIZE statement exceeds its exact representation");
        return CBM_STORE_ERR;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "configure mmap_size prepare");
        return CBM_STORE_ERR;
    }
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        store_set_error_sqlite(s, "configure mmap_size step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_int64 observed = sqlite3_column_int64(stmt, 0);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_set_error_sqlite(s, "configure mmap_size completion");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    if (observed != requested) {
        char requested_buf[ST_BUF_64];
        char observed_buf[ST_BUF_64];
        snprintf(requested_buf, sizeof(requested_buf), "%lld", (long long)requested);
        snprintf(observed_buf, sizeof(observed_buf), "%lld", (long long)observed);
        snprintf(s->errbuf, sizeof(s->errbuf),
                 "SQLite refused the requested mmap_size: requested=%s observed=%s", requested_buf,
                 observed_buf);
        cbm_log_error("store.configure_mmap", "code", "CBM_STORE_MMAP_CONFIG_NOT_HONORED",
                      "requested", requested_buf, "observed", observed_buf, "message", s->errbuf,
                      "remediation",
                      "choose a value within this SQLite build's mmap limit or rebuild SQLite with "
                      "the required limit");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* Configure connection pragmas.
 *   in_memory  — :memory: DB (synchronous OFF, no journal file).
 *   read_only  — query-only connection opened SQLITE_OPEN_READONLY. Runs
 *                ONLY non-writing pragmas (foreign_keys, temp_store,
 *                busy_timeout, mmap_size) and SKIPS journal_mode=WAL,
 *                wal_checkpoint and synchronous — those WRITE to the DB/WAL
 *                and would (a) mutate the DB on every read query and (b)
 *                fail on a read-only DB file / filesystem.
 * in_memory and read_only are mutually exclusive. */
static int configure_pragmas(cbm_store_t *s, bool in_memory, bool read_only) {
    int rc;
    rc = exec_sql(s, "PRAGMA foreign_keys = ON;");
    if (rc != CBM_STORE_OK) {
        return rc;
    }
    rc = exec_sql(s, "PRAGMA temp_store = MEMORY;");
    if (rc != CBM_STORE_OK) {
        return rc;
    }

    if (in_memory) {
        rc = exec_sql(s, "PRAGMA synchronous = OFF;");
    } else if (read_only) {
        /* Non-writing pragmas only — see the function comment. */
        rc = exec_sql(s, "PRAGMA busy_timeout = 10000;");
        if (rc != CBM_STORE_OK) {
            return rc;
        }
        rc = configure_mmap_size(s);
    } else {
        rc = exec_sql(s, "PRAGMA busy_timeout = 10000;");
        if (rc != CBM_STORE_OK) {
            return rc;
        }
        rc = exec_sql(s, "PRAGMA journal_mode = WAL;");
        if (rc != CBM_STORE_OK) {
            return rc;
        }
        rc = exec_sql(s, "PRAGMA synchronous = NORMAL;");
        if (rc != CBM_STORE_OK) {
            return rc;
        }
        rc = configure_mmap_size(s);
    }
    return rc;
}

/* ── camelCase splitter for FTS5 indexing ───────────────────────── */

/* Emits the original identifier plus a space-separated split version, so FTS5's
 * whitespace tokenizer produces both `updateCloudClient` (exact match) and the
 * word tokens `update`, `cloud`, `client`.  Rules:
 *   1. insert space before an uppercase letter preceded by a lowercase letter
 *      ("updateCloud" → "update Cloud")
 *   2. insert space before an uppercase letter preceded by another uppercase
 *      but followed by a lowercase letter ("XMLParser" → "XML Parser", not
 *      "X M L Parser")
 * snake_case is already split by FTS5's unicode61 tokenizer on `_`. */
enum {
    CAMEL_SPLIT_BUF = 2048,
    SQLITE_AUTO_LEN = -1, /* sqlite3_result_text sentinel: use strlen(). */
    CAMEL_BUF_GUARD = 2,  /* reserve room for inserted space + NUL terminator. */
};

/* Denominator epsilon guard for double-precision cosine. */
#define CBM_STORE_DENOM_EPS_D 1e-10
#define CBM_STORE_DENOM_EPS_F 1e-10F
#define CBM_STORE_INT8_MAX 127.0F
#define CBM_STORE_UNIT_POS_F 1.0F
#define CBM_STORE_UNIT_POS_D 1.0

/* Module-local copy of SQLite's SQLITE_TRANSIENT sentinel ((void*)-1).
 * We construct it via memcpy from a volatile intptr_t sentinel so the
 * resulting expression isn't syntactically a direct int-to-ptr cast —
 * clang-tidy's performance-no-int-to-ptr sees the memcpy boundary and
 * doesn't flag it per-use-site. */
static sqlite3_destructor_type cbm_sqlite_transient_destructor(void) {
    static const volatile intptr_t raw = -1;
    sqlite3_destructor_type dtor = NULL;
    memcpy(&dtor, (const void *)&raw, sizeof(dtor));
    return dtor;
}
#define CBM_SQLITE_TRANSIENT (cbm_sqlite_transient_destructor())

/* True if we should insert a space BEFORE input[i] to split a camelCase word
 * boundary (lowercase→uppercase or uppercase-run→uppercase-then-lowercase). */
static bool camel_should_split(const char *input, int i) {
    if (i <= 0) {
        return false;
    }
    char curr = input[i];
    char prev = input[i - SKIP_ONE];
    char next = input[i + SKIP_ONE];
    if (curr >= 'A' && curr <= 'Z' && prev >= 'a' && prev <= 'z') {
        return true;
    }
    if (curr >= 'A' && curr <= 'Z' && prev >= 'A' && prev <= 'Z' && next >= 'a' && next <= 'z') {
        return true;
    }
    return false;
}

static void sqlite_camel_split(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    const char *input = (const char *)sqlite3_value_text(argv[0]);
    if (!input || !input[0]) {
        sqlite3_result_text(ctx, input ? input : "", SQLITE_AUTO_LEN, CBM_SQLITE_TRANSIENT);
        return;
    }
    char buf[CAMEL_SPLIT_BUF];
    int len = snprintf(buf, sizeof(buf), "%s ", input);
    if (len < 0 || len >= (int)sizeof(buf)) {
        /* Input too long — fall back to the original string unmodified. */
        sqlite3_result_text(ctx, input, SQLITE_AUTO_LEN, CBM_SQLITE_TRANSIENT);
        return;
    }
    for (int i = 0; input[i] && len < (int)sizeof(buf) - CAMEL_BUF_GUARD; i++) {
        if (camel_should_split(input, i)) {
            buf[len++] = ' ';
        }
        buf[len++] = input[i];
    }
    buf[len] = '\0';
    sqlite3_result_text(ctx, buf, len, CBM_SQLITE_TRANSIENT);
}

/* ── REGEXP function for SQLite ──────────────────────────────────── */

/* Destructor passed to sqlite3_set_auxdata — frees the cached compiled regex. */
static void regex_free_cb(void *p) {
    cbm_regex_t *re = (cbm_regex_t *)p;
    cbm_regfree(re);
    free(re);
}

/* Cache the compiled regex on argument slot 0 for the lifetime of the statement.
 * sqlite3_get_auxdata returns the cached pointer on subsequent rows (same parameter
 * value), so cbm_regcomp is called exactly once per statement instead of once per row. */
static void sqlite_regexp(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    const char *pattern = (const char *)sqlite3_value_text(argv[0]);
    const char *text = (const char *)sqlite3_value_text(argv[SKIP_ONE]);
    if (!pattern || !text) {
        sqlite3_result_int(ctx, 0);
        return;
    }

    cbm_regex_t *re = (cbm_regex_t *)sqlite3_get_auxdata(ctx, 0);
    if (!re) {
        re = malloc(sizeof(cbm_regex_t));
        if (!re) {
            sqlite3_result_error_nomem(ctx);
            return;
        }
        if (cbm_regcomp(re, pattern, CBM_REG_EXTENDED | CBM_REG_NOSUB) != 0) {
            free(re);
            sqlite3_result_error(ctx, "invalid regex", CBM_NOT_FOUND);
            return;
        }
        sqlite3_set_auxdata(ctx, 0, re, regex_free_cb);
    }

    sqlite3_result_int(ctx, cbm_regexec(re, text, 0, NULL, 0) == 0 ? SKIP_ONE : 0);
}

/* Case-insensitive REGEXP variant — same auxdata caching strategy. */
static void sqlite_iregexp(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    const char *pattern = (const char *)sqlite3_value_text(argv[0]);
    const char *text = (const char *)sqlite3_value_text(argv[SKIP_ONE]);
    if (!pattern || !text) {
        sqlite3_result_int(ctx, 0);
        return;
    }

    cbm_regex_t *re = (cbm_regex_t *)sqlite3_get_auxdata(ctx, 0);
    if (!re) {
        re = malloc(sizeof(cbm_regex_t));
        if (!re) {
            sqlite3_result_error_nomem(ctx);
            return;
        }
        if (cbm_regcomp(re, pattern, CBM_REG_EXTENDED | CBM_REG_NOSUB | CBM_REG_ICASE) != 0) {
            free(re);
            sqlite3_result_error(ctx, "invalid regex", CBM_NOT_FOUND);
            return;
        }
        sqlite3_set_auxdata(ctx, 0, re, regex_free_cb);
    }

    sqlite3_result_int(ctx, cbm_regexec(re, text, 0, NULL, 0) == 0 ? SKIP_ONE : 0);
}

/* Cosine similarity between two int8 BLOB vectors.
 * Returns float in [-1, 1].  Used for vector search at query time. */
static void sqlite_cosine_i8(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    if (sqlite3_value_type(argv[0]) != SQLITE_BLOB ||
        sqlite3_value_type(argv[SKIP_ONE]) != SQLITE_BLOB) {
        sqlite3_result_double(ctx, 0.0);
        return;
    }
    int len_a = sqlite3_value_bytes(argv[0]);
    int len_b = sqlite3_value_bytes(argv[SKIP_ONE]);
    if (len_a != len_b || len_a == 0) {
        sqlite3_result_double(ctx, 0.0);
        return;
    }
    const int8_t *a = (const int8_t *)sqlite3_value_blob(argv[0]);
    const int8_t *b = (const int8_t *)sqlite3_value_blob(argv[SKIP_ONE]);
    int32_t dot = 0;
    int32_t mag_a = 0;
    int32_t mag_b = 0;
    for (int i = 0; i < len_a; i++) {
        dot += (int32_t)a[i] * (int32_t)b[i];
        mag_a += (int32_t)a[i] * (int32_t)a[i];
        mag_b += (int32_t)b[i] * (int32_t)b[i];
    }
    double denom = sqrt((double)mag_a) * sqrt((double)mag_b);
    sqlite3_result_double(ctx, denom > CBM_STORE_DENOM_EPS_D ? (double)dot / denom : 0.0);
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

/* SQLite authorizer: deny dangerous operations that could be exploited via
 * SQL injection through the Cypher→SQL translation layer. */
static int store_authorizer(void *user_data, int action, const char *p3, const char *p4,
                            const char *p5, const char *p6) {
    (void)user_data;
    (void)p3;
    (void)p4;
    (void)p5;
    (void)p6;
    switch (action) {
    case SQLITE_ATTACH: /* ATTACH DATABASE — could create/read arbitrary files */
    case SQLITE_DETACH: /* DETACH DATABASE */
        return SQLITE_DENY;
    default:
        return SQLITE_OK;
    }
}

static cbm_store_t *store_open_internal(const char *path, bool in_memory) {
    cbm_store_t *s = calloc(CBM_ALLOC_ONE, sizeof(cbm_store_t));
    if (!s) {
        return NULL;
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (in_memory) {
        flags |= SQLITE_OPEN_MEMORY;
    }

    int rc = sqlite3_open_v2(path, &s->db, flags, NULL);
    if (rc != SQLITE_OK) {
        free(s);
        return NULL;
    }

    if (path && !in_memory) {
        s->db_path = heap_strdup(path);
    }

    /* Security: block ATTACH/DETACH to prevent file creation via SQL injection.
     * The authorizer runs inside SQLite's query planner — no string-level bypass. */
    sqlite3_set_authorizer(s->db, store_authorizer, NULL);

    /* Register REGEXP function (SQLite doesn't have one built-in) */
    sqlite3_create_function(s->db, "regexp", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                            sqlite_regexp, NULL, NULL);
    /* Case-insensitive variant for search with case_sensitive=false */
    sqlite3_create_function(s->db, "iregexp", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                            sqlite_iregexp, NULL, NULL);
    /* Int8 cosine similarity for vector search */
    sqlite3_create_function(s->db, "cbm_cosine_i8", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                            NULL, sqlite_cosine_i8, NULL, NULL);
    /* camelCase splitter for FTS5 BM25 indexing */
    sqlite3_create_function(s->db, "cbm_camel_split", SKIP_ONE, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                            NULL, sqlite_camel_split, NULL, NULL);

    if (configure_pragmas(s, in_memory, false) != CBM_STORE_OK || init_schema(s) != CBM_STORE_OK ||
        create_user_indexes(s) != CBM_STORE_OK) {
        sqlite3_close(s->db);
        safe_str_free(&s->db_path);
        free(s);
        return NULL;
    }

    return s;
}

cbm_store_t *cbm_store_open_memory(void) {
    return store_open_internal(":memory:", true);
}

cbm_store_t *cbm_store_open_path(const char *db_path) {
    if (!db_path) {
        return NULL;
    }
    return store_open_internal(db_path, false);
}

const char *cbm_store_db_path(const cbm_store_t *s) {
    return s ? s->db_path : NULL;
}

static void store_query_open_error(int *out_sqlite_error, char *detail, size_t detail_size,
                                   sqlite3 *db, int rc) {
    int effective_error = db ? sqlite3_extended_errcode(db) : rc;
    if (effective_error == SQLITE_OK && rc != SQLITE_OK) {
        effective_error = rc;
    }
    if (out_sqlite_error) {
        *out_sqlite_error = effective_error;
    }
    if (detail && detail_size > 0) {
        snprintf(detail, detail_size, "%s",
                 db && sqlite3_extended_errcode(db) != SQLITE_OK ? sqlite3_errmsg(db)
                                                                 : sqlite3_errstr(effective_error));
    }
}

static cbm_store_t *store_open_path_query_internal(const char *db_path, int *out_sqlite_error,
                                                   char *detail, size_t detail_size) {
    if (out_sqlite_error) {
        *out_sqlite_error = SQLITE_OK;
    }
    if (detail && detail_size > 0) {
        detail[0] = '\0';
    }
    if (!db_path) {
        if (out_sqlite_error) {
            *out_sqlite_error = SQLITE_MISUSE;
        }
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "database path is null");
        }
        return NULL;
    }

    cbm_store_t *s = calloc(CBM_ALLOC_ONE, sizeof(cbm_store_t));
    if (!s) {
        if (out_sqlite_error) {
            *out_sqlite_error = SQLITE_NOMEM;
        }
        if (detail && detail_size > 0) {
            snprintf(detail, detail_size, "%s", sqlite3_errstr(SQLITE_NOMEM));
        }
        return NULL;
    }

    /* Query tools open the project DB READ-ONLY: a read query must never create
     * the database or run write pragmas.  The ordinary SQLite locking/WAL
     * contract is mandatory.  A failure to open or perform the first read is a
     * real failure: never retry with immutable=1, because that assertion skips
     * locking/change detection and can omit committed WAL state. */
    int rc = sqlite3_open_v2(db_path, &s->db, SQLITE_OPEN_READONLY, NULL);
    if (rc == SQLITE_OK) {
        /* Force first DB access so a read-only-FS WAL failure surfaces now. */
        int probe_rc =
            sqlite3_exec(s->db, "SELECT 1 FROM sqlite_master LIMIT 1;", NULL, NULL, NULL);
        if (probe_rc != SQLITE_OK) {
            store_query_open_error(out_sqlite_error, detail, detail_size, s->db, probe_rc);
            sqlite3_close(s->db);
            s->db = NULL;
            rc = probe_rc;
        }
    } else {
        store_query_open_error(out_sqlite_error, detail, detail_size, s->db, rc);
    }
    if (rc != SQLITE_OK) {
        sqlite3_close(s->db); /* no-op if already NULL */
        s->db = NULL;
        free(s);
        return NULL;
    }

    s->db_path = heap_strdup(db_path);
    if (!s->db_path) {
        store_query_open_error(out_sqlite_error, detail, detail_size, s->db, SQLITE_NOMEM);
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }

    /* Security: block ATTACH/DETACH to prevent file creation via SQL injection. */
    sqlite3_set_authorizer(s->db, store_authorizer, NULL);

    /* Register REGEXP functions. */
    sqlite3_create_function(s->db, "regexp", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                            sqlite_regexp, NULL, NULL);
    sqlite3_create_function(s->db, "iregexp", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                            sqlite_iregexp, NULL, NULL);
    sqlite3_create_function(s->db, "cbm_cosine_i8", ST_COL_2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                            NULL, sqlite_cosine_i8, NULL, NULL);
    sqlite3_create_function(s->db, "cbm_camel_split", SKIP_ONE, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                            NULL, sqlite_camel_split, NULL, NULL);

    if (configure_pragmas(s, false, true) != CBM_STORE_OK) {
        store_query_open_error(out_sqlite_error, detail, detail_size, s->db,
                               sqlite3_extended_errcode(s->db));
        sqlite3_close(s->db);
        safe_str_free(&s->db_path);
        free(s);
        return NULL;
    }

    return s;
}

cbm_store_t *cbm_store_open_path_query(const char *db_path) {
    int sqlite_error = SQLITE_OK;
    char detail[CBM_STORE_VERIFY_DETAIL_MAX] = "";
    cbm_store_t *store =
        store_open_path_query_internal(db_path, &sqlite_error, detail, sizeof(detail));
    if (!store) {
        char sqlite_error_buf[CBM_SZ_32];
        snprintf(sqlite_error_buf, sizeof(sqlite_error_buf), "%d", sqlite_error);
        cbm_log_error("store.query_open_failed", "code", "CBM_STORE_QUERY_OPEN_FAILED", "db_path",
                      db_path ? db_path : "", "operation", "sqlite.open_or_first_read",
                      "sqlite_error", sqlite_error_buf, "detail",
                      detail[0] ? detail : "SQLite query open failed", "remediation",
                      "preserve the database, WAL, and SHM together; resolve the reported SQLite "
                      "failure, then retry");
    }
    return store;
}

/* ── Integrity check ───────────────────────────────────────────── */

typedef enum {
    STORE_INTEGRITY_OK = 0,
    STORE_INTEGRITY_FAILED,
    STORE_INTEGRITY_IO_FAILED,
} store_integrity_status_t;

typedef struct {
    store_integrity_status_t status;
    char operation[CBM_STORE_VERIFY_OPERATION_MAX];
    int sqlite_error;
    char detail[CBM_STORE_VERIFY_DETAIL_MAX];
} store_integrity_result_t;

static void store_integrity_result_init(store_integrity_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->status = STORE_INTEGRITY_IO_FAILED;
}

static store_integrity_status_t store_integrity_sqlite_failure_status(int sqlite_error) {
    switch (sqlite_error & 0xFF) {
    case SQLITE_NOMEM:
    case SQLITE_IOERR:
    case SQLITE_FULL:
    case SQLITE_CANTOPEN:
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
        return STORE_INTEGRITY_IO_FAILED;
    default:
        return STORE_INTEGRITY_FAILED;
    }
}

static void store_integrity_set_failure(store_integrity_result_t *result,
                                        store_integrity_status_t status, const char *operation,
                                        int sqlite_error, const char *detail) {
    result->status = status;
    result->sqlite_error = sqlite_error;
    snprintf(result->operation, sizeof(result->operation), "%s", operation ? operation : "");
    snprintf(result->detail, sizeof(result->detail), "%s", detail ? detail : "");
}

static void store_integrity_set_sqlite_failure(store_integrity_result_t *result,
                                               const char *operation, sqlite3 *db, int rc) {
    int sqlite_error = db ? sqlite3_extended_errcode(db) : rc;
    if (sqlite_error == SQLITE_OK) {
        sqlite_error = rc;
    }
    const char *message = db ? sqlite3_errmsg(db) : sqlite3_errstr(sqlite_error);
    store_integrity_set_failure(result, store_integrity_sqlite_failure_status(sqlite_error),
                                operation, sqlite_error,
                                message ? message : "SQLite returned no diagnostic");
}

static bool store_root_path_is_absolute(const unsigned char *path, int bytes) {
    if (!path || bytes <= 0) {
        return false;
    }
    if (path[0] == '/') {
        return true;
    }
    if (bytes >= 2 && path[0] == '\\' && path[1] == '\\') {
        return true;
    }
    return bytes >= 3 &&
           ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
           path[1] == ':' && (path[2] == '/' || path[2] == '\\');
}

static bool store_integrity_prepare_probe(sqlite3 *db, const char *operation, const char *sql,
                                          store_integrity_result_t *result) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, operation, db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return false;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_integrity_set_sqlite_failure(result, operation, db, rc);
        sqlite3_finalize(stmt);
        return false;
    }
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, operation, db, rc);
        return false;
    }
    return true;
}

static store_integrity_status_t store_check_integrity_detailed(cbm_store_t *s,
                                                               store_integrity_result_t *result) {
    store_integrity_result_init(result);
    if (!s || !s->db) {
        store_integrity_set_failure(result, STORE_INTEGRITY_IO_FAILED, "connection", SQLITE_MISUSE,
                                    "store connection is absent");
        return result->status;
    }

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(s->db, "PRAGMA main.integrity_check(1);", CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "sqlite.integrity_check.prepare", s->db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        store_integrity_set_sqlite_failure(result, "sqlite.integrity_check.step", s->db, rc);
        sqlite3_finalize(stmt);
        return result->status;
    }
    const unsigned char *integrity_text = sqlite3_column_text(stmt, 0);
    int integrity_bytes = sqlite3_column_bytes(stmt, 0);
    if (!integrity_text || integrity_bytes != 2 || memcmp(integrity_text, "ok", 2) != 0) {
        if (!integrity_text) {
            store_integrity_set_failure(result, STORE_INTEGRITY_FAILED, "sqlite.integrity_check",
                                        SQLITE_OK, "PRAGMA integrity_check(1) returned NULL");
        } else if ((size_t)integrity_bytes >= sizeof(result->detail) - SLEN("integrity_check: ")) {
            char overflow[ST_BUF_64];
            snprintf(overflow, sizeof(overflow),
                     "integrity_check diagnostic exceeds capacity: bytes=%d", integrity_bytes);
            store_integrity_set_failure(result, STORE_INTEGRITY_IO_FAILED,
                                        "sqlite.integrity_check.diagnostic", SQLITE_TOOBIG,
                                        overflow);
        } else {
            snprintf(result->detail, sizeof(result->detail), "integrity_check: %.*s",
                     integrity_bytes, (const char *)integrity_text);
            result->status = STORE_INTEGRITY_FAILED;
            result->sqlite_error = SQLITE_OK;
            snprintf(result->operation, sizeof(result->operation), "%s", "sqlite.integrity_check");
        }
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_ROW) {
            store_integrity_set_failure(result, STORE_INTEGRITY_FAILED,
                                        "sqlite.integrity_check.cardinality", SQLITE_OK,
                                        "PRAGMA integrity_check returned extra rows after ok");
        } else {
            store_integrity_set_sqlite_failure(result, "sqlite.integrity_check.finish", s->db, rc);
        }
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "sqlite.integrity_check.finalize", s->db, rc);
        return result->status;
    }

    rc = sqlite3_prepare_v2(s->db, "PRAGMA main.foreign_key_check;", CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "sqlite.foreign_key_check.prepare", s->db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *table = (const char *)sqlite3_column_text(stmt, 0);
        const char *parent = (const char *)sqlite3_column_text(stmt, 2);
        sqlite3_int64 rowid =
            sqlite3_column_type(stmt, 1) == SQLITE_NULL ? -1 : sqlite3_column_int64(stmt, 1);
        int fk_index = sqlite3_column_int(stmt, 3);
        char detail[CBM_STORE_VERIFY_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
                 "foreign_key_check: table=%s rowid=%lld parent=%s fk_index=%d",
                 table ? table : "(null)", (long long)rowid, parent ? parent : "(null)", fk_index);
        store_integrity_set_failure(result, STORE_INTEGRITY_FAILED, "sqlite.foreign_key_check",
                                    SQLITE_OK, detail);
        sqlite3_finalize(stmt);
        return result->status;
    }
    if (rc != SQLITE_DONE) {
        store_integrity_set_sqlite_failure(result, "sqlite.foreign_key_check.step", s->db, rc);
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "sqlite.foreign_key_check.finalize", s->db, rc);
        return result->status;
    }

    rc = sqlite3_prepare_v2(s->db, "PRAGMA main.user_version;", CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.user_version.prepare", s->db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return result->status;
    }
    rc = sqlite3_step(stmt);
    int user_version = rc == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
    if (rc != SQLITE_ROW || user_version != CBM_STORE_SCHEMA_VERSION) {
        if (rc != SQLITE_ROW) {
            store_integrity_set_sqlite_failure(result, "application.user_version.step", s->db, rc);
        } else {
            char detail[ST_BUF_64];
            snprintf(detail, sizeof(detail), "user_version=%d expected=%d", user_version,
                     CBM_STORE_SCHEMA_VERSION);
            store_integrity_set_failure(result, STORE_INTEGRITY_FAILED, "application.user_version",
                                        SQLITE_OK, detail);
        }
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_integrity_set_failure(result, STORE_INTEGRITY_FAILED,
                                    "application.user_version.cardinality", SQLITE_OK,
                                    "PRAGMA user_version did not return exactly one row");
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.user_version.finalize", s->db, rc);
        return result->status;
    }

    static const struct {
        const char *operation;
        const char *sql;
    } SCHEMA_PROBES[] = {
        {"application.schema.projects",
         "SELECT name, indexed_at, root_path FROM projects LIMIT 0;"},
        {"application.schema.file_hashes",
         "SELECT project, rel_path, sha256, mtime_ns, size FROM file_hashes LIMIT 0;"},
        {"application.schema.nodes", "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes LIMIT 0;"},
        {"application.schema.edges",
         "SELECT id, project, source_id, target_id, type, properties, url_path_gen, "
         "local_name_gen FROM edges LIMIT 0;"},
        {"application.schema.project_summaries",
         "SELECT project, summary, source_hash, created_at, updated_at "
         "FROM project_summaries LIMIT 0;"},
        {"application.schema.nodes_fts",
         "SELECT rowid, name, qualified_name, label, file_path FROM nodes_fts LIMIT 0;"},
    };
    for (size_t i = 0; i < sizeof(SCHEMA_PROBES) / sizeof(SCHEMA_PROBES[0]); i++) {
        if (!store_integrity_prepare_probe(s->db, SCHEMA_PROBES[i].operation, SCHEMA_PROBES[i].sql,
                                           result)) {
            return result->status;
        }
    }

    rc = sqlite3_prepare_v2(s->db, "SELECT count(*) FROM projects;", CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.project_count.prepare", s->db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return result->status;
    }
    rc = sqlite3_step(stmt);
    sqlite3_int64 project_count = rc == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : -1;
    if (rc != SQLITE_ROW || project_count != 1) {
        if (rc != SQLITE_ROW) {
            store_integrity_set_sqlite_failure(result, "application.project_count.step", s->db, rc);
        } else {
            char detail[ST_BUF_64];
            snprintf(detail, sizeof(detail), "projects rows=%lld expected=1",
                     (long long)project_count);
            store_integrity_set_failure(result, STORE_INTEGRITY_FAILED, "application.project_count",
                                        SQLITE_OK, detail);
        }
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_integrity_set_failure(result, STORE_INTEGRITY_FAILED,
                                    "application.project_count.cardinality", SQLITE_OK,
                                    "project count query did not return exactly one row");
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.project_count.finalize", s->db, rc);
        return result->status;
    }

    rc = sqlite3_prepare_v2(s->db, "SELECT name, indexed_at, root_path FROM projects;",
                            CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.project_row.prepare", s->db, rc);
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        store_integrity_set_sqlite_failure(result, "application.project_row.step", s->db, rc);
        sqlite3_finalize(stmt);
        return result->status;
    }
    const unsigned char *name = sqlite3_column_text(stmt, 0);
    const unsigned char *indexed_at = sqlite3_column_text(stmt, 1);
    const unsigned char *root_path = sqlite3_column_text(stmt, 2);
    int name_bytes = sqlite3_column_bytes(stmt, 0);
    int indexed_at_bytes = sqlite3_column_bytes(stmt, 1);
    int root_path_bytes = sqlite3_column_bytes(stmt, 2);
    const char *row_violation = NULL;
    if (sqlite3_column_type(stmt, 0) != SQLITE_TEXT || name_bytes <= 0 || !name ||
        !cbm_validate_project_name((const char *)name)) {
        row_violation = "project name must be non-empty valid UTF-8 project-name text";
    } else if (sqlite3_column_type(stmt, 1) != SQLITE_TEXT || indexed_at_bytes <= 0 ||
               !indexed_at) {
        row_violation = "indexed_at must be non-empty text";
    } else if (sqlite3_column_type(stmt, 2) != SQLITE_TEXT ||
               !store_root_path_is_absolute(root_path, root_path_bytes)) {
        row_violation = "root_path must be a non-empty absolute POSIX, drive, or UNC path";
    }
    if (row_violation) {
        store_integrity_set_failure(result, STORE_INTEGRITY_FAILED, "application.project_row",
                                    SQLITE_OK, row_violation);
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_integrity_set_failure(result, STORE_INTEGRITY_FAILED,
                                    "application.project_row.cardinality", SQLITE_OK,
                                    "sole-project query returned more than one row");
        sqlite3_finalize(stmt);
        return result->status;
    }
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        store_integrity_set_sqlite_failure(result, "application.project_row.finalize", s->db, rc);
        return result->status;
    }

    result->status = STORE_INTEGRITY_OK;
    result->sqlite_error = SQLITE_OK;
    snprintf(result->operation, sizeof(result->operation), "%s", "application.project_row");
    snprintf(result->detail, sizeof(result->detail), "%s",
             "SQLite integrity, foreign keys, schema version, query schema, and sole-project "
             "invariants passed");
    return result->status;
}

bool cbm_store_check_integrity(cbm_store_t *s) {
    store_integrity_result_t result;
    if (store_check_integrity_detailed(s, &result) == STORE_INTEGRITY_OK) {
        return true;
    }
    char sqlite_error[ST_BUF_16];
    snprintf(sqlite_error, sizeof(sqlite_error), "%d", result.sqlite_error);
    cbm_log_error("store.integrity_refused", "code", "CBM_STORE_INTEGRITY_FAILED", "operation",
                  result.operation, "sqlite_error", sqlite_error, "detail", result.detail,
                  "remediation", "preserve the complete SQLite family and rebuild it from source");
    return false;
}

static void store_verify_result_init(cbm_store_verify_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->status = CBM_STORE_VERIFY_IO_FAILED;
    result->family_guard_release_complete = true;
    result->scratch_cleanup_complete = true;
    result->sqlite_error = SQLITE_OK;
}

static void store_verify_set_error(cbm_store_verify_result_t *result,
                                   cbm_store_verify_status_t status, const char *operation,
                                   uint32_t native_error, int sqlite_error, const char *detail) {
    result->status = status;
    result->native_error = native_error;
    result->sqlite_error = sqlite_error;
    snprintf(result->operation, sizeof(result->operation), "%s", operation ? operation : "unknown");
    snprintf(result->detail, sizeof(result->detail), "%s", detail ? detail : "unspecified");
}

#ifdef _WIN32

typedef struct {
    HANDLE db;
    HANDLE wal;
    HANDLE shm;
} store_frozen_family_t;

static void store_frozen_family_init(store_frozen_family_t *family) {
    family->db = INVALID_HANDLE_VALUE;
    family->wal = INVALID_HANDLE_VALUE;
    family->shm = INVALID_HANDLE_VALUE;
}

static DWORD store_frozen_family_close(store_frozen_family_t *family) {
    DWORD first_error = ERROR_SUCCESS;
    if (family->shm != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(family->shm) && first_error == ERROR_SUCCESS) {
            first_error = GetLastError();
        }
        family->shm = INVALID_HANDLE_VALUE;
    }
    if (family->wal != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(family->wal) && first_error == ERROR_SUCCESS) {
            first_error = GetLastError();
        }
        family->wal = INVALID_HANDLE_VALUE;
    }
    if (family->db != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(family->db) && first_error == ERROR_SUCCESS) {
            first_error = GetLastError();
        }
        family->db = INVALID_HANDLE_VALUE;
    }
    return first_error;
}

static char *store_member_path(const char *db_path, const char *suffix) {
    size_t db_len = strlen(db_path);
    size_t suffix_len = strlen(suffix);
    if (db_len > SIZE_MAX - suffix_len - 1) {
        return NULL;
    }
    char *path = malloc(db_len + suffix_len + 1);
    if (!path) {
        return NULL;
    }
    memcpy(path, db_path, db_len);
    memcpy(path + db_len, suffix, suffix_len + 1);
    return path;
}

static bool store_source_missing_error(DWORD error) {
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

static HANDLE store_freeze_member(const char *path, bool required, bool *present,
                                  cbm_store_verify_result_t *result, const char *operation) {
    *present = false;
    wchar_t *wide_path = cbm_utf8_to_wide_path(path);
    if (!wide_path) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation,
                               ERROR_NO_UNICODE_TRANSLATION, SQLITE_OK,
                               "UTF-8 path could not be converted to a Windows path");
        return INVALID_HANDLE_VALUE;
    }

    /* FILE_SHARE_READ deliberately omits write/delete sharing.  Windows rejects
     * this open when a writer or writable mapping already exists and rejects any
     * new writer/deleter while the returned handle remains live. */
    HANDLE handle = CreateFileW(
        wide_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE) {
        if (!required && store_source_missing_error(error)) {
            return INVALID_HANDLE_VALUE;
        }
        store_verify_set_error(result,
                               required && store_source_missing_error(error)
                                   ? CBM_STORE_VERIFY_SOURCE_MISSING
                                   : CBM_STORE_VERIFY_IO_FAILED,
                               operation, error, SQLITE_OK,
                               store_source_missing_error(error)
                                   ? "source database member is absent"
                                   : "source database member could not be frozen read-only");
        return INVALID_HANDLE_VALUE;
    }

    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(handle, &info)) {
        error = GetLastError();
        CloseHandle(handle);
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, error, SQLITE_OK,
                               "source database member identity could not be read");
        return INVALID_HANDLE_VALUE;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(handle);
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, ERROR_INVALID_DATA,
                               SQLITE_OK, "source database member is a directory or reparse point");
        return INVALID_HANDLE_VALUE;
    }

    *present = true;
    return handle;
}

static bool store_hash_handle(HANDLE handle, uint8_t digest[CBM_SHA256_DIGEST_LEN],
                              uint64_t *byte_count, DWORD *native_error) {
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(handle, zero, NULL, FILE_BEGIN)) {
        *native_error = GetLastError();
        return false;
    }

    enum { STORE_COPY_BUFFER_SIZE = 64 * 1024 };
    uint8_t buffer[STORE_COPY_BUFFER_SIZE];
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    *byte_count = 0;
    for (;;) {
        DWORD read_count = 0;
        if (!ReadFile(handle, buffer, (DWORD)sizeof(buffer), &read_count, NULL)) {
            *native_error = GetLastError();
            return false;
        }
        if (read_count == 0) {
            break;
        }
        cbm_sha256_update(&hash, buffer, read_count);
        *byte_count += read_count;
    }
    cbm_sha256_final(&hash, digest);
    return true;
}

static bool store_copy_frozen_member(HANDLE source, const char *destination,
                                     cbm_store_verify_result_t *result, const char *operation) {
    wchar_t *wide_destination = cbm_utf8_to_wide_path(destination);
    if (!wide_destination) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation,
                               ERROR_NO_UNICODE_TRANSLATION, SQLITE_OK,
                               "snapshot path could not be converted to a Windows path");
        return false;
    }

    HANDLE output = CreateFileW(wide_destination, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        free(wide_destination);
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, error, SQLITE_OK,
                               "exclusive snapshot destination could not be created");
        return false;
    }

    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    bool ok = true;
    DWORD error = ERROR_SUCCESS;
    cbm_sha256_ctx source_hash;
    cbm_sha256_init(&source_hash);
    uint64_t source_bytes = 0;
    if (!SetFilePointerEx(source, zero, NULL, FILE_BEGIN)) {
        error = GetLastError();
        ok = false;
    }

    enum { STORE_COPY_BUFFER_SIZE = 64 * 1024 };
    uint8_t buffer[STORE_COPY_BUFFER_SIZE];
    while (ok) {
        DWORD read_count = 0;
        if (!ReadFile(source, buffer, (DWORD)sizeof(buffer), &read_count, NULL)) {
            error = GetLastError();
            ok = false;
            break;
        }
        if (read_count == 0) {
            break;
        }
        DWORD offset = 0;
        while (offset < read_count) {
            DWORD written = 0;
            if (!WriteFile(output, buffer + offset, read_count - offset, &written, NULL) ||
                written == 0) {
                error = GetLastError();
                if (error == ERROR_SUCCESS) {
                    error = ERROR_WRITE_FAULT;
                }
                ok = false;
                break;
            }
            offset += written;
        }
        if (ok) {
            cbm_sha256_update(&source_hash, buffer, read_count);
            source_bytes += read_count;
        }
    }
    if (ok && !FlushFileBuffers(output)) {
        error = GetLastError();
        ok = false;
    }
    if (!CloseHandle(output) && ok) {
        error = GetLastError();
        ok = false;
    }
    if (!ok) {
        free(wide_destination);
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, error, SQLITE_OK,
                               "snapshot copy or durable flush failed");
        return false;
    }

    uint8_t source_digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(&source_hash, source_digest);
    HANDLE readback =
        CreateFileW(wide_destination, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    free(wide_destination);
    if (readback == INVALID_HANDLE_VALUE) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, GetLastError(),
                               SQLITE_OK, "snapshot readback could not be opened");
        return false;
    }

    uint8_t readback_digest[CBM_SHA256_DIGEST_LEN];
    uint64_t readback_bytes = 0;
    ok = store_hash_handle(readback, readback_digest, &readback_bytes, &error);
    if (!CloseHandle(readback) && ok) {
        error = GetLastError();
        ok = false;
    }
    if (!ok) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, error, SQLITE_OK,
                               "snapshot readback could not be hashed");
        return false;
    }
    if (source_bytes != readback_bytes ||
        memcmp(source_digest, readback_digest, sizeof(source_digest)) != 0) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, operation, ERROR_CRC, SQLITE_OK,
                               "snapshot bytes or SHA-256 differ from the frozen source member");
        return false;
    }
    return true;
}

static bool store_create_scratch_directory(cbm_store_verify_result_t *result) {
    wchar_t temp_wide[CBM_STORE_VERIFY_PATH_MAX];
    DWORD temp_len = GetTempPathW((DWORD)(sizeof(temp_wide) / sizeof(temp_wide[0])), temp_wide);
    if (temp_len == 0 || temp_len >= sizeof(temp_wide) / sizeof(temp_wide[0])) {
        DWORD error = temp_len == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.temp_path", error,
                               SQLITE_OK,
                               "Windows temporary directory could not be resolved exactly");
        return false;
    }
    char *temp_utf8 = cbm_wide_to_utf8(temp_wide);
    if (!temp_utf8) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.temp_path",
                               ERROR_NO_UNICODE_TRANSLATION, SQLITE_OK,
                               "Windows temporary directory is not valid UTF-8");
        return false;
    }

    uint8_t nonce[16];
    char nonce_hex[sizeof(nonce) * 2 + 1];
    static const char HEX[] = "0123456789abcdef";
    sqlite3_randomness((int)sizeof(nonce), nonce);
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce_hex[i * 2] = HEX[(nonce[i] >> 4) & 0xF];
        nonce_hex[i * 2 + 1] = HEX[nonce[i] & 0xF];
    }
    nonce_hex[sizeof(nonce) * 2] = '\0';

    size_t temp_size = strlen(temp_utf8);
    const char *separator =
        temp_size > 0 && (temp_utf8[temp_size - 1] == '/' || temp_utf8[temp_size - 1] == '\\')
            ? ""
            : "/";
    int wrote =
        snprintf(result->scratch_path, sizeof(result->scratch_path), "%s%scbm-integrity-%lu-%s",
                 temp_utf8, separator, (unsigned long)GetCurrentProcessId(), nonce_hex);
    free(temp_utf8);
    if (wrote < 0 || (size_t)wrote >= sizeof(result->scratch_path)) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.temp_path",
                               ERROR_BUFFER_OVERFLOW, SQLITE_OK,
                               "snapshot directory path exceeds the verified path capacity");
        return false;
    }

    wchar_t *scratch_wide = cbm_utf8_to_wide_path(result->scratch_path);
    if (!scratch_wide) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.create_directory",
                               ERROR_NO_UNICODE_TRANSLATION, SQLITE_OK,
                               "snapshot directory path could not be widened");
        return false;
    }
    if (!CreateDirectoryW(scratch_wide, NULL)) {
        DWORD error = GetLastError();
        free(scratch_wide);
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.create_directory",
                               error, SQLITE_OK,
                               "unique snapshot directory could not be created atomically");
        return false;
    }
    result->scratch_created = true;
    result->scratch_cleanup_complete = false;
    DWORD attributes = GetFileAttributesW(scratch_wide);
    DWORD attribute_error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    free(scratch_wide);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        store_verify_set_error(
            result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.verify_directory",
            attributes == INVALID_FILE_ATTRIBUTES ? attribute_error : ERROR_INVALID_DATA, SQLITE_OK,
            "created snapshot path is absent, non-directory, or a reparse point");
        return false;
    }
    return true;
}

static bool store_cleanup_file(const char *path, cbm_store_verify_result_t *result,
                               const char *operation) {
    wchar_t *wide_path = cbm_utf8_to_wide_path(path);
    if (!wide_path) {
        if (result->cleanup_operation[0] == '\0') {
            result->cleanup_native_error = ERROR_NO_UNICODE_TRANSLATION;
            snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s", operation);
        }
        return false;
    }
    BOOL removed = DeleteFileW(wide_path);
    DWORD error = removed ? ERROR_SUCCESS : GetLastError();
    free(wide_path);
    if (!removed && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
        if (result->cleanup_operation[0] == '\0') {
            result->cleanup_native_error = error;
            snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s", operation);
        }
        return false;
    }
    return true;
}

static bool store_cleanup_scratch(cbm_store_verify_result_t *result, const char *snapshot_db) {
    if (!result->scratch_created) {
        result->scratch_cleanup_complete = true;
        return true;
    }

    char derived_snapshot_db[CBM_STORE_VERIFY_PATH_MAX];
    if (!snapshot_db || snapshot_db[0] == '\0') {
        int wrote = snprintf(derived_snapshot_db, sizeof(derived_snapshot_db), "%s/snapshot.db",
                             result->scratch_path);
        if (wrote < 0 || (size_t)wrote >= sizeof(derived_snapshot_db)) {
            result->cleanup_native_error = ERROR_BUFFER_OVERFLOW;
            snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s",
                     "snapshot.cleanup_build_path");
            result->scratch_cleanup_complete = false;
            return false;
        }
        snapshot_db = derived_snapshot_db;
    }

    static const char *const SUFFIXES[] = {"-shm", "-wal", "-journal", ""};
    static const char *const OPERATIONS[] = {"snapshot.cleanup_shm", "snapshot.cleanup_wal",
                                             "snapshot.cleanup_journal", "snapshot.cleanup_db"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(SUFFIXES) / sizeof(SUFFIXES[0]); i++) {
        char *path = store_member_path(snapshot_db, SUFFIXES[i]);
        if (!path) {
            if (result->cleanup_operation[0] == '\0') {
                result->cleanup_native_error = ERROR_NOT_ENOUGH_MEMORY;
                snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s",
                         OPERATIONS[i]);
            }
            ok = false;
            continue;
        }
        if (!store_cleanup_file(path, result, OPERATIONS[i])) {
            ok = false;
        }
        free(path);
    }

    wchar_t *scratch_wide = cbm_utf8_to_wide_path(result->scratch_path);
    if (!scratch_wide) {
        if (result->cleanup_operation[0] == '\0') {
            result->cleanup_native_error = ERROR_NO_UNICODE_TRANSLATION;
            snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s",
                     "snapshot.cleanup_directory");
        }
        ok = false;
    } else {
        if (!RemoveDirectoryW(scratch_wide)) {
            if (result->cleanup_operation[0] == '\0') {
                result->cleanup_native_error = GetLastError();
                snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s",
                         "snapshot.cleanup_directory");
            }
            ok = false;
        }
        free(scratch_wide);
    }
    result->scratch_cleanup_complete = ok;
    return ok;
}

static bool store_sqlite_corruption_code(int sqlite_error) {
    int primary = sqlite_error & 0xFF;
    return primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB || primary == SQLITE_FORMAT ||
           primary == SQLITE_SCHEMA;
}

#endif /* _WIN32 */

cbm_store_verify_status_t cbm_store_open_path_query_verified(const char *db_path,
                                                             cbm_store_t **out_store,
                                                             cbm_store_verify_result_t *result) {
    cbm_store_verify_result_t local_result;
    if (out_store) {
        *out_store = NULL;
    }
    if (!result) {
        result = &local_result;
    }
    store_verify_result_init(result);
    if (!out_store) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "source.validate_output",
                               ERROR_INVALID_PARAMETER, SQLITE_MISUSE,
                               "verified store output pointer is required");
        return result->status;
    }
    if (!db_path || db_path[0] == '\0') {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "source.validate_path",
                               ERROR_INVALID_PARAMETER, SQLITE_MISUSE,
                               "database path is null or empty");
        return result->status;
    }

#ifndef _WIN32
    store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "source.freeze_family", 0,
                           SQLITE_MISUSE,
                           "source-preserving integrity verification requires native Windows");
    return result->status;
#else
    store_frozen_family_t family;
    store_frozen_family_init(&family);
    char *wal_path = store_member_path(db_path, "-wal");
    char *shm_path = store_member_path(db_path, "-shm");
    char snapshot_db[CBM_STORE_VERIFY_PATH_MAX] = "";
    cbm_store_t *snapshot_store = NULL;
    if (!wal_path || !shm_path) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "source.build_family_paths",
                               ERROR_NOT_ENOUGH_MEMORY, SQLITE_NOMEM,
                               "database family paths could not be allocated");
        goto cleanup;
    }

    family.db = store_freeze_member(db_path, true, &result->db_present, result, "source.freeze_db");
    if (family.db == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    family.wal =
        store_freeze_member(wal_path, false, &result->wal_present, result, "source.freeze_wal");
    if (family.wal == INVALID_HANDLE_VALUE && result->status == CBM_STORE_VERIFY_IO_FAILED &&
        result->operation[0] != '\0') {
        goto cleanup;
    }
    family.shm =
        store_freeze_member(shm_path, false, &result->shm_present, result, "source.freeze_shm");
    if (family.shm == INVALID_HANDLE_VALUE && result->status == CBM_STORE_VERIFY_IO_FAILED &&
        result->operation[0] != '\0') {
        goto cleanup;
    }
    result->family_frozen = true;

    if (!store_create_scratch_directory(result)) {
        goto cleanup;
    }
    int path_wrote =
        snprintf(snapshot_db, sizeof(snapshot_db), "%s/snapshot.db", result->scratch_path);
    if (path_wrote < 0 || (size_t)path_wrote >= sizeof(snapshot_db)) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.build_db_path",
                               ERROR_BUFFER_OVERFLOW, SQLITE_OK,
                               "snapshot database path exceeds the verified path capacity");
        goto cleanup;
    }
    if (!store_copy_frozen_member(family.db, snapshot_db, result, "snapshot.copy_db")) {
        goto cleanup;
    }
    if (result->wal_present) {
        char *snapshot_wal = store_member_path(snapshot_db, "-wal");
        if (!snapshot_wal) {
            store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED, "snapshot.build_wal_path",
                                   ERROR_NOT_ENOUGH_MEMORY, SQLITE_NOMEM,
                                   "snapshot WAL path could not be allocated");
            goto cleanup;
        }
        bool copied =
            store_copy_frozen_member(family.wal, snapshot_wal, result, "snapshot.copy_wal");
        free(snapshot_wal);
        if (!copied) {
            goto cleanup;
        }
    }

    int sqlite_error = SQLITE_OK;
    char sqlite_detail[CBM_STORE_VERIFY_DETAIL_MAX] = "";
    snapshot_store = store_open_path_query_internal(snapshot_db, &sqlite_error, sqlite_detail,
                                                    sizeof(sqlite_detail));
    if (!snapshot_store) {
        store_verify_set_error(
            result,
            store_sqlite_corruption_code(sqlite_error) ? CBM_STORE_VERIFY_INTEGRITY_FAILED
                                                       : CBM_STORE_VERIFY_IO_FAILED,
            "snapshot.sqlite_open", ERROR_SUCCESS, sqlite_error,
            sqlite_detail[0] ? sqlite_detail : "snapshot SQLite open or first read failed");
        goto cleanup;
    }
    store_integrity_result_t integrity_result;
    store_integrity_status_t integrity_status =
        store_check_integrity_detailed(snapshot_store, &integrity_result);
    if (integrity_status != STORE_INTEGRITY_OK) {
        char operation[CBM_STORE_VERIFY_OPERATION_MAX];
        int operation_wrote =
            snprintf(operation, sizeof(operation), "snapshot.%s", integrity_result.operation);
        if (operation_wrote < 0 || (size_t)operation_wrote >= sizeof(operation)) {
            store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED,
                                   "snapshot.integrity_operation_overflow", ERROR_BUFFER_OVERFLOW,
                                   SQLITE_TOOBIG,
                                   "integrity diagnostic operation exceeds verified capacity");
            goto cleanup;
        }
        store_verify_set_error(
            result,
            integrity_status == STORE_INTEGRITY_IO_FAILED ? CBM_STORE_VERIFY_IO_FAILED
                                                          : CBM_STORE_VERIFY_INTEGRITY_FAILED,
            operation, ERROR_SUCCESS, integrity_result.sqlite_error, integrity_result.detail);
        goto cleanup;
    }
    result->status = CBM_STORE_VERIFY_OK;
    result->native_error = ERROR_SUCCESS;
    result->sqlite_error = SQLITE_OK;
    snprintf(result->operation, sizeof(result->operation), "%s",
             "snapshot.application.project_row");
    snprintf(result->detail, sizeof(result->detail), "%s",
             "snapshot passed the project-store integrity contract");

cleanup:
    if (snapshot_store) {
        cbm_store_close(snapshot_store);
    }
    bool cleanup_ok = store_cleanup_scratch(result, snapshot_db);
    if (!cleanup_ok && result->status == CBM_STORE_VERIFY_OK) {
        store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED,
                               result->cleanup_operation[0] ? result->cleanup_operation
                                                            : "snapshot.cleanup",
                               result->cleanup_native_error, SQLITE_OK,
                               "verified snapshot could not be removed completely");
    }
    if (result->status == CBM_STORE_VERIFY_OK) {
        /* Releasing only the SHM guard permits the verified read connection to
         * rebuild/use the mutable wal-index.  DB and WAL remain write/delete
         * denied until SQLite has completed its first source read, closing the
         * verification-to-use race. */
        if (family.shm != INVALID_HANDLE_VALUE) {
            if (!CloseHandle(family.shm)) {
                result->family_guard_release_complete = false;
                store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED,
                                       "source.release_shm_guard", GetLastError(), SQLITE_OK,
                                       "source SHM freeze handle could not be released");
            } else {
                family.shm = INVALID_HANDLE_VALUE;
            }
        }
        if (result->status == CBM_STORE_VERIFY_OK) {
            int source_sqlite_error = SQLITE_OK;
            char source_sqlite_detail[CBM_STORE_VERIFY_DETAIL_MAX] = "";
            cbm_store_t *opened = store_open_path_query_internal(
                db_path, &source_sqlite_error, source_sqlite_detail, sizeof(source_sqlite_detail));
            if (!opened) {
                store_verify_set_error(
                    result, CBM_STORE_VERIFY_IO_FAILED, "source.sqlite_open_after_verify",
                    ERROR_SUCCESS, source_sqlite_error,
                    source_sqlite_detail[0]
                        ? source_sqlite_detail
                        : "verified source could not be opened before releasing DB/WAL guards");
            } else {
                *out_store = opened;
            }
        }
    }
    DWORD release_error = store_frozen_family_close(&family);
    if (release_error != ERROR_SUCCESS) {
        result->family_guard_release_complete = false;
        if (result->status == CBM_STORE_VERIFY_OK) {
            if (*out_store) {
                cbm_store_close(*out_store);
                *out_store = NULL;
            }
            store_verify_set_error(result, CBM_STORE_VERIFY_IO_FAILED,
                                   "source.release_family_guards", release_error, SQLITE_OK,
                                   "source DB/WAL freeze handles could not be released exactly");
        } else if (result->cleanup_operation[0] == '\0') {
            result->cleanup_native_error = release_error;
            snprintf(result->cleanup_operation, sizeof(result->cleanup_operation), "%s",
                     "source.release_family_guards");
        }
    }
    free(wal_path);
    free(shm_path);
    return result->status;
#endif
}

cbm_store_t *cbm_store_open(const char *project) {
    if (!project) {
        return NULL;
    }
    if (!cbm_validate_project_name(project)) {
        return NULL;
    }
    const char *cdir = cbm_resolve_cache_dir();
    if (!cdir) {
        cdir = cbm_tmpdir();
    }
    char path[CBM_SZ_1K];
    snprintf(path, sizeof(path), "%s/%s.db", cdir, project);
    return store_open_internal(path, false);
}

static void finalize_stmt(sqlite3_stmt **s) {
    if (*s) {
        sqlite3_finalize(*s);
        *s = NULL;
    }
}

void cbm_store_close(cbm_store_t *s) {
    if (!s) {
        return;
    }

    /* Finalize all cached statements */
    finalize_stmt(&s->stmt_upsert_node);
    finalize_stmt(&s->stmt_find_node_by_id);
    finalize_stmt(&s->stmt_find_node_by_atom_id);
    finalize_stmt(&s->stmt_find_node_by_qn);
    finalize_stmt(&s->stmt_find_node_by_qn_any);
    finalize_stmt(&s->stmt_find_nodes_by_name);
    finalize_stmt(&s->stmt_find_nodes_by_name_any);
    finalize_stmt(&s->stmt_find_nodes_by_label);
    finalize_stmt(&s->stmt_find_nodes_by_file);
    finalize_stmt(&s->stmt_count_nodes);
    finalize_stmt(&s->stmt_delete_nodes_by_project);
    finalize_stmt(&s->stmt_delete_nodes_by_file);
    finalize_stmt(&s->stmt_delete_nodes_by_label);

    finalize_stmt(&s->stmt_insert_edge);
    finalize_stmt(&s->stmt_find_edges_by_source);
    finalize_stmt(&s->stmt_find_edges_by_target);
    finalize_stmt(&s->stmt_find_edges_by_source_type);
    finalize_stmt(&s->stmt_find_edges_by_target_type);
    finalize_stmt(&s->stmt_find_edges_by_type);
    finalize_stmt(&s->stmt_count_edges);
    finalize_stmt(&s->stmt_count_edges_by_type);
    finalize_stmt(&s->stmt_delete_edges_by_project);
    finalize_stmt(&s->stmt_delete_edges_by_type);

    finalize_stmt(&s->stmt_upsert_project);
    finalize_stmt(&s->stmt_get_project);
    finalize_stmt(&s->stmt_list_projects);
    finalize_stmt(&s->stmt_delete_project);

    finalize_stmt(&s->stmt_upsert_file_hash);
    finalize_stmt(&s->stmt_get_file_hashes);
    finalize_stmt(&s->stmt_delete_file_hash);
    finalize_stmt(&s->stmt_delete_file_hashes);

    /* Use sqlite3_close_v2 — auto-deallocates when last statement finalizes.
     * Prevents ASan false-positive leaks from sqlite3 internal state. */
    sqlite3_close_v2(s->db);
    safe_str_free(&s->db_path);
    free(s);
}

sqlite3 *cbm_store_get_db(cbm_store_t *s) {
    return s ? s->db : NULL;
}

int cbm_store_exec(cbm_store_t *s, const char *sql) {
    return exec_sql(s, sql);
}

const char *cbm_store_error(cbm_store_t *s) {
    return s ? s->errbuf : "null store";
}

int cbm_store_error_code(cbm_store_t *s) {
    return s && s->db ? sqlite3_extended_errcode(s->db) : SQLITE_MISUSE;
}

/* ── Transaction ────────────────────────────────────────────────── */

int cbm_store_begin(cbm_store_t *s) {
    return exec_sql(s, "BEGIN IMMEDIATE;");
}

int cbm_store_commit(cbm_store_t *s) {
    return exec_sql(s, "COMMIT;");
}

int cbm_store_rollback(cbm_store_t *s) {
    return exec_sql(s, "ROLLBACK;");
}

/* ── Bulk write ─────────────────────────────────────────────────── */

int cbm_store_begin_bulk(cbm_store_t *s) {
    /* Stay in WAL mode throughout. Switching to MEMORY journal mode would
     * make the database unrecoverable if the process crashes mid-write,
     * because the in-memory rollback journal is lost on crash.
     * WAL mode is crash-safe: uncommitted WAL entries are simply discarded
     * on the next open. Performance is preserved via synchronous=OFF and a
     * larger cache, which are safe with WAL. */
    int rc = exec_sql(s, "PRAGMA synchronous = OFF;");
    if (rc != CBM_STORE_OK) {
        return rc;
    }
    return exec_sql(s, "PRAGMA cache_size = -65536;"); /* CBM_SZ_64 MB */
}

int cbm_store_end_bulk(cbm_store_t *s) {
    int rc = exec_sql(s, "PRAGMA synchronous = NORMAL;");
    if (rc != CBM_STORE_OK) {
        return rc;
    }
    return exec_sql(s, "PRAGMA cache_size = -2000;"); /* default ~2 MB */
}

int cbm_store_drop_indexes(cbm_store_t *s) {
    return exec_sql(s, "DROP INDEX IF EXISTS idx_nodes_label;"
                       "DROP INDEX IF EXISTS idx_nodes_name;"
                       "DROP INDEX IF EXISTS idx_nodes_file;"
                       "DROP INDEX IF EXISTS idx_edges_source;"
                       "DROP INDEX IF EXISTS idx_edges_target;"
                       "DROP INDEX IF EXISTS idx_edges_type;"
                       "DROP INDEX IF EXISTS idx_edges_target_type;"
                       "DROP INDEX IF EXISTS idx_edges_source_type;");
}

int cbm_store_create_indexes(cbm_store_t *s) {
    return create_user_indexes(s);
}

/* ── Checkpoint ─────────────────────────────────────────────────── */

int cbm_store_checkpoint(cbm_store_t *s) {
    if (!s) {
        return CBM_STORE_ERR;
    }
    /* Finalization requires the committed WAL to be fully materialized and
     * removed. TRUNCATE makes that claim observable on disk. Any active reader
     * that prevents completion is a hard error, never a successful partial
     * checkpoint. */
    int log_frames = -1;
    int checkpointed_frames = -1;
    int rc = sqlite3_wal_checkpoint_v2(s->db, "main", SQLITE_CHECKPOINT_TRUNCATE, &log_frames,
                                       &checkpointed_frames);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "checkpoint");
        char sqlite_code[ST_BUF_64];
        snprintf(sqlite_code, sizeof(sqlite_code), "%d", sqlite3_extended_errcode(s->db));
        cbm_log_error("store.checkpoint", "code", "CBM_STORE_CHECKPOINT_FAILED", "sqlite_error",
                      sqlite_code, "message", s->errbuf, "remediation",
                      "release active readers/checkpoint owners, repair the reported SQLite fault, "
                      "and retry");
        return CBM_STORE_ERR;
    }
    if (log_frames != 0 || checkpointed_frames != 0) {
        snprintf(s->errbuf, sizeof(s->errbuf),
                 "checkpoint incomplete: wal_frames=%d checkpointed_frames=%d", log_frames,
                 checkpointed_frames);
        cbm_log_error("store.checkpoint", "code", "CBM_STORE_CHECKPOINT_INCOMPLETE", "message",
                      s->errbuf, "remediation",
                      "release the reader or checkpoint owner named by SQLite and retry");
        return CBM_STORE_ERR;
    }
    if (exec_sql(s, "PRAGMA optimize;") != CBM_STORE_OK) {
        char sqlite_code[ST_BUF_64];
        snprintf(sqlite_code, sizeof(sqlite_code), "%d", sqlite3_extended_errcode(s->db));
        cbm_log_error("store.checkpoint", "code", "CBM_STORE_OPTIMIZE_FAILED", "sqlite_error",
                      sqlite_code, "message", s->errbuf, "remediation",
                      "repair the reported SQLite fault and retry finalization");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── Dump ───────────────────────────────────────────────────────── */

/* Dump entire in-memory database to a file via sqlite3_backup.
 * Writes to a temp file first, then atomically renames for crash safety.
 * sqlite3_backup_step(-1) copies ALL B-tree pages in one call —
 * the file on disk is an exact replica of the in-memory page layout. */
int cbm_store_dump_to_file(cbm_store_t *s, const char *dest_path) {
    if (!s || !dest_path) {
        return CBM_STORE_ERR;
    }

    /* Ensure parent directory exists */
    char dir[CBM_SZ_1K];
    snprintf(dir, sizeof(dir), "%s", dest_path);
    char *sl = strrchr(dir, '/');
    if (sl) {
        *sl = '\0';
        (void)cbm_mkdir(dir);
    }

    /* Write to temp file for atomic swap */
    char tmp_path[CBM_SZ_1K];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", dest_path);
    (void)cbm_unlink(tmp_path);

    sqlite3 *dest_db = NULL;
    int rc = sqlite3_open(tmp_path, &dest_db);
    if (rc != SQLITE_OK) {
        store_set_error(s, "dump: cannot open temp file");
        return CBM_STORE_ERR;
    }

    sqlite3_backup *bk = sqlite3_backup_init(dest_db, "main", s->db, "main");
    if (!bk) {
        store_set_error(s, "dump: backup init failed");
        sqlite3_close(dest_db);
        (void)cbm_unlink(tmp_path);
        return CBM_STORE_ERR;
    }

    rc = sqlite3_backup_step(bk, CBM_NOT_FOUND); /* copy ALL pages in one shot */
    sqlite3_backup_finish(bk);

    if (rc != SQLITE_DONE) {
        store_set_error(s, "dump: backup step failed");
        sqlite3_close(dest_db);
        (void)cbm_unlink(tmp_path);
        return CBM_STORE_ERR;
    }

    /* Enable WAL on the dumped file so readers can connect concurrently */
    sqlite3_exec(dest_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
    sqlite3_close(dest_db);

    /* Atomic rename: old WAL/SHM become stale and get recreated by
     * the next reader's configure_pragmas call. */
    if (cbm_rename_replace(tmp_path, dest_path) != 0) {
        store_set_error(s, "dump: rename failed");
        (void)cbm_unlink(tmp_path);
        return CBM_STORE_ERR;
    }

    return CBM_STORE_OK;
}

/* ── Project CRUD ───────────────────────────────────────────────── */

int cbm_store_upsert_project(cbm_store_t *s, const char *name, const char *root_path) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_upsert_project,
                       "INSERT INTO projects (name, indexed_at, root_path) VALUES (?1, ?2, ?3) "
                       "ON CONFLICT(name) DO UPDATE SET indexed_at=?2, root_path=?3;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    char ts[CBM_SZ_64];
    iso_now(ts, sizeof(ts));

    /* #503: name and root_path are caller-supplied text; sanitize to valid UTF-8.
     * `indexed_at` (ts) is machine-generated ISO-8601, always ASCII. */
    bind_text_utf8(stmt, SKIP_ONE, name);
    bind_text(stmt, ST_COL_2, ts);
    bind_text_utf8(stmt, ST_COL_3, root_path);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_set_error_sqlite(s, "upsert_project");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_get_project(cbm_store_t *s, const char *name, cbm_project_t *out) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_get_project,
                       "SELECT name, indexed_at, root_path FROM projects WHERE name = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, name);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out->name = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        out->indexed_at = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
        out->root_path = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
        return CBM_STORE_OK;
    }
    return CBM_STORE_NOT_FOUND;
}

int cbm_store_list_projects(cbm_store_t *s, cbm_project_t **out, int *count) {
    if (!s || !out || !count) {
        return CBM_STORE_ERR;
    }
    *out = NULL;
    *count = 0;
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_list_projects,
                       "SELECT name, indexed_at, root_path FROM projects ORDER BY name;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    /* Collect into dynamic array */
    int cap = 0;
    int n = 0;
    cbm_project_t *arr = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr), "list_projects") !=
            CBM_STORE_OK) {
            cbm_store_free_projects(arr, n);
            return CBM_STORE_ERR;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].name = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        arr[n].indexed_at = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
        arr[n].root_path = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
        if (!arr[n].name || !arr[n].indexed_at || !arr[n].root_path) {
            cbm_project_free_fields(&arr[n]);
            cbm_store_free_projects(arr, n);
            store_set_error(s, "list_projects row allocation failed");
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_projects(arr, n);
        store_set_error_sqlite(s, "list_projects step");
        return CBM_STORE_ERR;
    }

    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

int cbm_store_delete_project(cbm_store_t *s, const char *name) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_delete_project, "DELETE FROM projects WHERE name = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, name);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_project");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── Node CRUD ──────────────────────────────────────────────────── */

int64_t cbm_store_upsert_node(cbm_store_t *s, const cbm_node_t *n) {
    bool source_valid =
        n &&
        ((!n->source_present && !n->source_bytes && n->source_len == 0 &&
          (!n->source_sha256 || !n->source_sha256[0]) && n->start_byte == 0 && n->end_byte == 0) ||
         (n->source_present && (n->source_bytes || n->source_len == 0) &&
          is_canonical_atom_id(n->source_sha256) && n->end_byte >= n->start_byte &&
          n->start_byte <= INT64_MAX && n->end_byte <= INT64_MAX &&
          n->end_byte - n->start_byte == n->source_len));
    if (!s || !n || !is_canonical_atom_id(n->atom_id) || !source_valid) {
        cbm_log_error("store.node_atom_id_refused", "code", "CBM_NODE_ATOM_ID_REQUIRED", "message",
                      "node write lacks a canonical atom or internally consistent exact source",
                      "remediation",
                      "re-extract the source with the stable atom schema; never derive identity at "
                      "the persistence boundary");
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(
        s, &s->stmt_upsert_node,
        "INSERT INTO nodes (project, label, name, qualified_name, file_path, "
        "start_line, end_line, properties, atom_id, source_present, source_bytes, "
        "source_sha256, start_byte, end_byte) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) "
        "ON CONFLICT(project, atom_id) DO UPDATE SET "
        "properties=?8 WHERE label=?2 AND name=?3 AND qualified_name=?4 AND "
        "file_path=?5 AND start_line=?6 AND end_line=?7 AND source_present=?10 AND "
        "source_bytes IS ?11 AND source_sha256=?12 AND start_byte=?13 AND end_byte=?14 "
        "RETURNING id;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    /* #503: name/qualified_name/file_path/label/project are raw parser buffers
     * that bypass cbm_json_escape, so sanitize them to valid UTF-8 at the insert
     * boundary. `properties` is already UTF-8-safe via cbm_json_escape (#493). */
    bind_text_utf8(stmt, SKIP_ONE, safe_str(n->project));
    bind_text_utf8(stmt, ST_COL_2, safe_str(n->label));
    bind_text_utf8(stmt, ST_COL_3, safe_str(n->name));
    bind_text_utf8(stmt, ST_COL_4, safe_str(n->qualified_name));
    bind_text_utf8(stmt, ST_COL_5, safe_str(n->file_path));
    sqlite3_bind_int(stmt, ST_COL_6, n->start_line);
    sqlite3_bind_int(stmt, ST_COL_7, n->end_line);
    bind_text(stmt, ST_COL_8, safe_props(n->properties_json));
    bind_text(stmt, ST_COL_9, n->atom_id);
    sqlite3_bind_int(stmt, 10, n->source_present ? 1 : 0);
    if (n->source_present) {
        sqlite3_bind_blob64(stmt, 11, n->source_bytes, (sqlite3_uint64)n->source_len,
                            SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 11);
    }
    bind_text(stmt, 12, n->source_sha256 ? n->source_sha256 : "");
    sqlite3_bind_int64(stmt, 13, (sqlite3_int64)n->start_byte);
    sqlite3_bind_int64(stmt, 14, (sqlite3_int64)n->end_byte);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        sqlite3_reset(stmt); /* unblock COMMIT — RETURNING leaves stmt active */
        return id;
    }
    sqlite3_reset(stmt);
    store_set_error_sqlite(s, "upsert_node");
    return CBM_STORE_ERR;
}

static int scan_node_error(cbm_store_t *s, cbm_node_t *n, const char *message) {
    cbm_node_free_fields(n);
    store_set_error(s, message);
    cbm_log_error("store.node_read", "code", "CBM_STORE_NODE_SOURCE_INVALID", "message", message,
                  "remediation",
                  "repair or recreate the CBM SQLite from the authoritative codebase");
    return CBM_STORE_ERR;
}

/* Scan a node from current row of stmt. Heap-allocates strings and exact source bytes. */
static int scan_node(cbm_store_t *s, sqlite3_stmt *stmt, cbm_node_t *n) {
    memset(n, 0, sizeof(*n));
    if (sqlite3_column_count(stmt) < ST_NODE_COL_COUNT) {
        return scan_node_error(s, n, "node query omitted exact-source identity columns");
    }
    int source_present = sqlite3_column_int(stmt, ST_NODE_COL_SOURCE_PRESENT);
    int source_type = sqlite3_column_type(stmt, ST_NODE_COL_SOURCE_BYTES);
    int source_len = sqlite3_column_bytes(stmt, ST_NODE_COL_SOURCE_BYTES);
    int64_t start_byte = sqlite3_column_int64(stmt, ST_NODE_COL_START_BYTE);
    int64_t end_byte = sqlite3_column_int64(stmt, ST_NODE_COL_END_BYTE);
    const char *source_sha256 = (const char *)sqlite3_column_text(stmt, ST_NODE_COL_SOURCE_SHA256);
    if (source_present != 0 && source_present != 1) {
        return scan_node_error(s, n, "node source_present is not exactly zero or one");
    }
    if (source_present == 1) {
        if (source_type != SQLITE_BLOB || !source_sha256 || strlen(source_sha256) != 64 ||
            start_byte < 0 || end_byte < start_byte || end_byte - start_byte != source_len) {
            return scan_node_error(s, n,
                                   "node exact source bytes, hash, and byte span are inconsistent");
        }
    } else if (source_type != SQLITE_NULL || (source_sha256 && source_sha256[0] != '\0') ||
               start_byte != 0 || end_byte != 0) {
        return scan_node_error(s, n, "source-absent node carries exact-source metadata");
    }
    n->id = sqlite3_column_int64(stmt, 0);
    n->project = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
    n->label = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
    n->name = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_3));
    n->qualified_name = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_4));
    n->file_path = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_5));
    n->start_line = sqlite3_column_int(stmt, CBM_SZ_6);
    n->end_line = sqlite3_column_int(stmt, CBM_SZ_7);
    n->properties_json = heap_strdup((const char *)sqlite3_column_text(stmt, ST_COL_8));
    n->atom_id = heap_strdup((const char *)sqlite3_column_text(stmt, ST_NODE_COL_ATOM_ID));
    n->source_present = source_present == 1;
    if (n->source_present) {
        const uint8_t *source =
            (const uint8_t *)sqlite3_column_blob(stmt, ST_NODE_COL_SOURCE_BYTES);
        if (source_len > 0) {
            uint8_t *copy = malloc((size_t)source_len);
            if (!copy) {
                return scan_node_error(s, n, "node exact-source allocation failed");
            }
            memcpy(copy, source, (size_t)source_len);
            n->source_bytes = copy;
        }
        n->source_len = (size_t)source_len;
    }
    n->source_sha256 = heap_strdup(source_sha256);
    n->start_byte = (uint64_t)start_byte;
    n->end_byte = (uint64_t)end_byte;
    if (!n->project || !n->label || !n->name || !n->qualified_name || !n->file_path ||
        !n->properties_json || !n->atom_id || !n->source_sha256) {
        return scan_node_error(s, n, "node row string allocation failed");
    }
    return CBM_STORE_OK;
}

int cbm_store_find_node_by_id(cbm_store_t *s, int64_t id, cbm_node_t *out) {
    sqlite3_stmt *stmt = prepare_cached(
        s, &s->stmt_find_node_by_id, "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes WHERE id = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    sqlite3_bind_int64(stmt, SKIP_ONE, id);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        return scan_node(s, stmt, out);
    }
    return CBM_STORE_NOT_FOUND;
}

int cbm_store_find_node_by_atom_id(cbm_store_t *s, const char *project, const char *atom_id,
                                   cbm_node_t *out) {
    if (!s || !s->db || !project || !atom_id || !is_canonical_atom_id(atom_id)) {
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_find_node_by_atom_id,
                                        "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                                        "WHERE project = ?1 AND atom_id = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, atom_id);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        return scan_node(s, stmt, out);
    }
    return rc == SQLITE_DONE ? CBM_STORE_NOT_FOUND : CBM_STORE_ERR;
}

int cbm_store_find_node_by_qn(cbm_store_t *s, const char *project, const char *qn,
                              cbm_node_t *out) {
    if (!s || !s->db) {
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_find_node_by_qn,
                                        "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                                        "WHERE project = ?1 AND qualified_name = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, qn);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (scan_node(s, stmt, out) != CBM_STORE_OK) {
            return CBM_STORE_ERR;
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            cbm_node_free_fields(out);
            cbm_log_error("store.node_qn_ambiguous", "code", "CBM_NODE_QN_AMBIGUOUS",
                          "qualified_name", qn, "message",
                          "qualified name resolves to multiple stable source atoms", "remediation",
                          "resolve by atom_id, source location, or exact signature");
            return CBM_STORE_ERR;
        }
        return CBM_STORE_OK;
    }
    return CBM_STORE_NOT_FOUND;
}

int cbm_store_find_node_by_qn_any(cbm_store_t *s, const char *qn, cbm_node_t *out) {
    if (!s || !s->db) {
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_find_node_by_qn_any,
                                        "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                                        "WHERE qualified_name = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, qn);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (scan_node(s, stmt, out) != CBM_STORE_OK) {
            return CBM_STORE_ERR;
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            cbm_node_free_fields(out);
            cbm_log_error(
                "store.node_qn_ambiguous", "code", "CBM_NODE_QN_AMBIGUOUS", "qualified_name", qn,
                "message", "qualified name resolves to multiple stable source atoms", "remediation",
                "supply a project and resolve by atom_id, source location, or exact signature");
            return CBM_STORE_ERR;
        }
        return CBM_STORE_OK;
    }
    return CBM_STORE_NOT_FOUND;
}

int cbm_store_find_nodes_by_name_any(cbm_store_t *s, const char *name, cbm_node_t **out,
                                     int *count) {
    if (!s || !s->db) {
        *out = NULL;
        *count = 0;
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_find_nodes_by_name_any,
                                        "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                                        "WHERE name = ?1;");
    if (!stmt) {
        *out = NULL;
        *count = 0;
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, name);

    int cap = 0;
    int n = 0;
    cbm_node_t *arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "find_nodes_by_name_any") != CBM_STORE_OK) {
            cbm_store_free_nodes(arr, n);
            *out = NULL;
            *count = 0;
            return CBM_STORE_ERR;
        }
        if (scan_node(s, stmt, &arr[n]) != CBM_STORE_OK) {
            cbm_store_free_nodes(arr, n);
            *out = NULL;
            *count = 0;
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_nodes(arr, n);
        *out = NULL;
        *count = 0;
        store_set_error_sqlite(s, "find_nodes_by_name_any step");
        return CBM_STORE_ERR;
    }
    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

int cbm_store_find_node_ids_by_qns(cbm_store_t *s, const char *project, const char **qns,
                                   int qn_count, int64_t *out_ids) {
    if (!s || !project || !qns || !out_ids || qn_count <= 0) {
        return 0;
    }

    /* Zero out results */
    memset(out_ids, 0, (size_t)qn_count * sizeof(int64_t));

    int found = 0;
    cbm_node_t node = {0};
    for (int i = 0; i < qn_count; i++) {
        if (!qns[i]) {
            continue;
        }
        int rc = cbm_store_find_node_by_qn(s, project, qns[i], &node);
        if (rc == CBM_STORE_OK) {
            out_ids[i] = node.id;
            found++;
            cbm_node_free_fields(&node);
            memset(&node, 0, sizeof(node));
        }
    }
    return found;
}

/* Generic: find multiple nodes by a single-column filter. */
static int find_nodes_generic(cbm_store_t *s, sqlite3_stmt **slot, const char *sql,
                              const char *project, const char *val, cbm_node_t **out, int *count) {
    if (!out || !count) {
        return CBM_STORE_ERR;
    }
    *out = NULL;
    *count = 0;
    if (!s || !s->db || !slot || !sql || !project || !val) {
        if (s) {
            store_set_error(s, "find_nodes_generic received an invalid argument");
        }
        cbm_log_error("store.find_nodes", "code", "CBM_STORE_INVALID_ARGUMENT", "message",
                      "find_nodes_generic received a null store, query, filter, or output",
                      "remediation",
                      "supply a live store and non-null project/filter/output values");
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, slot, sql);
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, val);

    int cap = 0;
    int n = 0;
    cbm_node_t *arr = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "find_nodes_generic") != CBM_STORE_OK) {
            cbm_store_free_nodes(arr, n);
            return CBM_STORE_ERR;
        }
        if (scan_node(s, stmt, &arr[n]) != CBM_STORE_OK) {
            cbm_store_free_nodes(arr, n);
            *out = NULL;
            *count = 0;
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_nodes(arr, n);
        store_set_error_sqlite(s, "find_nodes_generic step");
        return CBM_STORE_ERR;
    }

    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

int cbm_store_find_nodes_by_name(cbm_store_t *s, const char *project, const char *name,
                                 cbm_node_t **out, int *count) {
    return find_nodes_generic(s, &s->stmt_find_nodes_by_name,
                              "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                              "WHERE project = ?1 AND name = ?2;",
                              project, name, out, count);
}

int cbm_store_find_nodes_by_label(cbm_store_t *s, const char *project, const char *label,
                                  cbm_node_t **out, int *count) {
    return find_nodes_generic(s, &s->stmt_find_nodes_by_label,
                              "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                              "WHERE project = ?1 AND label = ?2;",
                              project, label, out, count);
}

int cbm_store_find_nodes_by_file(cbm_store_t *s, const char *project, const char *file_path,
                                 cbm_node_t **out, int *count) {
    return find_nodes_generic(s, &s->stmt_find_nodes_by_file,
                              "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                              "WHERE project = ?1 AND file_path = ?2;",
                              project, file_path, out, count);
}

int cbm_store_count_nodes(cbm_store_t *s, const char *project) {
    if (!s || !s->db) {
        return 0;
    }
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_count_nodes, "SELECT COUNT(*) FROM nodes WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return sqlite3_column_int(stmt, 0);
    }
    return 0;
}

int cbm_store_delete_nodes_by_project(cbm_store_t *s, const char *project) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_nodes_by_project,
                                        "DELETE FROM nodes WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_nodes_by_project");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_delete_nodes_by_file(cbm_store_t *s, const char *project, const char *file_path) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_nodes_by_file,
                                        "DELETE FROM nodes WHERE project = ?1 AND file_path = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, file_path);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_nodes_by_file");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_delete_nodes_by_label(cbm_store_t *s, const char *project, const char *label) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_nodes_by_label,
                                        "DELETE FROM nodes WHERE project = ?1 AND label = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, label);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_nodes_by_label");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── Node batch ─────────────────────────────────────────────────── */

int cbm_store_upsert_node_batch(cbm_store_t *s, const cbm_node_t *nodes, int count,
                                int64_t *out_ids) {
    if (count == 0) {
        return CBM_STORE_OK;
    }

    exec_sql(s, "BEGIN IMMEDIATE;");
    for (int i = 0; i < count; i++) {
        int64_t id = cbm_store_upsert_node(s, &nodes[i]);
        if (id == CBM_STORE_ERR) {
            exec_sql(s, "ROLLBACK;");
            return CBM_STORE_ERR;
        }
        if (out_ids) {
            out_ids[i] = id;
        }
    }
    exec_sql(s, "COMMIT;");
    return CBM_STORE_OK;
}

/* ── Edge CRUD ──────────────────────────────────────────────────── */

int64_t cbm_store_insert_edge(cbm_store_t *s, const cbm_edge_t *e) {
    /* Conflict target includes local_name_gen (#768) so IMPORTS edges with
     * different local_name coexist while re-inserting the same import still
     * upserts. Must match the table's UNIQUE constraint in init_schema. */
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_insert_edge,
                       "INSERT INTO edges (project, source_id, target_id, type, properties) "
                       "VALUES (?1, ?2, ?3, ?4, ?5) "
                       "ON CONFLICT(source_id, target_id, type, local_name_gen) DO UPDATE SET "
                       "properties = json_patch(properties, ?5) "
                       "RETURNING id;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    /* #503: project and type are raw parser buffers — sanitize to valid UTF-8.
     * `properties` is already UTF-8-safe via cbm_json_escape (#493). */
    bind_text_utf8(stmt, SKIP_ONE, safe_str(e->project));
    sqlite3_bind_int64(stmt, PAIR_LEN, e->source_id);
    sqlite3_bind_int64(stmt, CBM_SZ_3, e->target_id);
    bind_text_utf8(stmt, ST_COL_4, safe_str(e->type));
    bind_text(stmt, ST_COL_5, safe_props(e->properties_json));

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        sqlite3_reset(stmt); /* unblock COMMIT — RETURNING leaves stmt active */
        return id;
    }
    sqlite3_reset(stmt);
    store_set_error_sqlite(s, "insert_edge");
    return CBM_STORE_ERR;
}

/* Scan an edge from current row of stmt. */
static int scan_edge(cbm_store_t *s, sqlite3_stmt *stmt, cbm_edge_t *e) {
    memset(e, 0, sizeof(*e));
    e->id = sqlite3_column_int64(stmt, 0);
    e->project = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
    e->source_id = sqlite3_column_int64(stmt, CBM_SZ_2);
    e->target_id = sqlite3_column_int64(stmt, CBM_SZ_3);
    e->type = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_4));
    e->properties_json = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_5));
    if (!e->project || !e->type || !e->properties_json) {
        cbm_store_free_edges(e, 1);
        store_set_error(s, "edge row string allocation failed");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* Generic: find multiple edges by a filter. */
static int find_edges_generic(cbm_store_t *s, sqlite3_stmt **slot, const char *sql,
                              void (*bind_fn)(sqlite3_stmt *, const void *), const void *bind_data,
                              cbm_edge_t **out, int *count) {
    if (!s || !s->db) {
        *out = NULL;
        *count = 0;
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = prepare_cached(s, slot, sql);
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_fn(stmt, bind_data);

    int cap = 0;
    int n = 0;
    cbm_edge_t *arr = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "find_edges_generic") != CBM_STORE_OK) {
            cbm_store_free_edges(arr, n);
            return CBM_STORE_ERR;
        }
        if (scan_edge(s, stmt, &arr[n]) != CBM_STORE_OK) {
            cbm_store_free_edges(arr, n);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_edges(arr, n);
        store_set_error_sqlite(s, "find_edges_generic step");
        return CBM_STORE_ERR;
    }

    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

/* Bind helpers for edge queries */
typedef struct {
    int64_t id;
} bind_id_t;
typedef struct {
    int64_t id;
    const char *type;
} bind_id_type_t;
typedef struct {
    const char *project;
    const char *type;
} bind_proj_type_t;

static void bind_source_id(sqlite3_stmt *stmt, const void *data) {
    const bind_id_t *b = data;
    sqlite3_bind_int64(stmt, SKIP_ONE, b->id);
}

static void bind_id_and_type(sqlite3_stmt *stmt, const void *data) {
    const bind_id_type_t *b = data;
    sqlite3_bind_int64(stmt, SKIP_ONE, b->id);
    bind_text(stmt, ST_COL_2, b->type);
}

static void bind_proj_and_type(sqlite3_stmt *stmt, const void *data) {
    const bind_proj_type_t *b = data;
    bind_text(stmt, SKIP_ONE, b->project);
    bind_text(stmt, ST_COL_2, b->type);
}

int cbm_store_find_edges_by_source(cbm_store_t *s, int64_t source_id, cbm_edge_t **out,
                                   int *count) {
    bind_id_t b = {source_id};
    return find_edges_generic(s, &s->stmt_find_edges_by_source,
                              "SELECT id, project, source_id, target_id, type, properties "
                              "FROM edges WHERE source_id = ?1;",
                              bind_source_id, &b, out, count);
}

int cbm_store_find_edges_by_target(cbm_store_t *s, int64_t target_id, cbm_edge_t **out,
                                   int *count) {
    bind_id_t b = {target_id};
    return find_edges_generic(s, &s->stmt_find_edges_by_target,
                              "SELECT id, project, source_id, target_id, type, properties "
                              "FROM edges WHERE target_id = ?1;",
                              bind_source_id, &b, out, count);
}

int cbm_store_find_edges_by_source_type(cbm_store_t *s, int64_t source_id, const char *type,
                                        cbm_edge_t **out, int *count) {
    bind_id_type_t b = {source_id, type};
    return find_edges_generic(s, &s->stmt_find_edges_by_source_type,
                              "SELECT id, project, source_id, target_id, type, properties "
                              "FROM edges WHERE source_id = ?1 AND type = ?2;",
                              bind_id_and_type, &b, out, count);
}

int cbm_store_find_edges_by_target_type(cbm_store_t *s, int64_t target_id, const char *type,
                                        cbm_edge_t **out, int *count) {
    bind_id_type_t b = {target_id, type};
    return find_edges_generic(s, &s->stmt_find_edges_by_target_type,
                              "SELECT id, project, source_id, target_id, type, properties "
                              "FROM edges WHERE target_id = ?1 AND type = ?2;",
                              bind_id_and_type, &b, out, count);
}

int cbm_store_find_edges_by_type(cbm_store_t *s, const char *project, const char *type,
                                 cbm_edge_t **out, int *count) {
    bind_proj_type_t b = {project, type};
    return find_edges_generic(s, &s->stmt_find_edges_by_type,
                              "SELECT id, project, source_id, target_id, type, properties "
                              "FROM edges WHERE project = ?1 AND type = ?2;",
                              bind_proj_and_type, &b, out, count);
}

int cbm_store_count_edges(cbm_store_t *s, const char *project) {
    if (!s || !s->db) {
        return 0;
    }
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_count_edges, "SELECT COUNT(*) FROM edges WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return sqlite3_column_int(stmt, 0);
    }
    return 0;
}

int cbm_store_count_edges_by_type(cbm_store_t *s, const char *project, const char *type) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_count_edges_by_type,
                       "SELECT COUNT(*) FROM edges WHERE project = ?1 AND type = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, type);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return sqlite3_column_int(stmt, 0);
    }
    return 0;
}

int cbm_store_delete_edges_by_project(cbm_store_t *s, const char *project) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_edges_by_project,
                                        "DELETE FROM edges WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_edges_by_project");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_delete_edges_by_type(cbm_store_t *s, const char *project, const char *type) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_edges_by_type,
                                        "DELETE FROM edges WHERE project = ?1 AND type = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, type);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_edges_by_type");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── Edge batch ─────────────────────────────────────────────────── */

int cbm_store_insert_edge_batch(cbm_store_t *s, const cbm_edge_t *edges, int count) {
    if (count == 0) {
        return CBM_STORE_OK;
    }

    exec_sql(s, "BEGIN IMMEDIATE;");
    for (int i = 0; i < count; i++) {
        int64_t id = cbm_store_insert_edge(s, &edges[i]);
        if (id == CBM_STORE_ERR) {
            exec_sql(s, "ROLLBACK;");
            return CBM_STORE_ERR;
        }
    }
    exec_sql(s, "COMMIT;");
    return CBM_STORE_OK;
}

/* ── File hash CRUD ─────────────────────────────────────────────── */

int cbm_store_upsert_file_hash(cbm_store_t *s, const char *project, const char *rel_path,
                               const char *sha256, int64_t mtime_ns, int64_t size) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_upsert_file_hash,
                       "INSERT INTO file_hashes (project, rel_path, sha256, mtime_ns, size) "
                       "VALUES (?1, ?2, ?3, ?4, ?5) "
                       "ON CONFLICT(project, rel_path) DO UPDATE SET "
                       "sha256=?3, mtime_ns=?4, size=?5;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    /* #503: project/rel_path/sha256 are caller-supplied text (rel_path is a raw
     * filesystem path); sanitize to valid UTF-8 at the insert boundary. */
    bind_text_utf8(stmt, SKIP_ONE, project);
    bind_text_utf8(stmt, ST_COL_2, rel_path);
    bind_text_utf8(stmt, ST_COL_3, sha256);
    sqlite3_bind_int64(stmt, CBM_SZ_4, mtime_ns);
    sqlite3_bind_int64(stmt, CBM_SZ_5, size);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "upsert_file_hash");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_get_file_hashes(cbm_store_t *s, const char *project, cbm_file_hash_t **out,
                              int *count) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_get_file_hashes,
                                        "SELECT project, rel_path, sha256, mtime_ns, size "
                                        "FROM file_hashes WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);

    int cap = 0;
    int n = 0;
    cbm_file_hash_t *arr = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr), "get_file_hashes") !=
            CBM_STORE_OK) {
            cbm_store_free_file_hashes(arr, n);
            return CBM_STORE_ERR;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].project = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        arr[n].rel_path = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
        arr[n].sha256 = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
        arr[n].mtime_ns = sqlite3_column_int64(stmt, CBM_SZ_3);
        arr[n].size = sqlite3_column_int64(stmt, CBM_SZ_4);
        if (!arr[n].project || !arr[n].rel_path || !arr[n].sha256) {
            cbm_store_free_file_hashes(arr, n + 1);
            store_set_error(s, "get_file_hashes row allocation failed");
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_file_hashes(arr, n);
        store_set_error_sqlite(s, "get_file_hashes step");
        return CBM_STORE_ERR;
    }

    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

int cbm_store_delete_file_hash(cbm_store_t *s, const char *project, const char *rel_path) {
    sqlite3_stmt *stmt =
        prepare_cached(s, &s->stmt_delete_file_hash,
                       "DELETE FROM file_hashes WHERE project = ?1 AND rel_path = ?2;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, rel_path);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_file_hash");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_store_delete_file_hashes(cbm_store_t *s, const char *project) {
    sqlite3_stmt *stmt = prepare_cached(s, &s->stmt_delete_file_hashes,
                                        "DELETE FROM file_hashes WHERE project = ?1;");
    if (!stmt) {
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        store_set_error_sqlite(s, "delete_file_hashes");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── FindNodesByFileOverlap ─────────────────────────────────────── */

int cbm_store_find_nodes_by_file_overlap(cbm_store_t *s, const char *project, const char *file_path,
                                         int start_line, int end_line, cbm_node_t **out,
                                         int *count) {
    *out = NULL;
    *count = 0;
    const char *sql = "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                      "WHERE project = ?1 AND file_path = ?2 "
                      "AND label NOT IN ('Module', 'Package', 'File', 'Folder') "
                      "AND start_line <= ?4 AND end_line >= ?3 "
                      "ORDER BY start_line";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "overlap prepare");
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, file_path);
    sqlite3_bind_int(stmt, ST_COL_3, start_line);
    sqlite3_bind_int(stmt, ST_COL_4, end_line);

    int cap = 0;
    int n = 0;
    cbm_node_t *nodes = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&nodes, &cap, n + 1, sizeof(*nodes),
                                "find_nodes_by_file_overlap") != CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        if (scan_node(s, stmt, &nodes[n]) != CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_nodes(nodes, n);
        store_set_error_sqlite(s, "find_nodes_by_file_overlap step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = nodes;
    *count = n;
    return CBM_STORE_OK;
}

/* ── FindNodesByQNSuffix ───────────────────────────────────────── */

int cbm_store_find_nodes_by_qn_suffix(cbm_store_t *s, const char *project, const char *suffix,
                                      cbm_node_t **out, int *count) {
    *out = NULL;
    *count = 0;
    if (!s || !s->db) {
        return CBM_STORE_ERR;
    }
    /* Match QNs ending with ".suffix" or exactly equal to suffix */
    char like_pattern[CBM_SZ_512];
    snprintf(like_pattern, sizeof(like_pattern), "%%.%s", suffix);

    const char *sql_with_project =
        "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
        "WHERE project = ?1 AND (qualified_name LIKE ?2 OR qualified_name = ?3)";
    const char *sql_any = "SELECT " ST_NODE_SELECT_COLUMNS " FROM nodes "
                          "WHERE (qualified_name LIKE ?1 OR qualified_name = ?2)";

    sqlite3_stmt *stmt = NULL;
    int rc =
        sqlite3_prepare_v2(s->db, project ? sql_with_project : sql_any, CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "qn_suffix prepare");
        return CBM_STORE_ERR;
    }

    if (project) {
        bind_text(stmt, SKIP_ONE, project);
        bind_text(stmt, ST_COL_2, like_pattern);
        bind_text(stmt, ST_COL_3, suffix);
    } else {
        bind_text(stmt, SKIP_ONE, like_pattern);
        bind_text(stmt, ST_COL_2, suffix);
    }

    int cap = 0;
    int n = 0;
    cbm_node_t *nodes = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&nodes, &cap, n + 1, sizeof(*nodes),
                                "find_nodes_by_qn_suffix") != CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        if (scan_node(s, stmt, &nodes[n]) != CBM_STORE_OK) {
            cbm_store_free_nodes(nodes, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_nodes(nodes, n);
        store_set_error_sqlite(s, "find_nodes_by_qn_suffix step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = nodes;
    *count = n;
    return CBM_STORE_OK;
}

/* ── NodeDegree ────────────────────────────────────────────────── */

void cbm_store_node_degree(cbm_store_t *s, int64_t node_id, int *in_deg, int *out_deg) {
    if (!s) {
        if (in_deg)
            *in_deg = 0;
        if (out_deg)
            *out_deg = 0;
        return;
    }
    *in_deg = 0;
    *out_deg = 0;

    const char *in_sql = "SELECT COUNT(*) FROM edges WHERE target_id = ?1 AND type = 'CALLS'";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, in_sql, CBM_NOT_FOUND, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, SKIP_ONE, node_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *in_deg = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    const char *out_sql = "SELECT COUNT(*) FROM edges WHERE source_id = ?1 AND type = 'CALLS'";
    if (sqlite3_prepare_v2(s->db, out_sql, CBM_NOT_FOUND, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, SKIP_ONE, node_id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *out_deg = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
}

/* ── List distinct file paths ────────────────────────────────── */

int cbm_store_list_files(cbm_store_t *s, const char *project, char ***out, int *count) {
    *out = NULL;
    *count = 0;
    if (!s || !s->db || !project) {
        return CBM_STORE_ERR;
    }

    const char *sql = "SELECT DISTINCT file_path FROM nodes "
                      "WHERE project = ?1 AND file_path IS NOT NULL AND file_path != ''";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "list_files.prepare");
        return CBM_STORE_ERR;
    }
    sqlite3_bind_text(stmt, SKIP_ONE, project, CBM_NOT_FOUND, SQLITE_STATIC);

    int cap = CBM_SZ_64;
    int n = 0;
    char **files = malloc(cap * sizeof(char *));
    if (!files) {
        sqlite3_finalize(stmt);
        store_set_error(s, "list_files allocation failed");
        return CBM_STORE_ERR;
    }
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        if (!fp) {
            continue;
        }
        if (n >= cap) {
            cap *= ST_GROWTH;
            char **grown = realloc(files, cap * sizeof(char *));
            if (!grown) {
                for (int i = 0; i < n; i++) {
                    free(files[i]);
                }
                free(files);
                sqlite3_finalize(stmt);
                store_set_error(s, "list_files growth allocation failed");
                return CBM_STORE_ERR;
            }
            files = grown;
        }
        files[n] = heap_strdup(fp);
        if (!files[n]) {
            for (int i = 0; i < n; i++) {
                free(files[i]);
            }
            free(files);
            sqlite3_finalize(stmt);
            store_set_error(s, "list_files path allocation failed");
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            free(files[i]);
        }
        free(files);
        store_set_error_sqlite(s, "list_files.step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = files;
    *count = n;
    return CBM_STORE_OK;
}

/* ── Node neighbor names ──────────────────────────────────────── */

static void store_free_strings(char **values, int count) {
    for (int i = 0; i < count; i++) {
        free(values[i]);
    }
    free(values);
}

static int query_neighbor_names(cbm_store_t *s, const char *sql, int64_t node_id, int limit,
                                char ***out, int *out_count) {
    *out = NULL;
    *out_count = 0;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "neighbor_names prepare");
        return CBM_STORE_ERR;
    }
    sqlite3_bind_int64(stmt, SKIP_ONE, node_id);
    sqlite3_bind_int(stmt, ST_COL_2, limit);

    int cap = 0;
    char **names = NULL;
    int count = 0;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        if (!name) {
            continue;
        }
        if (store_array_reserve(s, (void **)&names, &cap, count + 1, sizeof(*names),
                                "neighbor_names") != CBM_STORE_OK) {
            store_free_strings(names, count);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        names[count] = heap_strdup(name);
        if (!names[count]) {
            store_free_strings(names, count);
            sqlite3_finalize(stmt);
            store_set_error(s, "neighbor_names row allocation failed");
            return CBM_STORE_ERR;
        }
        count++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings(names, count);
        store_set_error_sqlite(s, "neighbor_names step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = names;
    *out_count = count;
    return 0;
}

int cbm_store_node_neighbor_names(cbm_store_t *s, int64_t node_id, int limit, char ***out_callers,
                                  int *caller_count, char ***out_callees, int *callee_count) {
    if (!s) {
        return CBM_NOT_FOUND;
    }
    *out_callers = NULL;
    *caller_count = 0;
    *out_callees = NULL;
    *callee_count = 0;

    if (query_neighbor_names(
            s,
            "SELECT DISTINCT n.name FROM edges e JOIN nodes n ON e.source_id = n.id "
            "WHERE e.target_id = ?1 AND e.type IN ('CALLS','HTTP_CALLS','ASYNC_CALLS') "
            "ORDER BY n.name LIMIT ?2",
            node_id, limit, out_callers, caller_count) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }

    if (query_neighbor_names(
            s,
            "SELECT DISTINCT n.name FROM edges e JOIN nodes n ON e.target_id = n.id "
            "WHERE e.source_id = ?1 AND e.type IN ('CALLS','HTTP_CALLS','ASYNC_CALLS') "
            "ORDER BY n.name LIMIT ?2",
            node_id, limit, out_callees, callee_count) != CBM_STORE_OK) {
        store_free_strings(*out_callers, *caller_count);
        *out_callers = NULL;
        *caller_count = 0;
        return CBM_STORE_ERR;
    }

    return 0;
}

static int count_degrees_direction(cbm_store_t *s, const int64_t *node_ids, int id_count,
                                   const char *in_clause, bool has_type, const char *edge_type,
                                   bool inbound, int *out_counts) {
    char sql[ST_SQL_BUF];
    const char *id_col = inbound ? "target_id" : "source_id";
    if (has_type) {
        snprintf(sql, sizeof(sql),
                 "SELECT %s, COUNT(*) FROM edges "
                 "WHERE %s IN (%s) AND type = ? GROUP BY %s",
                 id_col, id_col, in_clause, id_col);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT %s, COUNT(*) FROM edges "
                 "WHERE %s IN (%s) GROUP BY %s",
                 id_col, id_col, in_clause, id_col);
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, inbound ? "batch inbound degree prepare"
                                          : "batch outbound degree prepare");
        return CBM_STORE_ERR;
    }

    for (int i = 0; i < id_count; i++) {
        if (sqlite3_bind_int64(stmt, i + SKIP_ONE, node_ids[i]) != SQLITE_OK) {
            store_set_error_sqlite(s, inbound ? "batch inbound degree bind node"
                                              : "batch outbound degree bind node");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
    }
    if (has_type && sqlite3_bind_text(stmt, id_count + SKIP_ONE, edge_type, SQLITE_AUTO_LEN,
                                      SQLITE_STATIC) != SQLITE_OK) {
        store_set_error_sqlite(s, inbound ? "batch inbound degree bind type"
                                          : "batch outbound degree bind type");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t nid = sqlite3_column_int64(stmt, 0);
        int cnt = sqlite3_column_int(stmt, SKIP_ONE);
        for (int i = 0; i < id_count; i++) {
            if (node_ids[i] == nid) {
                out_counts[i] = cnt;
                break;
            }
        }
    }
    if (step_rc != SQLITE_DONE) {
        store_set_error_sqlite(s, inbound ? "batch inbound degree step"
                                          : "batch outbound degree step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    return CBM_STORE_OK;
}

int cbm_store_batch_count_degrees(cbm_store_t *s, const int64_t *node_ids, int id_count,
                                  const char *edge_type, int *out_in, int *out_out) {
    if (!s || !node_ids || id_count <= 0 || !out_in || !out_out) {
        return CBM_STORE_ERR;
    }

    memset(out_in, 0, (size_t)id_count * sizeof(int));
    memset(out_out, 0, (size_t)id_count * sizeof(int));

    int sqlite_variable_limit = sqlite3_limit(s->db, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
    bool has_type = edge_type && edge_type[0] != '\0';
    if (id_count > sqlite_variable_limit - (has_type ? 1 : 0) ||
        (size_t)id_count > (SIZE_MAX - 1) / ST_COL_2) {
        store_set_error(s, "batch degree request exceeds the SQLite variable limit");
        return CBM_STORE_ERR;
    }

    /* Build an exact IN clause.  A fixed buffer can silently omit ids while
     * still binding and returning plausible partial counts. */
    size_t clause_size = (size_t)id_count * ST_COL_2;
    char *in_clause = malloc(clause_size);
    if (!in_clause) {
        store_set_error(s, "batch degree IN-clause allocation failed");
        return CBM_STORE_ERR;
    }
    size_t pos = 0;
    for (int i = 0; i < id_count; i++) {
        if (i > 0) {
            in_clause[pos++] = ',';
        }
        in_clause[pos++] = '?';
    }
    in_clause[pos] = '\0';

    int rc = count_degrees_direction(s, node_ids, id_count, in_clause, has_type, edge_type, true,
                                     out_in);
    if (rc != CBM_STORE_OK) {
        free(in_clause);
        return rc;
    }

    rc = count_degrees_direction(s, node_ids, id_count, in_clause, has_type, edge_type, false,
                                 out_out);
    free(in_clause);
    return rc;
}

/* ── UpsertFileHashBatch ───────────────────────────────────────── */

int cbm_store_upsert_file_hash_batch(cbm_store_t *s, const cbm_file_hash_t *hashes, int count) {
    if (count == 0) {
        return CBM_STORE_OK;
    }

    int rc = cbm_store_begin(s);
    if (rc != CBM_STORE_OK) {
        return rc;
    }

    for (int i = 0; i < count; i++) {
        rc = cbm_store_upsert_file_hash(s, hashes[i].project, hashes[i].rel_path, hashes[i].sha256,
                                        hashes[i].mtime_ns, hashes[i].size);
        if (rc != CBM_STORE_OK) {
            cbm_store_rollback(s);
            return rc;
        }
    }

    return cbm_store_commit(s);
}

/* ── FindEdgesByURLPath ────────────────────────────────────────── */

int cbm_store_find_edges_by_url_path(cbm_store_t *s, const char *project, const char *keyword,
                                     cbm_edge_t **out, int *count) {
    *out = NULL;
    *count = 0;

    /* Search properties JSON for url_path containing keyword */
    char like_pattern[CBM_SZ_512];
    snprintf(like_pattern, sizeof(like_pattern), "%%\"url_path\":\"%%%s%%\"%%", keyword);

    const char *sql = "SELECT id, project, source_id, target_id, type, properties FROM edges "
                      "WHERE project = ?1 AND properties LIKE ?2";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "url_path prepare");
        return CBM_STORE_ERR;
    }

    bind_text(stmt, SKIP_ONE, project);
    bind_text(stmt, ST_COL_2, like_pattern);

    int cap = 0;
    int n = 0;
    cbm_edge_t *edges = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&edges, &cap, n + 1, sizeof(*edges),
                                "find_edges_by_url_path") != CBM_STORE_OK) {
            cbm_store_free_edges(edges, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        if (scan_edge(s, stmt, &edges[n]) != CBM_STORE_OK) {
            cbm_store_free_edges(edges, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        cbm_store_free_edges(edges, n);
        store_set_error_sqlite(s, "find_edges_by_url_path step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = edges;
    *count = n;
    return CBM_STORE_OK;
}

/* ── RestoreFrom ───────────────────────────────────────────────── */

int cbm_store_restore_from(cbm_store_t *dst, cbm_store_t *src) {
    if (!dst || !src) {
        return CBM_STORE_ERR;
    }
    sqlite3_backup *bk = sqlite3_backup_init(dst->db, "main", src->db, "main");
    if (!bk) {
        store_set_error_sqlite(dst, "backup init");
        return CBM_STORE_ERR;
    }
    int rc = sqlite3_backup_step(bk, CBM_NOT_FOUND); /* copy all pages */
    sqlite3_backup_finish(bk);

    if (rc != SQLITE_DONE) {
        store_set_error(dst, "backup step failed");
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

/* ── Search ─────────────────────────────────────────────────────── */

/* Convert a glob pattern to SQL LIKE pattern. */
char *cbm_glob_to_like(const char *pattern) {
    if (!pattern) {
        return NULL;
    }
    size_t len = strlen(pattern);
    char *out = malloc((len * ST_GROWTH) + SKIP_ONE);
    size_t j = 0;

    for (size_t i = 0; i < len; i++) {
        if (pattern[i] == '*' && i + SKIP_ONE < len && pattern[i + SKIP_ONE] == '*') {
            /* Remove leading / from output if present (handles glob dir-star) */
            if (j > 0 && out[j - SKIP_ONE] == '/') {
                j--;
            }
            out[j++] = '%';
            i++; /* skip second * */
            if (i + SKIP_ONE < len && pattern[i + SKIP_ONE] == '/') {
                i++; /* skip trailing / */
            }
        } else if (pattern[i] == '*') {
            out[j++] = '%';
        } else if (pattern[i] == '?') {
            out[j++] = '_';
        } else {
            out[j++] = pattern[i];
        }
    }
    out[j] = '\0';
    return out;
}

/* ── extractLikeHints ─────────────────────────────────────────── */

int cbm_extract_like_hints(const char *pattern, char **out, int max_out) {
    if (!pattern || !out || max_out <= 0) {
        return 0;
    }

    /* Bail on alternation — can't convert OR regex to AND LIKE */
    for (const char *p = pattern; *p; p++) {
        if (*p == '|') {
            return 0;
        }
    }

    int count = 0;
    char buf[CBM_SZ_256];
    int blen = 0;

    int i = 0;
    while (pattern[i]) {
        char ch = pattern[i];
        switch (ch) {
        case '\\':
            /* Escaped char — the next char is literal */
            if (pattern[i + SKIP_ONE]) {
                if (blen < (int)sizeof(buf) - SKIP_ONE) {
                    buf[blen++] = pattern[i + SKIP_ONE];
                }
                i += ST_GLOB_SKIP;
            } else {
                i++;
            }
            break;
        case '.':
        case '*':
        case '+':
        case '?':
        case '^':
        case '$':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
            /* Meta character — flush current literal segment */
            if (blen >= ST_GLOB_MIN_LEN && count < max_out) {
                buf[blen] = '\0';
                out[count++] = strdup(buf);
            }
            blen = 0;
            i++;
            break;
        default:
            if (blen < (int)sizeof(buf) - SKIP_ONE) {
                buf[blen++] = ch;
            }
            i++;
            break;
        }
    }
    /* Flush trailing segment */
    if (blen >= ST_GLOB_MIN_LEN && count < max_out) {
        buf[blen] = '\0';
        out[count++] = strdup(buf);
    }
    return count;
}

/* ── ensureCaseInsensitive / stripCaseFlag ────────────────────── */

const char *cbm_ensure_case_insensitive(const char *pattern) {
    static char buf[CBM_SZ_2K];
    if (!pattern) {
        buf[0] = '\0';
        return buf;
    }
    /* Already has (?i) prefix? Return as-is. */
    if (strncmp(pattern, "(?i)", SLEN("(?i)")) == 0) {
        snprintf(buf, sizeof(buf), "%s", pattern);
    } else {
        snprintf(buf, sizeof(buf), "(?i)%s", pattern);
    }
    return buf;
}

const char *cbm_strip_case_flag(const char *pattern) {
    static char buf[CBM_SZ_2K];
    if (!pattern) {
        buf[0] = '\0';
        return buf;
    }
    if (strncmp(pattern, "(?i)", SLEN("(?i)")) == 0) {
        snprintf(buf, sizeof(buf), "%s", pattern + 4);
    } else {
        snprintf(buf, sizeof(buf), "%s", pattern);
    }
    return buf;
}

/* Bind value tracker for dynamic query building */
typedef struct {
    const char *text;
} search_bind_t;

/* Pool of malloc'd strings that must outlive statement execution.
 * Freed in one shot after both statements are finalized. */
typedef struct {
    char *ptrs[ST_LIKE_POOL_MAX];
    int count;
} search_like_pool_t;

static void like_pool_add(search_like_pool_t *pool, char *ptr) {
    if (ptr && pool->count < ST_LIKE_POOL_MAX) {
        pool->ptrs[pool->count++] = ptr;
    } else {
        free(ptr); /* pool full — don't leak */
    }
}

static void like_pool_free(search_like_pool_t *pool) {
    for (int i = 0; i < pool->count; i++) {
        free(pool->ptrs[i]);
    }
    pool->count = 0;
}

/* Wrap a literal string in % for use as a LIKE pattern (%literal%). */
static char *make_like_hint(const char *literal) {
    size_t len = strlen(literal);
    char *buf = malloc(len + 3); /* % + literal + % + NUL */
    if (buf) {
        buf[0] = '%';
        memcpy(buf + SKIP_ONE, literal, len);
        buf[len + SKIP_ONE] = '%';
        buf[len + 2] = '\0';
    }
    return buf;
}

static void search_apply_degree_filter(char *sql, size_t sql_sz, const cbm_search_params_t *p) {
    bool has_degree_filter = (p->min_degree >= 0 || p->max_degree >= 0);
    if (!has_degree_filter) {
        return;
    }
    char inner_sql[CBM_SZ_4K];
    snprintf(inner_sql, sizeof(inner_sql), "%s", sql);
    if (p->min_degree >= 0 && p->max_degree >= 0) {
        snprintf(sql, sql_sz,
                 "SELECT * FROM (%s) WHERE (in_deg + out_deg) >= %d AND (in_deg + out_deg) <= %d",
                 inner_sql, p->min_degree, p->max_degree);
    } else if (p->min_degree >= 0) {
        snprintf(sql, sql_sz, "SELECT * FROM (%s) WHERE (in_deg + out_deg) >= %d", inner_sql,
                 p->min_degree);
    } else {
        snprintf(sql, sql_sz, "SELECT * FROM (%s) WHERE (in_deg + out_deg) <= %d", inner_sql,
                 p->max_degree);
    }
}

/* Append a WHERE clause fragment, joining with AND if not the first. */
static int where_append(char *where, int where_sz, int wlen, int *nparams, const char *cond) {
    if (*nparams > 0) {
        wlen += snprintf(where + wlen, where_sz - wlen, " AND ");
    }
    wlen += snprintf(where + wlen, where_sz - wlen, "%s", cond);
    (*nparams)++;
    return wlen;
}

/* Bind a text parameter and increment the bind index. */
static void where_bind_text(search_bind_t *binds, int *bind_idx, const char *val) {
    binds[*bind_idx].text = val;
    (*bind_idx)++;
}

/* Build exclude-labels NOT IN clause with bind placeholders. */
static void search_build_exclude_labels(const char **labels, search_bind_t *binds, int *bind_idx,
                                        char *clause, int clause_sz) {
    int elen = snprintf(clause, clause_sz, "n.label NOT IN (");
    for (int i = 0; labels[i]; i++) {
        if (i > 0) {
            elen += snprintf(clause + elen, clause_sz - elen, ",");
            if (elen >= clause_sz) {
                elen = clause_sz - SKIP_ONE;
            }
        }
        elen += snprintf(clause + elen, clause_sz - elen, "?%d", *bind_idx + SKIP_ONE);
        if (elen >= clause_sz) {
            elen = clause_sz - SKIP_ONE;
        }
        where_bind_text(binds, bind_idx, labels[i]);
    }
    snprintf(clause + elen, clause_sz - elen, ")");
}

/* Append a regex WHERE clause for a column (case-sensitive or insensitive). */
static void where_add_regex(char *where, int where_sz, int *wlen, int *nparams,
                            search_bind_t *binds, int *bind_idx, const char *column,
                            const char *pattern, bool case_sensitive) {
    char buf[CBM_SZ_128];
    if (case_sensitive) {
        snprintf(buf, sizeof(buf), "%s REGEXP ?%d", column, *bind_idx + SKIP_ONE);
    } else {
        snprintf(buf, sizeof(buf), "iregexp(?%d, %s)", *bind_idx + SKIP_ONE, column);
    }
    *wlen = where_append(where, where_sz, *wlen, nparams, buf);
    where_bind_text(binds, bind_idx, pattern);
}

/* Prepend LIKE pre-filter conditions for literal segments of a regex pattern.
 * The idx_nodes_name index satisfies LIKE '%literal%', cutting the rows that
 * reach the (more expensive) iregexp call to only those containing the literal.
 * cbm_extract_like_hints bails on alternation, so no false negatives. */
static void where_add_like_hints(const char *column, const char *pattern, char *where, int where_sz,
                                 int *wlen, int *nparams, search_bind_t *binds, int *bind_idx,
                                 search_like_pool_t *pool) {
    char *hints[ST_LIKE_HINT_MAX];
    int nhints = cbm_extract_like_hints(pattern, hints, ST_LIKE_HINT_MAX);
    char bind_buf[CBM_SZ_64];
    for (int i = 0; i < nhints; i++) {
        char *lp = make_like_hint(hints[i]);
        free(hints[i]);
        if (!lp)
            continue;
        int pool_was_full = (pool->count >= ST_LIKE_POOL_MAX);
        like_pool_add(pool, lp);
        if (pool_was_full)
            continue; /* lp was freed — skip bind */
        snprintf(bind_buf, sizeof(bind_buf), "%s LIKE ?%d", column, *bind_idx + SKIP_ONE);
        *wlen = where_append(where, where_sz, *wlen, nparams, bind_buf);
        where_bind_text(binds, bind_idx, lp);
    }
}

/* Build basic WHERE clauses: project, label, name, file, qn patterns. */
static int search_where_basic(const cbm_search_params_t *params, char *where, int where_sz,
                              int *wlen, int *nparams, search_bind_t *binds, int *bind_idx,
                              search_like_pool_t *pool) {
    char bind_buf[CBM_SZ_64];

    if (params->project) {
        snprintf(bind_buf, sizeof(bind_buf), "n.project = ?%d", *bind_idx + SKIP_ONE);
        *wlen = where_append(where, where_sz, *wlen, nparams, bind_buf);
        where_bind_text(binds, bind_idx, params->project);
    }
    /* Ignore an empty-string label: it is non-NULL but should behave like an
     * omitted label (no filter), matching the BM25 query path. Without the
     * params->label[0] guard, name_pattern/qn_pattern searches that pass
     * label="" append `n.label = ''`, which matches no node and silently
     * returns zero results (issue #481). */
    if (params->label && params->label[0]) {
        snprintf(bind_buf, sizeof(bind_buf), "n.label = ?%d", *bind_idx + SKIP_ONE);
        *wlen = where_append(where, where_sz, *wlen, nparams, bind_buf);
        where_bind_text(binds, bind_idx, params->label);
    }
    if (params->name_pattern) {
        where_add_like_hints("n.name", params->name_pattern, where, where_sz, wlen, nparams, binds,
                             bind_idx, pool);
        where_add_regex(where, where_sz, wlen, nparams, binds, bind_idx, "n.name",
                        params->name_pattern, params->case_sensitive);
    }
    if (params->qn_pattern) {
        where_add_like_hints("n.qualified_name", params->qn_pattern, where, where_sz, wlen, nparams,
                             binds, bind_idx, pool);
        where_add_regex(where, where_sz, wlen, nparams, binds, bind_idx, "n.qualified_name",
                        params->qn_pattern, params->case_sensitive);
    }
    if (params->file_pattern) {
        char *lp = cbm_glob_to_like(params->file_pattern);
        /* A file_pattern with no glob wildcards is treated as a path-substring
         * match (issue #200): file_pattern="offer-server" should match
         * "src/offer-server/x.js", not only a path equal to "offer-server".
         * Patterns that DO contain * / ? keep their explicit glob semantics. */
        if (lp && !strchr(params->file_pattern, '*') && !strchr(params->file_pattern, '?')) {
            size_t lplen = strlen(lp);
            char *contains = malloc(lplen + 3);
            if (contains) {
                contains[0] = '%';
                memcpy(contains + 1, lp, lplen);
                contains[lplen + 1] = '%';
                contains[lplen + 2] = '\0';
                free(lp);
                lp = contains;
            }
        }
        int pool_was_full = (pool->count >= ST_LIKE_POOL_MAX);
        like_pool_add(pool, lp);
        if (!pool_was_full && lp) {
            snprintf(bind_buf, sizeof(bind_buf), "n.file_path LIKE ?%d", *bind_idx + SKIP_ONE);
            *wlen = where_append(where, where_sz, *wlen, nparams, bind_buf);
            where_bind_text(binds, bind_idx, lp);
        }
    }
    return *nparams;
}

/* Build advanced WHERE clauses: relationship, entry points, exclude labels. */
static void search_where_advanced(const cbm_search_params_t *params, char *where, int where_sz,
                                  int *wlen, int *nparams, search_bind_t *binds, int *bind_idx) {
    if (params->relationship) {
        char rel_clause[CBM_SZ_256];
        snprintf(rel_clause, sizeof(rel_clause),
                 "EXISTS(SELECT 1 FROM edges e WHERE "
                 "(e.source_id = n.id OR e.target_id = n.id) AND e.type = ?%d)",
                 *bind_idx + SKIP_ONE);
        *wlen = where_append(where, where_sz, *wlen, nparams, rel_clause);
        where_bind_text(binds, bind_idx, params->relationship);
    }
    if (params->exclude_entry_points) {
        /* Exclude nodes with no inbound CALLS but at least one outbound CALLS.
         * Dead code (degree=0) is NOT excluded — only true entry points. */
        *wlen = where_append(where, where_sz, *wlen, nparams,
                             "NOT (NOT EXISTS(SELECT 1 FROM edges e WHERE e.target_id = n.id "
                             "AND e.type = 'CALLS') "
                             "AND EXISTS(SELECT 1 FROM edges e2 WHERE e2.source_id = n.id "
                             "AND e2.type = 'CALLS'))");
    }
    if (params->exclude_labels) {
        char excl_clause[CBM_SZ_512];
        search_build_exclude_labels(params->exclude_labels, binds, bind_idx, excl_clause,
                                    (int)sizeof(excl_clause));
        (void)where_append(where, where_sz, *wlen, nparams, excl_clause);
    }
}

static int search_build_where(const cbm_search_params_t *params, char *where, int where_sz,
                              search_bind_t *binds, int *bind_idx, search_like_pool_t *pool) {
    int wlen = 0;
    int nparams = 0;

    search_where_basic(params, where, where_sz, &wlen, &nparams, binds, bind_idx, pool);
    search_where_advanced(params, where, where_sz, &wlen, &nparams, binds, bind_idx);

    return nparams;
}

int cbm_store_search(cbm_store_t *s, const cbm_search_params_t *params, cbm_search_output_t *out) {
    memset(out, 0, sizeof(*out));
    if (!s || !s->db) {
        return CBM_STORE_ERR;
    }

    char sql[CBM_SZ_4K];
    char count_sql[CBM_SZ_4K];
    int bind_idx = 0;

    const char *select_cols = "SELECT " ST_NODE_SELECT_COLUMNS_N ", "
                              "(SELECT COUNT(*) FROM edges e WHERE e.target_id = n.id AND "
                              "e.type IN ('CALLS', 'USAGE', 'INHERITS', 'IMPLEMENTS')) AS in_deg, "
                              "(SELECT COUNT(*) FROM edges e WHERE e.source_id = n.id AND "
                              "e.type IN ('CALLS', 'USAGE', 'INHERITS', 'IMPLEMENTS')) AS out_deg ";

    char where[CBM_SZ_2K] = "";
    search_bind_t binds[ST_SEARCH_MAX_BINDS];
    search_like_pool_t like_pool = {0};

    int nparams =
        search_build_where(params, where, (int)sizeof(where), binds, &bind_idx, &like_pool);

    /* Build full SQL */
    if (nparams > 0) {
        snprintf(sql, sizeof(sql), "%s FROM nodes n WHERE %s", select_cols, where);
    } else {
        snprintf(sql, sizeof(sql), "%s FROM nodes n", select_cols);
    }

    /* Degree filters */
    bool has_degree_filter = (params->min_degree >= 0 || params->max_degree >= 0);
    search_apply_degree_filter(sql, sizeof(sql), params);

    /* Count query — stripped of per-row edge subqueries for the common (no-degree-filter)
     * case, since we only need the row count, not in_deg/out_deg.  The degree-filter
     * case must wrap the full query because the filter references those columns. */
    if (has_degree_filter) {
        snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM (%s)", sql);
    } else if (nparams > 0) {
        snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM nodes n WHERE %s", where);
    } else {
        snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM nodes n");
    }

    /* Add ORDER BY + LIMIT */
    int limit = params->limit > 0 ? params->limit : CBM_DEFAULT_SEARCH_LIMIT;
    int offset = params->offset;
    const char *name_col = has_degree_filter ? "name" : "n.name";
    char order_limit[CBM_SZ_128];
    snprintf(order_limit, sizeof(order_limit), " ORDER BY %s LIMIT %d OFFSET %d", name_col, limit,
             offset);
    strncat(sql, order_limit, sizeof(sql) - strlen(sql) - 1);

    /* Execute count query */
    sqlite3_stmt *cnt_stmt = NULL;
    int rc = sqlite3_prepare_v2(s->db, count_sql, CBM_NOT_FOUND, &cnt_stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "search count prepare");
        like_pool_free(&like_pool);
        return CBM_STORE_ERR;
    }
    for (int i = 0; i < bind_idx; i++) {
        bind_text(cnt_stmt, i + SKIP_ONE, binds[i].text);
    }
    rc = sqlite3_step(cnt_stmt);
    if (rc != SQLITE_ROW) {
        store_set_error_sqlite(s, "search count step");
        sqlite3_finalize(cnt_stmt);
        like_pool_free(&like_pool);
        return CBM_STORE_ERR;
    }
    out->total = sqlite3_column_int(cnt_stmt, 0);
    sqlite3_finalize(cnt_stmt);

    /* Execute main query */
    sqlite3_stmt *main_stmt = NULL;
    rc = sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &main_stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "search prepare");
        like_pool_free(&like_pool);
        return CBM_STORE_ERR;
    }

    for (int i = 0; i < bind_idx; i++) {
        bind_text(main_stmt, i + SKIP_ONE, binds[i].text);
    }

    int cap = 0;
    int n = 0;
    cbm_search_result_t *results = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(main_stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&results, &cap, n + 1, sizeof(*results), "search") !=
            CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                cbm_node_free_fields(&results[i].node);
            }
            free(results);
            sqlite3_finalize(main_stmt);
            like_pool_free(&like_pool);
            return CBM_STORE_ERR;
        }
        memset(&results[n], 0, sizeof(cbm_search_result_t));
        if (scan_node(s, main_stmt, &results[n].node) != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                cbm_node_free_fields(&results[i].node);
            }
            free(results);
            sqlite3_finalize(main_stmt);
            like_pool_free(&like_pool);
            return CBM_STORE_ERR;
        }
        results[n].in_degree = sqlite3_column_int(main_stmt, ST_NODE_COL_COUNT);
        results[n].out_degree = sqlite3_column_int(main_stmt, ST_NODE_COL_COUNT + SKIP_ONE);
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            cbm_node_free_fields(&results[i].node);
        }
        free(results);
        store_set_error_sqlite(s, "search step");
        sqlite3_finalize(main_stmt);
        like_pool_free(&like_pool);
        return CBM_STORE_ERR;
    }

    sqlite3_finalize(main_stmt);
    like_pool_free(&like_pool);

    out->results = results;
    out->count = n;
    return CBM_STORE_OK;
}

void cbm_store_search_free(cbm_search_output_t *out) {
    if (!out) {
        return;
    }
    for (int i = 0; i < out->count; i++) {
        cbm_search_result_t *r = &out->results[i];
        safe_str_free(&r->node.project);
        safe_str_free(&r->node.label);
        safe_str_free(&r->node.name);
        safe_str_free(&r->node.qualified_name);
        safe_str_free(&r->node.file_path);
        safe_str_free(&r->node.properties_json);
        for (int j = 0; j < r->connected_count; j++) {
            safe_str_free(&r->connected_names[j]);
        }
        free(r->connected_names);
    }
    free(out->results);
    memset(out, 0, sizeof(*out));
}

/* ── BFS Traversal ──────────────────────────────────────────────── */

static int bfs_collect_edges(cbm_store_t *s, int64_t start_id, const cbm_node_hop_t *visited,
                             int visited_count, const char *types_clause, const char **edge_types,
                             int edge_type_count, cbm_edge_info_t **out_edges,
                             int *out_edge_count) {
    /* Build ID set: root + all visited */
    char id_set[CBM_SZ_4K];
    int ilen = snprintf(id_set, sizeof(id_set), "%lld", (long long)start_id);
    if (ilen >= (int)sizeof(id_set)) {
        ilen = (int)sizeof(id_set) - SKIP_ONE;
    }
    for (int i = 0; i < visited_count; i++) {
        ilen += snprintf(id_set + ilen, sizeof(id_set) - (size_t)ilen, ",%lld",
                         (long long)visited[i].node.id);
        if (ilen >= (int)sizeof(id_set)) {
            ilen = (int)sizeof(id_set) - SKIP_ONE;
        }
    }

    char edge_sql[ST_SQL_BUF];
    snprintf(edge_sql, sizeof(edge_sql),
             "SELECT n1.name, n2.name, e.type, e.source_id, e.target_id, e.properties "
             "FROM edges e "
             "JOIN nodes n1 ON n1.id = e.source_id "
             "JOIN nodes n2 ON n2.id = e.target_id "
             "WHERE e.source_id IN (%s) AND e.target_id IN (%s) "
             "AND e.type IN (%s)",
             id_set, id_set, types_clause);

    sqlite3_stmt *estmt = NULL;
    int rc = sqlite3_prepare_v2(s->db, edge_sql, CBM_NOT_FOUND, &estmt, NULL);
    if (rc != SQLITE_OK) {
        *out_edges = NULL;
        *out_edge_count = 0;
        store_set_error_sqlite(s, "bfs edges prepare");
        return CBM_STORE_ERR;
    }

    if (edge_type_count > 0) {
        for (int i = 0; i < edge_type_count; i++) {
            bind_text(estmt, i + SKIP_ONE, edge_types[i]);
        }
    } else {
        bind_text(estmt, SKIP_ONE, "CALLS");
    }

    int ecap = 0;
    int en = 0;
    cbm_edge_info_t *edges = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(estmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&edges, &ecap, en + 1, sizeof(*edges),
                                "bfs_collect_edges") != CBM_STORE_OK) {
            for (int i = 0; i < en; i++) {
                free((void *)edges[i].from_name);
                free((void *)edges[i].to_name);
                free((void *)edges[i].type);
                free((void *)edges[i].properties_json);
            }
            free(edges);
            sqlite3_finalize(estmt);
            return CBM_STORE_ERR;
        }
        memset(&edges[en], 0, sizeof(edges[en]));
        edges[en].from_name = heap_strdup((const char *)sqlite3_column_text(estmt, 0));
        edges[en].to_name = heap_strdup((const char *)sqlite3_column_text(estmt, SKIP_ONE));
        edges[en].type = heap_strdup((const char *)sqlite3_column_text(estmt, CBM_SZ_2));
        edges[en].confidence = (double)SKIP_ONE;
        edges[en].source_id = sqlite3_column_int64(estmt, ST_COL_3);
        edges[en].target_id = sqlite3_column_int64(estmt, ST_COL_4);
        edges[en].properties_json = heap_strdup((const char *)sqlite3_column_text(estmt, CBM_SZ_5));
        if (!edges[en].from_name || !edges[en].to_name || !edges[en].type ||
            !edges[en].properties_json) {
            for (int i = 0; i <= en; i++) {
                free((void *)edges[i].from_name);
                free((void *)edges[i].to_name);
                free((void *)edges[i].type);
                free((void *)edges[i].properties_json);
            }
            free(edges);
            store_set_error(s, "bfs edge row allocation failed");
            sqlite3_finalize(estmt);
            return CBM_STORE_ERR;
        }
        en++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < en; i++) {
            free((void *)edges[i].from_name);
            free((void *)edges[i].to_name);
            free((void *)edges[i].type);
            free((void *)edges[i].properties_json);
        }
        free(edges);
        store_set_error_sqlite(s, "bfs edges step");
        sqlite3_finalize(estmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(estmt);

    *out_edges = edges;
    *out_edge_count = en;
    return CBM_STORE_OK;
}

/* Build parameterized placeholder list "?1,?2,?3" for N edge types. */
static void bfs_build_types_clause(int edge_type_count, char *buf, int buf_sz) {
    if (edge_type_count <= 0) {
        snprintf(buf, buf_sz, "?1");
        return;
    }
    int tlen = 0;
    for (int i = 0; i < edge_type_count; i++) {
        if (i > 0) {
            tlen += snprintf(buf + tlen, buf_sz - tlen, ",");
            if (tlen >= buf_sz) {
                tlen = buf_sz - SKIP_ONE;
            }
        }
        tlen += snprintf(buf + tlen, buf_sz - tlen, "?%d", i + SKIP_ONE);
        if (tlen >= buf_sz) {
            tlen = buf_sz - SKIP_ONE;
        }
    }
}

int cbm_store_bfs(cbm_store_t *s, int64_t start_id, const char *direction, const char **edge_types,
                  int edge_type_count, int max_depth, int max_results, cbm_traverse_result_t *out) {
    memset(out, 0, sizeof(*out));

    cbm_node_t root = {0};
    int rc = cbm_store_find_node_by_id(s, start_id, &root);
    if (rc != CBM_STORE_OK) {
        return rc;
    }
    out->root = root;

    char types_clause[CBM_SZ_512];
    bfs_build_types_clause(edge_type_count, types_clause, (int)sizeof(types_clause));

    /* Build recursive CTE for BFS */
    char sql[CBM_SZ_4K];
    const char *join_cond;
    const char *next_id;
    bool is_inbound = (direction != NULL) && (strcmp(direction, "inbound") == 0);

    if (is_inbound) {
        join_cond = "e.target_id = bfs.node_id";
        next_id = "e.source_id";
    } else {
        join_cond = "e.source_id = bfs.node_id";
        next_id = "e.target_id";
    }

    snprintf(sql, sizeof(sql),
             "WITH RECURSIVE bfs(node_id, hop) AS ("
             "  SELECT %lld, 0"
             "  UNION"
             "  SELECT %s, bfs.hop + 1"
             "  FROM bfs"
             "  JOIN edges e ON %s"
             "  WHERE e.type IN (%s) AND bfs.hop < %d"
             ")"
             "SELECT DISTINCT " ST_NODE_SELECT_COLUMNS_N ", bfs.hop "
             "FROM bfs "
             "JOIN nodes n ON n.id = bfs.node_id "
             "WHERE bfs.hop > 0 " /* exclude root */
             "ORDER BY bfs.hop "
             "LIMIT %d;",
             (long long)start_id, next_id, join_cond, types_clause, max_depth, max_results);

    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL);
    if (rc != SQLITE_OK) {
        store_set_error_sqlite(s, "bfs prepare");
        return CBM_STORE_ERR;
    }

    /* Bind edge type parameters */
    if (edge_type_count > 0) {
        for (int i = 0; i < edge_type_count; i++) {
            bind_text(stmt, i + SKIP_ONE, edge_types[i]);
        }
    } else {
        bind_text(stmt, SKIP_ONE, "CALLS");
    }

    int cap = 0;
    int n = 0;
    cbm_node_hop_t *visited = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&visited, &cap, n + 1, sizeof(*visited), "bfs") !=
            CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                cbm_node_free_fields(&visited[i].node);
            }
            free(visited);
            sqlite3_finalize(stmt);
            cbm_store_traverse_free(out);
            return CBM_STORE_ERR;
        }
        if (scan_node(s, stmt, &visited[n].node) != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                cbm_node_free_fields(&visited[i].node);
            }
            free(visited);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        visited[n].hop = sqlite3_column_int(stmt, ST_NODE_COL_COUNT);
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            cbm_node_free_fields(&visited[i].node);
        }
        free(visited);
        store_set_error_sqlite(s, "bfs step");
        sqlite3_finalize(stmt);
        cbm_store_traverse_free(out);
        return CBM_STORE_ERR;
    }

    sqlite3_finalize(stmt);

    out->visited = visited;
    out->visited_count = n;

    /* Collect edges between visited nodes (including root) */
    if (n > 0) {
        if (bfs_collect_edges(s, start_id, out->visited, n, types_clause, edge_types,
                              edge_type_count, &out->edges, &out->edge_count) != CBM_STORE_OK) {
            cbm_store_traverse_free(out);
            return CBM_STORE_ERR;
        }
    } else {
        out->edges = NULL;
        out->edge_count = 0;
    }

    return CBM_STORE_OK;
}

void cbm_store_traverse_free(cbm_traverse_result_t *out) {
    if (!out) {
        return;
    }
    /* Free root */
    safe_str_free(&out->root.project);
    safe_str_free(&out->root.label);
    safe_str_free(&out->root.name);
    safe_str_free(&out->root.qualified_name);
    safe_str_free(&out->root.file_path);
    safe_str_free(&out->root.properties_json);

    /* Free visited */
    for (int i = 0; i < out->visited_count; i++) {
        cbm_node_hop_t *h = &out->visited[i];
        safe_str_free(&h->node.project);
        safe_str_free(&h->node.label);
        safe_str_free(&h->node.name);
        safe_str_free(&h->node.qualified_name);
        safe_str_free(&h->node.file_path);
        safe_str_free(&h->node.properties_json);
    }
    free(out->visited);

    /* Free edges */
    for (int i = 0; i < out->edge_count; i++) {
        safe_str_free(&out->edges[i].from_name);
        safe_str_free(&out->edges[i].to_name);
        safe_str_free(&out->edges[i].type);
        safe_str_free(&out->edges[i].properties_json);
    }
    free(out->edges);

    memset(out, 0, sizeof(*out));
}

/* ── Impact analysis ────────────────────────────────────────────── */

cbm_risk_level_t cbm_hop_to_risk(int hop) {
    switch (hop) {
    case SKIP_ONE:
        return CBM_RISK_CRITICAL;
    case ST_COL_2:
        return CBM_RISK_HIGH;
    case ST_COL_3:
        return CBM_RISK_MEDIUM;
    default:
        return CBM_RISK_LOW;
    }
}

const char *cbm_risk_label(cbm_risk_level_t level) {
    switch (level) {
    case CBM_RISK_CRITICAL:
        return "CRITICAL";
    case CBM_RISK_HIGH:
        return "HIGH";
    case CBM_RISK_MEDIUM:
        return "MEDIUM";
    case CBM_RISK_LOW:
    default:
        return "LOW";
    }
}

cbm_impact_summary_t cbm_build_impact_summary(const cbm_node_hop_t *hops, int hop_count,
                                              const cbm_edge_info_t *edges, int edge_count) {
    cbm_impact_summary_t s = {0};
    for (int i = 0; i < hop_count; i++) {
        switch (cbm_hop_to_risk(hops[i].hop)) {
        case CBM_RISK_CRITICAL:
            s.critical++;
            break;
        case CBM_RISK_HIGH:
            s.high++;
            break;
        case CBM_RISK_MEDIUM:
            s.medium++;
            break;
        case CBM_RISK_LOW:
            s.low++;
            break;
        }
        s.total++;
    }
    for (int i = 0; i < edge_count; i++) {
        if (edges[i].type && (strcmp(edges[i].type, "HTTP_CALLS") == 0 ||
                              strcmp(edges[i].type, "ASYNC_CALLS") == 0)) {
            s.has_cross_service = true;
            break;
        }
    }
    return s;
}

int cbm_deduplicate_hops(const cbm_node_hop_t *hops, int hop_count, cbm_node_hop_t **out,
                         int *out_count) {
    *out = NULL;
    *out_count = 0;
    if (hop_count == 0) {
        return CBM_STORE_OK;
    }

    /* Simple O(n²) dedup — keep minimum hop per node ID */
    if (hop_count < 0 || (size_t)hop_count > SIZE_MAX / sizeof(cbm_node_hop_t)) {
        return CBM_STORE_ERR;
    }
    cbm_node_hop_t *result = malloc(hop_count * sizeof(cbm_node_hop_t));
    if (!result) {
        cbm_log_error(
            "store.deduplicate_hops", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
            "deduplicated hop allocation failed", "remediation",
            "free memory or narrow the traversal, then retry; no partial result was returned");
        return CBM_STORE_ERR;
    }
    int n = 0;

    for (int i = 0; i < hop_count; i++) {
        int found = ST_FOUND;
        for (int j = 0; j < n; j++) {
            if (result[j].node.id == hops[i].node.id) {
                found = j;
                break;
            }
        }
        if (found >= 0) {
            if (hops[i].hop < result[found].hop) {
                result[found].hop = hops[i].hop;
            }
        } else {
            result[n] = hops[i];
            n++;
        }
    }

    *out = result;
    *out_count = n;
    return CBM_STORE_OK;
}

/* ── Schema ─────────────────────────────────────────────────────── */

enum { SCHEMA_MAX_JSON_KEYS = 50 };

/* Discover distinct JSON property keys for a table/column via json_each().
 * Prepends base_cols, then appends up to SCHEMA_MAX_JSON_KEYS from the query.
 * Caller must free the returned array and each string in it. */
static void schema_discover_props(sqlite3 *db, const char *sql, const char *project,
                                  const char *filter, const char **base_cols, int base_col_count,
                                  char ***out_props, int *out_count) {
    int pcap = base_col_count + SCHEMA_MAX_JSON_KEYS;
    char **props = malloc(pcap * sizeof(char *));
    int pn = 0;

    for (int b = 0; b < base_col_count; b++) {
        props[pn++] = heap_strdup(base_cols[b]);
    }

    sqlite3_stmt *pstmt = NULL;
    if (sqlite3_prepare_v2(db, sql, CBM_NOT_FOUND, &pstmt, NULL) == SQLITE_OK) {
        bind_text(pstmt, SKIP_ONE, project);
        bind_text(pstmt, PAIR_LEN, filter);
        while (sqlite3_step(pstmt) == SQLITE_ROW && pn < pcap) {
            props[pn++] = heap_strdup((const char *)sqlite3_column_text(pstmt, 0));
        }
        sqlite3_finalize(pstmt);
    }

    *out_props = props;
    *out_count = pn;
}

/* Path scoping for architecture / schema (shared). */
static bool arch_path_is_set(const char *path) {
    if (!path) {
        return false;
    }
    while (*path == ' ' || *path == '\t' || *path == '\n' || *path == '\r') {
        path++;
    }
    return path[0] != '\0';
}

static bool arch_path_prepare(const char *path, char *norm_out, size_t norm_sz, char *like_out,
                              size_t like_sz) {
    if (!arch_path_is_set(path)) {
        return false;
    }
    while (*path == ' ' || *path == '\t' || *path == '\n' || *path == '\r') {
        path++;
    }
    if (path[0] == '\0') {
        return false;
    }
    if (strncmp(path, "./", 2) == 0) {
        path += 2;
    }
    while (*path == '/') {
        path++;
    }
    if (path[0] == '\0') {
        return false;
    }
    strncpy(norm_out, path, norm_sz - 1);
    norm_out[norm_sz - 1] = '\0';
    size_t len = strlen(norm_out);
    while (len > 0 &&
           (norm_out[len - 1] == ' ' || norm_out[len - 1] == '\t' || norm_out[len - 1] == '/')) {
        norm_out[--len] = '\0';
    }
    /* Collapse duplicate slashes */
    size_t w = 0;
    for (size_t r = 0; norm_out[r] != '\0'; r++) {
        if (norm_out[r] == '/' && w > 0 && norm_out[w - 1] == '/') {
            continue;
        }
        norm_out[w++] = norm_out[r];
    }
    norm_out[w] = '\0';
    if (norm_out[0] == '\0') {
        return false;
    }
    snprintf(like_out, like_sz, "%s/%%", norm_out);
    return true;
}

static const char *arch_path_scope_sql(void) {
    return " AND (file_path = ? OR file_path LIKE ?)";
}

static void arch_bind_path_scope(sqlite3_stmt *stmt, int exact_idx, int like_idx, const char *norm,
                                 const char *like_pat) {
    bind_text(stmt, exact_idx, norm);
    bind_text(stmt, like_idx, like_pat);
}

bool cbm_store_arch_path_scoped(const char *path) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512 + 4];
    return arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
}

bool cbm_store_normalize_arch_path(const char *path, char *norm_out, size_t norm_sz) {
    char like[CBM_SZ_512 + 4];
    return arch_path_prepare(path, norm_out, norm_sz, like, sizeof(like));
}

int cbm_store_count_nodes_scoped(cbm_store_t *s, const char *project, const char *path) {
    if (!s || !s->db || !project) {
        return 0;
    }
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    if (!arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like))) {
        return cbm_store_count_nodes(s, project);
    }
    const char *sql = "SELECT COUNT(*) FROM nodes WHERE project = ?1 "
                      "AND (file_path = ?2 OR file_path LIKE ?3);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return CBM_STORE_ERR;
    }
    bind_text(stmt, ST_COL_1, project);
    arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    int n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        n = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return n;
}

int cbm_store_count_edges_scoped(cbm_store_t *s, const char *project, const char *path) {
    if (!s || !s->db || !project) {
        return 0;
    }
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    if (!arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like))) {
        return cbm_store_count_edges(s, project);
    }
    const char *sql =
        "SELECT COUNT(*) FROM edges e WHERE e.project = ?1 "
        "AND EXISTS (SELECT 1 FROM nodes ns WHERE ns.id = e.source_id AND ns.project = ?1 "
        "AND (ns.file_path = ?2 OR ns.file_path LIKE ?3)) "
        "AND EXISTS (SELECT 1 FROM nodes nt WHERE nt.id = e.target_id AND nt.project = ?1 "
        "AND (nt.file_path = ?2 OR nt.file_path LIKE ?3));";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return CBM_STORE_ERR;
    }
    bind_text(stmt, ST_COL_1, project);
    arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    int n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        n = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return n;
}

/* with_props=false skips the per-label/per-type JSON property-key discovery:
 * those json_each() scans walk EVERY row of each label/type (minutes-scale on
 * multi-million-node graphs) and get_architecture only needs the counts. */
static int get_schema_impl(cbm_store_t *s, const char *project, cbm_schema_info_t *out,
                           bool with_props) {
    memset(out, 0, sizeof(*out));
    if (!s || !s->db) {
        return CBM_NOT_FOUND;
    }

    /* Node labels */
    {
        const char *sql = "SELECT label, COUNT(*) FROM nodes WHERE project = ?1 GROUP BY label "
                          "ORDER BY COUNT(*) DESC;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
            return CBM_NOT_FOUND;
        }
        bind_text(stmt, SKIP_ONE, project);

        int cap = ST_INIT_CAP_8;
        int n = 0;
        cbm_label_count_t *arr = malloc(cap * sizeof(cbm_label_count_t));
        if (!arr) {
            sqlite3_finalize(stmt);
            return CBM_NOT_FOUND;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (n >= cap) {
                int new_cap = cap * ST_GROWTH;
                void *tmp = realloc(arr, new_cap * sizeof(cbm_label_count_t));
                if (!tmp) {
                    for (int i = 0; i < n; i++) {
                        safe_str_free(&arr[i].label);
                    }
                    free(arr);
                    sqlite3_finalize(stmt);
                    return CBM_NOT_FOUND;
                }
                arr = tmp;
                cap = new_cap;
            }
            arr[n].label = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
            arr[n].count = sqlite3_column_int(stmt, SKIP_ONE);
            arr[n].properties = NULL;
            arr[n].property_count = 0;
            n++;
        }
        sqlite3_finalize(stmt);
        out->node_labels = arr;
        out->node_label_count = n;
    }

    /* Node label property keys: base columns + distinct JSON property keys per label */
    if (with_props) {
        static const char *node_base_cols[] = {"name", "qualified_name", "file_path", "start_line",
                                               "end_line"};
        const char *prop_sql = "SELECT DISTINCT je.key "
                               "FROM nodes, json_each(nodes.properties) AS je "
                               "WHERE nodes.project = ?1 AND nodes.label = ?2 "
                               "  AND nodes.properties != '{}' "
                               "ORDER BY je.key "
                               "LIMIT 50;";

        for (int i = 0; i < out->node_label_count; i++) {
            schema_discover_props(
                s->db, prop_sql, project, out->node_labels[i].label, node_base_cols,
                (int)(sizeof(node_base_cols) / sizeof(node_base_cols[0])),
                &out->node_labels[i].properties, &out->node_labels[i].property_count);
        }
    }

    /* Edge types */
    {
        const char *sql = "SELECT type, COUNT(*) FROM edges WHERE project = ?1 GROUP BY type ORDER "
                          "BY COUNT(*) DESC;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
            cbm_store_schema_free(out);
            return CBM_NOT_FOUND;
        }
        bind_text(stmt, SKIP_ONE, project);

        int cap = ST_INIT_CAP_8;
        int n = 0;
        cbm_type_count_t *arr = malloc(cap * sizeof(cbm_type_count_t));
        if (!arr) {
            sqlite3_finalize(stmt);
            cbm_store_schema_free(out);
            return CBM_NOT_FOUND;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (n >= cap) {
                int new_cap = cap * ST_GROWTH;
                void *tmp = realloc(arr, new_cap * sizeof(cbm_type_count_t));
                if (!tmp) {
                    for (int i = 0; i < n; i++) {
                        safe_str_free(&arr[i].type);
                    }
                    free(arr);
                    sqlite3_finalize(stmt);
                    cbm_store_schema_free(out);
                    return CBM_NOT_FOUND;
                }
                arr = tmp;
                cap = new_cap;
            }
            arr[n].type = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
            arr[n].count = sqlite3_column_int(stmt, SKIP_ONE);
            arr[n].properties = NULL;
            arr[n].property_count = 0;
            n++;
        }
        sqlite3_finalize(stmt);
        out->edge_types = arr;
        out->edge_type_count = n;
    }

    /* Edge type property keys: base columns + distinct JSON property keys per type */
    if (with_props) {
        static const char *edge_base_cols[] = {"source_id", "target_id"};
        const char *prop_sql = "SELECT DISTINCT je.key "
                               "FROM edges, json_each(edges.properties) AS je "
                               "WHERE edges.project = ?1 AND edges.type = ?2 "
                               "  AND edges.properties != '{}' "
                               "ORDER BY je.key "
                               "LIMIT 50;";

        for (int i = 0; i < out->edge_type_count; i++) {
            schema_discover_props(s->db, prop_sql, project, out->edge_types[i].type, edge_base_cols,
                                  (int)(sizeof(edge_base_cols) / sizeof(edge_base_cols[0])),
                                  &out->edge_types[i].properties,
                                  &out->edge_types[i].property_count);
        }
    }

    return CBM_STORE_OK;
}

int cbm_store_get_schema(cbm_store_t *s, const char *project, cbm_schema_info_t *out) {
    return get_schema_impl(s, project, out, true);
}

int cbm_store_get_schema_counts(cbm_store_t *s, const char *project, cbm_schema_info_t *out) {
    return get_schema_impl(s, project, out, false);
}

int cbm_store_get_schema_counts_scoped(cbm_store_t *s, const char *project, const char *path,
                                       cbm_schema_info_t *out) {
    memset(out, 0, sizeof(*out));
    if (!s || !s->db) {
        return CBM_NOT_FOUND;
    }
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    if (!scoped) {
        return get_schema_impl(s, project, out, false);
    }

    char sqlbuf[ST_SQL_BUF];
    {
        const char *base = "SELECT label, COUNT(*) FROM nodes WHERE project = ?1";
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s GROUP BY label ORDER BY COUNT(*) DESC;", base,
                 arch_path_scope_sql());
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
            return CBM_NOT_FOUND;
        }
        bind_text(stmt, SKIP_ONE, project);
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);

        int cap = ST_INIT_CAP_8;
        int n = 0;
        cbm_label_count_t *arr = malloc(cap * sizeof(cbm_label_count_t));
        if (!arr) {
            sqlite3_finalize(stmt);
            return CBM_NOT_FOUND;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (n >= cap) {
                int new_cap = cap * ST_GROWTH;
                void *tmp = realloc(arr, new_cap * sizeof(cbm_label_count_t));
                if (!tmp) {
                    for (int i = 0; i < n; i++) {
                        safe_str_free(&arr[i].label);
                    }
                    free(arr);
                    sqlite3_finalize(stmt);
                    return CBM_NOT_FOUND;
                }
                arr = tmp;
                cap = new_cap;
            }
            arr[n].label = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
            arr[n].count = sqlite3_column_int(stmt, SKIP_ONE);
            arr[n].properties = NULL;
            arr[n].property_count = 0;
            n++;
        }
        sqlite3_finalize(stmt);
        out->node_labels = arr;
        out->node_label_count = n;
    }

    {
        const char *esql =
            "SELECT e.type, COUNT(*) FROM edges e WHERE e.project = ?1 "
            "AND EXISTS (SELECT 1 FROM nodes ns WHERE ns.id = e.source_id AND ns.project = ?1 "
            "AND (ns.file_path = ?2 OR ns.file_path LIKE ?3)) "
            "AND EXISTS (SELECT 1 FROM nodes nt WHERE nt.id = e.target_id AND nt.project = ?1 "
            "AND (nt.file_path = ?2 OR nt.file_path LIKE ?3)) "
            "GROUP BY e.type ORDER BY COUNT(*) DESC;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(s->db, esql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
            cbm_store_schema_free(out);
            return CBM_NOT_FOUND;
        }
        bind_text(stmt, SKIP_ONE, project);
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);

        int cap = ST_INIT_CAP_8;
        int n = 0;
        cbm_type_count_t *arr = malloc(cap * sizeof(cbm_type_count_t));
        if (!arr) {
            sqlite3_finalize(stmt);
            cbm_store_schema_free(out);
            return CBM_NOT_FOUND;
        }
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (n >= cap) {
                int new_cap = cap * ST_GROWTH;
                void *tmp = realloc(arr, new_cap * sizeof(cbm_type_count_t));
                if (!tmp) {
                    for (int i = 0; i < n; i++) {
                        safe_str_free(&arr[i].type);
                    }
                    free(arr);
                    sqlite3_finalize(stmt);
                    cbm_store_schema_free(out);
                    return CBM_NOT_FOUND;
                }
                arr = tmp;
                cap = new_cap;
            }
            arr[n].type = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
            arr[n].count = sqlite3_column_int(stmt, SKIP_ONE);
            arr[n].properties = NULL;
            arr[n].property_count = 0;
            n++;
        }
        sqlite3_finalize(stmt);
        out->edge_types = arr;
        out->edge_type_count = n;
    }

    return CBM_STORE_OK;
}

void cbm_store_schema_free(cbm_schema_info_t *out) {
    if (!out) {
        return;
    }
    for (int i = 0; i < out->node_label_count; i++) {
        safe_str_free(&out->node_labels[i].label);
        for (int j = 0; j < out->node_labels[i].property_count; j++) {
            free(out->node_labels[i].properties[j]);
        }
        free(out->node_labels[i].properties);
    }
    free(out->node_labels);

    for (int i = 0; i < out->edge_type_count; i++) {
        safe_str_free(&out->edge_types[i].type);
        for (int j = 0; j < out->edge_types[i].property_count; j++) {
            free(out->edge_types[i].properties[j]);
        }
        free(out->edge_types[i].properties);
    }
    free(out->edge_types);

    for (int i = 0; i < out->rel_pattern_count; i++) {
        safe_str_free(&out->rel_patterns[i]);
    }
    free(out->rel_patterns);

    for (int i = 0; i < out->sample_func_count; i++) {
        safe_str_free(&out->sample_func_names[i]);
    }
    free(out->sample_func_names);

    for (int i = 0; i < out->sample_class_count; i++) {
        safe_str_free(&out->sample_class_names[i]);
    }
    free(out->sample_class_names);

    for (int i = 0; i < out->sample_qn_count; i++) {
        safe_str_free(&out->sample_qns[i]);
    }
    free(out->sample_qns);

    memset(out, 0, sizeof(*out));
}

/* ── Architecture helpers ───────────────────────────────────────── */

/* Extract sub-package from QN: project.dir1.dir2.sym → dir1 (4+ parts → [2], else [1]) */
const char *cbm_qn_to_package(const char *qn) {
    if (!qn || !qn[0]) {
        return "";
    }
    static CBM_TLS char buf[CBM_SZ_256];
    /* Find dots and extract segment */
    const char *dots[ST_QN_MAX_DOTS] = {NULL};
    int ndots = 0;
    for (const char *p = qn; *p && ndots < ST_QN_MAX_DOTS; p++) {
        if (*p == '.') {
            dots[ndots++] = p;
        }
    }
    /* 4+ segments: return segment[2] */
    if (ndots >= ST_QN_MIN_DOTS) {
        const char *start = dots[SKIP_ONE] + SKIP_ONE;
        int len = (int)(dots[ST_COL_2] - start);
        if (len > 0 && len < (int)sizeof(buf)) {
            memcpy(buf, start, len);
            buf[len] = '\0';
            return buf;
        }
    }
    /* 2+ segments: return segment[1] */
    if (ndots >= SKIP_ONE) {
        const char *start = dots[0] + SKIP_ONE;
        const char *end = (ndots >= ST_COL_2) ? dots[SKIP_ONE] : qn + strlen(qn);
        int len = (int)(end - start);
        if (len > 0 && len < (int)sizeof(buf)) {
            memcpy(buf, start, len);
            buf[len] = '\0';
            return buf;
        }
    }
    return "";
}

/* Extract top-level package from QN: project.dir1.rest → dir1 (segment[1]) */
const char *cbm_qn_to_top_package(const char *qn) {
    if (!qn || !qn[0]) {
        return "";
    }
    static CBM_TLS char buf[CBM_SZ_256];
    const char *first_dot = strchr(qn, '.');
    if (!first_dot) {
        return "";
    }
    const char *start = first_dot + SKIP_ONE;
    const char *second_dot = strchr(start, '.');
    const char *end = second_dot ? second_dot : qn + strlen(qn);
    int len = (int)(end - start);
    if (len > 0 && len < (int)sizeof(buf)) {
        memcpy(buf, start, len);
        buf[len] = '\0';
        return buf;
    }
    return "";
}

bool cbm_is_test_file_path(const char *fp) {
    if (!fp || fp[0] == '\0') {
        return false;
    }
    return strstr(fp, "test") != NULL;
}

/* File extension → language name mapping (table-driven) */
typedef struct {
    const char *ext;
    const char *lang;
} ext_lang_entry_t;

static const ext_lang_entry_t ext_lang_table[] = {
    {".py", "Python"},     {".go", "Go"},          {".js", "JavaScript"}, {".jsx", "JavaScript"},
    {".ts", "TypeScript"}, {".tsx", "TypeScript"}, {".rs", "Rust"},       {".java", "Java"},
    {".cpp", "C++"},       {".cc", "C++"},         {".cxx", "C++"},       {".c", "C"},
    {".h", "C"},           {".cs", "C#"},          {".php", "PHP"},       {".lua", "Lua"},
    {".scala", "Scala"},   {".kt", "Kotlin"},      {".rb", "Ruby"},       {".sh", "Bash"},
    {".bash", "Bash"},     {".zig", "Zig"},        {".ex", "Elixir"},     {".exs", "Elixir"},
    {".hs", "Haskell"},    {".ml", "OCaml"},       {".mli", "OCaml"},     {".html", "HTML"},
    {".css", "CSS"},       {".yaml", "YAML"},      {".yml", "YAML"},      {".toml", "TOML"},
    {".hcl", "HCL"},       {".tf", "HCL"},         {".sql", "SQL"},       {".erl", "Erlang"},
    {".swift", "Swift"},   {".dart", "Dart"},      {".groovy", "Groovy"}, {".pl", "Perl"},
    {".r", "R"},           {".scss", "SCSS"},      {".vue", "Vue"},       {".svelte", "Svelte"},
    {NULL, NULL},
};

static const char *ext_to_lang(const char *ext) {
    if (!ext) {
        return NULL;
    }
    for (const ext_lang_entry_t *e = ext_lang_table; e->ext; e++) {
        if (strcmp(ext, e->ext) == 0) {
            return e->lang;
        }
    }
    return NULL;
}

/* Get lowercase file extension from path */
static const char *file_ext(const char *path) {
    if (!path) {
        return NULL;
    }
    const char *dot = strrchr(path, '.');
    if (!dot) {
        return NULL;
    }
    static CBM_TLS char buf[CBM_SZ_16];
    int len = (int)strlen(dot);
    if (len >= (int)sizeof(buf)) {
        return NULL;
    }
    for (int i = 0; i < len; i++) {
        buf[i] = (char)((dot[i] >= 'A' && dot[i] <= 'Z') ? dot[i] + CBM_SZ_32 : dot[i]);
    }
    buf[len] = '\0';
    return buf;
}

/* ── Architecture aspect implementations ───────────────────────── */

static int arch_languages(cbm_store_t *s, const char *project, const char *path,
                          cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT file_path FROM nodes WHERE project=?1 AND label='File'";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s", base, arch_path_scope_sql());
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_languages");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    /* Count per language using a simple parallel array */
    const char *lang_names[CBM_SZ_64];
    int lang_counts[CBM_SZ_64];
    int nlang = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        const char *ext = file_ext(fp);
        const char *lang = ext_to_lang(ext);
        if (!lang) {
            continue;
        }
        int found = ST_FOUND;
        for (int i = 0; i < nlang; i++) {
            if (strcmp(lang_names[i], lang) == 0) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            lang_counts[found]++;
        } else if (nlang < CBM_SZ_64) {
            lang_names[nlang] = lang;
            lang_counts[nlang] = SKIP_ONE;
            nlang++;
        }
    }
    sqlite3_finalize(stmt);

    /* Sort by count descending (simple insertion sort) */
    for (int i = SKIP_ONE; i < nlang; i++) {
        int j = i;
        while (j > 0 && lang_counts[j] > lang_counts[j - SKIP_ONE]) {
            int tc = lang_counts[j];
            lang_counts[j] = lang_counts[j - SKIP_ONE];
            lang_counts[j - SKIP_ONE] = tc;
            const char *tn = lang_names[j];
            lang_names[j] = lang_names[j - SKIP_ONE];
            lang_names[j - SKIP_ONE] = tn;
            j--;
        }
    }
    if (nlang > CBM_DECIMAL_BASE) {
        nlang = ST_MAX_LANG;
    }

    out->languages = (nlang > 0) ? calloc(nlang, sizeof(cbm_language_count_t)) : NULL;
    out->language_count = nlang;
    for (int i = 0; i < nlang; i++) {
        out->languages[i].language = heap_strdup(lang_names[i]);
        out->languages[i].file_count = lang_counts[i];
    }
    return CBM_STORE_OK;
}

static int arch_entry_points(cbm_store_t *s, const char *project, const char *path,
                             cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT name, qualified_name, file_path FROM nodes "
                       "WHERE project=?1 AND json_extract(properties, '$.is_entry_point') = 1 "
                       "AND (json_extract(properties, '$.is_test') IS NULL OR "
                       "json_extract(properties, '$.is_test') != 1) "
                       "AND file_path NOT LIKE '%test%'";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s LIMIT 20", base, arch_path_scope_sql());
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s LIMIT 20", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_entry_points");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int cap = 0;
    int n = 0;
    cbm_entry_point_t *arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "architecture entry points") != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                free((void *)arr[i].name);
                free((void *)arr[i].qualified_name);
                free((void *)arr[i].file);
            }
            free(arr);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].name = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        arr[n].qualified_name = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
        arr[n].file = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
        if (!arr[n].name || !arr[n].qualified_name || !arr[n].file) {
            for (int i = 0; i <= n; i++) {
                free((void *)arr[i].name);
                free((void *)arr[i].qualified_name);
                free((void *)arr[i].file);
            }
            free(arr);
            store_set_error(s, "architecture entry point row allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            free((void *)arr[i].name);
            free((void *)arr[i].qualified_name);
            free((void *)arr[i].file);
        }
        free(arr);
        store_set_error_sqlite(s, "architecture entry points step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    out->entry_points = arr;
    out->entry_point_count = n;
    return CBM_STORE_OK;
}

/* Extract a JSON string value from a simple JSON object by key name. */
static char *extract_json_string_prop(const char *json, const char *key, int key_len) {
    if (!json) {
        return NULL;
    }
    const char *m = strstr(json, key);
    if (!m) {
        return NULL;
    }
    m = strchr(m + key_len, '"');
    if (!m) {
        return NULL;
    }
    m++;
    const char *end = strchr(m, '"');
    if (!end || end - m >= CBM_SZ_256) {
        return NULL;
    }
    char vbuf[CBM_SZ_256];
    memcpy(vbuf, m, end - m);
    vbuf[end - m] = '\0';
    return heap_strdup(vbuf);
}

static int arch_routes(cbm_store_t *s, const char *project, const char *path,
                       cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT name, properties, COALESCE(file_path, '') FROM nodes "
                       "WHERE project=?1 AND label='Route' "
                       "AND (json_extract(properties, '$.is_test') IS NULL OR "
                       "json_extract(properties, '$.is_test') != 1)";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s LIMIT 20", base, arch_path_scope_sql());
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s LIMIT 20", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_routes");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int cap = 0;
    int n = 0;
    cbm_route_info_t *arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        const char *props = (const char *)sqlite3_column_text(stmt, SKIP_ONE);
        const char *fp = (const char *)sqlite3_column_text(stmt, CBM_SZ_2);
        if (cbm_is_test_file_path(fp)) {
            continue;
        }
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "architecture routes") != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                free((void *)arr[i].method);
                free((void *)arr[i].path);
                free((void *)arr[i].handler);
            }
            free(arr);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }

        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].method = heap_strdup("");
        arr[n].path = heap_strdup(name);
        arr[n].handler = heap_strdup("");
        if (!arr[n].method || !arr[n].path || !arr[n].handler) {
            for (int i = 0; i <= n; i++) {
                free((void *)arr[i].method);
                free((void *)arr[i].path);
                free((void *)arr[i].handler);
            }
            free(arr);
            store_set_error(s, "architecture route row allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }

        char *val;
        val = extract_json_string_prop(props, "\"method\"", ST_METHOD_PROP_LEN);
        if (val) {
            safe_str_free(&arr[n].method);
            arr[n].method = val;
        }
        val = extract_json_string_prop(props, "\"path\"", ST_PATH_PROP_LEN);
        if (val) {
            safe_str_free(&arr[n].path);
            arr[n].path = val;
        }
        val = extract_json_string_prop(props, "\"handler\"", ST_HANDLER_PROP_LEN);
        if (val) {
            safe_str_free(&arr[n].handler);
            arr[n].handler = val;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            free((void *)arr[i].method);
            free((void *)arr[i].path);
            free((void *)arr[i].handler);
        }
        free(arr);
        store_set_error_sqlite(s, "architecture routes step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    out->routes = arr;
    out->route_count = n;
    return CBM_STORE_OK;
}

static int arch_hotspots(cbm_store_t *s, const char *project, const char *path,
                         cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT n.name, n.qualified_name, COUNT(*) as fan_in "
                       "FROM nodes n JOIN edges e ON e.target_id = n.id AND e.type = 'CALLS' "
                       "WHERE n.project=?1 AND n.label IN ('Function', 'Method') "
                       "AND (json_extract(n.properties, '$.is_test') IS NULL OR "
                       "json_extract(n.properties, '$.is_test') != 1) "
                       "AND n.file_path NOT LIKE '%test%'";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf),
                 "%s AND (n.file_path = ?2 OR n.file_path LIKE ?3) "
                 "GROUP BY n.id ORDER BY fan_in DESC LIMIT 10",
                 base);
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s GROUP BY n.id ORDER BY fan_in DESC LIMIT 10", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_hotspots");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int cap = 0;
    int n = 0;
    cbm_hotspot_t *arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "architecture hotspots") != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                free((void *)arr[i].name);
                free((void *)arr[i].qualified_name);
            }
            free(arr);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].name = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        arr[n].qualified_name = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
        arr[n].fan_in = sqlite3_column_int(stmt, CBM_SZ_2);
        if (!arr[n].name || !arr[n].qualified_name) {
            for (int i = 0; i <= n; i++) {
                free((void *)arr[i].name);
                free((void *)arr[i].qualified_name);
            }
            free(arr);
            store_set_error(s, "architecture hotspot row allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            free((void *)arr[i].name);
            free((void *)arr[i].qualified_name);
        }
        free(arr);
        store_set_error_sqlite(s, "architecture hotspots step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    out->hotspots = arr;
    out->hotspot_count = n;
    return CBM_STORE_OK;
}

/* Look up package name for a node ID in the parallel arrays. nids must be
 * sorted ascending (the node query orders by id) — a linear scan here is
 * O(E×N) across the edge loop and spun for >10 minutes on Linux-kernel-sized
 * graphs (~1.4M defs × ~1.4M CALLS edges). */
static const char *lookup_pkg(const int64_t *nids, char **npkgs, int nn, int64_t id) {
    int lo = 0;
    int hi = nn - SKIP_ONE;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / PAIR_LEN;
        if (nids[mid] == id) {
            return npkgs[mid];
        }
        if (nids[mid] < id) {
            lo = mid + SKIP_ONE;
        } else {
            hi = mid - SKIP_ONE;
        }
    }
    return NULL;
}

/* Accumulate a cross-package boundary into parallel arrays. */
static bool accum_boundary(const char *src_pkg, const char *tgt_pkg, char **bfroms, char **btos,
                           int *bcounts, int *bn, int bcap) {
    int found = ST_FOUND;
    for (int i = 0; i < *bn; i++) {
        if (strcmp(bfroms[i], src_pkg) == 0 && strcmp(btos[i], tgt_pkg) == 0) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        bcounts[found]++;
        return true;
    } else if (*bn < bcap) {
        char *from = heap_strdup(src_pkg);
        char *to = heap_strdup(tgt_pkg);
        if (!from || !to) {
            free(from);
            free(to);
            return false;
        }
        bfroms[*bn] = from;
        btos[*bn] = to;
        bcounts[*bn] = SKIP_ONE;
        (*bn)++;
    }
    return true;
}

static int arch_boundaries(cbm_store_t *s, const char *project, const char *path,
                           cbm_cross_pkg_boundary_t **out_arr, int *out_count) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char nsqlbuf[ST_SQL_BUF];
    const char *nbase =
        "SELECT id, qualified_name, file_path FROM nodes WHERE project=?1 AND label IN "
        "('Function','Method','Class')";
    if (scoped) {
        snprintf(nsqlbuf, sizeof(nsqlbuf), "%s%s ORDER BY id", nbase, arch_path_scope_sql());
    } else {
        snprintf(nsqlbuf, sizeof(nsqlbuf), "%s ORDER BY id", nbase);
    }
    sqlite3_stmt *nstmt = NULL;
    if (sqlite3_prepare_v2(s->db, nsqlbuf, CBM_NOT_FOUND, &nstmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_boundaries_nodes");
        return CBM_STORE_ERR;
    }
    bind_text(nstmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(nstmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int nid_cap = 0;
    int pkg_cap = 0;
    int nn = 0;
    int64_t *nids = NULL;
    char **npkgs = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(nstmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&nids, &nid_cap, nn + 1, sizeof(*nids),
                                "architecture boundary node ids") != CBM_STORE_OK ||
            store_array_reserve(s, (void **)&npkgs, &pkg_cap, nn + 1, sizeof(*npkgs),
                                "architecture boundary packages") != CBM_STORE_OK) {
            store_free_strings(npkgs, nn);
            free(nids);
            sqlite3_finalize(nstmt);
            return CBM_STORE_ERR;
        }
        int64_t nid = sqlite3_column_int64(nstmt, 0);
        nids[nn] = nid;
        const char *qn = (const char *)sqlite3_column_text(nstmt, SKIP_ONE);
        npkgs[nn] = heap_strdup(cbm_qn_to_package(qn));
        if (!npkgs[nn]) {
            store_free_strings(npkgs, nn);
            free(nids);
            store_set_error(s, "architecture boundary package allocation failed");
            sqlite3_finalize(nstmt);
            return CBM_STORE_ERR;
        }
        nn++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings(npkgs, nn);
        free(nids);
        store_set_error_sqlite(s, "architecture boundary nodes step");
        sqlite3_finalize(nstmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(nstmt);

    /* Scan edges, count cross-package calls */
    const char *esql = "SELECT source_id, target_id FROM edges WHERE project=?1 AND type='CALLS'";
    sqlite3_stmt *estmt = NULL;
    if (sqlite3_prepare_v2(s->db, esql, CBM_NOT_FOUND, &estmt, NULL) != SQLITE_OK) {
        for (int i = 0; i < nn; i++) {
            free(npkgs[i]);
        }
        free(nids);
        free(npkgs);
        store_set_error_sqlite(s, "arch_boundaries_edges");
        return CBM_STORE_ERR;
    }
    bind_text(estmt, SKIP_ONE, project);

    int bcap = CBM_SZ_32;
    int bn = 0;
    char **bfroms = calloc((size_t)bcap, sizeof(char *));
    char **btos = calloc((size_t)bcap, sizeof(char *));
    int *bcounts = calloc((size_t)bcap, sizeof(int));
    if (!bfroms || !btos || !bcounts) {
        free(bfroms);
        free(btos);
        free(bcounts);
        store_free_strings(npkgs, nn);
        free(nids);
        sqlite3_finalize(estmt);
        store_set_error(s, "architecture boundary accumulator allocation failed");
        return CBM_STORE_ERR;
    }

    step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(estmt)) == SQLITE_ROW) {
        int64_t src_id = sqlite3_column_int64(estmt, 0);
        int64_t tgt_id = sqlite3_column_int64(estmt, SKIP_ONE);
        const char *src_pkg = lookup_pkg(nids, npkgs, nn, src_id);
        const char *tgt_pkg = lookup_pkg(nids, npkgs, nn, tgt_id);
        if (!src_pkg || !tgt_pkg || !src_pkg[0] || !tgt_pkg[0] || strcmp(src_pkg, tgt_pkg) == 0) {
            continue;
        }
        if (!accum_boundary(src_pkg, tgt_pkg, bfroms, btos, bcounts, &bn, bcap)) {
            store_free_strings(bfroms, bn);
            store_free_strings(btos, bn);
            free(bcounts);
            store_free_strings(npkgs, nn);
            free(nids);
            store_set_error(s, "architecture boundary row allocation failed");
            sqlite3_finalize(estmt);
            return CBM_STORE_ERR;
        }
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings(bfroms, bn);
        store_free_strings(btos, bn);
        free(bcounts);
        store_free_strings(npkgs, nn);
        free(nids);
        store_set_error_sqlite(s, "architecture boundary edges step");
        sqlite3_finalize(estmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(estmt);
    for (int i = 0; i < nn; i++) {
        free(npkgs[i]);
    }
    free(nids);
    free(npkgs);

    /* Sort by count descending */
    for (int i = SKIP_ONE; i < bn; i++) {
        int j = i;
        while (j > 0 && bcounts[j] > bcounts[j - SKIP_ONE]) {
            int tc = bcounts[j];
            bcounts[j] = bcounts[j - SKIP_ONE];
            bcounts[j - SKIP_ONE] = tc;
            char *tf = bfroms[j];
            bfroms[j] = bfroms[j - SKIP_ONE];
            bfroms[j - SKIP_ONE] = tf;
            char *tt = btos[j];
            btos[j] = btos[j - SKIP_ONE];
            btos[j - SKIP_ONE] = tt;
            j--;
        }
    }
    if (bn > CBM_DECIMAL_BASE) {
        for (int i = ST_MAX_ITERATIONS; i < bn; i++) {
            free(bfroms[i]);
            free(btos[i]);
        }
        bn = ST_MAX_ITERATIONS;
    }

    cbm_cross_pkg_boundary_t *result =
        (bn > 0) ? calloc(bn, sizeof(cbm_cross_pkg_boundary_t)) : NULL;
    if (bn > 0 && !result) {
        store_free_strings(bfroms, bn);
        store_free_strings(btos, bn);
        free(bcounts);
        store_set_error(s, "architecture boundary result allocation failed");
        return CBM_STORE_ERR;
    }
    for (int i = 0; i < bn; i++) {
        result[i].from = bfroms[i];
        result[i].to = btos[i];
        result[i].call_count = bcounts[i];
    }
    free(bfroms);
    free(btos);
    free(bcounts);
    *out_arr = result;
    *out_count = bn;
    return CBM_STORE_OK;
}

#define MAX_PREVIEW_NAMES 15

/* Fallback: derive packages from QN segments when no Package nodes exist. */
static int arch_packages_from_qn(cbm_store_t *s, const char *project, const char *path,
                                 cbm_package_summary_t **out_arr, int *out_count) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char qsqlbuf[ST_SQL_BUF];
    const char *qbase = "SELECT qualified_name FROM nodes WHERE project=?1 AND label IN "
                        "('Function','Method','Class')";
    if (scoped) {
        snprintf(qsqlbuf, sizeof(qsqlbuf), "%s%s", qbase, arch_path_scope_sql());
    } else {
        snprintf(qsqlbuf, sizeof(qsqlbuf), "%s", qbase);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, qsqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_packages_qn");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    char *pnames[CBM_SZ_64];
    int pcounts[CBM_SZ_64];
    int np = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *qn = (const char *)sqlite3_column_text(stmt, 0);
        const char *pkg = cbm_qn_to_package(qn);
        if (!pkg[0]) {
            continue;
        }
        int found = ST_FOUND;
        for (int i = 0; i < np; i++) {
            if (strcmp(pnames[i], pkg) == 0) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            pcounts[found]++;
        } else if (np < CBM_SZ_64) {
            pnames[np] = heap_strdup(pkg);
            pcounts[np] = SKIP_ONE;
            np++;
        }
    }
    sqlite3_finalize(stmt);

    /* Sort by count desc */
    for (int i = SKIP_ONE; i < np; i++) {
        int j = i;
        while (j > 0 && pcounts[j] > pcounts[j - SKIP_ONE]) {
            int tc = pcounts[j];
            pcounts[j] = pcounts[j - SKIP_ONE];
            pcounts[j - SKIP_ONE] = tc;
            char *tn = pnames[j];
            pnames[j] = pnames[j - SKIP_ONE];
            pnames[j - SKIP_ONE] = tn;
            j--;
        }
    }
    if (np > MAX_PREVIEW_NAMES) {
        for (int i = MAX_PREVIEW_NAMES; i < np; i++) {
            free(pnames[i]);
        }
        np = MAX_PREVIEW_NAMES;
    }

    cbm_package_summary_t *arr = (np > 0) ? calloc(np, sizeof(cbm_package_summary_t)) : NULL;
    for (int i = 0; i < np; i++) {
        arr[i].name = pnames[i];
        arr[i].node_count = pcounts[i];
    }
    *out_arr = arr;
    *out_count = np;
    return CBM_STORE_OK;
}

static int arch_packages(cbm_store_t *s, const char *project, const char *path,
                         cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT n.name, COUNT(*) as cnt FROM nodes n "
                       "WHERE n.project=?1 AND n.label='Package'";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf),
                 "%s AND (n.file_path = ?2 OR n.file_path LIKE ?3) "
                 "GROUP BY n.name ORDER BY cnt DESC LIMIT 15",
                 base);
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s GROUP BY n.name ORDER BY cnt DESC LIMIT 15", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_packages");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int cap = 0;
    int n = 0;
    cbm_package_summary_t *arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "architecture packages") != CBM_STORE_OK) {
            for (int i = 0; i < n; i++) {
                free((void *)arr[i].name);
            }
            free(arr);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].name = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        arr[n].node_count = sqlite3_column_int(stmt, SKIP_ONE);
        if (!arr[n].name) {
            for (int i = 0; i < n; i++) {
                free((void *)arr[i].name);
            }
            free(arr);
            store_set_error(s, "architecture package row allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        for (int i = 0; i < n; i++) {
            free((void *)arr[i].name);
        }
        free(arr);
        store_set_error_sqlite(s, "architecture packages step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);

    /* Fallback: group by QN segment if no Package nodes */
    if (n == 0) {
        free(arr);
        int rc = arch_packages_from_qn(s, project, path, &arr, &n);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }

    out->packages = arr;
    out->package_count = n;
    return CBM_STORE_OK;
}

static void classify_layer(const char *pkg, int in, int out_deg, bool has_routes,
                           bool has_entry_points, const char **layer, const char **reason) {
    static CBM_TLS char reason_buf[CBM_SZ_128];
    if (has_entry_points && out_deg > 0 && in == 0) {
        *layer = "entry";
        *reason = "has entry points, only outbound calls";
        return;
    }
    if (has_routes) {
        *layer = "api";
        *reason = "has HTTP route definitions";
        return;
    }
    if (in > out_deg && in > ST_MIN_INDEGREE) {
        snprintf(reason_buf, sizeof(reason_buf), "high fan-in (%d in, %d out)", in, out_deg);
        *layer = "core";
        *reason = reason_buf;
        return;
    }
    if (out_deg == 0 && in > 0) {
        *layer = "leaf";
        *reason = "only inbound calls, no outbound";
        return;
    }
    if (in == 0 && out_deg > 0) {
        *layer = "entry";
        *reason = "only outbound calls";
        return;
    }
    snprintf(reason_buf, sizeof(reason_buf), "fan-in=%d, fan-out=%d", in, out_deg);
    *layer = "internal";
    *reason = reason_buf;
    (void)pkg;
}

/* Find or insert a package name, returning its index. Returns -1 if full. */
static int find_or_add_pkg(char **all_pkgs, int *npkgs, int max_pkgs, const char *pkg) {
    for (int j = 0; j < *npkgs; j++) {
        if (strcmp(all_pkgs[j], pkg) == 0) {
            return j;
        }
    }
    if (*npkgs < max_pkgs) {
        int idx = *npkgs;
        all_pkgs[idx] = heap_strdup(pkg);
        (*npkgs)++;
        return idx;
    }
    return CBM_NOT_FOUND;
}

/* Check if a package name appears in an array. */
static bool pkg_in_list(const char *pkg, char **list, int count) {
    for (int j = 0; j < count; j++) {
        if (strcmp(pkg, list[j]) == 0) {
            return true;
        }
    }
    return false;
}

/* Collect package names from nodes matching a SQL query (must use ?1 = project). */
static int collect_pkg_names(cbm_store_t *s, const char *sql, const char *project, const char *path,
                             char **pkgs, int max_pkgs) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s", sql, arch_path_scope_sql());
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s", sql);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK || !stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
        }
        return CBM_NOT_FOUND;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_pkgs) {
        const char *qn = (const char *)sqlite3_column_text(stmt, 0);
        pkgs[count++] = heap_strdup(cbm_qn_to_package(qn));
    }
    sqlite3_finalize(stmt);
    return count;
}

static int arch_layers(cbm_store_t *s, const char *project, const char *path,
                       cbm_architecture_info_t *out) {
    /* Get boundaries for fan analysis */
    cbm_cross_pkg_boundary_t *boundaries = NULL;
    int bcount = 0;
    int rc = arch_boundaries(s, project, path, &boundaries, &bcount);
    if (rc != CBM_STORE_OK) {
        return rc;
    }

    /* Collect route and entry point packages */
    char *route_pkgs[CBM_SZ_32];
    int nrpkgs =
        collect_pkg_names(s, "SELECT qualified_name FROM nodes WHERE project=?1 AND label='Route'",
                          project, path, route_pkgs, CBM_SZ_32);

    char *entry_pkgs[CBM_SZ_32];
    int nepkgs = collect_pkg_names(s,
                                   "SELECT qualified_name FROM nodes WHERE project=?1 AND "
                                   "json_extract(properties, '$.is_entry_point') = 1",
                                   project, path, entry_pkgs, CBM_SZ_32);

    /* Compute fan-in/out per package */
    char *all_pkgs[CBM_SZ_64];
    int fan_in[CBM_SZ_64];
    int fan_out[CBM_SZ_64];
    int npkgs = 0;
    memset(fan_in, 0, sizeof(fan_in));
    memset(fan_out, 0, sizeof(fan_out));

    for (int i = 0; i < bcount; i++) {
        int fi = find_or_add_pkg(all_pkgs, &npkgs, ST_MAX_PKGS, boundaries[i].from);
        if (fi >= 0) {
            fan_out[fi] += boundaries[i].call_count;
        }
        int ti = find_or_add_pkg(all_pkgs, &npkgs, ST_MAX_PKGS, boundaries[i].to);
        if (ti >= 0) {
            fan_in[ti] += boundaries[i].call_count;
        }
    }

    /* Also include route/entry packages */
    for (int i = 0; i < nrpkgs; i++) {
        find_or_add_pkg(all_pkgs, &npkgs, ST_MAX_PKGS, route_pkgs[i]);
    }
    for (int i = 0; i < nepkgs; i++) {
        find_or_add_pkg(all_pkgs, &npkgs, ST_MAX_PKGS, entry_pkgs[i]);
    }

    /* Classify each package */
    out->layers = (npkgs > 0) ? calloc(npkgs, sizeof(cbm_package_layer_t)) : NULL;
    out->layer_count = npkgs;
    for (int i = 0; i < npkgs; i++) {
        bool has_route = pkg_in_list(all_pkgs[i], route_pkgs, nrpkgs);
        bool has_entry = pkg_in_list(all_pkgs[i], entry_pkgs, nepkgs);
        const char *layer;
        const char *reason;
        classify_layer(all_pkgs[i], fan_in[i], fan_out[i], has_route, has_entry, &layer, &reason);
        out->layers[i].name = all_pkgs[i]; /* transfer ownership */
        out->layers[i].layer = heap_strdup(layer);
        out->layers[i].reason = heap_strdup(reason);
    }

    /* Sort layers by name */
    for (int i = SKIP_ONE; i < npkgs; i++) {
        int j = i;
        while (j > 0 && strcmp(out->layers[j].name, out->layers[j - SKIP_ONE].name) < 0) {
            cbm_package_layer_t tmp = out->layers[j];
            out->layers[j] = out->layers[j - SKIP_ONE];
            out->layers[j - SKIP_ONE] = tmp;
            j--;
        }
    }

    /* Cleanup */
    for (int i = 0; i < bcount; i++) {
        safe_str_free(&boundaries[i].from);
        safe_str_free(&boundaries[i].to);
    }
    free(boundaries);
    for (int i = 0; i < nrpkgs; i++) {
        free(route_pkgs[i]);
    }
    for (int i = 0; i < nepkgs; i++) {
        free(entry_pkgs[i]);
    }

    return CBM_STORE_OK;
}

/* Add a child to a dir entry if not already present. */
static bool dir_add_child(char ***children, int *child_count, int *child_cap, const char *child) {
    for (int k = 0; k < *child_count; k++) {
        if (strcmp((*children)[k], child) == 0) {
            return true;
        }
    }
    if (!cbm_da_ensure_capacity((void **)children, child_cap, *child_count + 1,
                                sizeof(**children))) {
        return false;
    }
    char *copy = heap_strdup(child);
    if (!copy) {
        return false;
    }
    (*children)[(*child_count)++] = copy;
    return true;
}

/* Find or create a directory entry by path. Returns its index, or -1 if full. */
static int dir_find_or_create(char **dir_paths, int *dir_child_counts, char ***dir_children,
                              int *dir_children_caps, int *dn, int dcap, const char *dir) {
    for (int i = 0; i < *dn; i++) {
        if (strcmp(dir_paths[i], dir) == 0) {
            return i;
        }
    }
    if (*dn < dcap) {
        int idx = *dn;
        dir_paths[idx] = heap_strdup(dir);
        if (!dir_paths[idx]) {
            return CBM_NOT_FOUND;
        }
        dir_child_counts[idx] = 0;
        dir_children[idx] = NULL;
        dir_children_caps[idx] = 0;
        (*dn)++;
        return idx;
    }
    return CBM_NOT_FOUND;
}

/* Create a file tree entry by checking if a path is a file and counting dir children. */
static cbm_file_tree_entry_t make_tree_entry(const char *path, char **files, int fn,
                                             char **dir_paths, const int *dir_child_counts,
                                             int dn) {
    cbm_file_tree_entry_t e = {0};
    e.path = heap_strdup(path);
    bool is_file = false;
    for (int f = 0; f < fn; f++) {
        if (strcmp(files[f], path) == 0) {
            is_file = true;
            break;
        }
    }
    e.type = heap_strdup(is_file ? "file" : "dir");
    for (int d = 0; d < dn; d++) {
        if (strcmp(dir_paths[d], path) == 0) {
            e.children = dir_child_counts[d];
            break;
        }
    }
    return e;
}

/* Split a path by '/' into parts. Returns number of parts. */
static int split_path_parts(const char *fp, char *buf, int buf_sz, char **parts, int max_parts) {
    strncpy(buf, fp, buf_sz - SKIP_ONE);
    buf[buf_sz - SKIP_ONE] = '\0';
    int nparts = 0;
    char *p = buf;
    parts[nparts++] = p;
    while (*p && nparts < max_parts) {
        if (*p == '/') {
            *p = '\0';
            parts[nparts++] = p + SKIP_ONE;
        }
        p++;
    }
    return nparts;
}

/* Register dir hierarchy for one file path. */
static bool arch_register_file_dirs(const char *fp, char **dir_paths, int *dir_child_counts,
                                    char ***dir_children, int *dir_children_caps, int *dn,
                                    int dcap) {
    char tmp[CBM_SZ_512];
    char *parts[ST_SEARCH_MAX_BINDS];
    int nparts = split_path_parts(fp, tmp, (int)sizeof(tmp), parts, ST_SEARCH_MAX_BINDS);

    int ri = dir_find_or_create(dir_paths, dir_child_counts, dir_children, dir_children_caps, dn,
                                dcap, "");
    if (ri < 0 || (nparts > 0 && !dir_add_child(&dir_children[ri], &dir_child_counts[ri],
                                                &dir_children_caps[ri], parts[0]))) {
        return false;
    }

    for (int depth = 0; depth < nparts - SKIP_ONE && depth < ST_MAX_PATH_DEPTH; depth++) {
        char dir[CBM_SZ_512] = "";
        for (int k = 0; k <= depth; k++) {
            if (k > 0) {
                strcat(dir, "/");
            }
            strcat(dir, parts[k]);
        }
        const char *child = (depth + SKIP_ONE < nparts) ? parts[depth + SKIP_ONE] : NULL;
        if (!child) {
            continue;
        }
        int di = dir_find_or_create(dir_paths, dir_child_counts, dir_children, dir_children_caps,
                                    dn, dcap, dir);
        if (di < 0 || !dir_add_child(&dir_children[di], &dir_child_counts[di],
                                     &dir_children_caps[di], child)) {
            return false;
        }
    }
    return true;
}

/* Count the number of '/' in a string. */
static int count_slashes(const char *s) {
    int n = 0;
    for (; *s; s++) {
        if (*s == '/') {
            n++;
        }
    }
    return n;
}

/* Push a tree entry, growing the array if needed. */
static int push_tree_entry(cbm_store_t *s, cbm_file_tree_entry_t **entries, int *en, int *ecap,
                           cbm_file_tree_entry_t e) {
    if (!e.path || !e.type ||
        store_array_reserve(s, (void **)entries, ecap, *en + 1, sizeof(**entries),
                            "architecture file tree") != CBM_STORE_OK) {
        free((void *)e.path);
        free((void *)e.type);
        return CBM_STORE_ERR;
    }
    (*entries)[(*en)++] = e;
    return CBM_STORE_OK;
}

/* Collect tree entries from dir arrays. */
static int arch_collect_entries(cbm_store_t *s, char **dir_paths, int *dir_child_counts,
                                char ***dir_children, int dn, char **files, int fn,
                                cbm_file_tree_entry_t **entries_out, int *en_out) {
    int ecap = 0;
    int en = 0;
    cbm_file_tree_entry_t *entries = NULL;

    /* Root children */
    for (int i = 0; i < dn; i++) {
        if (strcmp(dir_paths[i], "") != 0) {
            continue;
        }
        for (int k = 0; k < dir_child_counts[i]; k++) {
            if (push_tree_entry(s, &entries, &en, &ecap,
                                make_tree_entry(dir_children[i][k], files, fn, dir_paths,
                                                dir_child_counts, dn)) != CBM_STORE_OK) {
                goto failed;
            }
        }
    }

    /* Non-root dir children (depth < ST_COL_3) */
    for (int i = 0; i < dn; i++) {
        if (strcmp(dir_paths[i], "") == 0 || count_slashes(dir_paths[i]) >= ST_MAX_PATH_DEPTH) {
            continue;
        }
        for (int k = 0; k < dir_child_counts[i]; k++) {
            char path[CBM_SZ_512];
            snprintf(path, sizeof(path), "%s/%s", dir_paths[i], dir_children[i][k]);
            if (push_tree_entry(s, &entries, &en, &ecap,
                                make_tree_entry(path, files, fn, dir_paths, dir_child_counts,
                                                dn)) != CBM_STORE_OK) {
                goto failed;
            }
        }
    }

    /* Sort by path */
    for (int i = SKIP_ONE; i < en; i++) {
        int j = i;
        while (j > 0 && strcmp(entries[j].path, entries[j - SKIP_ONE].path) < 0) {
            cbm_file_tree_entry_t tmp = entries[j];
            entries[j] = entries[j - SKIP_ONE];
            entries[j - SKIP_ONE] = tmp;
            j--;
        }
    }

    *entries_out = entries;
    *en_out = en;
    return CBM_STORE_OK;

failed:
    for (int i = 0; i < en; i++) {
        free((void *)entries[i].path);
        free((void *)entries[i].type);
    }
    free(entries);
    return CBM_STORE_ERR;
}

/* Free dir arrays. */
static void arch_free_dirs(char **dir_paths, int *dir_child_counts, char ***dir_children,
                           int *dir_children_caps, int dn, char **files, int fn) {
    for (int i = 0; i < dn; i++) {
        free(dir_paths[i]);
        for (int k = 0; k < dir_child_counts[i]; k++) {
            free(dir_children[i][k]);
        }
        free(dir_children[i]);
    }
    free(dir_paths);
    free(dir_child_counts);
    free(dir_children);
    free(dir_children_caps);
    for (int i = 0; i < fn; i++) {
        free(files[i]);
    }
    free(files);
}

static int arch_file_tree(cbm_store_t *s, const char *project, const char *path,
                          cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char sqlbuf[ST_SQL_BUF];
    const char *base = "SELECT file_path FROM nodes WHERE project=?1 AND label='File'";
    if (scoped) {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s%s", base, arch_path_scope_sql());
    } else {
        snprintf(sqlbuf, sizeof(sqlbuf), "%s", base);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sqlbuf, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "arch_file_tree");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(stmt, ST_COL_2, ST_COL_3, norm, like);
    }

    int fcap = 0;
    int fn = 0;
    char **files = NULL;

    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        if (!fp) {
            continue;
        }
        if (store_array_reserve(s, (void **)&files, &fcap, fn + 1, sizeof(*files),
                                "architecture file paths") != CBM_STORE_OK) {
            store_free_strings(files, fn);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        files[fn] = heap_strdup(fp);
        if (!files[fn]) {
            store_free_strings(files, fn);
            store_set_error(s, "architecture file path allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        fn++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings(files, fn);
        store_set_error_sqlite(s, "architecture file tree step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);

    if ((size_t)fn > ((size_t)INT32_MAX - 1U) / ((size_t)ST_MAX_PATH_DEPTH + 1U)) {
        store_free_strings(files, fn);
        store_set_error(s, "architecture directory capacity overflow");
        return CBM_STORE_ERR;
    }
    int dcap = fn * (ST_MAX_PATH_DEPTH + 1) + 1;
    int dn = 0;
    char **dir_paths = calloc((size_t)dcap, sizeof(char *));
    int *dir_child_counts = calloc((size_t)dcap, sizeof(int));
    char ***dir_children = calloc((size_t)dcap, sizeof(char **));
    int *dir_children_caps = calloc((size_t)dcap, sizeof(int));
    if (!dir_paths || !dir_child_counts || !dir_children || !dir_children_caps) {
        arch_free_dirs(dir_paths, dir_child_counts, dir_children, dir_children_caps, dn, files, fn);
        store_set_error(s, "architecture directory table allocation failed");
        return CBM_STORE_ERR;
    }
    for (int i = 0; i < fn; i++) {
        if (!arch_register_file_dirs(files[i], dir_paths, dir_child_counts, dir_children,
                                     dir_children_caps, &dn, dcap)) {
            arch_free_dirs(dir_paths, dir_child_counts, dir_children, dir_children_caps, dn, files,
                           fn);
            store_set_error(s, "architecture directory registration allocation failed");
            return CBM_STORE_ERR;
        }
    }

    if (arch_collect_entries(s, dir_paths, dir_child_counts, dir_children, dn, files, fn,
                             &out->file_tree, &out->file_tree_count) != CBM_STORE_OK) {
        arch_free_dirs(dir_paths, dir_child_counts, dir_children, dir_children_caps, dn, files, fn);
        return CBM_STORE_ERR;
    }

    arch_free_dirs(dir_paths, dir_child_counts, dir_children, dir_children_caps, dn, files, fn);
    return CBM_STORE_OK;
}

/* ── Louvain community detection ───────────────────────────────── */

/* Build deduplicated, normalized edge weight arrays from raw edges.
 * Returns total number of unique edges in *out_wn. */
/* Find the index of a node ID in the nodes array, or -1. */
static int louvain_node_index(const int64_t *nodes, int n, int64_t id) {
    for (int i = 0; i < n; i++) {
        if (nodes[i] == id) {
            return i;
        }
    }
    return CBM_NOT_FOUND;
}

static int louvain_build_weights(const int64_t *nodes, int n, const cbm_louvain_edge_t *edges,
                                 int edge_count, int **out_wsi, int **out_wdi, double **out_ww,
                                 int *out_wn) {
    int wsi_cap = 0;
    int wdi_cap = 0;
    int ww_cap = 0;
    int wn = 0;
    int *wsi = NULL;
    int *wdi = NULL;
    double *ww = NULL;

    for (int e = 0; e < edge_count; e++) {
        int si = louvain_node_index(nodes, n, edges[e].src);
        int di = louvain_node_index(nodes, n, edges[e].dst);
        if (si < 0 || di < 0 || si == di) {
            continue;
        }
        if (si > di) {
            int tmp = si;
            si = di;
            di = tmp;
        }
        int found = ST_FOUND;
        for (int i = 0; i < wn; i++) {
            if (wsi[i] == si && wdi[i] == di) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            ww[found] += (double)SKIP_ONE;
        } else {
            if (!cbm_da_ensure_capacity((void **)&wsi, &wsi_cap, wn + 1, sizeof(*wsi)) ||
                !cbm_da_ensure_capacity((void **)&wdi, &wdi_cap, wn + 1, sizeof(*wdi)) ||
                !cbm_da_ensure_capacity((void **)&ww, &ww_cap, wn + 1, sizeof(*ww))) {
                free(wsi);
                free(wdi);
                free(ww);
                *out_wsi = NULL;
                *out_wdi = NULL;
                *out_ww = NULL;
                *out_wn = 0;
                cbm_log_error("store.leiden_weights", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED",
                              "message", "Leiden weight-array allocation failed", "remediation",
                              "free memory or reduce the graph scope, then retry; no clustering "
                              "result was returned");
                return CBM_STORE_ERR;
            }
            wsi[wn] = si;
            wdi[wn] = di;
            ww[wn] = (double)SKIP_ONE;
            wn++;
        }
    }
    *out_wsi = wsi;
    *out_wdi = wdi;
    *out_ww = ww;
    *out_wn = wn;
    return CBM_STORE_OK;
}

enum { LEIDEN_MAX_LEVELS = 64, LEIDEN_MOVE_PASS_CAP = 100 };

/* Weighted undirected graph in CSR form. Each undirected edge is stored as
 * two directed entries; k[i] is the weighted degree of node i. Self-loops are
 * never materialised — an aggregate node's intra-community weight is folded
 * into k[i] (which is preserved across levels), while nbr/w hold only
 * inter-community edges. The modularity gain therefore uses k[] for the
 * null-model term and nbr/w for connectivity, so intra weight affects the
 * degree but is never mistaken for an edge to another community. */
typedef struct {
    int n;
    int *off;  /* CSR offsets, length n + 1 */
    int *nbr;  /* neighbour indices, length off[n] */
    double *w; /* edge weights aligned with nbr */
    double *k; /* weighted degree per node */
} cbm_lg_t;

static void lg_free(cbm_lg_t *g) {
    free(g->off);
    free(g->nbr);
    free(g->w);
    free(g->k);
    g->off = NULL;
    g->nbr = NULL;
    g->w = NULL;
    g->k = NULL;
}

/* Build a CSR graph from a deduplicated undirected edge list. */
static int lg_build(int n, const int *wsi, const int *wdi, const double *ww, int wn,
                    cbm_lg_t *out) {
    int *off = calloc((size_t)n + 1, sizeof(int));
    double *k = calloc((size_t)n, sizeof(double));
    int *fill = malloc((size_t)n * sizeof(int));
    if (!off || !k || !fill) {
        free(off);
        free(k);
        free(fill);
        return CBM_NOT_FOUND;
    }
    for (int e = 0; e < wn; e++) {
        off[wsi[e] + 1]++;
        off[wdi[e] + 1]++;
    }
    for (int i = 0; i < n; i++) {
        off[i + 1] += off[i];
    }
    int total = off[n];
    int *nbr = malloc((size_t)(total > 0 ? total : 1) * sizeof(int));
    double *w = malloc((size_t)(total > 0 ? total : 1) * sizeof(double));
    if (!nbr || !w) {
        free(off);
        free(k);
        free(fill);
        free(nbr);
        free(w);
        return CBM_NOT_FOUND;
    }
    memcpy(fill, off, (size_t)n * sizeof(int));
    for (int e = 0; e < wn; e++) {
        int a = wsi[e];
        int b = wdi[e];
        double we = ww[e];
        nbr[fill[a]] = b;
        w[fill[a]] = we;
        fill[a]++;
        nbr[fill[b]] = a;
        w[fill[b]] = we;
        fill[b]++;
        k[a] += we;
        k[b] += we;
    }
    free(fill);
    out->n = n;
    out->off = off;
    out->nbr = nbr;
    out->w = w;
    out->k = k;
    return CBM_STORE_OK;
}

/* Local-moving phase: greedily move each node to the neighbouring community
 * with the highest modularity gain, using a work queue seeded with every node
 * and re-queueing only the neighbours of a node that actually moved. Mutates
 * comm[] in place. */
static void leiden_move(const cbm_lg_t *g, int *comm, double gamma, double twom) {
    int n = g->n;
    double *stot = calloc((size_t)n, sizeof(double));
    double *acc = calloc((size_t)n, sizeof(double));
    int *queue = malloc((size_t)n * sizeof(int));
    int *dirty = malloc((size_t)n * sizeof(int));
    bool *inq = calloc((size_t)n, sizeof(bool));
    if (!stot || !acc || !queue || !dirty || !inq) {
        free(stot);
        free(acc);
        free(queue);
        free(dirty);
        free(inq);
        return;
    }
    for (int i = 0; i < n; i++) {
        stot[comm[i]] += g->k[i];
        queue[i] = i;
        inq[i] = true;
    }
    int qhead = 0;
    int qcount = n;
    long cap = (long)n * LEIDEN_MOVE_PASS_CAP + LEIDEN_MAX_LEVELS;
    while (qcount > 0 && cap-- > 0) {
        int v = queue[qhead];
        qhead = (qhead + 1) % n;
        qcount--;
        inq[v] = false;
        int cv = comm[v];
        int ndirty = 0;
        for (int e = g->off[v]; e < g->off[v + 1]; e++) {
            int u = g->nbr[e];
            if (u == v) {
                continue;
            }
            int cu = comm[u];
            if (acc[cu] == 0.0) {
                dirty[ndirty++] = cu;
            }
            acc[cu] += g->w[e];
        }
        stot[cv] -= g->k[v];
        double kv = g->k[v];
        int best_c = cv;
        double best_gain = acc[cv] - gamma * kv * stot[cv] / twom;
        for (int d = 0; d < ndirty; d++) {
            int c = dirty[d];
            double gain = acc[c] - gamma * kv * stot[c] / twom;
            if (gain > best_gain) {
                best_gain = gain;
                best_c = c;
            }
        }
        stot[best_c] += kv;
        comm[v] = best_c;
        if (best_c != cv) {
            for (int e = g->off[v]; e < g->off[v + 1]; e++) {
                int u = g->nbr[e];
                if (comm[u] != best_c && !inq[u] && qcount < n) {
                    queue[(qhead + qcount) % n] = u;
                    qcount++;
                    inq[u] = true;
                }
            }
        }
        for (int d = 0; d < ndirty; d++) {
            acc[dirty[d]] = 0.0;
        }
    }
    free(stot);
    free(acc);
    free(queue);
    free(dirty);
    free(inq);
}

/* Compact community labels in comm[] to the dense range [0, returned count). */
static int leiden_relabel(int *comm, int n) {
    int *map = malloc((size_t)n * sizeof(int));
    if (!map) {
        return n;
    }
    for (int i = 0; i < n; i++) {
        map[i] = CBM_NOT_FOUND;
    }
    int next = 0;
    for (int i = 0; i < n; i++) {
        int c = comm[i];
        if (map[c] == CBM_NOT_FOUND) {
            map[c] = next++;
        }
        comm[i] = map[c];
    }
    free(map);
    return next;
}

/* Refinement phase: within each move-phase community, merge singleton nodes
 * into the best connected sub-community (positive modularity gain, edge must
 * exist). This re-derives communities bottom-up so each one is guaranteed
 * internally connected — the defect single-level Louvain suffers from, which
 * fragments the graph into hundreds of tiny noisy clusters. Writes
 * sub-community labels into refined[] and returns their count. */
static int leiden_refine(const cbm_lg_t *g, const int *comm, double gamma, double twom,
                         int *refined) {
    int n = g->n;
    double *stot = calloc((size_t)n, sizeof(double));
    double *acc = calloc((size_t)n, sizeof(double));
    int *rsize = malloc((size_t)n * sizeof(int));
    int *dirty = malloc((size_t)n * sizeof(int));
    if (!stot || !acc || !rsize || !dirty) {
        free(stot);
        free(acc);
        free(rsize);
        free(dirty);
        for (int i = 0; i < n; i++) {
            refined[i] = i;
        }
        return leiden_relabel(refined, n);
    }
    for (int i = 0; i < n; i++) {
        refined[i] = i;
        stot[i] = g->k[i];
        rsize[i] = 1;
    }
    for (int v = 0; v < n; v++) {
        if (rsize[refined[v]] != 1) {
            continue; /* only singletons merge, per the refinement rule */
        }
        int cv = comm[v];
        int ndirty = 0;
        for (int e = g->off[v]; e < g->off[v + 1]; e++) {
            int u = g->nbr[e];
            if (u == v || comm[u] != cv) {
                continue; /* stay within the move-phase community */
            }
            int ru = refined[u];
            if (acc[ru] == 0.0) {
                dirty[ndirty++] = ru;
            }
            acc[ru] += g->w[e];
        }
        int rv = refined[v];
        double kv = g->k[v];
        stot[rv] -= kv;
        int best_r = rv;
        double best_gain = 0.0;
        for (int d = 0; d < ndirty; d++) {
            int r = dirty[d];
            if (r == rv) {
                continue;
            }
            double gain = acc[r] - gamma * kv * stot[r] / twom;
            if (gain > best_gain) {
                best_gain = gain;
                best_r = r;
            }
        }
        if (best_r != rv) {
            refined[v] = best_r;
            stot[best_r] += kv;
            rsize[best_r]++;
            rsize[rv]--;
        } else {
            stot[rv] += kv;
        }
        for (int d = 0; d < ndirty; d++) {
            acc[dirty[d]] = 0.0;
        }
    }
    free(stot);
    free(acc);
    free(rsize);
    free(dirty);
    return leiden_relabel(refined, n);
}

/* Aggregation phase: collapse each refined sub-community into a single node.
 * Builds the coarser graph in *out and records, for each aggregate node, the
 * move-phase community it belonged to in seed[] so the next level starts from
 * the coarse structure rather than from singletons. */
static int leiden_aggregate(const cbm_lg_t *g, const int *refined, int r_count, const int *comm,
                            cbm_lg_t *out, int *seed) {
    int n = g->n;
    double *k2 = calloc((size_t)r_count, sizeof(double));
    int *gcount = calloc((size_t)r_count, sizeof(int));
    int *gstart = malloc(((size_t)r_count + 1) * sizeof(int));
    int *members = malloc((size_t)n * sizeof(int));
    int *fill = malloc((size_t)r_count * sizeof(int));
    double *acc = calloc((size_t)r_count, sizeof(double));
    int *dirty = malloc((size_t)r_count * sizeof(int));
    int *off2 = malloc(((size_t)r_count + 1) * sizeof(int));
    if (!k2 || !gcount || !gstart || !members || !fill || !acc || !dirty || !off2) {
        free(k2);
        free(gcount);
        free(gstart);
        free(members);
        free(fill);
        free(acc);
        free(dirty);
        free(off2);
        return CBM_NOT_FOUND;
    }
    for (int r = 0; r < r_count; r++) {
        seed[r] = CBM_NOT_FOUND;
    }
    for (int i = 0; i < n; i++) {
        int r = refined[i];
        k2[r] += g->k[i];
        gcount[r]++;
        if (seed[r] == CBM_NOT_FOUND) {
            seed[r] = comm[i];
        }
    }
    gstart[0] = 0;
    for (int r = 0; r < r_count; r++) {
        gstart[r + 1] = gstart[r] + gcount[r];
        fill[r] = gstart[r];
    }
    for (int i = 0; i < n; i++) {
        members[fill[refined[i]]++] = i;
    }
    /* Pass 1: count distinct inter-community neighbours per aggregate node. */
    off2[0] = 0;
    for (int r = 0; r < r_count; r++) {
        int nd = 0;
        for (int m = gstart[r]; m < gstart[r + 1]; m++) {
            int i = members[m];
            for (int e = g->off[i]; e < g->off[i + 1]; e++) {
                int rb = refined[g->nbr[e]];
                if (rb == r || acc[rb] != 0.0) {
                    continue;
                }
                acc[rb] = 1.0;
                dirty[nd++] = rb;
            }
        }
        off2[r + 1] = off2[r] + nd;
        for (int d = 0; d < nd; d++) {
            acc[dirty[d]] = 0.0;
        }
    }
    int total = off2[r_count];
    int *nbr2 = malloc((size_t)(total > 0 ? total : 1) * sizeof(int));
    double *w2 = malloc((size_t)(total > 0 ? total : 1) * sizeof(double));
    if (!nbr2 || !w2) {
        free(k2);
        free(gcount);
        free(gstart);
        free(members);
        free(fill);
        free(acc);
        free(dirty);
        free(off2);
        free(nbr2);
        free(w2);
        return CBM_NOT_FOUND;
    }
    /* Pass 2: accumulate inter-community edge weights. */
    for (int r = 0; r < r_count; r++) {
        int nd = 0;
        for (int m = gstart[r]; m < gstart[r + 1]; m++) {
            int i = members[m];
            for (int e = g->off[i]; e < g->off[i + 1]; e++) {
                int rb = refined[g->nbr[e]];
                if (rb == r) {
                    continue;
                }
                if (acc[rb] == 0.0) {
                    dirty[nd++] = rb;
                }
                acc[rb] += g->w[e];
            }
        }
        int base = off2[r];
        for (int d = 0; d < nd; d++) {
            nbr2[base + d] = dirty[d];
            w2[base + d] = acc[dirty[d]];
            acc[dirty[d]] = 0.0;
        }
    }
    free(gcount);
    free(gstart);
    free(members);
    free(fill);
    free(acc);
    free(dirty);
    out->n = r_count;
    out->off = off2;
    out->nbr = nbr2;
    out->w = w2;
    out->k = k2;
    return CBM_STORE_OK;
}

int cbm_leiden(const int64_t *nodes, int node_count, const cbm_louvain_edge_t *edges,
               int edge_count, double resolution, cbm_louvain_result_t **out, int *out_count) {
    if (!out || !out_count || node_count < 0 || edge_count < 0 || (node_count > 0 && !nodes) ||
        (edge_count > 0 && !edges)) {
        return CBM_STORE_ERR;
    }
    *out = NULL;
    *out_count = 0;
    if (node_count <= 0) {
        return CBM_STORE_OK;
    }
    int n = node_count;
    double gamma = resolution > 0.0 ? resolution : 1.0;

    cbm_louvain_result_t *result = malloc((size_t)n * sizeof(*result));
    if (!result) {
        cbm_log_error(
            "store.leiden", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
            "Leiden result allocation failed", "remediation",
            "free memory or reduce the graph scope, then retry; no clustering result was returned");
        return CBM_STORE_ERR;
    }
    for (int i = 0; i < n; i++) {
        result[i].node_id = nodes[i];
        result[i].community = i;
    }

    /* Build deduplicated undirected edge weights, then a CSR graph. */
    int *wsi;
    int *wdi;
    double *ww;
    int wn;
    if (louvain_build_weights(nodes, n, edges, edge_count, &wsi, &wdi, &ww, &wn) != CBM_STORE_OK) {
        free(result);
        return CBM_STORE_ERR;
    }
    if (wn == 0) {
        free(wsi);
        free(wdi);
        free(ww);
        *out = result;
        *out_count = n;
        return CBM_STORE_OK;
    }
    cbm_lg_t g;
    int built = lg_build(n, wsi, wdi, ww, wn, &g);
    free(wsi);
    free(wdi);
    free(ww);
    if (built != CBM_STORE_OK) {
        free(result);
        cbm_log_error("store.leiden", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
                      "Leiden CSR graph construction failed", "remediation",
                      "free memory or reduce the graph scope, then retry; no singleton fallback "
                      "was returned");
        return CBM_STORE_ERR;
    }

    double twom = 0.0;
    for (int i = 0; i < n; i++) {
        twom += g.k[i];
    }

    int *orig = malloc((size_t)n * sizeof(int)); /* original node -> current graph node */
    int *comm = malloc((size_t)n * sizeof(int));
    if (!orig || !comm) {
        free(orig);
        free(comm);
        lg_free(&g);
        free(result);
        cbm_log_error("store.leiden", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
                      "Leiden community workspace allocation failed", "remediation",
                      "free memory or reduce the graph scope, then retry; no partial clustering "
                      "result was returned");
        return CBM_STORE_ERR;
    }
    if (twom <= 0.0) {
        free(orig);
        free(comm);
        lg_free(&g);
        *out = result;
        *out_count = n;
        return CBM_STORE_OK;
    }
    for (int i = 0; i < n; i++) {
        orig[i] = i;
        comm[i] = i;
    }

    for (int level = 0; level < LEIDEN_MAX_LEVELS; level++) {
        leiden_move(&g, comm, gamma, twom);
        int c_count = leiden_relabel(comm, g.n);
        if (c_count >= g.n) {
            break; /* every node already isolated — nothing to coarsen */
        }
        int *refined = malloc((size_t)g.n * sizeof(int));
        if (!refined) {
            free(comm);
            free(orig);
            lg_free(&g);
            free(result);
            cbm_log_error("store.leiden", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
                          "Leiden refinement allocation failed", "remediation",
                          "free memory or reduce the graph scope, then retry; no earlier-level "
                          "result was substituted");
            return CBM_STORE_ERR;
        }
        int r_count = leiden_refine(&g, comm, gamma, twom, refined);
        if (r_count >= g.n) {
            free(refined);
            break; /* refinement cannot reduce the graph further */
        }
        for (int i = 0; i < n; i++) {
            orig[i] = refined[orig[i]];
        }
        cbm_lg_t g2;
        int *seed = malloc((size_t)r_count * sizeof(int));
        if (!seed || leiden_aggregate(&g, refined, r_count, comm, &g2, seed) != CBM_STORE_OK) {
            free(seed);
            free(refined);
            free(comm);
            free(orig);
            lg_free(&g);
            free(result);
            cbm_log_error("store.leiden", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED", "message",
                          "Leiden aggregation allocation failed", "remediation",
                          "free memory or reduce the graph scope, then retry; no earlier-level "
                          "result was substituted");
            return CBM_STORE_ERR;
        }
        free(refined);
        lg_free(&g);
        g = g2;
        free(comm);
        comm = seed;
    }

    for (int i = 0; i < n; i++) {
        result[i].community = comm[orig[i]];
    }
    free(comm);
    free(orig);
    lg_free(&g);
    *out = result;
    *out_count = n;
    return CBM_STORE_OK;
}

int cbm_louvain(const int64_t *nodes, int node_count, const cbm_louvain_edge_t *edges,
                int edge_count, cbm_louvain_result_t **out, int *out_count) {
    return cbm_leiden(nodes, node_count, edges, edge_count, 1.0, out, out_count);
}

/* ── Architecture: community clusters via Leiden ───────────────── */

enum {
    CBM_CLUSTER_TOP_N = 12,       /* report at most this many clusters */
    CBM_CLUSTER_MAX_TOPNODES = 5, /* representative node names per cluster */
    CBM_CLUSTER_MAX_PKGS = 5,     /* packages listed per cluster */
    CBM_CLUSTER_MIN_MEMBERS = 2,  /* skip singletons */
    CBM_CLUSTER_NODE_CAP = 8000   /* bound the work for very large graphs */
};

static int cluster_id_cmp(const void *key, const void *el) {
    int64_t k = *(const int64_t *)key;
    int64_t e = *(const int64_t *)el;
    return (k > e) - (k < e);
}

/* Index of node id within the id-sorted ids[], or CBM_NOT_FOUND. */
static int cluster_id_index(const int64_t *ids, int n, int64_t id) {
    const int64_t *hit = bsearch(&id, ids, (size_t)n, sizeof(int64_t), cluster_id_cmp);
    return hit ? (int)(hit - ids) : CBM_NOT_FOUND;
}

/* Append `pkg` to a distinct package list (with a per-package count). */
static bool cluster_add_pkg(const char **pkgs, int *counts, int *count, int cap, const char *pkg) {
    if (!pkg || !pkg[0]) {
        return true;
    }
    for (int i = 0; i < *count; i++) {
        if (strcmp(pkgs[i], pkg) == 0) {
            counts[i]++;
            return true;
        }
    }
    if (*count < cap) {
        pkgs[*count] = heap_strdup(pkg);
        if (!pkgs[*count]) {
            return false;
        }
        counts[*count] = 1;
        (*count)++;
    }
    return true;
}

static void cluster_info_free(cbm_cluster_info_t *ci) {
    safe_str_free(&ci->label);
    for (int i = 0; i < ci->top_node_count; i++) {
        safe_str_free(&ci->top_nodes[i]);
    }
    free(ci->top_nodes);
    for (int i = 0; i < ci->package_count; i++) {
        safe_str_free(&ci->packages[i]);
    }
    free(ci->packages);
    for (int i = 0; i < ci->edge_type_count; i++) {
        safe_str_free(&ci->edge_types[i]);
    }
    free(ci->edge_types);
    memset(ci, 0, sizeof(*ci));
}

/* Build the cluster_info for one community c into *ci. */
static int cluster_build_one(cbm_cluster_info_t *ci, int c, int n, const int *comm,
                             const int *degree, const char **names, const char **qns, int members,
                             double cohesion) {
    memset(ci, 0, sizeof(*ci));
    ci->id = c;
    ci->members = members;
    ci->cohesion = cohesion;

    /* Top nodes by degree. */
    int top_idx[CBM_CLUSTER_MAX_TOPNODES];
    int top_deg[CBM_CLUSTER_MAX_TOPNODES];
    int tn = 0;
    for (int i = 0; i < n; i++) {
        if (comm[i] != c) {
            continue;
        }
        int d = degree[i];
        int pos = tn;
        while (pos > 0 && top_deg[pos - 1] < d) {
            pos--;
        }
        if (pos < CBM_CLUSTER_MAX_TOPNODES) {
            int last = (tn < CBM_CLUSTER_MAX_TOPNODES) ? tn : CBM_CLUSTER_MAX_TOPNODES - 1;
            for (int k = last; k > pos; k--) {
                top_idx[k] = top_idx[k - 1];
                top_deg[k] = top_deg[k - 1];
            }
            top_idx[pos] = i;
            top_deg[pos] = d;
            if (tn < CBM_CLUSTER_MAX_TOPNODES) {
                tn++;
            }
        }
    }
    if (tn > 0) {
        ci->top_nodes = malloc((size_t)tn * sizeof(char *));
        if (!ci->top_nodes) {
            goto allocation_failed;
        }
        memset(ci->top_nodes, 0, (size_t)tn * sizeof(char *));
        for (int i = 0; i < tn; i++) {
            ci->top_nodes[i] = heap_strdup(names[top_idx[i]]);
            if (!ci->top_nodes[i]) {
                ci->top_node_count = tn;
                goto allocation_failed;
            }
        }
        ci->top_node_count = tn;
    }

    /* Distinct packages (+ dominant one as the label). */
    const char *pkgs[CBM_CLUSTER_MAX_PKGS];
    int pkg_counts[CBM_CLUSTER_MAX_PKGS];
    int pc = 0;
    for (int i = 0; i < n; i++) {
        if (comm[i] == c) {
            if (!cluster_add_pkg(pkgs, pkg_counts, &pc, CBM_CLUSTER_MAX_PKGS,
                                 cbm_qn_to_top_package(qns[i]))) {
                for (int j = 0; j < pc; j++) {
                    safe_str_free(&pkgs[j]);
                }
                goto allocation_failed;
            }
        }
    }
    if (pc > 0) {
        ci->packages = malloc((size_t)pc * sizeof(char *));
        if (!ci->packages) {
            for (int i = 0; i < pc; i++) {
                safe_str_free(&pkgs[i]);
            }
            goto allocation_failed;
        }
        memset(ci->packages, 0, (size_t)pc * sizeof(char *));
        int best = 0;
        for (int i = 0; i < pc; i++) {
            ci->packages[i] = heap_strdup(pkgs[i]);
            if (!ci->packages[i]) {
                ci->package_count = pc;
                for (int j = 0; j < pc; j++) {
                    safe_str_free(&pkgs[j]);
                }
                goto allocation_failed;
            }
            if (pkg_counts[i] > pkg_counts[best]) {
                best = i;
            }
        }
        ci->package_count = pc;
        ci->label = heap_strdup(pkgs[best]);
        for (int i = 0; i < pc; i++) {
            safe_str_free(&pkgs[i]);
        }
    }
    if (!ci->label) {
        ci->label = heap_strdup(ci->top_node_count > 0 ? ci->top_nodes[0] : "cluster");
        if (!ci->label) {
            goto allocation_failed;
        }
    }

    ci->edge_types = malloc(sizeof(char *));
    if (!ci->edge_types) {
        goto allocation_failed;
    }
    ci->edge_types[0] = heap_strdup("CALLS");
    if (!ci->edge_types[0]) {
        goto allocation_failed;
    }
    ci->edge_type_count = 1;
    return CBM_STORE_OK;

allocation_failed:
    cluster_info_free(ci);
    return CBM_STORE_ERR;
}

/* Comparator for sorting community indices by descending member count. */
typedef struct {
    int comm;
    int members;
} cluster_rank_t;
static int cluster_rank_cmp(const void *a, const void *b) {
    const cluster_rank_t *ca = a;
    const cluster_rank_t *cb = b;
    return cb->members - ca->members;
}

static int arch_clusters(cbm_store_t *s, const char *project, const char *path,
                         cbm_architecture_info_t *out) {
    char norm[CBM_SZ_512];
    char like[CBM_SZ_512];
    bool scoped = arch_path_prepare(path, norm, sizeof(norm), like, sizeof(like));
    char nsqlbuf[ST_SQL_BUF];
    const char *nbase = "SELECT id, name, qualified_name, file_path FROM nodes "
                        "WHERE project=?1 AND label IN ('Function','Method','Class')";
    if (scoped) {
        snprintf(nsqlbuf, sizeof(nsqlbuf), "%s%s ORDER BY id LIMIT ?4", nbase,
                 arch_path_scope_sql());
    } else {
        snprintf(nsqlbuf, sizeof(nsqlbuf), "%s ORDER BY id LIMIT ?2", nbase);
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, nsqlbuf, CBM_NOT_FOUND, &st, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "architecture clusters nodes prepare");
        return CBM_STORE_ERR;
    }
    bind_text(st, SKIP_ONE, project);
    if (scoped) {
        arch_bind_path_scope(st, ST_COL_2, ST_COL_3, norm, like);
        sqlite3_bind_int(st, ST_COL_4, CBM_CLUSTER_NODE_CAP);
    } else {
        sqlite3_bind_int(st, CBM_SZ_2, CBM_CLUSTER_NODE_CAP);
    }
    int ids_cap = 0;
    int names_cap = 0;
    int qns_cap = 0;
    int n = 0;
    int64_t *ids = NULL;
    const char **names = NULL;
    const char **qns = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&ids, &ids_cap, n + 1, sizeof(*ids),
                                "architecture cluster node ids") != CBM_STORE_OK ||
            store_array_reserve(s, (void **)&names, &names_cap, n + 1, sizeof(*names),
                                "architecture cluster node names") != CBM_STORE_OK ||
            store_array_reserve(s, (void **)&qns, &qns_cap, n + 1, sizeof(*qns),
                                "architecture cluster qualified names") != CBM_STORE_OK) {
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            sqlite3_finalize(st);
            return CBM_STORE_ERR;
        }
        ids[n] = sqlite3_column_int64(st, 0);
        names[n] = heap_strdup((const char *)sqlite3_column_text(st, SKIP_ONE));
        qns[n] = heap_strdup((const char *)sqlite3_column_text(st, CBM_SZ_2));
        if (!names[n] || !qns[n]) {
            free((void *)names[n]);
            free((void *)qns[n]);
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            store_set_error(s, "architecture cluster node row allocation failed");
            sqlite3_finalize(st);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        store_set_error_sqlite(s, "architecture clusters nodes step");
        sqlite3_finalize(st);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(st);
    if (n < CBM_CLUSTER_MIN_MEMBERS) {
        for (int i = 0; i < n; i++) {
            safe_str_free(&names[i]);
            safe_str_free(&qns[i]);
        }
        free(ids);
        free(names);
        free(qns);
        return CBM_STORE_OK;
    }

    /* 2. Load CALLS edges with both endpoints in the node set (store indices). */
    cbm_louvain_edge_t *edges = NULL;
    int *esrc = NULL;
    int *edst = NULL;
    int *degree = calloc((size_t)n, sizeof(int));
    if (!degree) {
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        store_set_error(s, "architecture cluster degree allocation failed");
        return CBM_STORE_ERR;
    }
    int ne = 0;
    const char *esql = "SELECT source_id, target_id FROM edges WHERE project=?1 AND type='CALLS'";
    if (sqlite3_prepare_v2(s->db, esql, CBM_NOT_FOUND, &st, NULL) != SQLITE_OK) {
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        free(degree);
        store_set_error_sqlite(s, "architecture clusters edges prepare");
        return CBM_STORE_ERR;
    }
    int edges_cap = 0;
    int esrc_cap = 0;
    int edst_cap = 0;
    bind_text(st, SKIP_ONE, project);
    step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        int si = cluster_id_index(ids, n, sqlite3_column_int64(st, 0));
        int ti = cluster_id_index(ids, n, sqlite3_column_int64(st, SKIP_ONE));
        if (si < 0 || ti < 0 || si == ti) {
            continue;
        }
        if (store_array_reserve(s, (void **)&edges, &edges_cap, ne + 1, sizeof(*edges),
                                "architecture cluster edges") != CBM_STORE_OK ||
            store_array_reserve(s, (void **)&esrc, &esrc_cap, ne + 1, sizeof(*esrc),
                                "architecture cluster edge sources") != CBM_STORE_OK ||
            store_array_reserve(s, (void **)&edst, &edst_cap, ne + 1, sizeof(*edst),
                                "architecture cluster edge targets") != CBM_STORE_OK) {
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            free(edges);
            free(esrc);
            free(edst);
            free(degree);
            sqlite3_finalize(st);
            return CBM_STORE_ERR;
        }
        edges[ne].src = ids[si];
        edges[ne].dst = ids[ti];
        esrc[ne] = si;
        edst[ne] = ti;
        degree[si]++;
        degree[ti]++;
        ne++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        free(edges);
        free(esrc);
        free(edst);
        free(degree);
        store_set_error_sqlite(s, "architecture clusters edges step");
        sqlite3_finalize(st);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(st);

    /* 3. Community detection. */
    cbm_louvain_result_t *res = NULL;
    int rn = 0;
    int *comm = NULL;
    int C = 0;
    if (cbm_leiden(ids, n, edges, ne, 1.0, &res, &rn) != CBM_STORE_OK || !res || rn != n) {
        free(res);
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        free(edges);
        free(esrc);
        free(edst);
        free(degree);
        store_set_error(s, "architecture Leiden clustering failed");
        return CBM_STORE_ERR;
    }
    comm = malloc((size_t)n * sizeof(int));
    if (!comm) {
        free(res);
        store_free_strings((char **)names, n);
        store_free_strings((char **)qns, n);
        free(ids);
        free(edges);
        free(esrc);
        free(edst);
        free(degree);
        store_set_error(s, "architecture cluster assignment allocation failed");
        return CBM_STORE_ERR;
    }
    for (int i = 0; i < n; i++) {
        comm[i] = res[i].community;
        if (comm[i] + 1 > C) {
            C = comm[i] + 1;
        }
    }
    free(res);

    if (comm && C > 0) {
        /* 4. Members + cohesion (internal vs boundary edges) per community. */
        int *members = calloc((size_t)C, sizeof(int));
        int *internal = calloc((size_t)C, sizeof(int));
        int *boundary = calloc((size_t)C, sizeof(int));
        if (!members || !internal || !boundary) {
            free(members);
            free(internal);
            free(boundary);
            free(comm);
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            free(edges);
            free(esrc);
            free(edst);
            free(degree);
            store_set_error(s, "architecture cluster metric allocation failed");
            return CBM_STORE_ERR;
        }
        for (int i = 0; i < n; i++) {
            members[comm[i]]++;
        }
        for (int e = 0; e < ne; e++) {
            int cs = comm[esrc[e]];
            int cd = comm[edst[e]];
            if (cs == cd) {
                internal[cs]++;
            } else {
                boundary[cs]++;
                boundary[cd]++;
            }
        }

        /* 5. Rank communities by size, take the top N non-singletons. */
        cluster_rank_t *rank = malloc((size_t)C * sizeof(cluster_rank_t));
        if (!rank) {
            free(members);
            free(internal);
            free(boundary);
            free(comm);
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            free(edges);
            free(esrc);
            free(edst);
            free(degree);
            store_set_error(s, "architecture cluster ranking allocation failed");
            return CBM_STORE_ERR;
        }
        for (int c = 0; c < C; c++) {
            rank[c] = (cluster_rank_t){c, members[c]};
        }
        qsort(rank, (size_t)C, sizeof(cluster_rank_t), cluster_rank_cmp);

        cbm_cluster_info_t *clusters =
            calloc((size_t)CBM_CLUSTER_TOP_N, sizeof(cbm_cluster_info_t));
        if (!clusters) {
            free(members);
            free(internal);
            free(boundary);
            free(rank);
            free(comm);
            store_free_strings((char **)names, n);
            store_free_strings((char **)qns, n);
            free(ids);
            free(edges);
            free(esrc);
            free(edst);
            free(degree);
            store_set_error(s, "architecture cluster result allocation failed");
            return CBM_STORE_ERR;
        }
        int cc = 0;
        for (int r = 0; r < C && cc < CBM_CLUSTER_TOP_N; r++) {
            int c = rank[r].comm;
            if (members[c] < CBM_CLUSTER_MIN_MEMBERS) {
                break; /* sorted desc — the rest are singletons too */
            }
            double denom = internal[c] + boundary[c];
            double cohesion = denom > 0 ? (double)internal[c] / denom : 0.0;
            if (cluster_build_one(&clusters[cc], c, n, comm, degree, names, qns, members[c],
                                  cohesion) != CBM_STORE_OK) {
                for (int i = 0; i < cc; i++) {
                    cluster_info_free(&clusters[i]);
                }
                free(clusters);
                free(members);
                free(internal);
                free(boundary);
                free(rank);
                free(comm);
                store_free_strings((char **)names, n);
                store_free_strings((char **)qns, n);
                free(ids);
                free(edges);
                free(esrc);
                free(edst);
                free(degree);
                store_set_error(s, "architecture cluster detail allocation failed");
                return CBM_STORE_ERR;
            }
            cc++;
        }
        out->clusters = clusters;
        out->cluster_count = cc;

        free(members);
        free(internal);
        free(boundary);
        free(rank);
    }

    free(comm);
    for (int i = 0; i < n; i++) {
        safe_str_free(&names[i]);
        safe_str_free(&qns[i]);
    }
    free(ids);
    free(names);
    free(qns);
    free(edges);
    free(esrc);
    free(edst);
    free(degree);
    return CBM_STORE_OK;
}

/* ── GetArchitecture dispatch ──────────────────────────────────── */

/* "overview" = compact architecture summary: every aspect EXCEPT the large
 * per-file listing (file_tree), which alone dominates the payload on real
 * repos and can push the MCP response past the output cap. Declared in
 * store.h and shared with aspect_wanted in src/mcp/mcp.c so the store-side
 * DB gate and the MCP-side serialization gate cannot drift. */
bool cbm_store_arch_aspect_in_overview(const char *name) {
    return strcmp(name, "file_tree") != 0;
}

static bool want_aspect(const char **aspects, int aspect_count, const char *name) {
    if (!aspects || aspect_count == 0) {
        return true;
    }
    for (int i = 0; i < aspect_count; i++) {
        if (strcmp(aspects[i], "all") == 0) {
            return true;
        }
        if (strcmp(aspects[i], "overview") == 0 && cbm_store_arch_aspect_in_overview(name)) {
            return true;
        }
        if (strcmp(aspects[i], name) == 0) {
            return true;
        }
    }
    return false;
}

int cbm_store_get_architecture(cbm_store_t *s, const char *project, const char *path,
                               const char **aspects, int aspect_count,
                               cbm_architecture_info_t *out) {
    memset(out, 0, sizeof(*out));
    int rc;

    if (want_aspect(aspects, aspect_count, "languages")) {
        rc = arch_languages(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "packages")) {
        rc = arch_packages(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "entry_points")) {
        rc = arch_entry_points(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "routes")) {
        rc = arch_routes(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "hotspots")) {
        rc = arch_hotspots(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "boundaries")) {
        cbm_cross_pkg_boundary_t *barr = NULL;
        int bcount = 0;
        rc = arch_boundaries(s, project, path, &barr, &bcount);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
        out->boundaries = barr;
        out->boundary_count = bcount;
    }
    if (want_aspect(aspects, aspect_count, "layers")) {
        rc = arch_layers(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "file_tree")) {
        rc = arch_file_tree(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }
    if (want_aspect(aspects, aspect_count, "clusters")) {
        rc = arch_clusters(s, project, path, out);
        if (rc != CBM_STORE_OK) {
            return rc;
        }
    }

    return CBM_STORE_OK;
}

void cbm_store_architecture_free(cbm_architecture_info_t *out) {
    if (!out) {
        return;
    }
    for (int i = 0; i < out->language_count; i++) {
        safe_str_free(&out->languages[i].language);
    }
    free(out->languages);
    for (int i = 0; i < out->package_count; i++) {
        safe_str_free(&out->packages[i].name);
    }
    free(out->packages);
    for (int i = 0; i < out->entry_point_count; i++) {
        safe_str_free(&out->entry_points[i].name);
        safe_str_free(&out->entry_points[i].qualified_name);
        safe_str_free(&out->entry_points[i].file);
    }
    free(out->entry_points);
    for (int i = 0; i < out->route_count; i++) {
        safe_str_free(&out->routes[i].method);
        safe_str_free(&out->routes[i].path);
        safe_str_free(&out->routes[i].handler);
    }
    free(out->routes);
    for (int i = 0; i < out->hotspot_count; i++) {
        safe_str_free(&out->hotspots[i].name);
        safe_str_free(&out->hotspots[i].qualified_name);
    }
    free(out->hotspots);
    for (int i = 0; i < out->boundary_count; i++) {
        safe_str_free(&out->boundaries[i].from);
        safe_str_free(&out->boundaries[i].to);
    }
    free(out->boundaries);
    for (int i = 0; i < out->service_count; i++) {
        safe_str_free(&out->services[i].from);
        safe_str_free(&out->services[i].to);
        safe_str_free(&out->services[i].type);
    }
    free(out->services);
    for (int i = 0; i < out->layer_count; i++) {
        safe_str_free(&out->layers[i].name);
        safe_str_free(&out->layers[i].layer);
        safe_str_free(&out->layers[i].reason);
    }
    free(out->layers);
    for (int i = 0; i < out->cluster_count; i++) {
        safe_str_free(&out->clusters[i].label);
        for (int j = 0; j < out->clusters[i].top_node_count; j++) {
            safe_str_free(&out->clusters[i].top_nodes[j]);
        }
        free(out->clusters[i].top_nodes);
        for (int j = 0; j < out->clusters[i].package_count; j++) {
            safe_str_free(&out->clusters[i].packages[j]);
        }
        free(out->clusters[i].packages);
        for (int j = 0; j < out->clusters[i].edge_type_count; j++) {
            safe_str_free(&out->clusters[i].edge_types[j]);
        }
        free(out->clusters[i].edge_types);
    }
    free(out->clusters);
    for (int i = 0; i < out->file_tree_count; i++) {
        safe_str_free(&out->file_tree[i].path);
        safe_str_free(&out->file_tree[i].type);
    }
    free(out->file_tree);
    memset(out, 0, sizeof(*out));
}

/* ── ADR (Architecture Decision Record) ────────────────────────── */

static const char *canonical_sections[] = {"PURPOSE",  "STACK",     "ARCHITECTURE",
                                           "PATTERNS", "TRADEOFFS", "PHILOSOPHY"};
static const int canonical_section_count = 6;

static bool is_canonical_section(const char *name) {
    for (int i = 0; i < canonical_section_count; i++) {
        if (strcmp(name, canonical_sections[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Save a completed ADR section into result, trimming whitespace. */
static void adr_save_section(cbm_adr_sections_t *result, char *section_name, char *buf,
                             int buf_len) {
    if (!section_name || result->count >= ST_BUF_16) {
        return;
    }
    /* Trim trailing whitespace */
    while (buf_len > 0 && (buf[buf_len - SKIP_ONE] == '\n' || buf[buf_len - SKIP_ONE] == ' ')) {
        buf[--buf_len] = '\0';
    }
    /* Skip leading whitespace */
    char *trimmed = buf;
    while (*trimmed == '\n' || *trimmed == ' ') {
        trimmed++;
    }
    result->keys[result->count] = section_name;
    result->values[result->count] = heap_strdup(trimmed);
    result->count++;
}

/* Try to extract a canonical section header from a "## Header" line.
 * Returns heap-allocated header string if canonical, NULL otherwise. */
static char *adr_try_section_header(const char *line, int line_len) {
    if (line_len <= ST_HEADER_PREFIX || line[0] != '#' || line[SKIP_ONE] != '#' ||
        line[PAIR_LEN] != ' ') {
        return NULL;
    }
    char header[CBM_SZ_64];
    int hlen = line_len - ST_HEADER_PREFIX;
    if (hlen >= (int)sizeof(header)) {
        hlen = (int)sizeof(header) - SKIP_ONE;
    }
    memcpy(header, line + 3, hlen);
    header[hlen] = '\0';
    while (hlen > 0 && (header[hlen - SKIP_ONE] == ' ' || header[hlen - SKIP_ONE] == '\t' ||
                        header[hlen - SKIP_ONE] == '\r')) {
        header[--hlen] = '\0';
    }
    if (!is_canonical_section(header)) {
        return NULL;
    }
    return heap_strdup(header);
}

/* Append a line to the current section content buffer. */
static void adr_append_line(char *buf, int buf_sz, int *len, const char *line, int line_len) {
    if (*len > 0) {
        buf[(*len)++] = '\n';
    }
    if (*len + line_len < buf_sz - SKIP_ONE) {
        memcpy(buf + *len, line, line_len);
        *len += line_len;
        buf[*len] = '\0';
    }
}

cbm_adr_sections_t cbm_adr_parse_sections(const char *content) {
    cbm_adr_sections_t result;
    memset(&result, 0, sizeof(result));
    if (!content || !content[0]) {
        return result;
    }

    const char *p = content;
    char *current_section = NULL;
    char current_content[ST_SQL_BUF] = "";
    int content_len = 0;

    while (*p) {
        const char *eol = strchr(p, '\n');
        int line_len = eol ? (int)(eol - p) : (int)strlen(p);

        char *new_section = adr_try_section_header(p, line_len);
        if (new_section) {
            adr_save_section(&result, current_section, current_content, content_len);
            current_section = new_section;
            current_content[0] = '\0';
            content_len = 0;
        } else if (current_section && (content_len > 0 || line_len > 0)) {
            adr_append_line(current_content, (int)sizeof(current_content), &content_len, p,
                            line_len);
        }

        p = eol ? eol + SKIP_ONE : p + line_len;
    }

    adr_save_section(&result, current_section, current_content, content_len);
    return result;
}

/* Append a section to the render buffer. */
static int adr_render_section(char *buf, int buf_sz, int pos, const char *key, const char *value) {
    if (pos > 0) {
        pos += snprintf(buf + pos, buf_sz - pos, "\n\n");
    }
    pos += snprintf(buf + pos, buf_sz - pos, "## %s\n%s", key, value);
    return pos;
}

char *cbm_adr_render(const cbm_adr_sections_t *sections) {
    if (!sections || sections->count == 0) {
        return heap_strdup("");
    }

    char buf[ST_MAX_DEGREE * ST_GROWTH] = "";
    int pos = 0;
    bool rendered[ST_MAX_SECTIONS] = {false};

    /* Canonical sections first, in order */
    for (int c = 0; c < canonical_section_count; c++) {
        for (int i = 0; i < sections->count; i++) {
            if (rendered[i]) {
                continue;
            }
            if (strcmp(sections->keys[i], canonical_sections[c]) == 0) {
                pos = adr_render_section(buf, (int)sizeof(buf), pos, sections->keys[i],
                                         sections->values[i]);
                rendered[i] = true;
                break;
            }
        }
    }

    /* Non-canonical sections alphabetically */
    int extra[ST_BUF_16];
    int nextra = 0;
    for (int i = 0; i < sections->count; i++) {
        if (!rendered[i]) {
            extra[nextra++] = i;
        }
    }
    for (int i = SKIP_ONE; i < nextra; i++) {
        int j = i;
        while (j > 0 && strcmp(sections->keys[extra[j]], sections->keys[extra[j - SKIP_ONE]]) < 0) {
            int tmp = extra[j];
            extra[j] = extra[j - SKIP_ONE];
            extra[j - SKIP_ONE] = tmp;
            j--;
        }
    }
    for (int i = 0; i < nextra; i++) {
        int idx = extra[i];
        pos = adr_render_section(buf, (int)sizeof(buf), pos, sections->keys[idx],
                                 sections->values[idx]);
    }

    return heap_strdup(buf);
}

int cbm_adr_validate_content(const char *content, char *errbuf, int errbuf_size) {
    cbm_adr_sections_t sections = cbm_adr_parse_sections(content);
    char missing[CBM_SZ_256] = "";
    int mlen = 0;
    int nmissing = 0;

    for (int c = 0; c < canonical_section_count; c++) {
        bool found = false;
        for (int i = 0; i < sections.count; i++) {
            if (strcmp(sections.keys[i], canonical_sections[c]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            if (mlen > 0) {
                mlen += snprintf(missing + mlen, sizeof(missing) - mlen, ", ");
            }
            mlen += snprintf(missing + mlen, sizeof(missing) - mlen, "%s", canonical_sections[c]);
            nmissing++;
        }
    }
    cbm_adr_sections_free(&sections);

    if (nmissing > 0) {
        snprintf(errbuf, errbuf_size,
                 "missing required sections: %s. All 6 required: PURPOSE, STACK, ARCHITECTURE, "
                 "PATTERNS, TRADEOFFS, PHILOSOPHY",
                 missing);
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

int cbm_adr_validate_section_keys(const char **keys, int count, char *errbuf, int errbuf_size) {
    char invalid[CBM_SZ_256] = "";
    int ilen = 0;
    int ninvalid = 0;

    /* Collect and sort invalid keys */
    const char *inv_keys[ST_MAX_SECTIONS];
    int inv_n = 0;
    for (int i = 0; i < count; i++) {
        if (!is_canonical_section(keys[i])) {
            if (inv_n < ST_BUF_16) {
                inv_keys[inv_n++] = keys[i];
            }
        }
    }
    /* Sort alphabetically */
    for (int i = SKIP_ONE; i < inv_n; i++) {
        int j = i;
        while (j > 0 && strcmp(inv_keys[j], inv_keys[j - SKIP_ONE]) < 0) {
            const char *tmp = inv_keys[j];
            inv_keys[j] = inv_keys[j - SKIP_ONE];
            inv_keys[j - SKIP_ONE] = tmp;
            j--;
        }
    }

    for (int i = 0; i < inv_n; i++) {
        if (ilen > 0) {
            ilen += snprintf(invalid + ilen, sizeof(invalid) - ilen, ", ");
        }
        ilen += snprintf(invalid + ilen, sizeof(invalid) - ilen, "%s", inv_keys[i]);
        ninvalid++;
    }

    if (ninvalid > 0) {
        snprintf(errbuf, errbuf_size,
                 "invalid section names: %s. Valid sections: PURPOSE, STACK, ARCHITECTURE, "
                 "PATTERNS, TRADEOFFS, PHILOSOPHY",
                 invalid);
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

void cbm_adr_sections_free(cbm_adr_sections_t *s) {
    if (!s) {
        return;
    }
    for (int i = 0; i < s->count; i++) {
        free(s->keys[i]);
        free(s->values[i]);
    }
    memset(s, 0, sizeof(*s));
}

int cbm_store_adr_store(cbm_store_t *s, const char *project, const char *content) {
    char now[CBM_SZ_32];
    iso_now(now, sizeof(now));

    const char *sql =
        "INSERT INTO project_summaries (project, summary, source_hash, created_at, updated_at) "
        "VALUES (?1, ?2, '', ?3, ?4) "
        "ON CONFLICT(project) DO UPDATE SET summary=excluded.summary, "
        "updated_at=excluded.updated_at";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "adr_store");
        return CBM_STORE_ERR;
    }
    /* #503: project and summary content are caller-supplied text; sanitize to
     * valid UTF-8. `created_at`/`updated_at` (now) are ASCII ISO-8601. */
    bind_text_utf8(stmt, SKIP_ONE, project);
    bind_text_utf8(stmt, ST_COL_2, content);
    bind_text(stmt, ST_COL_3, now);
    bind_text(stmt, ST_COL_4, now);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? CBM_STORE_OK : CBM_STORE_ERR;
}

int cbm_store_adr_get(cbm_store_t *s, const char *project, cbm_adr_t *out) {
    const char *sql = "SELECT project, summary, created_at, updated_at FROM project_summaries "
                      "WHERE project=?1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "adr_get");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        store_set_error(s, "no ADR found");
        return CBM_STORE_NOT_FOUND;
    }
    out->project = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
    out->content = heap_strdup((const char *)sqlite3_column_text(stmt, SKIP_ONE));
    out->created_at = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_2));
    out->updated_at = heap_strdup((const char *)sqlite3_column_text(stmt, CBM_SZ_3));
    sqlite3_finalize(stmt);
    return CBM_STORE_OK;
}

int cbm_store_adr_delete(cbm_store_t *s, const char *project) {
    const char *sql = "DELETE FROM project_summaries WHERE project=?1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "adr_delete");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(s->db);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return CBM_STORE_ERR;
    }
    if (changes == 0) {
        store_set_error(s, "no ADR found");
        return CBM_STORE_NOT_FOUND;
    }
    return CBM_STORE_OK;
}

int cbm_store_adr_update_sections(cbm_store_t *s, const char *project, const char **keys,
                                  const char **values, int count, cbm_adr_t *out) {
    /* Get existing ADR */
    cbm_adr_t existing;
    int rc = cbm_store_adr_get(s, project, &existing);
    if (rc != CBM_STORE_OK) {
        store_set_error(s, "no existing ADR to update");
        return rc;
    }

    /* Parse existing sections */
    cbm_adr_sections_t sections = cbm_adr_parse_sections(existing.content);
    cbm_store_adr_free(&existing);

    /* Merge new sections */
    for (int i = 0; i < count; i++) {
        bool found = false;
        for (int j = 0; j < sections.count; j++) {
            if (strcmp(sections.keys[j], keys[i]) == 0) {
                free(sections.values[j]);
                sections.values[j] = heap_strdup(values[i]);
                found = true;
                break;
            }
        }
        if (!found && sections.count < ST_BUF_16) {
            sections.keys[sections.count] = heap_strdup(keys[i]);
            sections.values[sections.count] = heap_strdup(values[i]);
            sections.count++;
        }
    }

    /* Render merged */
    char *merged = cbm_adr_render(&sections);
    cbm_adr_sections_free(&sections);

    /* Check length */
    if ((int)strlen(merged) > CBM_ADR_MAX_LENGTH) {
        char msg[CBM_SZ_128];
        snprintf(msg, sizeof(msg), "merged ADR exceeds %d chars (%d chars)", CBM_ADR_MAX_LENGTH,
                 (int)strlen(merged));
        store_set_error(s, msg);
        free(merged);
        return CBM_STORE_ERR;
    }

    /* Store merged */
    rc = cbm_store_adr_store(s, project, merged);
    free(merged);
    if (rc != CBM_STORE_OK) {
        return rc;
    }

    return cbm_store_adr_get(s, project, out);
}

void cbm_store_adr_free(cbm_adr_t *adr) {
    if (!adr) {
        return;
    }
    safe_str_free(&adr->project);
    safe_str_free(&adr->content);
    safe_str_free(&adr->created_at);
    safe_str_free(&adr->updated_at);
    memset(adr, 0, sizeof(*adr));
}

/* ── Architecture doc discovery ────────────────────────────────── */

int cbm_store_find_architecture_docs(cbm_store_t *s, const char *project, char ***out, int *count) {
    if (!s || !project || !out || !count) {
        return CBM_STORE_ERR;
    }
    *out = NULL;
    *count = 0;
    const char *sql = "SELECT file_path FROM nodes WHERE project=?1 AND label='File' "
                      "AND (file_path LIKE '%ARCHITECTURE.md' OR file_path LIKE '%ADR.md' "
                      "OR file_path LIKE '%DECISIONS.md' OR file_path LIKE 'docs/adr/%' "
                      "OR file_path LIKE 'doc/adr/%' OR file_path LIKE 'adr/%') "
                      "ORDER BY file_path LIMIT 20";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, CBM_NOT_FOUND, &stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "find_arch_docs");
        return CBM_STORE_ERR;
    }
    bind_text(stmt, SKIP_ONE, project);

    int cap = 0;
    int n = 0;
    char **arr = NULL;
    int step_rc = SQLITE_OK;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (store_array_reserve(s, (void **)&arr, &cap, n + 1, sizeof(*arr),
                                "find architecture documents") != CBM_STORE_OK) {
            store_free_strings(arr, n);
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        arr[n] = heap_strdup((const char *)sqlite3_column_text(stmt, 0));
        if (!arr[n]) {
            store_free_strings(arr, n);
            store_set_error(s, "architecture document path allocation failed");
            sqlite3_finalize(stmt);
            return CBM_STORE_ERR;
        }
        n++;
    }
    if (step_rc != SQLITE_DONE) {
        store_free_strings(arr, n);
        store_set_error_sqlite(s, "find architecture documents step");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(stmt);
    *out = arr;
    *count = n;
    return CBM_STORE_OK;
}

/* ── Memory management ──────────────────────────────────────────── */

void cbm_node_free_fields(cbm_node_t *n) {
    safe_str_free(&n->project);
    safe_str_free(&n->label);
    safe_str_free(&n->name);
    safe_str_free(&n->atom_id);
    safe_str_free(&n->qualified_name);
    safe_str_free(&n->file_path);
    free((void *)n->source_bytes);
    n->source_bytes = NULL;
    n->source_len = 0;
    safe_str_free(&n->source_sha256);
    safe_str_free(&n->properties_json);
}

void cbm_store_free_nodes(cbm_node_t *nodes, int count) {
    if (!nodes) {
        return;
    }
    for (int i = 0; i < count; i++) {
        cbm_node_free_fields(&nodes[i]);
    }
    free(nodes);
}

void cbm_store_free_edges(cbm_edge_t *edges, int count) {
    if (!edges) {
        return;
    }
    for (int i = 0; i < count; i++) {
        safe_str_free(&edges[i].project);
        safe_str_free(&edges[i].type);
        safe_str_free(&edges[i].properties_json);
    }
    free(edges);
}

void cbm_project_free_fields(cbm_project_t *p) {
    safe_str_free(&p->name);
    safe_str_free(&p->indexed_at);
    safe_str_free(&p->root_path);
}

void cbm_store_free_projects(cbm_project_t *projects, int count) {
    if (!projects) {
        return;
    }
    for (int i = 0; i < count; i++) {
        cbm_project_free_fields(&projects[i]);
    }
    free(projects);
}

void cbm_store_free_file_hashes(cbm_file_hash_t *hashes, int count) {
    if (!hashes) {
        return;
    }
    for (int i = 0; i < count; i++) {
        safe_str_free(&hashes[i].project);
        safe_str_free(&hashes[i].rel_path);
        safe_str_free(&hashes[i].sha256);
    }
    free(hashes);
}

/* ── Vector search ────────────────────────��──────────────────────── */

int cbm_store_count_vectors(cbm_store_t *s, const char *project) {
    if (!s || !project) {
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT count(*) FROM node_vectors WHERE project = ?1";
    if (sqlite3_prepare_v2(s->db, sql, SQLITE_AUTO_LEN, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    sqlite3_bind_text(stmt, SKIP_ONE, project, SQLITE_AUTO_LEN, SQLITE_STATIC);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

void cbm_store_free_vector_results(cbm_vector_result_t *results, int count) {
    if (!results) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(results[i].atom_id);
        free(results[i].name);
        free(results[i].qualified_name);
        free(results[i].file_path);
        free(results[i].label);
    }
    free(results);
}

/* Per-keyword scoring: score each keyword independently against each node
 * vector, then combine using min(cosine_k) across keywords.  This ensures
 * ALL keywords must be relevant, not just the average. */
enum {
    VS_VEC_DIM = 768,
    VS_MAX_KW = 32,
    VS_STR_BUF = 16,
};

/* Look up the persisted enriched vector for `token`.  Missing or malformed
 * vectors are errors at the search boundary; vector search must never invent
 * replacement geometry. */
static int vs_load_enriched_vector(cbm_store_t *s, const char *project, const char *token,
                                   float *out) {
    sqlite3_stmt *tv_stmt = NULL;
    const char *tv_sql = "SELECT vector, idf FROM token_vectors"
                         " WHERE project = ?1 AND token = ?2 LIMIT 1";
    if (sqlite3_prepare_v2(s->db, tv_sql, SQLITE_AUTO_LEN, &tv_stmt, NULL) != SQLITE_OK) {
        store_set_error_sqlite(s, "vector keyword prepare");
        return CBM_STORE_ERR;
    }
    if (sqlite3_bind_text(tv_stmt, SKIP_ONE, project, SQLITE_AUTO_LEN, SQLITE_STATIC) !=
            SQLITE_OK ||
        sqlite3_bind_text(tv_stmt, ST_COL_2, token, SQLITE_AUTO_LEN, SQLITE_STATIC) != SQLITE_OK) {
        store_set_error_sqlite(s, "vector keyword bind");
        sqlite3_finalize(tv_stmt);
        return CBM_STORE_ERR;
    }
    int step_rc = sqlite3_step(tv_stmt);
    if (step_rc == SQLITE_ROW) {
        const int8_t *vec = (const int8_t *)sqlite3_value_blob(sqlite3_column_value(tv_stmt, 0));
        int vec_len = sqlite3_column_bytes(tv_stmt, 0);
        if (vec && vec_len == VS_VEC_DIM) {
            for (int d = 0; d < VS_VEC_DIM; d++) {
                out[d] = (float)vec[d] / CBM_STORE_INT8_MAX;
            }
            sqlite3_finalize(tv_stmt);
            return CBM_STORE_OK;
        }
        sqlite3_finalize(tv_stmt);
        store_set_error(s, "vector keyword row has an invalid dimension");
        return CBM_STORE_ERR;
    }
    if (step_rc != SQLITE_DONE) {
        store_set_error_sqlite(s, "vector keyword step");
        sqlite3_finalize(tv_stmt);
        return CBM_STORE_ERR;
    }
    sqlite3_finalize(tv_stmt);
    return CBM_STORE_NOT_FOUND;
}

/* Clamp one float into the int8 representable range. */
static int8_t vs_clamp_int8(float v) {
    if (v > CBM_STORE_INT8_MAX) {
        return (int8_t)CBM_STORE_INT8_MAX;
    }
    if (v < -CBM_STORE_INT8_MAX) {
        return (int8_t)-CBM_STORE_INT8_MAX;
    }
    return (int8_t)v;
}

/* Normalize + int8 quantize a float vector.  Returns false if the vector is
 * effectively zero (magnitude below epsilon), in which case `dst` is left in
 * an indeterminate state and the caller should skip this keyword. */
static bool vs_normalize_and_quantize(const float *src, int8_t *dst) {
    float mag = 0.0F;
    for (int d = 0; d < VS_VEC_DIM; d++) {
        mag += src[d] * src[d];
    }
    mag = sqrtf(mag);
    if (mag < CBM_STORE_DENOM_EPS_F) {
        return false;
    }
    float inv = CBM_STORE_UNIT_POS_F / mag;
    for (int d = 0; d < VS_VEC_DIM; d++) {
        dst[d] = vs_clamp_int8(src[d] * inv * CBM_STORE_INT8_MAX);
    }
    return true;
}

/* Build int8 query vectors for each keyword.  Returns the number of
 * successfully built vectors, or CBM_STORE_ERR. Every non-empty keyword must
 * have a persisted enriched vector; inventing query geometry for a missing
 * token would make similarity results ungrounded. */
static int vs_build_keyword_vectors(cbm_store_t *s, const char *project, const char **keywords,
                                    int keyword_count, int8_t (*kw_vecs)[VS_VEC_DIM]) {
    int actual_kw = 0;
    if (keyword_count > VS_MAX_KW) {
        snprintf(s->errbuf, sizeof(s->errbuf), "vector search received %d keywords; maximum is %d",
                 keyword_count, VS_MAX_KW);
        cbm_log_error("store.vector_search", "code", "CBM_VECTOR_KEYWORD_LIMIT_EXCEEDED", "message",
                      s->errbuf, "remediation",
                      "submit no more than the documented keyword maximum");
        return CBM_STORE_ERR;
    }
    for (int k = 0; k < keyword_count; k++) {
        if (!keywords[k] || !keywords[k][0]) {
            snprintf(s->errbuf, sizeof(s->errbuf), "vector search keyword %d is empty", k);
            cbm_log_error("store.vector_search", "code", "CBM_VECTOR_KEYWORD_INVALID", "message",
                          s->errbuf, "remediation",
                          "provide a non-empty keyword with a persisted enriched vector");
            return CBM_STORE_ERR;
        }
        float kw_f[VS_VEC_DIM];
        memset(kw_f, 0, sizeof(kw_f));
        int load_rc = vs_load_enriched_vector(s, project, keywords[k], kw_f);
        if (load_rc != CBM_STORE_OK) {
            snprintf(s->errbuf, sizeof(s->errbuf),
                     "vector keyword '%s' has no valid persisted enriched vector", keywords[k]);
            cbm_log_error("store.vector_search", "code", "CBM_VECTOR_KEYWORD_UNAVAILABLE",
                          "keyword", keywords[k], "message", s->errbuf, "remediation",
                          "complete semantic enrichment for this project and retry; no synthetic "
                          "vector was substituted");
            return CBM_STORE_ERR;
        }
        if (!vs_normalize_and_quantize(kw_f, kw_vecs[actual_kw])) {
            snprintf(s->errbuf, sizeof(s->errbuf),
                     "vector keyword '%s' normalized to zero magnitude", keywords[k]);
            return CBM_STORE_ERR;
        }
        actual_kw++;
    }
    return actual_kw;
}

/* Compute the per-keyword min cosine score between a node's int8 vector and
 * each of the query vectors.  Returns 0.0 if the node vector is unavailable
 * or mis-sized. */
static double vs_min_cosine_score(const int8_t *node_vec, int node_vec_len,
                                  const int8_t (*kw_vecs)[VS_VEC_DIM], int actual_kw) {
    if (!node_vec || node_vec_len != VS_VEC_DIM) {
        return 0.0;
    }
    double min_score = CBM_STORE_UNIT_POS_D;
    for (int k = 0; k < actual_kw; k++) {
        int32_t dot = 0;
        int32_t ma = 0;
        int32_t mb = 0;
        for (int d = 0; d < VS_VEC_DIM; d++) {
            dot += (int32_t)kw_vecs[k][d] * (int32_t)node_vec[d];
            ma += (int32_t)kw_vecs[k][d] * (int32_t)kw_vecs[k][d];
            mb += (int32_t)node_vec[d] * (int32_t)node_vec[d];
        }
        double denom = sqrt((double)ma) * sqrt((double)mb);
        double cos_k = denom > CBM_STORE_DENOM_EPS_D ? (double)dot / denom : 0.0;
        if (cos_k < min_score) {
            min_score = cos_k;
        }
    }
    return min_score;
}

/* Append one candidate row without exposing a partial row or losing the
 * authoritative prefix when allocation fails. */
static int vs_append_result(cbm_store_t *s, cbm_vector_result_t **results, int *count, int *cap,
                            sqlite3_stmt *stmt, const int8_t (*kw_vecs)[VS_VEC_DIM],
                            int actual_kw) {
    if (store_array_reserve(s, (void **)results, cap, *count + 1, sizeof(**results),
                            "vector search result") != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    int idx = *count;
    cbm_vector_result_t *row = &(*results)[idx];
    memset(row, 0, sizeof(*row));
    row->node_id = sqlite3_column_int64(stmt, 0);
    const char *atom_id = (const char *)sqlite3_column_text(stmt, SKIP_ONE);
    const char *name = (const char *)sqlite3_column_text(stmt, ST_COL_2);
    const char *qn = (const char *)sqlite3_column_text(stmt, ST_COL_3);
    const char *fp = (const char *)sqlite3_column_text(stmt, ST_COL_4);
    const char *label = (const char *)sqlite3_column_text(stmt, ST_COL_5);
    row->atom_id = strdup(atom_id ? atom_id : "");
    row->name = strdup(name ? name : "");
    row->qualified_name = strdup(qn ? qn : "");
    row->file_path = strdup(fp ? fp : "");
    row->label = strdup(label ? label : "");
    if (!row->atom_id || !row->name || !row->qualified_name || !row->file_path || !row->label) {
        free(row->atom_id);
        free(row->name);
        free(row->qualified_name);
        free(row->file_path);
        free(row->label);
        memset(row, 0, sizeof(*row));
        store_set_error(s, "vector search row string allocation failed");
        cbm_log_error("store.vector_search", "code", "CBM_STORE_RESULT_ALLOCATION_FAILED",
                      "message", s->errbuf, "remediation",
                      "free memory and retry; no partial result was returned");
        return CBM_STORE_ERR;
    }
    const int8_t *node_vec = (const int8_t *)sqlite3_column_blob(stmt, ST_COL_7);
    int node_vec_len = sqlite3_column_bytes(stmt, ST_COL_7);
    row->score = vs_min_cosine_score(node_vec, node_vec_len, kw_vecs, actual_kw);
    *count = idx + 1;
    return CBM_STORE_OK;
}

int cbm_store_vector_search(cbm_store_t *s, const char *project, const char **keywords,
                            int keyword_count, int limit, cbm_vector_result_t **out,
                            int *out_count) {
    if (!out || !out_count) {
        return CBM_STORE_ERR;
    }
    *out = NULL;
    *out_count = 0;
    if (!s || !project || !project[0] || !keywords || keyword_count <= 0 || limit < 0) {
        if (s) {
            store_set_error(s, "vector search arguments are invalid");
        }
        return CBM_STORE_ERR;
    }

    int8_t kw_vecs[VS_MAX_KW][VS_VEC_DIM];
    int actual_kw = vs_build_keyword_vectors(s, project, keywords, keyword_count, kw_vecs);
    if (actual_kw <= 0) {
        return CBM_STORE_ERR;
    }

    /* Scan all node vectors, compute per-keyword cosine, take min.
     * We use the FIRST keyword as the SQL sort (for top-K pre-filter),
     * then re-score with min across all keywords in the append helper. */
    const char *sql = "SELECT n.id, n.atom_id, n.name, n.qualified_name, n.file_path, n.label,"
                      "       cbm_cosine_i8(v.vector, ?1) as score, v.vector"
                      " FROM node_vectors v"
                      " INNER JOIN nodes n ON n.id = v.node_id"
                      " WHERE v.project = ?2"
                      " AND n.label IN ('Function','Method','Class')"
                      " ORDER BY score DESC"
                      " LIMIT ?3";

    sqlite3_stmt *stmt = NULL;
    int prep_rc = sqlite3_prepare_v2(s->db, sql, SQLITE_AUTO_LEN, &stmt, NULL);
    if (prep_rc != SQLITE_OK) {
        store_set_error_sqlite(s, "vector search prepare");
        return CBM_STORE_ERR;
    }

    /* Use first keyword for SQL pre-filter, fetch more candidates for re-ranking */
    int final_limit = limit > 0 ? limit : CBM_SZ_16;
    if (final_limit > INT_MAX / ST_COL_5) {
        store_set_error(s, "vector search limit overflows the candidate bound");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }
    int fetch_limit = final_limit * ST_COL_5;
    if (sqlite3_bind_blob(stmt, SKIP_ONE, kw_vecs[0], VS_VEC_DIM, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, ST_COL_2, project, SQLITE_AUTO_LEN, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, ST_COL_3, fetch_limit) != SQLITE_OK) {
        store_set_error_sqlite(s, "vector search bind");
        sqlite3_finalize(stmt);
        return CBM_STORE_ERR;
    }

    {
        char kw_buf[VS_STR_BUF];
        char fl_buf[VS_STR_BUF];
        snprintf(kw_buf, sizeof(kw_buf), "%d", actual_kw);
        snprintf(fl_buf, sizeof(fl_buf), "%d", fetch_limit);
        cbm_log_info("vector_search.exec", "kw_count", kw_buf, "fetch_limit", fl_buf, "project",
                     project);
    }

    cbm_vector_result_t *results = NULL;
    int count = 0;
    int cap = 0;
    int step_rc = 0;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (vs_append_result(s, &results, &count, &cap, stmt, kw_vecs, actual_kw) != CBM_STORE_OK) {
            sqlite3_finalize(stmt);
            cbm_store_free_vector_results(results, count);
            return CBM_STORE_ERR;
        }
    }

    if (step_rc != SQLITE_DONE) {
        store_set_error_sqlite(s, "vector search step");
        sqlite3_finalize(stmt);
        cbm_store_free_vector_results(results, count);
        return CBM_STORE_ERR;
    }
    {
        char cnt_buf[VS_STR_BUF];
        snprintf(cnt_buf, sizeof(cnt_buf), "%d", count);
        cbm_log_info("vector_search.done", "candidates", cnt_buf);
    }
    sqlite3_finalize(stmt);

    /* Re-sort by min-score (SQL sorted by first keyword only) */
    for (int i = 0; i < count - SKIP_ONE; i++) {
        for (int j = i + SKIP_ONE; j < count; j++) {
            if (results[j].score > results[i].score) {
                cbm_vector_result_t tmp = results[i];
                results[i] = results[j];
                results[j] = tmp;
            }
        }
    }

    /* Trim to requested limit */
    if (count > final_limit) {
        for (int i = final_limit; i < count; i++) {
            free(results[i].atom_id);
            free(results[i].name);
            free(results[i].qualified_name);
            free(results[i].file_path);
            free(results[i].label);
        }
        count = final_limit;
    }

    *out = results;
    *out_count = count;
    return CBM_STORE_OK;
}
