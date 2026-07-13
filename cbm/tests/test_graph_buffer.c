/*
 * test_graph_buffer.c — Tests for in-memory graph buffer.
 *
 * RED phase: Tests define expected behavior for node/edge insertion,
 * lookup, dedup, delete, and dump to SQLite.
 */
#include "../src/foundation/compat.h"
#include "test_framework.h"
#include "foundation/compat_thread.h"
#include "graph_buffer/graph_buffer.h"
#include "store/store.h"
#include <stdatomic.h>
#include <string.h>

static int make_temp_gbuf_db(char *path, size_t pathsz, const char *name) {
    snprintf(path, pathsz, "/tmp/cbm_gbuf_%s_XXXXXX", name);
    int fd = cbm_mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    unlink(path);
    return 0;
}

static cbm_gbuf_t *make_row_sink_fixture(void) {
    cbm_gbuf_t *gb = cbm_gbuf_new("proj", "/tmp/repo");
    if (!gb) {
        return NULL;
    }
    int64_t consumer = cbm_gbuf_upsert_node(gb, "File", "consumer.ts",
                                            "proj.consumer.ts.__file__", "consumer.ts", 1, 3,
                                            "{\"source_snippet\":\"import { Alpha }\"}");
    int64_t lib = cbm_gbuf_upsert_node(gb, "File", "lib.ts", "proj.lib.ts.__file__", "lib.ts", 1,
                                       2, "{}");
    cbm_gbuf_insert_edge(gb, consumer, lib, "CALLS", "{\"confidence\":0.9}");
    cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", "{\"local_name\":\"Alpha\"}");
    return gb;
}

typedef struct {
    int node_count;
    int edge_count;
    int imports_seen;
    int bad_rows;
    int fail_on_edge;
    char import_local_name[64];
} row_sink_state_t;

static int test_row_node_sink(const cbm_gbuf_row_node_t *node, void *ctx) {
    row_sink_state_t *state = (row_sink_state_t *)ctx;
    if (!node || !state) {
        return -1;
    }
    state->node_count++;
    if (node->id != state->node_count || !node->project || strcmp(node->project, "proj") != 0 ||
        !node->qualified_name || !node->properties_json) {
        state->bad_rows++;
    }
    return 0;
}

static int test_row_edge_sink(const cbm_gbuf_row_edge_t *edge, void *ctx) {
    row_sink_state_t *state = (row_sink_state_t *)ctx;
    if (!edge || !state) {
        return -1;
    }
    if (state->fail_on_edge) {
        return -1;
    }
    state->edge_count++;
    if (edge->id != state->edge_count || edge->source_id != 1 || edge->target_id != 2 ||
        !edge->project || strcmp(edge->project, "proj") != 0 || !edge->properties_json) {
        state->bad_rows++;
    }
    if (edge->type && strcmp(edge->type, "IMPORTS") == 0) {
        state->imports_seen++;
        snprintf(state->import_local_name, sizeof(state->import_local_name), "%s",
                 edge->local_name_gen ? edge->local_name_gen : "");
    }
    return 0;
}

typedef struct {
    atomic_int node_count;
    atomic_int edge_count;
    atomic_int bad_rows;
    atomic_int in_flight;
    atomic_int max_in_flight;
    atomic_int first_node_entered;
    atomic_int release_first_node;
} row_sink_backpressure_state_t;

static void init_row_sink_backpressure_state(row_sink_backpressure_state_t *state) {
    atomic_init(&state->node_count, 0);
    atomic_init(&state->edge_count, 0);
    atomic_init(&state->bad_rows, 0);
    atomic_init(&state->in_flight, 0);
    atomic_init(&state->max_in_flight, 0);
    atomic_init(&state->first_node_entered, 0);
    atomic_init(&state->release_first_node, 0);
}

static void row_sink_note_enter(row_sink_backpressure_state_t *state) {
    int current = atomic_fetch_add(&state->in_flight, 1) + 1;
    int observed = atomic_load(&state->max_in_flight);
    while (current > observed &&
           !atomic_compare_exchange_weak(&state->max_in_flight, &observed, current)) {
    }
}

static void row_sink_note_exit(row_sink_backpressure_state_t *state) {
    atomic_fetch_sub(&state->in_flight, 1);
}

static int blocking_row_node_sink(const cbm_gbuf_row_node_t *node, void *ctx) {
    row_sink_backpressure_state_t *state = (row_sink_backpressure_state_t *)ctx;
    if (!state) {
        return -1;
    }
    row_sink_note_enter(state);
    if (!node || !node->qualified_name) {
        atomic_fetch_add(&state->bad_rows, 1);
    }
    int seen = atomic_fetch_add(&state->node_count, 1) + 1;
    if (seen == 1) {
        atomic_store(&state->first_node_entered, 1);
        while (!atomic_load(&state->release_first_node)) {
            cbm_usleep(0);
        }
    }
    row_sink_note_exit(state);
    return 0;
}

static int blocking_row_edge_sink(const cbm_gbuf_row_edge_t *edge, void *ctx) {
    row_sink_backpressure_state_t *state = (row_sink_backpressure_state_t *)ctx;
    if (!state) {
        return -1;
    }
    row_sink_note_enter(state);
    if (!edge || !edge->type) {
        atomic_fetch_add(&state->bad_rows, 1);
    }
    atomic_fetch_add(&state->edge_count, 1);
    row_sink_note_exit(state);
    return 0;
}

typedef struct {
    cbm_gbuf_t *gb;
    const char *path;
    int rc;
    atomic_int done;
} row_sink_dump_thread_t;

static void init_row_sink_dump_thread(row_sink_dump_thread_t *thread, cbm_gbuf_t *gb,
                                      const char *path) {
    thread->gb = gb;
    thread->path = path;
    thread->rc = -1;
    atomic_init(&thread->done, 0);
}

static void *row_sink_dump_thread_main(void *arg) {
    row_sink_dump_thread_t *thread = (row_sink_dump_thread_t *)arg;
    thread->rc = cbm_gbuf_dump_to_sqlite(thread->gb, thread->path);
    atomic_store(&thread->done, 1);
    return NULL;
}

/* Deadlock fuse for a broken row-sink implementation. This is not a production
 * threshold; the assertion below is on state while the first callback is held. */
enum { ROW_SINK_BACKPRESSURE_WAIT_SPINS = 1000000 };

static int wait_for_first_row_sink_callback(row_sink_backpressure_state_t *state,
                                            row_sink_dump_thread_t *dump) {
    for (int i = 0; i < ROW_SINK_BACKPRESSURE_WAIT_SPINS; i++) {
        if (atomic_load(&state->first_node_entered)) {
            return 0;
        }
        if (atomic_load(&dump->done)) {
            return 1;
        }
        cbm_usleep(0);
    }
    return -1;
}

/* ── Node operations ───────────────────────────────────────────── */

TEST(gbuf_create_free) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test-proj", "/tmp/repo");
    ASSERT_NOT_NULL(gb);
    ASSERT_EQ(cbm_gbuf_node_count(gb), 0);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 0);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_free_null) {
    cbm_gbuf_free(NULL); /* should not crash */
    PASS();
}

TEST(gbuf_upsert_node) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "main", "pkg.main", "main.go", 1, 10, "{}");
    ASSERT_GT(id, 0);
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1);

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, "pkg.main");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->label, "Function");
    ASSERT_STR_EQ(n->name, "main");
    ASSERT_STR_EQ(n->qualified_name, "pkg.main");
    ASSERT_STR_EQ(n->file_path, "main.go");
    ASSERT_EQ(n->start_line, 1);
    ASSERT_EQ(n->end_line, 10);
    ASSERT_EQ(n->id, id);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_upsert_updates) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t id1 = cbm_gbuf_upsert_node(gb, "Function", "main", "pkg.main", "main.go", 1, 10, "{}");
    /* Upsert same QN with different fields */
    int64_t id2 = cbm_gbuf_upsert_node(gb, "Method", "main", "pkg.main", "main.go", 5, 20,
                                       "{\"key\":\"val\"}");
    ASSERT_EQ(id1, id2);                   /* same temp ID */
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1); /* still one node */

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, "pkg.main");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->label, "Method"); /* updated */
    ASSERT_EQ(n->end_line, 20);        /* updated */

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_id) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "foo.go", 1, 5, "{}");

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_id(gb, id);
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->name, "foo");

    /* Not found */
    ASSERT_NULL(cbm_gbuf_find_by_id(gb, 999));

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_label) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(gb, "Function", "bar", "pkg.bar", "f.go", 6, 10, "{}");
    cbm_gbuf_upsert_node(gb, "Class", "Baz", "pkg.Baz", "f.go", 11, 20, "{}");

    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    int rc = cbm_gbuf_find_by_label(gb, "Function", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 2);

    rc = cbm_gbuf_find_by_label(gb, "Class", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 1);

    rc = cbm_gbuf_find_by_label(gb, "Module", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_name) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "main", "a.main", "a.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(gb, "Function", "main", "b.main", "b.go", 1, 5, "{}");

    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    int rc = cbm_gbuf_find_by_name(gb, "main", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 2);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_delete_by_label) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t f1 = cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");
    int64_t f2 = cbm_gbuf_upsert_node(gb, "Function", "bar", "pkg.bar", "f.go", 6, 10, "{}");
    cbm_gbuf_upsert_node(gb, "Class", "Baz", "pkg.Baz", "f.go", 11, 20, "{}");

    /* Add edge between functions */
    cbm_gbuf_insert_edge(gb, f1, f2, "CALLS", "{}");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);

    /* Delete all functions — should cascade-delete the CALLS edge */
    cbm_gbuf_delete_by_label(gb, "Function");
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1); /* only Class remains */
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 0); /* edge cascade-deleted */

    ASSERT_NULL(cbm_gbuf_find_by_qn(gb, "pkg.foo"));
    ASSERT_NULL(cbm_gbuf_find_by_qn(gb, "pkg.bar"));
    ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(gb, "pkg.Baz"));

    cbm_gbuf_free(gb);
    PASS();
}

/* ── Edge operations ───────────────────────────────────────────── */

TEST(gbuf_insert_edge) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t n1 = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t n2 = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    int64_t eid = cbm_gbuf_insert_edge(gb, n1, n2, "CALLS", "{}");
    ASSERT_GT(eid, 0);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_edge_dedup) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t n1 = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t n2 = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    int64_t eid1 = cbm_gbuf_insert_edge(gb, n1, n2, "CALLS", "{}");
    int64_t eid2 = cbm_gbuf_insert_edge(gb, n1, n2, "CALLS", "{\"weight\":5}");
    ASSERT_EQ(eid1, eid2); /* same edge, deduped */
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);

    /* Different type = different edge */
    int64_t eid3 = cbm_gbuf_insert_edge(gb, n1, n2, "IMPORTS", "{}");
    ASSERT_NEQ(eid1, eid3);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    cbm_gbuf_free(gb);
    PASS();
}

/* #768: two named imports from the same specifier (same source, same target
 * file) must produce two distinct IMPORTS edges, keyed apart by local_name --
 * not collapse into one edge that silently drops whichever import lost the
 * dedup race. Re-inserting the SAME local_name (e.g. an idempotent re-index)
 * must still dedup to one edge. */
TEST(gbuf_imports_multi_symbol_dedup) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t consumer =
        cbm_gbuf_upsert_node(gb, "File", "consumer.ts", "pkg.consumer", "consumer.ts", 1, 1, "{}");
    int64_t lib = cbm_gbuf_upsert_node(gb, "File", "lib.ts", "pkg.lib", "lib.ts", 1, 1, "{}");

    int64_t eid_a = cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", "{\"local_name\":\"A\"}");
    int64_t eid_b = cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", "{\"local_name\":\"B\"}");
    ASSERT_GT(eid_a, 0);
    ASSERT_GT(eid_b, 0);
    ASSERT_NEQ(eid_a, eid_b); /* distinct symbols -> distinct edges */
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_source_type(gb, consumer, "IMPORTS", &edges, &count);
    ASSERT_EQ(count, 2);
    ASSERT_TRUE(strstr(edges[0]->properties_json, "\"local_name\":\"A\"") != NULL ||
                strstr(edges[1]->properties_json, "\"local_name\":\"A\"") != NULL);
    ASSERT_TRUE(strstr(edges[0]->properties_json, "\"local_name\":\"B\"") != NULL ||
                strstr(edges[1]->properties_json, "\"local_name\":\"B\"") != NULL);

    /* Re-inserting the same symbol (idempotent re-index) still dedups. */
    int64_t eid_a_again =
        cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", "{\"local_name\":\"A\"}");
    ASSERT_EQ(eid_a_again, eid_a);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    cbm_gbuf_free(gb);
    PASS();
}

/* #768 hardening: the dedup key lives in a fixed-size stack buffer. Two long
 * local_names sharing a prefix must NOT silently collide when the verbatim
 * key would be truncated — the key builder re-keys oversized local_names with
 * a hash of the FULL name. Determinism must hold: re-inserting the same long
 * name still dedups to the same edge. */
TEST(gbuf_imports_long_local_name_no_collision) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t consumer =
        cbm_gbuf_upsert_node(gb, "File", "consumer.ts", "pkg.consumer", "consumer.ts", 1, 1, "{}");
    int64_t lib = cbm_gbuf_upsert_node(gb, "File", "lib.ts", "pkg.lib", "lib.ts", 1, 1, "{}");

    /* 300-char shared prefix, distinct 4-char tails — a truncated verbatim
     * key keeps only the shared prefix and would merge the two edges. */
    enum { LONG_PREFIX = 300 };
    char name_a[LONG_PREFIX + 8];
    char name_b[LONG_PREFIX + 8];
    memset(name_a, 'x', LONG_PREFIX);
    memset(name_b, 'x', LONG_PREFIX);
    memcpy(name_a + LONG_PREFIX, "AAAA", 5);
    memcpy(name_b + LONG_PREFIX, "BBBB", 5);

    char props_a[512];
    char props_b[512];
    snprintf(props_a, sizeof(props_a), "{\"local_name\":\"%s\"}", name_a);
    snprintf(props_b, sizeof(props_b), "{\"local_name\":\"%s\"}", name_b);

    int64_t eid_a = cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", props_a);
    int64_t eid_b = cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", props_b);
    ASSERT_GT(eid_a, 0);
    ASSERT_GT(eid_b, 0);
    ASSERT_NEQ(eid_a, eid_b); /* prefix-sharing long names stay distinct */
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    /* Hash re-keying is deterministic: same long name dedups. */
    int64_t eid_a_again = cbm_gbuf_insert_edge(gb, consumer, lib, "IMPORTS", props_a);
    ASSERT_EQ(eid_a_again, eid_a);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_edges_by_source_type) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    int64_t c = cbm_gbuf_upsert_node(gb, "Function", "c", "pkg.c", "f.go", 11, 15, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, a, c, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, a, b, "IMPORTS", "{}");

    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_source_type(gb, a, "CALLS", &edges, &count);
    ASSERT_EQ(count, 2);

    cbm_gbuf_find_edges_by_source_type(gb, a, "IMPORTS", &edges, &count);
    ASSERT_EQ(count, 1);

    cbm_gbuf_find_edges_by_source_type(gb, b, "CALLS", &edges, &count);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_edges_by_target_type) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");

    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_target_type(gb, b, "CALLS", &edges, &count);
    ASSERT_EQ(count, 1);

    cbm_gbuf_find_edges_by_target_type(gb, a, "CALLS", &edges, &count);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_edges_by_type) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, b, a, "CALLS", "{}");

    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_type(gb, "CALLS", &edges, &count);
    ASSERT_EQ(count, 2);

    cbm_gbuf_find_edges_by_type(gb, "IMPORTS", &edges, &count);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_delete_edges_by_type) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, a, b, "IMPORTS", "{}");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);

    cbm_gbuf_delete_edges_by_type(gb, "CALLS");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "CALLS"), 0);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "IMPORTS"), 1);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_edge_count_by_type) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    int64_t c = cbm_gbuf_upsert_node(gb, "Function", "c", "pkg.c", "f.go", 11, 15, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, a, c, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, b, c, "IMPORTS", "{}");

    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "CALLS"), 2);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "IMPORTS"), 1);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "HTTP_CALLS"), 0);

    cbm_gbuf_free(gb);
    PASS();
}

/* ── Dump to SQLite ────────────────────────────────────────────── */

TEST(gbuf_dump_empty) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");

    /* Dump empty buffer should succeed */
    int rc = cbm_gbuf_flush_to_store(gb, NULL);
    /* NULL store should be handled gracefully — we just skip */
    (void)rc;

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_row_sink_receives_final_dump_rows) {
    char path[256];
    ASSERT_EQ(make_temp_gbuf_db(path, sizeof(path), "row_sink"), 0);
    cbm_gbuf_t *gb = make_row_sink_fixture();
    ASSERT_NOT_NULL(gb);
    row_sink_state_t state = {0};
    cbm_gbuf_set_row_sink(gb, test_row_node_sink, test_row_edge_sink, &state);

    ASSERT_EQ(cbm_gbuf_dump_to_sqlite(gb, path), 0);
    ASSERT_EQ(state.bad_rows, 0);
    ASSERT_EQ(state.node_count, 2);
    ASSERT_EQ(state.edge_count, 2);
    ASSERT_EQ(state.imports_seen, 1);
    ASSERT_STR_EQ(state.import_local_name, "Alpha");

    cbm_store_t *store = cbm_store_open_path(path);
    ASSERT_NOT_NULL(store);
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 2);
    ASSERT_EQ(cbm_store_count_edges(store, "proj"), 2);
    cbm_store_close(store);

    unlink(path);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_row_sink_failure_aborts_before_sqlite_open) {
    char path[256];
    ASSERT_EQ(make_temp_gbuf_db(path, sizeof(path), "row_sink_fail"), 0);
    cbm_gbuf_t *gb = make_row_sink_fixture();
    ASSERT_NOT_NULL(gb);
    row_sink_state_t state = {.fail_on_edge = 1};
    cbm_gbuf_set_row_sink(gb, test_row_node_sink, test_row_edge_sink, &state);

    ASSERT_EQ(cbm_gbuf_dump_to_sqlite(gb, path), -1);
    ASSERT_EQ(state.node_count, 2);
    ASSERT_EQ(state.edge_count, 0);
    ASSERT_NEQ(access(path, F_OK), 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_row_sink_null_default_writes_sqlite) {
    char path[256];
    ASSERT_EQ(make_temp_gbuf_db(path, sizeof(path), "row_sink_null"), 0);
    cbm_gbuf_t *gb = make_row_sink_fixture();
    ASSERT_NOT_NULL(gb);
    cbm_gbuf_set_row_sink(gb, NULL, NULL, NULL);

    ASSERT_EQ(cbm_gbuf_dump_to_sqlite(gb, path), 0);
    cbm_store_t *store = cbm_store_open_path(path);
    ASSERT_NOT_NULL(store);
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 2);
    ASSERT_EQ(cbm_store_count_edges(store, "proj"), 2);
    cbm_store_close(store);

    unlink(path);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_row_sink_backpressure_blocks_at_current_callback) {
    char path[256];
    ASSERT_EQ(make_temp_gbuf_db(path, sizeof(path), "row_sink_backpressure"), 0);
    cbm_gbuf_t *gb = make_row_sink_fixture();
    ASSERT_NOT_NULL(gb);

    row_sink_backpressure_state_t state;
    init_row_sink_backpressure_state(&state);
    cbm_gbuf_set_row_sink(gb, blocking_row_node_sink, blocking_row_edge_sink, &state);

    row_sink_dump_thread_t dump;
    init_row_sink_dump_thread(&dump, gb, path);
    cbm_thread_t thread;
    ASSERT_EQ(cbm_thread_create(&thread, 0, row_sink_dump_thread_main, &dump), 0);

    int wait_rc = wait_for_first_row_sink_callback(&state, &dump);
    if (wait_rc != 0) {
        atomic_store(&state.release_first_node, 1);
        cbm_thread_join(&thread);
        unlink(path);
        cbm_gbuf_free(gb);
        FAIL("row sink did not reach the first node callback before dump finished");
    }

    int pre_release_nodes = atomic_load(&state.node_count);
    int pre_release_edges = atomic_load(&state.edge_count);
    int pre_release_done = atomic_load(&dump.done);
    int pre_release_max_in_flight = atomic_load(&state.max_in_flight);

    atomic_store(&state.release_first_node, 1);
    ASSERT_EQ(cbm_thread_join(&thread), 0);

    ASSERT_EQ(dump.rc, 0);
    ASSERT_EQ(pre_release_nodes, 1);
    ASSERT_EQ(pre_release_edges, 0);
    ASSERT_EQ(pre_release_done, 0);
    ASSERT_EQ(pre_release_max_in_flight, 1);
    ASSERT_EQ(atomic_load(&state.bad_rows), 0);
    ASSERT_EQ(atomic_load(&state.node_count), 2);
    ASSERT_EQ(atomic_load(&state.edge_count), 2);
    ASSERT_EQ(atomic_load(&state.in_flight), 0);
    ASSERT_EQ(atomic_load(&state.max_in_flight), 1);

    cbm_store_t *store = cbm_store_open_path(path);
    ASSERT_NOT_NULL(store);
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 2);
    ASSERT_EQ(cbm_store_count_edges(store, "proj"), 2);
    cbm_store_close(store);

    unlink(path);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_flush_to_store) {
    /* Create a buffer with some data */
    cbm_gbuf_t *gb = cbm_gbuf_new("test-proj", "/tmp/repo");
    int64_t n1 = cbm_gbuf_upsert_node(gb, "Function", "main", "test-proj::main.go::main", "main.go",
                                      1, 10, "{}");
    int64_t n2 = cbm_gbuf_upsert_node(gb, "Function", "helper", "test-proj::helper.go::helper",
                                      "helper.go", 1, 5, "{}");
    cbm_gbuf_insert_edge(gb, n1, n2, "CALLS", "{}");

    /* Open an in-memory store and flush */
    cbm_store_t *store = cbm_store_open_memory();
    ASSERT_NOT_NULL(store);

    int rc = cbm_gbuf_flush_to_store(gb, store);
    ASSERT_EQ(rc, 0);

    /* Verify data landed in store */
    int node_count = cbm_store_count_nodes(store, "test-proj");
    ASSERT_EQ(node_count, 2);

    int edge_count = cbm_store_count_edges(store, "test-proj");
    ASSERT_EQ(edge_count, 1);

    cbm_store_close(store);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_many_nodes) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");

    /* Insert 1000 nodes */
    for (int i = 0; i < 1000; i++) {
        char name[32], qn[64];
        snprintf(name, sizeof(name), "func_%d", i);
        snprintf(qn, sizeof(qn), "pkg.func_%d", i);
        int64_t id = cbm_gbuf_upsert_node(gb, "Function", name, qn, "f.go", i, i + 5, "{}");
        ASSERT_GT(id, 0);
    }
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1000);

    /* Verify lookup */
    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, "pkg.func_500");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->name, "func_500");

    cbm_gbuf_free(gb);
    PASS();
}

/* ── Node edge cases ───────────────────────────────────────────── */

TEST(gbuf_upsert_null_qn) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    /* NULL qualified_name → returns 0 (error), no node inserted */
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "foo", NULL, "f.go", 1, 5, "{}");
    ASSERT_EQ(id, 0);
    ASSERT_EQ(cbm_gbuf_node_count(gb), 0);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_upsert_empty_qn) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    /* Empty string QN is valid — it's a non-NULL key */
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "anon", "", "f.go", 1, 5, "{}");
    ASSERT_GT(id, 0);
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1);

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, "");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->qualified_name, "");

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_upsert_same_qn_updates_all_fields) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t id1 = cbm_gbuf_upsert_node(gb, "Function", "old_name", "pkg.fn", "old.go", 1, 10,
                                       "{\"k\":\"v1\"}");
    int64_t id2 = cbm_gbuf_upsert_node(gb, "Method", "new_name", "pkg.fn", "new.go", 20, 30,
                                       "{\"k\":\"v2\"}");
    ASSERT_EQ(id1, id2);
    ASSERT_EQ(cbm_gbuf_node_count(gb), 1);

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, "pkg.fn");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->label, "Method");
    ASSERT_STR_EQ(n->name, "new_name");
    ASSERT_STR_EQ(n->file_path, "new.go");
    ASSERT_EQ(n->start_line, 20);
    ASSERT_EQ(n->end_line, 30);
    ASSERT_STR_EQ(n->properties_json, "{\"k\":\"v2\"}");

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_upsert_long_qn) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");

    /* Build a 1200-char QN */
    char long_qn[1201];
    memset(long_qn, 'a', 1200);
    long_qn[1200] = '\0';

    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "long", long_qn, "f.go", 1, 5, "{}");
    ASSERT_GT(id, 0);

    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(gb, long_qn);
    ASSERT_NOT_NULL(n);
    ASSERT_EQ(strlen(n->qualified_name), 1200);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_qn_missing) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");

    ASSERT_NULL(cbm_gbuf_find_by_qn(gb, "does.not.exist"));
    ASSERT_NULL(cbm_gbuf_find_by_qn(gb, ""));
    ASSERT_NULL(cbm_gbuf_find_by_qn(gb, "pkg.FOO")); /* case sensitive */

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_id_missing) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");

    ASSERT_NULL(cbm_gbuf_find_by_id(gb, 0));
    ASSERT_NULL(cbm_gbuf_find_by_id(gb, -1));
    ASSERT_NULL(cbm_gbuf_find_by_id(gb, 999));
    ASSERT_NULL(cbm_gbuf_find_by_id(gb, INT64_MAX));

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_label_no_matches) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");

    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    int rc = cbm_gbuf_find_by_label(gb, "Route", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_by_name_multiple) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_upsert_node(gb, "Function", "init", "a.init", "a.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(gb, "Function", "init", "b.init", "b.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(gb, "Method", "init", "c.S.init", "c.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(gb, "Function", "other", "d.other", "d.go", 1, 5, "{}");

    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    int rc = cbm_gbuf_find_by_name(gb, "init", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 3);

    rc = cbm_gbuf_find_by_name(gb, "other", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 1);

    rc = cbm_gbuf_find_by_name(gb, "missing", &nodes, &count);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_delete_by_label_cascades_edges) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t f = cbm_gbuf_upsert_node(gb, "Function", "fn", "pkg.fn", "f.go", 1, 5, "{}");
    int64_t c = cbm_gbuf_upsert_node(gb, "Class", "Cls", "pkg.Cls", "f.go", 10, 20, "{}");
    int64_t m = cbm_gbuf_upsert_node(gb, "Method", "meth", "pkg.Cls.meth", "f.go", 12, 18, "{}");

    /* Edges: fn→Cls, fn→meth, meth→fn */
    cbm_gbuf_insert_edge(gb, f, c, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, f, m, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, m, f, "CALLS", "{}");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 3);

    /* Delete all Class nodes — should remove fn→Cls edge only */
    cbm_gbuf_delete_by_label(gb, "Class");
    ASSERT_EQ(cbm_gbuf_node_count(gb), 2);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2); /* fn→meth and meth→fn survive */

    /* Verify edge source/target type lookups are consistent after cascade */
    const cbm_gbuf_edge_t **edges = NULL;
    int ecount = 0;
    cbm_gbuf_find_edges_by_source_type(gb, f, "CALLS", &edges, &ecount);
    ASSERT_EQ(ecount, 1); /* only fn→meth remains */

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_node_count_empty) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    ASSERT_EQ(cbm_gbuf_node_count(gb), 0);
    ASSERT_EQ(cbm_gbuf_node_count(NULL), 0);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_upsert_100_nodes_stress) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    for (int i = 0; i < 100; i++) {
        char name[32], qn[64];
        snprintf(name, sizeof(name), "f%d", i);
        snprintf(qn, sizeof(qn), "pkg.f%d", i);
        int64_t id = cbm_gbuf_upsert_node(gb, "Function", name, qn, "f.go", i, i + 1, "{}");
        ASSERT_GT(id, 0);
    }
    ASSERT_EQ(cbm_gbuf_node_count(gb), 100);

    /* Verify each node is findable */
    for (int i = 0; i < 100; i++) {
        char qn[64];
        snprintf(qn, sizeof(qn), "pkg.f%d", i);
        ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(gb, qn));
    }

    cbm_gbuf_free(gb);
    PASS();
}

/* ── Edge edge cases ──────────────────────────────────────────── */

TEST(gbuf_edge_nonexistent_endpoints) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    /* Edges with non-existent source/target IDs are accepted (no FK validation
     * in the buffer — validation happens at flush time when remapping IDs) */
    int64_t eid = cbm_gbuf_insert_edge(gb, 9999, 8888, "CALLS", "{}");
    ASSERT_GT(eid, 0);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_edge_dedup_merges_properties) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");

    int64_t eid1 = cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{\"weight\":1}");
    int64_t eid2 = cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{\"weight\":5}");
    ASSERT_EQ(eid1, eid2);
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 1);

    /* Verify second insert's properties win (merge = replace) */
    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_source_type(gb, a, "CALLS", &edges, &count);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(edges[0]->properties_json, "{\"weight\":5}");

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_edge_count_empty) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 0);
    ASSERT_EQ(cbm_gbuf_edge_count(NULL), 0);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_edge_count_by_type_missing) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "CALLS"), 0);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "UNKNOWN"), 0);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, ""), 0);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_delete_edges_preserves_other_types) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    int64_t c = cbm_gbuf_upsert_node(gb, "Function", "c", "pkg.c", "f.go", 11, 15, "{}");

    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, b, c, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, a, b, "IMPORTS", "{}");
    cbm_gbuf_insert_edge(gb, a, c, "HTTP_CALLS", "{}");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 4);

    cbm_gbuf_delete_edges_by_type(gb, "CALLS");
    ASSERT_EQ(cbm_gbuf_edge_count(gb), 2);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "CALLS"), 0);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "IMPORTS"), 1);
    ASSERT_EQ(cbm_gbuf_edge_count_by_type(gb, "HTTP_CALLS"), 1);

    /* Verify secondary indexes are consistent after rebuild */
    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_source_type(gb, a, "IMPORTS", &edges, &count);
    ASSERT_EQ(count, 1);
    cbm_gbuf_find_edges_by_target_type(gb, c, "HTTP_CALLS", &edges, &count);
    ASSERT_EQ(count, 1);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_find_edges_by_target_type_multiple) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    int64_t a = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    int64_t c = cbm_gbuf_upsert_node(gb, "Function", "c", "pkg.c", "f.go", 11, 15, "{}");

    /* Both a and c call b */
    cbm_gbuf_insert_edge(gb, a, b, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, c, b, "CALLS", "{}");

    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    cbm_gbuf_find_edges_by_target_type(gb, b, "CALLS", &edges, &count);
    ASSERT_EQ(count, 2);

    /* No IMPORTS edges targeting b */
    cbm_gbuf_find_edges_by_target_type(gb, b, "IMPORTS", &edges, &count);
    ASSERT_EQ(count, 0);

    cbm_gbuf_free(gb);
    PASS();
}

/* ── Merge tests ──────────────────────────────────────────────── */

TEST(gbuf_merge_overlapping_qns) {
    cbm_gbuf_t *dst = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_t *src = cbm_gbuf_new("test", "/tmp");

    /* dst has node with QN "pkg.fn" */
    cbm_gbuf_upsert_node(dst, "Function", "fn_old", "pkg.fn", "old.go", 1, 10,
                         "{\"from\":\"dst\"}");
    cbm_gbuf_upsert_node(dst, "Function", "unique_dst", "pkg.unique_dst", "u.go", 1, 5, "{}");

    /* src has same QN with different fields — src should win */
    cbm_gbuf_upsert_node(src, "Method", "fn_new", "pkg.fn", "new.go", 20, 30, "{\"from\":\"src\"}");
    cbm_gbuf_upsert_node(src, "Function", "unique_src", "pkg.unique_src", "s.go", 1, 5, "{}");

    int rc = cbm_gbuf_merge(dst, src);
    ASSERT_EQ(rc, 0);

    /* Total: 3 nodes (1 merged + 1 dst-only + 1 src-only) */
    ASSERT_EQ(cbm_gbuf_node_count(dst), 3);

    /* Verify src fields won for the overlapping QN */
    const cbm_gbuf_node_t *n = cbm_gbuf_find_by_qn(dst, "pkg.fn");
    ASSERT_NOT_NULL(n);
    ASSERT_STR_EQ(n->label, "Method");
    ASSERT_STR_EQ(n->name, "fn_new");
    ASSERT_STR_EQ(n->file_path, "new.go");
    ASSERT_EQ(n->start_line, 20);
    ASSERT_STR_EQ(n->properties_json, "{\"from\":\"src\"}");

    /* Both unique nodes present */
    ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(dst, "pkg.unique_dst"));
    ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(dst, "pkg.unique_src"));

    cbm_gbuf_free(dst);
    cbm_gbuf_free(src);
    PASS();
}

TEST(gbuf_merge_edge_dedup) {
    _Atomic int64_t shared = 1;
    cbm_gbuf_t *dst = cbm_gbuf_new_shared_ids("test", "/tmp", &shared);
    cbm_gbuf_t *src = cbm_gbuf_new_shared_ids("test", "/tmp", &shared);

    int64_t a = cbm_gbuf_upsert_node(dst, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(dst, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    cbm_gbuf_insert_edge(dst, a, b, "CALLS", "{}");

    /* src has same nodes (by QN) and same edge */
    cbm_gbuf_upsert_node(src, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(src, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    /* This edge's src/target IDs differ from dst's, but after merge remap
     * it becomes the same (src, tgt, type) tuple → deduped */
    int64_t sa = cbm_gbuf_find_by_qn(src, "pkg.a")->id;
    int64_t sb = cbm_gbuf_find_by_qn(src, "pkg.b")->id;
    cbm_gbuf_insert_edge(src, sa, sb, "CALLS", "{}");

    int rc = cbm_gbuf_merge(dst, src);
    ASSERT_EQ(rc, 0);

    ASSERT_EQ(cbm_gbuf_node_count(dst), 2);
    ASSERT_EQ(cbm_gbuf_edge_count(dst), 1); /* deduped */

    cbm_gbuf_free(dst);
    cbm_gbuf_free(src);
    PASS();
}

TEST(gbuf_merge_empty_src_into_populated_dst) {
    cbm_gbuf_t *dst = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_t *src = cbm_gbuf_new("test", "/tmp");

    cbm_gbuf_upsert_node(dst, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");
    cbm_gbuf_upsert_node(dst, "Function", "bar", "pkg.bar", "f.go", 6, 10, "{}");

    int rc = cbm_gbuf_merge(dst, src);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(cbm_gbuf_node_count(dst), 2); /* unchanged */

    cbm_gbuf_free(dst);
    cbm_gbuf_free(src);
    PASS();
}

TEST(gbuf_merge_populated_src_into_empty_dst) {
    cbm_gbuf_t *dst = cbm_gbuf_new("test", "/tmp");
    cbm_gbuf_t *src = cbm_gbuf_new("test", "/tmp");

    int64_t a = cbm_gbuf_upsert_node(src, "Function", "foo", "pkg.foo", "f.go", 1, 5, "{}");
    int64_t b = cbm_gbuf_upsert_node(src, "Function", "bar", "pkg.bar", "f.go", 6, 10, "{}");
    cbm_gbuf_insert_edge(src, a, b, "CALLS", "{}");

    int rc = cbm_gbuf_merge(dst, src);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(cbm_gbuf_node_count(dst), 2);
    ASSERT_EQ(cbm_gbuf_edge_count(dst), 1);

    /* Verify nodes are findable in dst */
    ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(dst, "pkg.foo"));
    ASSERT_NOT_NULL(cbm_gbuf_find_by_qn(dst, "pkg.bar"));

    cbm_gbuf_free(dst);
    cbm_gbuf_free(src);
    PASS();
}

TEST(gbuf_merge_null_args) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    ASSERT_EQ(cbm_gbuf_merge(NULL, gb), -1);
    ASSERT_EQ(cbm_gbuf_merge(gb, NULL), -1);
    ASSERT_EQ(cbm_gbuf_merge(NULL, NULL), -1);
    cbm_gbuf_free(gb);
    PASS();
}

/* ── Flush / merge-into-store tests ───────────────────────────── */

TEST(gbuf_flush_to_store_null) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");
    /* NULL store returns -1 */
    ASSERT_EQ(cbm_gbuf_flush_to_store(gb, NULL), -1);
    /* NULL gbuf returns -1 */
    cbm_store_t *store = cbm_store_open_memory();
    ASSERT_EQ(cbm_gbuf_flush_to_store(NULL, store), -1);
    cbm_store_close(store);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_flush_verify_store_data) {
    cbm_gbuf_t *gb = cbm_gbuf_new("proj", "/tmp/repo");
    int64_t n1 = cbm_gbuf_upsert_node(gb, "Function", "alpha", "proj::alpha", "a.go", 1, 10, "{}");
    int64_t n2 = cbm_gbuf_upsert_node(gb, "Class", "Beta", "proj::Beta", "b.go", 1, 20, "{}");
    int64_t n3 = cbm_gbuf_upsert_node(gb, "Function", "gamma", "proj::gamma", "c.go", 1, 5, "{}");
    cbm_gbuf_insert_edge(gb, n1, n2, "CALLS", "{}");
    cbm_gbuf_insert_edge(gb, n1, n3, "IMPORTS", "{}");

    cbm_store_t *store = cbm_store_open_memory();
    ASSERT_NOT_NULL(store);
    int rc = cbm_gbuf_flush_to_store(gb, store);
    ASSERT_EQ(rc, 0);

    /* Verify counts */
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 3);
    ASSERT_EQ(cbm_store_count_edges(store, "proj"), 2);

    /* Verify node lookup by QN */
    cbm_node_t out;
    rc = cbm_store_find_node_by_qn(store, "proj", "proj::alpha", &out);
    ASSERT_EQ(rc, CBM_STORE_OK);
    ASSERT_STR_EQ(out.name, "alpha");
    ASSERT_STR_EQ(out.label, "Function");
    cbm_node_free_fields(&out);

    rc = cbm_store_find_node_by_qn(store, "proj", "proj::Beta", &out);
    ASSERT_EQ(rc, CBM_STORE_OK);
    ASSERT_STR_EQ(out.label, "Class");
    cbm_node_free_fields(&out);

    cbm_store_close(store);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_merge_into_store_preserves) {
    /* First, flush initial data via flush_to_store */
    cbm_gbuf_t *gb1 = cbm_gbuf_new("proj", "/tmp/repo");
    cbm_gbuf_upsert_node(gb1, "Function", "existing", "proj::existing", "e.go", 1, 10, "{}");

    cbm_store_t *store = cbm_store_open_memory();
    ASSERT_NOT_NULL(store);
    cbm_store_upsert_project(store, "proj", "/tmp/repo");
    int rc = cbm_gbuf_flush_to_store(gb1, store);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 1);

    /* Now merge_into_store with new data — should NOT delete existing */
    cbm_gbuf_t *gb2 = cbm_gbuf_new("proj", "/tmp/repo");
    cbm_gbuf_upsert_node(gb2, "Function", "newone", "proj::newone", "n.go", 1, 5, "{}");

    rc = cbm_gbuf_merge_into_store(gb2, store);
    ASSERT_EQ(rc, 0);

    /* Both nodes should exist */
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 2);

    cbm_node_t out;
    rc = cbm_store_find_node_by_qn(store, "proj", "proj::existing", &out);
    ASSERT_EQ(rc, CBM_STORE_OK);
    cbm_node_free_fields(&out);

    rc = cbm_store_find_node_by_qn(store, "proj", "proj::newone", &out);
    ASSERT_EQ(rc, CBM_STORE_OK);
    cbm_node_free_fields(&out);

    cbm_store_close(store);
    cbm_gbuf_free(gb1);
    cbm_gbuf_free(gb2);
    PASS();
}

/* ── Shared ID tests ──────────────────────────────────────────── */

TEST(gbuf_shared_ids_unique) {
    _Atomic int64_t shared = 1;
    cbm_gbuf_t *gb1 = cbm_gbuf_new_shared_ids("test", "/tmp", &shared);
    cbm_gbuf_t *gb2 = cbm_gbuf_new_shared_ids("test", "/tmp", &shared);

    int64_t id1 = cbm_gbuf_upsert_node(gb1, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    int64_t id2 = cbm_gbuf_upsert_node(gb2, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    int64_t id3 = cbm_gbuf_upsert_node(gb1, "Function", "c", "pkg.c", "f.go", 11, 15, "{}");
    int64_t id4 = cbm_gbuf_upsert_node(gb2, "Function", "d", "pkg.d", "f.go", 16, 20, "{}");

    /* All IDs must be unique */
    ASSERT_NEQ(id1, id2);
    ASSERT_NEQ(id1, id3);
    ASSERT_NEQ(id1, id4);
    ASSERT_NEQ(id2, id3);
    ASSERT_NEQ(id2, id4);
    ASSERT_NEQ(id3, id4);

    /* IDs should be sequential from the shared source */
    ASSERT_EQ(id1, 1);
    ASSERT_EQ(id2, 2);
    ASSERT_EQ(id3, 3);
    ASSERT_EQ(id4, 4);

    cbm_gbuf_free(gb1);
    cbm_gbuf_free(gb2);
    PASS();
}

TEST(gbuf_shared_ids_null_fallback) {
    /* NULL id_source → behaves like cbm_gbuf_new() */
    cbm_gbuf_t *gb = cbm_gbuf_new_shared_ids("test", "/tmp", NULL);
    ASSERT_NOT_NULL(gb);
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    ASSERT_EQ(id, 1);
    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_next_id_set_next_id_roundtrip) {
    cbm_gbuf_t *gb = cbm_gbuf_new("test", "/tmp");

    /* Initial next_id is 1 */
    ASSERT_EQ(cbm_gbuf_next_id(gb), 1);

    /* Insert a node, next_id advances */
    cbm_gbuf_upsert_node(gb, "Function", "a", "pkg.a", "f.go", 1, 5, "{}");
    ASSERT_EQ(cbm_gbuf_next_id(gb), 2);

    /* Set next_id to an arbitrary value */
    cbm_gbuf_set_next_id(gb, 100);
    ASSERT_EQ(cbm_gbuf_next_id(gb), 100);

    /* Next insert uses the new base */
    int64_t id = cbm_gbuf_upsert_node(gb, "Function", "b", "pkg.b", "f.go", 6, 10, "{}");
    ASSERT_EQ(id, 100);
    ASSERT_EQ(cbm_gbuf_next_id(gb), 101);

    cbm_gbuf_free(gb);
    PASS();
}

TEST(gbuf_next_id_null_safe) {
    /* next_id on NULL returns 1 (default) */
    ASSERT_EQ(cbm_gbuf_next_id(NULL), 1);
    /* set_next_id on NULL should not crash */
    cbm_gbuf_set_next_id(NULL, 42);
    PASS();
}

/* ── Flush edge case: orphan edges skipped ────────────────────── */

TEST(gbuf_flush_skips_orphan_edges) {
    cbm_gbuf_t *gb = cbm_gbuf_new("proj", "/tmp/repo");
    int64_t n1 = cbm_gbuf_upsert_node(gb, "Function", "real", "proj::real", "f.go", 1, 5, "{}");

    /* Valid edge */
    cbm_gbuf_insert_edge(gb, n1, n1, "CALLS", "{}");
    /* Orphan edge — target ID 9999 does not map to any node */
    cbm_gbuf_insert_edge(gb, n1, 9999, "CALLS", "{}");

    cbm_store_t *store = cbm_store_open_memory();
    ASSERT_NOT_NULL(store);
    int rc = cbm_gbuf_flush_to_store(gb, store);
    ASSERT_EQ(rc, 0);

    /* Only the valid edge should land in the store */
    ASSERT_EQ(cbm_store_count_nodes(store, "proj"), 1);
    ASSERT_EQ(cbm_store_count_edges(store, "proj"), 1);

    cbm_store_close(store);
    cbm_gbuf_free(gb);
    PASS();
}

/* ── Suite ─────────────────────────────────────────────────────── */

SUITE(graph_buffer) {
    /* Original tests */
    RUN_TEST(gbuf_create_free);
    RUN_TEST(gbuf_free_null);
    RUN_TEST(gbuf_upsert_node);
    RUN_TEST(gbuf_upsert_updates);
    RUN_TEST(gbuf_find_by_id);
    RUN_TEST(gbuf_find_by_label);
    RUN_TEST(gbuf_find_by_name);
    RUN_TEST(gbuf_delete_by_label);
    RUN_TEST(gbuf_insert_edge);
    RUN_TEST(gbuf_edge_dedup);
    RUN_TEST(gbuf_imports_multi_symbol_dedup);
    RUN_TEST(gbuf_imports_long_local_name_no_collision);
    RUN_TEST(gbuf_find_edges_by_source_type);
    RUN_TEST(gbuf_find_edges_by_target_type);
    RUN_TEST(gbuf_find_edges_by_type);
    RUN_TEST(gbuf_delete_edges_by_type);
    RUN_TEST(gbuf_edge_count_by_type);
    RUN_TEST(gbuf_dump_empty);
    RUN_TEST(gbuf_row_sink_receives_final_dump_rows);
    RUN_TEST(gbuf_row_sink_failure_aborts_before_sqlite_open);
    RUN_TEST(gbuf_row_sink_null_default_writes_sqlite);
    RUN_TEST(gbuf_row_sink_backpressure_blocks_at_current_callback);
    RUN_TEST(gbuf_flush_to_store);
    RUN_TEST(gbuf_many_nodes);

    /* Node edge cases */
    RUN_TEST(gbuf_upsert_null_qn);
    RUN_TEST(gbuf_upsert_empty_qn);
    RUN_TEST(gbuf_upsert_same_qn_updates_all_fields);
    RUN_TEST(gbuf_upsert_long_qn);
    RUN_TEST(gbuf_find_by_qn_missing);
    RUN_TEST(gbuf_find_by_id_missing);
    RUN_TEST(gbuf_find_by_label_no_matches);
    RUN_TEST(gbuf_find_by_name_multiple);
    RUN_TEST(gbuf_delete_by_label_cascades_edges);
    RUN_TEST(gbuf_node_count_empty);
    RUN_TEST(gbuf_upsert_100_nodes_stress);

    /* Edge edge cases */
    RUN_TEST(gbuf_edge_nonexistent_endpoints);
    RUN_TEST(gbuf_edge_dedup_merges_properties);
    RUN_TEST(gbuf_edge_count_empty);
    RUN_TEST(gbuf_edge_count_by_type_missing);
    RUN_TEST(gbuf_delete_edges_preserves_other_types);
    RUN_TEST(gbuf_find_edges_by_target_type_multiple);

    /* Merge tests */
    RUN_TEST(gbuf_merge_overlapping_qns);
    RUN_TEST(gbuf_merge_edge_dedup);
    RUN_TEST(gbuf_merge_empty_src_into_populated_dst);
    RUN_TEST(gbuf_merge_populated_src_into_empty_dst);
    RUN_TEST(gbuf_merge_null_args);

    /* Flush/merge-into-store tests */
    RUN_TEST(gbuf_flush_to_store_null);
    RUN_TEST(gbuf_flush_verify_store_data);
    RUN_TEST(gbuf_merge_into_store_preserves);
    RUN_TEST(gbuf_flush_skips_orphan_edges);

    /* Shared ID tests */
    RUN_TEST(gbuf_shared_ids_unique);
    RUN_TEST(gbuf_shared_ids_null_fallback);
    RUN_TEST(gbuf_next_id_set_next_id_roundtrip);
    RUN_TEST(gbuf_next_id_null_safe);
}
