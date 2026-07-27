#include "cbm.h"
#include "arena.h" // CBMArena, cbm_arena_init/alloc/strdup/destroy
#include "helpers.h"
#include "lang_specs.h"
#include "extract_unified.h"
#include "lsp/go_lsp.h"
#include "lsp/c_lsp.h"
#include "lsp/php_lsp.h"
#include "lsp/py_lsp.h"
#include "lsp/ts_lsp.h"
#include "lsp/cs_lsp.h"
#include "lsp/java_lsp.h"
#include "lsp/kotlin_lsp.h"
#include "lsp/rust_lsp.h"
#include "preprocessor.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h" // cbm_fopen — crash-supervisor per-file marker write
#include "foundation/log.h"       // cbm_log_warn — explicit preprocessor diagnostics
#include "tree_sitter/api.h" // TSParser, TSNode, TSTree, TSInput, TSLanguage, TSPoint, TSParseOptions, TSParseState
#include "foundation/constants.h"
#include "mimalloc.h" // mi_malloc/mi_calloc/mi_realloc/mi_free/mi_usable_size — bind 3rd-party allocators (#424)
#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR
#include "sqlite3.h" // sqlite3_mem_methods, sqlite3_config, SQLITE_CONFIG_MALLOC — bind sqlite to mimalloc
#endif
#include <stdint.h> // uint32_t, uint64_t, int64_t
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h> // struct timespec, CLOCK_MONOTONIC

// Atomic counters for profiling parse vs extraction time (nanoseconds).
// Accessed from multiple threads; using _Atomic for safe accumulation.
#include <stdatomic.h>
static _Atomic uint64_t total_parse_ns = 0;
static _Atomic uint64_t total_extract_ns = 0;
static _Atomic uint64_t total_lsp_ns = 0;
static _Atomic uint64_t total_preprocess_ns = 0;
static _Atomic uint64_t total_files_preprocessed = 0;
static _Atomic uint64_t total_files = 0;

// C/C++ preprocessor #define macros are extracted as Macro nodes (#375). On a
// macro-dense codebase (e.g. the Linux kernel: ~2.4M macros, 49% of all nodes)
// this is the dominant extraction cost, so it is gated to the full/advanced
// index modes. Default ON to preserve behavior for direct callers/tests; the
// pipeline sets it from the index mode before extraction. Set once pre-extract,
// read-only during, so a relaxed atomic is sufficient.
static _Atomic int g_extract_macros = 1;
void cbm_set_macro_extraction(int enabled) {
    atomic_store_explicit(&g_extract_macros, enabled ? 1 : 0, memory_order_relaxed);
}
int cbm_macro_extraction_enabled(void) {
    return atomic_load_explicit(&g_extract_macros, memory_order_relaxed);
}

static bool remap_preprocessed_calls(CBMFileResult *result, int calls_before,
                                     const uint32_t *primary_source_lines,
                                     size_t expanded_line_count, const char *rel_path) {
    int write = calls_before;
    int foreign_calls = 0;
    for (int read = calls_before; read < result->calls.count; read++) {
        CBMCall call = result->calls.items[read];
        if (call.start_line <= 0 || (size_t)call.start_line > expanded_line_count) {
            cbm_log_error("preprocessor.call_source_map_failed", "code",
                          "CBM_PREPROCESS_CALL_LINE_UNMAPPED", "file",
                          rel_path ? rel_path : "<input>", "expanded_line", "out_of_range");
            cbm_file_result_set_error(
                result, "CBM_PREPROCESS_CALL_LINE_UNMAPPED", "remap_preprocessed_calls",
                "preprocessor_source_map", (size_t)(call.start_line > 0 ? call.start_line : 0),
                "a macro-expanded call has no bounded expansion location in the parsed buffer",
                "preserve the outermost macro expansion location for every emitted token, then "
                "retry the complete corpus");
            return false;
        }
        uint32_t source_line = primary_source_lines[call.start_line - 1];
        if (source_line == UINT32_MAX) {
            foreign_calls++;
            continue;
        }
        if (source_line == 0) {
            cbm_log_error("preprocessor.call_source_map_failed", "code",
                          "CBM_PREPROCESS_CALL_ORIGIN_INVALID", "file",
                          rel_path ? rel_path : "<input>", "expanded_line", "unmapped");
            cbm_file_result_set_error(
                result, "CBM_PREPROCESS_CALL_ORIGIN_INVALID", "remap_preprocessed_calls",
                "preprocessor_source_map", (size_t)call.start_line,
                "a macro-expanded call resolves to a generated or invalid source-map line",
                "repair the expansion map so the call names one exact primary-file invocation "
                "line, then retry the complete corpus");
            return false;
        }
        call.start_line = (int)source_line;
        result->calls.items[write++] = call;
    }
    result->calls.count = write;
    if (foreign_calls > 0) {
        char skipped[32];
        snprintf(skipped, sizeof(skipped), "%d", foreign_calls);
        cbm_log_info("preprocessor.foreign_source_calls_excluded", "file",
                     rel_path ? rel_path : "<input>", "calls", skipped, "reason",
                     "included_file_owned");
    }
    return true;
}

#define NSEC_PER_SEC 1000000000ULL
#define USEC_TO_NSEC 1000ULL
/* Use compat.h's cbm_clock_gettime which accepts CLOCK_MONOTONIC (value
 * varies by platform: 1 on Linux/Windows, 6 on macOS). We pass the
 * platform value via the compat.h fallback. */
#if defined(CLOCK_MONOTONIC)
#define CBM_CLOCK_MONO CLOCK_MONOTONIC
#elif defined(__APPLE__)
#define CBM_CLOCK_MONO 6
#else
#define CBM_CLOCK_MONO 1
#endif

static uint64_t now_ns(void) {
    struct timespec ts;
    cbm_clock_gettime(CBM_CLOCK_MONO, &ts);
    return ((uint64_t)ts.tv_sec * NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;
}

// cbm_get_profile returns accumulated parse/extract times and file count.
void cbm_get_profile(cbm_profile_out_t out) {
    *out.parse_ns = atomic_load(&total_parse_ns);
    *out.extract_ns = atomic_load(&total_extract_ns);
    *out.files = atomic_load(&total_files);
}

uint64_t cbm_get_lsp_ns(void) {
    return atomic_load(&total_lsp_ns);
}

uint64_t cbm_get_preprocess_ns(void) {
    return atomic_load(&total_preprocess_ns);
}

uint64_t cbm_get_files_preprocessed(void) {
    return atomic_load(&total_files_preprocessed);
}

// cbm_reset_profile zeros the profiling counters.
void cbm_reset_profile(void) {
    atomic_store(&total_parse_ns, 0);
    atomic_store(&total_extract_ns, 0);
    atomic_store(&total_lsp_ns, 0);
    atomic_store(&total_preprocess_ns, 0);
    atomic_store(&total_files_preprocessed, 0);
    atomic_store(&total_files, 0);
}

// --- Growable array push functions ---

static bool grow_array_checked(void **items, int *count, int *cap, size_t item_size, CBMArena *a,
                               const char *operation) {
    if (!items || !count || !cap || !a || item_size == 0 || *count < 0 || *cap < 0 ||
        *count > *cap || (*cap > 0 && !*items)) {
        cbm_arena_mark_failed(a, "CBM_EXTRACTION_ARRAY_INVARIANT", operation, item_size);
        return false;
    }
    if (*count < *cap) {
        return true;
    }
    if (*cap > INT_MAX / PAIR_LEN) {
        cbm_arena_mark_failed(a, "CBM_EXTRACTION_ARRAY_CAPACITY_OVERFLOW", operation, item_size);
        return false;
    }
    int new_cap = *cap == 0 ? CBM_SZ_32 : *cap * PAIR_LEN;
    if ((size_t)new_cap > SIZE_MAX / item_size) {
        cbm_arena_mark_failed(a, "CBM_EXTRACTION_ARRAY_CAPACITY_OVERFLOW", operation, item_size);
        return false;
    }
    size_t new_bytes = (size_t)new_cap * item_size;
    void *new_items = cbm_arena_alloc(a, new_bytes);
    if (!new_items) {
        cbm_arena_mark_failed(a, "CBM_EXTRACTION_ARRAY_GROW_FAILED", operation, new_bytes);
        return false;
    }
    if (*items && *count > 0) {
        memcpy(new_items, *items, (size_t)*count * item_size);
    }
    *items = new_items;
    *cap = new_cap;
    return true;
}

#define GROW_ARRAY_CHECKED(arr, arena, operation)                                                 \
    grow_array_checked((void **)&(arr)->items, &(arr)->count, &(arr)->cap, sizeof(*(arr)->items), \
                       (arena), (operation))

bool cbm_defs_push(CBMDefArray *arr, CBMArena *a, CBMDefinition def) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "definitions.push"))
        return false;
    arr->items[arr->count++] = def;
    return true;
}

bool cbm_calls_push(CBMCallArray *arr, CBMArena *a, CBMCall call) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "calls.push"))
        return false;
    arr->items[arr->count++] = call;
    return true;
}

bool cbm_imports_push(CBMImportArray *arr, CBMArena *a, CBMImport imp) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "imports.push"))
        return false;
    arr->items[arr->count++] = imp;
    return true;
}

bool cbm_usages_push(CBMUsageArray *arr, CBMArena *a, CBMUsage usage) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "usages.push"))
        return false;
    arr->items[arr->count++] = usage;
    return true;
}

bool cbm_local_bindings_push(CBMLocalBindingArray *arr, CBMArena *a, CBMLocalBinding binding) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "local_bindings.push"))
        return false;
    arr->items[arr->count++] = binding;
    return true;
}

bool cbm_throws_push(CBMThrowArray *arr, CBMArena *a, CBMThrow thr) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "throws.push"))
        return false;
    arr->items[arr->count++] = thr;
    return true;
}

bool cbm_rw_push(CBMRWArray *arr, CBMArena *a, CBMReadWrite rw) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "read_write.push"))
        return false;
    arr->items[arr->count++] = rw;
    return true;
}

bool cbm_typerefs_push(CBMTypeRefArray *arr, CBMArena *a, CBMTypeRef tr) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "type_refs.push"))
        return false;
    arr->items[arr->count++] = tr;
    return true;
}

bool cbm_envaccess_push(CBMEnvAccessArray *arr, CBMArena *a, CBMEnvAccess ea) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "env_accesses.push"))
        return false;
    arr->items[arr->count++] = ea;
    return true;
}

bool cbm_typeassign_push(CBMTypeAssignArray *arr, CBMArena *a, CBMTypeAssign ta) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "type_assignments.push"))
        return false;
    arr->items[arr->count++] = ta;
    return true;
}

bool cbm_stringref_push(CBMStringRefArray *arr, CBMArena *a, CBMStringRef sr) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "string_refs.push"))
        return false;
    arr->items[arr->count++] = sr;
    return true;
}

bool cbm_infrabinding_push(CBMInfraBindingArray *arr, CBMArena *a, CBMInfraBinding ib) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "infra_bindings.push"))
        return false;
    arr->items[arr->count++] = ib;
    return true;
}

bool cbm_impltrait_push(CBMImplTraitArray *arr, CBMArena *a, CBMImplTrait it) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "impl_traits.push"))
        return false;
    arr->items[arr->count++] = it;
    return true;
}

bool cbm_resolvedcall_push(CBMResolvedCallArray *arr, CBMArena *a, CBMResolvedCall rc) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "resolved_calls.push"))
        return false;
    arr->items[arr->count++] = rc;
    return true;
}

bool cbm_channels_push(CBMChannelArray *arr, CBMArena *a, CBMChannel ch) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "channels.push"))
        return false;
    arr->items[arr->count++] = ch;
    return true;
}

bool cbm_diagnostics_push(CBMParseDiagnosticArray *arr, CBMArena *a, CBMParseDiagnostic diag) {
    if (!arr || !GROW_ARRAY_CHECKED(arr, a, "diagnostics.push"))
        return false;
    arr->items[arr->count++] = diag;
    return true;
}

// --- String input reader (for parse_with_options) ---

typedef struct {
    const char *string;
    uint32_t length;
} CBMStringInput;

static const char *cbm_string_read(void *payload, uint32_t byte, TSPoint point,
                                   uint32_t *bytes_read) {
    (void)point;
    CBMStringInput *self = (CBMStringInput *)payload;
    if (byte >= self->length) {
        *bytes_read = 0;
        return "";
    }
    *bytes_read = self->length - byte;
    return self->string + byte;
}

// --- Parse timeout callback ---

static bool cbm_timeout_cb(TSParseState *state) {
    uint64_t deadline = *(uint64_t *)state->payload;
    return now_ns() > deadline;
}

// --- Thread-local parser pool ---
// TSParser is not thread-safe, but can be reused across files on the same thread.
// We keep one parser per thread, and just switch language as needed.
// This avoids ~70K ts_parser_new()/ts_parser_delete() cycles on large repos.

static CBM_TLS TSParser *tl_parser = NULL;
static CBM_TLS CBMLanguage tl_parser_lang = CBM_LANG_COUNT; // invalid sentinel

// Get or create a thread-local parser configured for the given language.
static TSParser *get_thread_parser(const TSLanguage *ts_lang, CBMLanguage lang) {
    if (!tl_parser) {
        tl_parser = ts_parser_new();
        if (!tl_parser) {
            return NULL;
        }
        tl_parser_lang = CBM_LANG_COUNT;
    }
    if (tl_parser_lang != lang) {
        ts_parser_set_language(tl_parser, ts_lang);
        tl_parser_lang = lang;
    }
    return tl_parser;
}

// --- Allocator binding (defense-in-depth, #424) ---

/* Bind tree-sitter and sqlite3 to mimalloc explicitly so a correct
 * binary does NOT depend on the fragile MI_OVERRIDE symbol override. Under
 * MI_OVERRIDE=1 — particularly the Windows static-MinGW link with
 * --allow-multiple-definition — `malloc`/`free` can resolve to DIFFERENT
 * allocators (mimalloc vs the CRT) inside third-party libs, so a block
 * allocated by mimalloc gets freed by the CRT (or vice-versa), corrupting the
 * heap freelist (#424). Binding each library through one explicit allocator
 * eliminates that mismatch class generically, on every platform.
 *
 * Guarded to the production build (CBM_BIND_TS_ALLOCATOR=1, which CFLAGS_PROD
 * defines alongside MI_OVERRIDE=1). The test build is CRT + ASan, where binding
 * to mimalloc would mismatch ASan/CRT frees — there these binds compile to
 * no-ops and the build stays unchanged. */

#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR
#include <assert.h>

/* sqlite3 mem methods backed by mimalloc. sqlite's xMalloc/xRealloc/xSize use
 * `int` sizes; wrap with size_t casts. xRoundup rounds to an 8-byte boundary
 * (sqlite requires 8-byte-aligned roundup, and mimalloc honors that alignment).
 * Field order matches struct sqlite3_mem_methods exactly:
 * xMalloc, xFree, xRealloc, xSize, xRoundup, xInit, xShutdown, pAppData. */
static void *cbm_sqlite_malloc(int n) {
    return mi_malloc((size_t)n);
}
static void cbm_sqlite_free(void *p) {
    mi_free(p);
}
static void *cbm_sqlite_realloc(void *p, int n) {
    return mi_realloc(p, (size_t)n);
}
static int cbm_sqlite_size(void *p) {
    return (int)mi_usable_size(p);
}
static int cbm_sqlite_roundup(int n) {
    return (n + 7) & ~7; /* round up to 8-byte boundary */
}
static int cbm_sqlite_meminit(void *appdata) {
    (void)appdata;
    return SQLITE_OK;
}
static void cbm_sqlite_memshutdown(void *appdata) {
    (void)appdata;
}
#endif /* CBM_BIND_TS_ALLOCATOR */

/* Allocator-binding state (#5). File-scope (was a function-local static) so
 * cbm_alloc_bindings_active() can read back whether cbm_alloc_init() has already
 * bound the tree-sitter/sqlite allocators to mimalloc. This gives the Rust FFI
 * tests a deterministic init-order probe: the flag flips 0 -> 1 exactly once,
 * the first time cbm_alloc_init() runs in a build that enables the binding.
 * Single-threaded startup; a plain int is fine. Always 0 in the test build
 * (CBM_BIND_TS_ALLOCATOR undefined) because the binding is a no-op there. */
static int cbm_alloc_bound = 0;
static int cbm_alloc_error = 0;

int cbm_alloc_init(void) {
#if defined(CBM_BIND_TS_ALLOCATOR) && CBM_BIND_TS_ALLOCATOR
    if (cbm_alloc_bound) {
        return SQLITE_OK;
    }
    if (cbm_alloc_error != SQLITE_OK) {
        return cbm_alloc_error;
    }

    /* sqlite3. SQLITE_CONFIG_MALLOC MUST run before sqlite3_initialize / the
     * first sqlite3_open* — otherwise sqlite3_config returns SQLITE_MISUSE
     * silently and the binding is ignored. cbm_alloc_init() runs as the very
     * first statement of main(), before cbm_mcp_server_new → cbm_store_open*. */
    static sqlite3_mem_methods cbm_sqlite_mem = {
        cbm_sqlite_malloc,      /* xMalloc */
        cbm_sqlite_free,        /* xFree */
        cbm_sqlite_realloc,     /* xRealloc */
        cbm_sqlite_size,        /* xSize */
        cbm_sqlite_roundup,     /* xRoundup */
        cbm_sqlite_meminit,     /* xInit */
        cbm_sqlite_memshutdown, /* xShutdown */
        NULL,                   /* pAppData */
    };
    int sqlite_rc = sqlite3_config(SQLITE_CONFIG_MALLOC, &cbm_sqlite_mem);
    if (sqlite_rc != SQLITE_OK) {
        cbm_alloc_error = sqlite_rc;
        char sqlite_rc_buf[32];
        snprintf(sqlite_rc_buf, sizeof(sqlite_rc_buf), "%d", sqlite_rc);
        cbm_log_error(
            "allocator.bind_failed", "code", "CBM_SQLITE_ALLOCATOR_BIND_FAILED", "operation",
            "sqlite3_config(SQLITE_CONFIG_MALLOC)", "sqlite_error", sqlite_rc_buf, "message",
            "SQLite rejected the process allocator before CBM initialization", "remediation",
            "ensure cbm_alloc_init is the first SQLite-related process call and restart");
        return sqlite_rc;
    }

    /* SQLite accepted its allocator. Tree-sitter has a void setter and cannot
     * reject this complete function table, so publish success only after both
     * bindings have been installed. */
    ts_set_allocator(mi_malloc, mi_calloc, mi_realloc, mi_free);
    cbm_alloc_bound = 1;
#endif /* CBM_BIND_TS_ALLOCATOR */
    return 0;
}

int cbm_alloc_bindings_active(void) {
    /* Reads back the file-scope binding flag cbm_alloc_init() sets. Non-zero
     * proves cbm_alloc_init() has run and bound tree-sitter/sqlite to mimalloc
     * (only possible in a CBM_BIND_TS_ALLOCATOR build — libcbm.a and the prod
     * binary). Used by the Rust init-order FFI test as independent evidence,
     * not a return-value echo. */
    return cbm_alloc_bound;
}

int cbm_alloc_last_error(void) {
    return cbm_alloc_error;
}

// --- Init/Shutdown ---

static int cbm_initialized = 0;

int cbm_init(void) {
    if (cbm_initialized) {
        return 0;
    }
    int allocator_rc = cbm_alloc_init();
    if (allocator_rc != 0) {
        return allocator_rc;
    }
    enum { CBM_INIT_DONE = 1 };
    cbm_initialized = CBM_INIT_DONE;
    /* Defense-in-depth allocator binds (idempotent). main() calls cbm_alloc_init
     * first; this covers non-main entry points (pipeline passes call cbm_init).
     * For sqlite the SQLITE_CONFIG_MALLOC bind only takes effect if it runs
     * before sqlite initializes — main() guarantees that ordering; here it is a
     * best-effort idempotent re-assert for paths that never hit main(). */
    return 0;
}

void cbm_reset_thread_parser(void) {
    // Release parser's internal slab-allocated subtrees (stack, cached token).
    // Must be called BEFORE cbm_slab_reset_thread() to avoid corrupting
    // live slab chunks that the parser still references.
    if (tl_parser) {
        ts_parser_reset(tl_parser);
    }
}

void cbm_destroy_thread_parser(void) {
    // Full cleanup: delete the parser. Call on worker thread exit.
    if (tl_parser) {
        ts_parser_delete(tl_parser);
        tl_parser = NULL;
        tl_parser_lang = CBM_LANG_COUNT;
    }
}

void cbm_shutdown(void) {
    // Clean up thread-local parser for the calling thread.
    // Note: other threads' TLS parsers are freed when those threads exit.
    cbm_destroy_thread_parser();
    cbm_initialized = 0;
}

// --- Bottleneck call-name classification (language-agnostic heuristics) ---

// Case-insensitive equality for short callee names.
static bool name_ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
    }
    return *a == '\0' && *b == '\0';
}

static bool name_in_set(const char *name, const char *const *set) {
    for (const char *const *s = set; *s; s++) {
        if (name_ieq(name, *s)) {
            return true;
        }
    }
    return false;
}

// Linear-scan / membership calls: a hit inside a loop is the textbook hidden
// O(n^2) (cf. Olivo et al., PLDI'15) that syntactic loop-depth alone misses.
static bool is_linear_scan_name(const char *n) {
    static const char *const set[] = {"find",    "indexof",   "contains", "includes", "search",
                                      "lookup",  "strstr",    "strchr",   "strrchr",  "memchr",
                                      "find_if", "findindex", "count",    "index",    NULL};
    return name_in_set(n, set);
}

// Allocation / growable-append calls: repeated inside a loop is the classic
// accidental reallocation / string-concat O(n^2). Names are deliberately
// conservative; meaningless in some languages → simply never matches there.
static bool is_alloc_name(const char *n) {
    static const char *const set[] = {"malloc",  "calloc",    "realloc",      "strdup", "strndup",
                                      "append",  "push_back", "emplace_back", "concat", "strcat",
                                      "strncat", "push",      "pushback",     NULL};
    return name_in_set(n, set);
}

// Extract the receiver identifier from a def's receiver text — Go's
// "(s *Store)" / "(s Store)" → "s". Stores the identifier start in *out and
// returns its length; returns 0 for unnamed receivers ("(*Store)", "(Store)"),
// where no second token follows the identifier (a lone token is the TYPE, not
// a name — such methods have no receiver variable to call through anyway).
static size_t receiver_ident(const char *recv_text, const char **out) {
    const char *p = recv_text;
    if (*p == '(') {
        p++;
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    const char *start = p;
    while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
           *p == '_') {
        p++;
    }
    size_t len = (size_t)(p - start);
    if (len == 0) {
        return 0; // "(*Store)": leading '*', no identifier
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p == ')' || *p == '\0') {
        return 0; // "(Store)": single token is the type, receiver unnamed
    }
    *out = start;
    return len;
}

// Whether a callee expression targets the same instance/class as the enclosing
// def, i.e. counts as genuine self-recursion rather than a same-named call on a
// different receiver. callee_name may be bare ("recur") or qualified
// ("self.recur", "this.recur", "super().save", "axios.get", "self.obj.recur").
//
// Bare names have no receiver → assume self-call (free function calling itself
// by bare name; preserves prior behavior). Qualified names: the receiver chain
// is everything before the LAST '.', and the WHOLE chain must name the same
// object — self/this/cls/@self, or the enclosing def's own receiver identifier
// (Go: `s` in `func (s *Store) save()`, from CBMDefinition.receiver). Matching
// the whole chain (not its first segment) keeps self.obj.recur() out: it
// targets self's FIELD obj, a different object. super() is the parent class and
// any other receiver (axios, console, ...) a different target. See #599.
static bool is_self_receiver(const char *callee_name, const char *def_receiver) {
    if (!callee_name || !callee_name[0]) {
        return false;
    }
    const char *dot = strrchr(callee_name, '.');
    if (!dot) {
        return true; // bare name → self-recursion candidate
    }
    size_t rlen = (size_t)(dot - callee_name);
    static const char *const self_receivers[] = {"self", "this", "cls", "@self", NULL};
    for (int i = 0; self_receivers[i]; i++) {
        size_t sl = strlen(self_receivers[i]);
        if (rlen == sl && strncmp(callee_name, self_receivers[i], sl) == 0) {
            return true;
        }
    }
    if (def_receiver) {
        const char *rid = NULL;
        size_t ril = receiver_ident(def_receiver, &rid);
        if (ril > 0 && ril == rlen && strncmp(callee_name, rid, ril) == 0) {
            return true; // call through the enclosing method's own receiver
        }
    }
    return false; // super() / axios / console / self.obj / any other receiver
}

// Count parameters from a signature string like "(int a, Foo* b, cb (*)(int,int))".
// Fallback for languages where param_names isn't populated (e.g. C keeps only the
// signature text). Counts commas at the top paren level; treats "()"/"(void)" as 0.
// Approximate by design (a structural smell, not an exact arity).
static int count_params_from_signature(const char *sig) {
    if (!sig) {
        return 0;
    }
    const char *p = sig;
    while (*p && *p != '(') {
        p++;
    }
    if (*p != '(') {
        return 0;
    }
    p++;
    const char *list = p;
    int depth = 0;
    int commas = 0;
    bool any = false;
    for (; *p; p++) {
        char ch = *p;
        if (ch == '(' || ch == '[' || ch == '{' || ch == '<') {
            depth++;
        } else if (ch == ')') {
            if (depth == 0) {
                break;
            }
            depth--;
        } else if (ch == ']' || ch == '}' || ch == '>') {
            if (depth > 0) {
                depth--;
            }
        } else if (ch == ',' && depth == 0) {
            commas++;
        } else if (!isspace((unsigned char)ch)) {
            any = true;
        }
    }
    if (!any) {
        return 0; /* "()" */
    }
    if (commas == 0) {
        while (*list == ' ' || *list == '\t') {
            list++;
        }
        if (strncmp(list, "void", 4) == 0 &&
            (list[4] == ')' || list[4] == ' ' || list[4] == '\0')) {
            return 0; /* C "(void)" */
        }
    }
    return commas + 1;
}

// --- Main extraction function ---

static CBMFileResult *cbm_extract_file_impl(const char *source, int source_len,
                                            CBMLanguage language, const char *project,
                                            const char *rel_path, const char *source_path,
                                            int64_t timeout_micros, const char **extra_defines,
                                            const char **include_paths);

static void cbm_file_result_discard_atoms(CBMFileResult *result) {
    if (!result) {
        return;
    }
    result->defs.count = 0;
    result->calls.count = 0;
    result->imports.count = 0;
    result->usages.count = 0;
    result->local_bindings.count = 0;
    result->throws.count = 0;
    result->rw.count = 0;
    result->type_refs.count = 0;
    result->env_accesses.count = 0;
    result->type_assigns.count = 0;
    result->impl_traits.count = 0;
    result->resolved_calls.count = 0;
    result->string_refs.count = 0;
    result->infra_bindings.count = 0;
    result->channels.count = 0;
    result->diagnostics.count = 0;
    result->imports_count = 0;
    result->exports = NULL;
    result->constants = NULL;
    result->global_vars = NULL;
    result->macros = NULL;
    result->module_qn = NULL;
    result->namespace_name = NULL;
    result->source = NULL;
    result->source_len = 0;
}

void cbm_file_result_set_error(CBMFileResult *result, const char *code, const char *operation,
                               const char *phase, size_t requested, const char *message,
                               const char *remediation) {
    if (!result || result->has_error) {
        return;
    }
    result->has_error = true;
    result->error.code = code ? code : "CBM_EXTRACTION_FAILED";
    result->error.operation = operation ? operation : "extract";
    result->error.phase = phase ? phase : "extract";
    result->error.message =
        message ? message : "authoritative parser extraction failed; partial atoms were discarded";
    result->error.remediation =
        remediation ? remediation
                    : "inspect the structured extraction code and operation, fix the cause, then "
                      "retry the complete corpus";
    result->error.requested = requested;
    result->error_msg = result->error.message;
    cbm_file_result_discard_atoms(result);
}

static bool cbm_extract_code_is_resource_failure(const char *code) {
    return code && (strstr(code, "ALLOC") != NULL || strstr(code, "CAPACITY") != NULL ||
                    strstr(code, "OVERFLOW") != NULL || strstr(code, "LIMIT_EXCEEDED") != NULL);
}

static const char *cbm_extract_failure_message(const char *code) {
    if (code && strcmp(code, "CBM_RUST_MACRO_NO_MATCH") == 0) {
        return "a Rust macro_rules invocation matched no declared rule; no partial extraction may "
               "be persisted";
    }
    if (code && strstr(code, "UNSUPPORTED") != NULL) {
        return "the authoritative parser encountered an unsupported source construct; no partial "
               "extraction may be persisted";
    }
    if (code && strstr(code, "ALLOC") != NULL) {
        return "authoritative parser extraction could not allocate required memory; no partial "
               "extraction may be persisted";
    }
    if (cbm_extract_code_is_resource_failure(code)) {
        return "authoritative parser extraction exhausted a declared resource boundary; no partial "
               "extraction may be persisted";
    }
    return "authoritative parser extraction failed; no partial extraction may be persisted";
}

static const char *cbm_extract_failure_remediation(const char *code) {
    if (code && strcmp(code, "CBM_RUST_MACRO_NO_MATCH") == 0) {
        return "correct the macro invocation or its macro_rules patterns, then retry the complete "
               "corpus";
    }
    if (code && strstr(code, "UNSUPPORTED") != NULL) {
        return "extend the authoritative extractor for this construct, then retry; do not accept a "
               "partial graph";
    }
    if (code && strstr(code, "ALLOC") != NULL) {
        return "inspect the requested quantity, free memory or reduce concurrent extraction "
               "workload, then retry the complete corpus";
    }
    if (cbm_extract_code_is_resource_failure(code)) {
        return "inspect the requested quantity and operation, raise the declared limit "
               "deliberately "
               "or reduce resource demand, then retry";
    }
    return "inspect the exact code and operation, fix the source or extractor, then retry the "
           "complete corpus";
}

static bool cbm_extract_arena_ok(CBMFileResult *result, const char *phase, const char *rel_path) {
    CBMArena *a = result ? &result->arena : NULL;
    if (!a || !cbm_arena_failed(a)) {
        return true;
    }
    const char *code = cbm_arena_failure_code(a);
    const char *operation = cbm_arena_failure_operation(a);
    size_t failure_bytes = cbm_arena_failure_bytes(a);
    char requested[32];
    snprintf(requested, sizeof(requested), "%zu", failure_bytes);
    const char *message = cbm_extract_failure_message(code);
    const char *remediation = cbm_extract_failure_remediation(code);
    cbm_log_error("extract.failed", "code", code, "component", "parser_extraction", "operation",
                  operation, "phase", phase ? phase : "unknown", "file",
                  rel_path ? rel_path : "<input>", "requested", requested, "message", message,
                  "remediation", remediation);
    cbm_file_result_set_error(result, code, operation, phase, failure_bytes, message, remediation);
    return false;
}

CBMFileResult *cbm_extract_file(const char *source, int source_len, CBMLanguage language,
                                const char *project, const char *rel_path, int64_t timeout_micros,
                                const char **extra_defines, const char **include_paths) {
    return cbm_extract_file_impl(source, source_len, language, project, rel_path, NULL,
                                 timeout_micros, extra_defines, include_paths);
}

CBMFileResult *cbm_extract_file_at_path(const char *source, int source_len, CBMLanguage language,
                                        const char *project, const char *rel_path,
                                        const char *source_path, int64_t timeout_micros,
                                        const char **extra_defines, const char **include_paths) {
    return cbm_extract_file_impl(source, source_len, language, project, rel_path, source_path,
                                 timeout_micros, extra_defines, include_paths);
}

static CBMFileResult *cbm_extract_file_impl(const char *source, int source_len,
                                            CBMLanguage language, const char *project,
                                            const char *rel_path, const char *source_path,
                                            int64_t timeout_micros, const char **extra_defines,
                                            const char **include_paths) {
    // Allocate result on heap (arena inside for all string data)
    enum { SINGLE = 1 };
    CBMFileResult *result = (CBMFileResult *)calloc(SINGLE, sizeof(CBMFileResult));
    if (!result) {
        return NULL;
    }

    cbm_arena_init(&result->arena);
    CBMArena *a = &result->arena;
    if (!cbm_extract_arena_ok(result, "arena_init", rel_path)) {
        return result;
    }

    // Get language spec
    const CBMLangSpec *spec = cbm_lang_spec(language);
    if (!spec) {
        cbm_file_result_set_error(
            result, "CBM_LANGUAGE_UNSUPPORTED", "cbm_lang_spec", "language", 0,
            "the requested source language has no authoritative extraction specification",
            "register a complete language specification before retrying the corpus");
        return result;
    }

    // Get tree-sitter language
    const TSLanguage *ts_lang = cbm_ts_language(language);
    if (!ts_lang) {
        // #283 grammar-subset build: distinguish a grammar STUBBED OUT of this
        // build from a language with genuinely no grammar. In a full build every
        // real tree_sitter_*() factory returns a non-NULL pointer, so a non-NULL
        // ts_factory that yields NULL can only be the NULL-returning stub linked
        // in place of a dropped grammar (grammar_stubs.c). Fail closed with a
        // labeled {code, message, remediation} error naming the build knob —
        // never a silent parse miss. This branch is dormant (never taken) in a
        // full build, so default behavior is unchanged.
        if (spec->ts_factory != NULL) {
            cbm_file_result_set_error(
                result, "CBM_GRAMMAR_STUBBED", "cbm_ts_language", "grammar", 0,
                "the tree-sitter grammar for this language is absent from the current libcbm build",
                "rebuild libcbm with CBM_GRAMMAR_SET=full or add the language to "
                "CBM_GRAMMAR_CORE_LANGS, then retry");
        } else {
            cbm_file_result_set_error(
                result, "CBM_GRAMMAR_UNAVAILABLE", "cbm_ts_language", "grammar", 0,
                "the requested language has no tree-sitter grammar",
                "install and register an authoritative grammar before retrying");
        }
        return result;
    }

    // Get thread-local parser (reused across files on same thread)
    TSParser *parser = get_thread_parser(ts_lang, language);
    if (!parser) {
        cbm_file_result_set_error(
            result, "CBM_PARSER_ALLOC_FAILED", "get_thread_parser", "parse", 0,
            "the authoritative tree-sitter parser could not be allocated",
            "free memory or reduce concurrent extraction workers, then retry");
        return result;
    }

    // Reset parser state from any previous parse (cancellation flags etc.)
    ts_parser_reset(parser);

    uint64_t t0 = now_ns();

    // Build string input + timeout options for parse_with_options
    CBMStringInput str_input = {source, (uint32_t)source_len};
    TSInput ts_input = {
        &str_input,
        cbm_string_read,
        TSInputEncodingUTF8,
        NULL,
    };

    TSParseOptions opts = {0};
    uint64_t deadline_ns = 0; // cppcheck-suppress unreadVariable
    if (timeout_micros > 0) {
        deadline_ns = t0 + ((uint64_t)timeout_micros * USEC_TO_NSEC);
        opts.payload = &deadline_ns;
        opts.progress_callback = cbm_timeout_cb;
    }

    TSTree *tree = ts_parser_parse_with_options(parser, NULL, ts_input, opts);
    uint64_t t1 = now_ns();

    if (!tree) {
        cbm_file_result_set_error(
            result, timeout_micros > 0 ? "CBM_PARSE_TIMEOUT" : "CBM_PARSE_FAILED",
            "ts_parser_parse_with_options", "parse",
            timeout_micros > 0 ? (size_t)timeout_micros : 0,
            timeout_micros > 0 ? "the authoritative parse exceeded its declared time budget"
                               : "the authoritative tree-sitter parse failed",
            timeout_micros > 0
                ? "inspect parser complexity and raise the declared timeout deliberately or reduce "
                  "the source unit, then retry"
                : "inspect the exact source and grammar, repair the parser failure, then retry");
        return result;
    }

    TSNode root = ts_tree_root_node(tree);

    // Compute module QN. Java/Go derive the module from the CONTAINING
    // DIRECTORY (package semantics) rather than baking the filename stem in,
    // so def QNs, the LSP caller_qn, and the textual calls-enclosing QN all
    // agree (e.g. Outer.java -> module "proj", not "proj.Outer"). Other
    // languages are unchanged.
    result->module_qn = cbm_fqn_module_source_lang(a, project, rel_path, language);
    result->is_test_file = cbm_is_test_file(rel_path, language);
    if (!cbm_extract_arena_ok(result, "module_identity", rel_path)) {
        goto extraction_failed;
    }

    // Build extraction context
    CBMExtractCtx ctx = {
        .arena = a,
        .result = result,
        .source = source,
        .source_len = source_len,
        .language = language,
        .project = project,
        .rel_path = rel_path,
        .module_qn = result->module_qn,
        .root = root,
    };

    if (language == CBM_LANG_POWERSHELL) {
        cbm_powershell_record_parse_diagnostics(&ctx);
        if (!cbm_extract_arena_ok(result, "powershell_parse_diagnostics", rel_path)) {
            goto extraction_failed;
        }
    }

    // Run extractors: defs + imports use separate walks (unique recursion patterns),
    // then a single unified cursor walk handles the remaining 7 extractors.
    cbm_extract_definitions(&ctx);
    if (result->has_error) {
        goto extraction_failed;
    }
    if (!cbm_extract_arena_ok(result, "definitions", rel_path)) {
        goto extraction_failed;
    }
    cbm_extract_imports(&ctx);
    if (!cbm_extract_arena_ok(result, "imports", rel_path)) {
        goto extraction_failed;
    }
    cbm_extract_reference_bindings(&ctx);
    if (!cbm_extract_arena_ok(result, "reference_bindings", rel_path)) {
        goto extraction_failed;
    }
    cbm_extract_unified(&ctx);
    if (!cbm_extract_arena_ok(result, "unified_atoms", rel_path)) {
        goto extraction_failed;
    }

    if (language == CBM_LANG_POWERSHELL) {
        cbm_powershell_extract_embedded_csharp(&ctx);
        if (result->has_error ||
            !cbm_extract_arena_ok(result, "powershell_embedded_csharp", rel_path)) {
            goto extraction_failed;
        }
    }

    // Channel detection (Socket.IO / EventEmitter) — JS/TS only.
    cbm_extract_channels(&ctx);
    if (!cbm_extract_arena_ok(result, "channels", rel_path)) {
        goto extraction_failed;
    }

    // K8s / Kustomize semantic pass (additional structured extraction for YAML-based infra files).
    if (ctx.language == CBM_LANG_KUSTOMIZE || ctx.language == CBM_LANG_K8S) {
        cbm_extract_k8s(&ctx);
        if (!cbm_extract_arena_ok(result, "kubernetes_atoms", rel_path)) {
            goto extraction_failed;
        }
    }

    // LSP type-aware call/usage resolution (per-file). Runs in every mode;
    // refines the tree-sitter + textual-resolution graph with type info.
    uint64_t lsp_start = now_ns();
    {
        if (language == CBM_LANG_GO) {
            cbm_run_go_lsp(a, result, source, source_len, root);
        }
        if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA) {
            cbm_run_c_lsp(a, result, source, source_len, root, language != CBM_LANG_C);
        }
        if (language == CBM_LANG_PHP) {
            cbm_run_php_lsp(a, result, source, source_len, root);
        }
        if (language == CBM_LANG_PYTHON) {
            cbm_run_py_lsp(a, result, source, source_len, root);
        }
        if (language == CBM_LANG_JAVASCRIPT || language == CBM_LANG_TYPESCRIPT ||
            language == CBM_LANG_TSX) {
            bool js_mode = (language == CBM_LANG_JAVASCRIPT);
            // jsx_mode: TSX always; .jsx in the JS bucket also enables it.
            bool jsx_mode = (language == CBM_LANG_TSX);
            if (language == CBM_LANG_JAVASCRIPT && rel_path) {
                size_t rl = strlen(rel_path);
                if (rl >= 4 && strcmp(rel_path + rl - 4, ".jsx") == 0)
                    jsx_mode = true;
            }
            // dts_mode: ".d.ts" suffix (TypeScript only).
            bool dts_mode = false;
            if (language == CBM_LANG_TYPESCRIPT && rel_path) {
                size_t rl = strlen(rel_path);
                if (rl >= 5 && strcmp(rel_path + rl - 5, ".d.ts") == 0)
                    dts_mode = true;
            }
            cbm_run_ts_lsp(a, result, source, source_len, root, js_mode, jsx_mode, dts_mode);
        }
        if (language == CBM_LANG_CSHARP) {
            cbm_run_cs_lsp(a, result, source, source_len, root);
        }
    }
    if (language == CBM_LANG_JAVA) {
        cbm_run_java_lsp(a, result, source, source_len, root);
    }
    if (language == CBM_LANG_KOTLIN) {
        cbm_run_kotlin_lsp(a, result, source, source_len, root);
    }
    if (language == CBM_LANG_RUST) {
        cbm_run_rust_lsp(a, result, source, source_len, root);
    }
    if (!cbm_extract_arena_ok(result, "per_file_lsp", rel_path)) {
        goto extraction_failed;
    }
    atomic_fetch_add(&total_lsp_ns, now_ns() - lsp_start);

    // Second pass: preprocess C/C++/CUDA and extract additional macro-hidden calls.
    // Defs keep original-source positions. The expansion map translates every
    // appended CALL back to its exact primary-file invocation line before the
    // result can leave this block; no other unified record kind is appended.
    if (language == CBM_LANG_C || language == CBM_LANG_CPP || language == CBM_LANG_CUDA) {
        uint64_t pp_start = now_ns();
        CBMPreprocessStatus pp_status = CBM_PREPROCESS_NO_DIRECTIVES;
        char *pp_diagnostic = NULL;
        uint32_t *primary_source_lines = NULL;
        size_t expanded_line_count = 0;
        const char *preprocessor_path = source_path && source_path[0] ? source_path : rel_path;
        char *expanded =
            cbm_preprocess(source, source_len, preprocessor_path, extra_defines, include_paths,
                           language != CBM_LANG_C, &pp_status, &pp_diagnostic,
                           &primary_source_lines, &expanded_line_count);
        if (pp_status == CBM_PREPROCESS_FAILED) {
            cbm_log_error("preprocessor.failed", "code", "CBM_PREPROCESS_FAILED", "reason",
                          pp_diagnostic ? pp_diagnostic : "unknown", "file",
                          rel_path ? rel_path : "<input>");
            cbm_file_result_set_error(
                result, "CBM_PREPROCESS_FAILED", "cbm_preprocess", "preprocessor_source_map", 0,
                "authoritative C-family preprocessing or expansion mapping failed; no partial "
                "original-only graph may be persisted",
                "inspect the exact preprocessor diagnostic, repair the source or expansion-map "
                "contract, then retry the complete corpus");
        }
        if (expanded && !result->has_error) {
            size_t expanded_size = strlen(expanded);
            if (expanded_size > INT_MAX || !primary_source_lines || expanded_line_count == 0) {
                cbm_log_error("preprocessor.expansion_invalid", "code",
                              "CBM_PREPROCESS_EXPANSION_INVALID", "file",
                              rel_path ? rel_path : "<input>");
                cbm_file_result_set_error(
                    result, "CBM_PREPROCESS_EXPANSION_INVALID", "cbm_preprocess",
                    "preprocessor_source_map", expanded_size,
                    "the expanded source and its physical expansion map are incomplete or exceed "
                    "the parser boundary",
                    "produce one bounded map entry for every expanded physical line, then retry "
                    "the complete corpus");
            }
            int expanded_len = result->has_error ? 0 : (int)expanded_size;

            // Once preprocessing succeeds, its mapped tree is the authoritative call view for
            // this translation unit. The original syntax tree can contain calls in inactive
            // conditional branches and cannot expose macro replacement calls, so mixing the two
            // views creates both false positives and duplicates. Definitions and every non-call
            // record remain owned by the original physical-source tree.
            int original_calls = result->calls.count;
            int original_resolved_calls = result->resolved_calls.count;
            result->calls.count = 0;
            result->resolved_calls.count = 0;
            if (original_calls > 0 || original_resolved_calls > 0) {
                char calls_replaced[32];
                char resolutions_replaced[32];
                snprintf(calls_replaced, sizeof(calls_replaced), "%d", original_calls);
                snprintf(resolutions_replaced, sizeof(resolutions_replaced), "%d",
                         original_resolved_calls);
                cbm_log_info("preprocessor.original_call_view_replaced", "file",
                             rel_path ? rel_path : "<input>", "calls", calls_replaced,
                             "resolved_calls", resolutions_replaced);
            }
            int calls_before = result->calls.count;

            // Parse expanded source with fresh tree
            TSParser *pp_parser = result->has_error ? NULL : get_thread_parser(ts_lang, language);
            if (pp_parser) {
                ts_parser_reset(pp_parser);
                CBMStringInput pp_input = {expanded, (uint32_t)expanded_len};
                TSInput pp_ts_input = {
                    &pp_input,
                    cbm_string_read,
                    TSInputEncodingUTF8,
                    NULL,
                };
                TSParseOptions pp_opts = {0};
                TSTree *pp_tree =
                    ts_parser_parse_with_options(pp_parser, NULL, pp_ts_input, pp_opts);
                if (pp_tree) {
                    TSNode pp_root = ts_tree_root_node(pp_tree);

                    // Build context for expanded source — extract only calls via unified extractor
                    CBMExtractCtx pp_ctx = {
                        .arena = a,
                        .result = result,
                        .source = expanded,
                        .source_len = expanded_len,
                        .language = language,
                        .project = project,
                        .rel_path = rel_path,
                        .module_qn = result->module_qn,
                        .root = pp_root,
                        .string_constants = ctx.string_constants,
                    };
                    cbm_extract_preprocessed_calls(&pp_ctx);

                    // Also run LSP on expanded source for additional type-resolved
                    // calls (language is already C/C++/CUDA — checked in enclosing
                    // block). Runs in every mode.
                    if (!result->has_error) {
                        cbm_run_c_lsp_mapped(a, result, expanded, expanded_len, pp_root,
                                             language != CBM_LANG_C, primary_source_lines,
                                             expanded_line_count);
                    }
                    if (!result->has_error) {
                        remap_preprocessed_calls(result, calls_before, primary_source_lines,
                                                 expanded_line_count, rel_path);
                    }

                    ts_tree_delete(pp_tree);
                } else {
                    cbm_file_result_set_error(
                        result, "CBM_PREPROCESS_PARSE_FAILED", "ts_parser_parse_with_options",
                        "preprocessor_parse", expanded_size,
                        "the mapped preprocessor output could not be parsed; no partial "
                        "original-only graph may be persisted",
                        "inspect the exact expanded source and grammar, repair the parse failure, "
                        "then retry the complete corpus");
                }
            } else if (!result->has_error) {
                cbm_file_result_set_error(
                    result, "CBM_PREPROCESS_PARSER_ALLOC_FAILED", "get_thread_parser",
                    "preprocessor_parse", expanded_size,
                    "the authoritative parser for mapped preprocessor output could not be "
                    "allocated",
                    "free memory or reduce concurrent extraction workers, then retry the "
                    "complete corpus");
            }
            atomic_fetch_add(&total_files_preprocessed, 1);
        }
        cbm_preprocess_free(expanded);
        cbm_preprocess_line_map_free(primary_source_lines);
        cbm_preprocess_diagnostic_free(pp_diagnostic);
        atomic_fetch_add(&total_preprocess_ns, now_ns() - pp_start);
        if (result->has_error) {
            goto extraction_failed;
        }
        if (!cbm_extract_arena_ok(result, "preprocessor_atoms", rel_path)) {
            goto extraction_failed;
        }
    }

    // Bottleneck call-context metrics. Each call is attributed to the INNERMOST
    // enclosing Function/Method def by source-line range (defs and calls in one
    // CBMFileResult share the same file). Range matching is used instead of
    // enclosing_func_qn string matching because some grammars (notably C, whose
    // function_definition has no "name" field) attribute the call's scope to the
    // module rather than the function — line ranges are unambiguous and
    // language-agnostic. Bounded per file (defs x calls), not a repo-scale scan.
    int def_count = result->defs.count;
    bool *has_self = def_count > 0 ? calloc((size_t)def_count, sizeof(bool)) : NULL;
    bool *has_guarded = def_count > 0 ? calloc((size_t)def_count, sizeof(bool)) : NULL;

    // param_count is a standalone structural smell (independent of calls). Prefer
    // the parsed param_names array; fall back to counting from the signature text
    // for languages (e.g. C) that populate only the signature.
    for (int di = 0; di < def_count; di++) {
        CBMDefinition *d = &result->defs.items[di];
        int pc = 0;
        if (d->param_names) {
            while (d->param_names[pc]) {
                pc++;
            }
        }
        if (pc == 0 && d->signature) {
            pc = count_params_from_signature(d->signature);
        }
        d->param_count = pc;
    }

    for (int ci = 0; ci < result->calls.count; ci++) {
        const CBMCall *c = &result->calls.items[ci];
        if (!c->callee_name || c->start_line <= 0) {
            continue;
        }
        // Innermost enclosing Function/Method def by line range (smallest span).
        int best = -1;
        int best_span = -1;
        for (int di = 0; di < def_count; di++) {
            const CBMDefinition *d = &result->defs.items[di];
            if (!d->name || !d->label ||
                (strcmp(d->label, "Function") != 0 && strcmp(d->label, "Method") != 0)) {
                continue;
            }
            if ((int)d->start_line <= c->start_line && c->start_line <= (int)d->end_line) {
                int span = (int)d->end_line - (int)d->start_line;
                if (best < 0 || span < best_span) {
                    best_span = span;
                    best = di;
                }
            }
        }
        if (best < 0) {
            continue;
        }
        CBMDefinition *d = &result->defs.items[best];
        // callee_name may be bare ("recur") or qualified ("self.recur",
        // "super().save", "axios.get"). A short-name match alone is not
        // self-recursion: the callee must also target the same object
        // (is_self_receiver), or super().save() inside save and axios.get
        // inside get are false positives (#599).
        const char *dot = strrchr(c->callee_name, '.');
        const char *callee_short = dot ? dot + 1 : c->callee_name;
        bool in_loop = c->loop_depth > 0;

        if (strcmp(callee_short, d->name) == 0 && is_self_receiver(c->callee_name, d->receiver)) {
            // Direct self-recursion. The call graph omits self-edges (pass_calls
            // skips source==target), so detect it here; seeds "recursive".
            d->is_recursive = true;
            if (has_self) {
                has_self[best] = true;
            }
            if (in_loop) {
                d->recursion_in_loop = true; // recursion compounded by a loop
            }
            if (c->branch_depth > 0 && has_guarded) {
                has_guarded[best] = true; // a self-call guarded by some conditional
            }
        }
        if (in_loop && is_linear_scan_name(callee_short)) {
            d->linear_scan_in_loop++; // hidden O(n^2): linear scan inside a loop
        }
        if (in_loop && is_alloc_name(callee_short)) {
            d->alloc_in_loop++; // repeated allocation/append inside a loop
        }
    }

    // Recursive with no self-call guarded by any conditional → no obvious base
    // case on the recursive path: a stronger "potentially unbounded" signal.
    for (int di = 0; di < def_count; di++) {
        if (has_self && has_self[di] && !(has_guarded && has_guarded[di])) {
            result->defs.items[di].unguarded_recursion = true;
        }
    }
    free(has_self);
    free(has_guarded);

    // #501/#473: capture the byte-exact parse-time source of every definition while
    // the file buffer is still alive. The per-type extractors recorded each def's
    // tree-sitter byte span (def.start_byte/def.end_byte, end-exclusive); slice the
    // exact bytes source[start_byte..end_byte] into the arena. This is the real code
    // payload the row layer persists so ingest's `source_snippet_bytes` carries true
    // content instead of the #413 property-fingerprint proxy. Fail closed on an
    // invalid/unset span (end<=start, or end past the buffer): leave def->source NULL
    // so the persisted symbol is honestly source-absent rather than carrying wrong
    // bytes. The span/source are exact node offsets, never line-based reconstruction.
    for (int di = 0; di < result->defs.count; di++) {
        CBMDefinition *d = &result->defs.items[di];
        if (d->source) {
            if (d->source_len == 0 && d->end_byte > d->start_byte) {
                d->source_len = d->end_byte - d->start_byte;
            }
            continue; // already captured (e.g. a synthetic def set it explicitly)
        }
        if (d->end_byte > d->start_byte && source != NULL &&
            (size_t)d->end_byte <= (size_t)source_len) {
            uint32_t span_len = d->end_byte - d->start_byte;
            d->source = cbm_arena_strndup(a, source + d->start_byte, (size_t)span_len);
            d->source_len = span_len;
        }
    }
    if (!cbm_extract_arena_ok(result, "source_capture", rel_path)) {
        goto extraction_failed;
    }

    uint64_t t2 = now_ns();

    result->imports_count = result->imports.count;

    // Accumulate profiling counters
    atomic_fetch_add(&total_parse_ns, t1 - t0);
    atomic_fetch_add(&total_extract_ns, t2 - t1);
    atomic_fetch_add(&total_files, 1);

    // Retain tree for cross-file LSP reuse (caller frees via cbm_free_tree)
    result->cached_tree = tree;
    result->cached_lang = language;
    return result;

extraction_failed:
    cbm_file_result_discard_atoms(result);
    ts_tree_delete(tree);
    result->cached_tree = NULL;
    return result;
}

void cbm_free_result(CBMFileResult *result) {
    if (!result) {
        return;
    }
    if (result->cached_tree) {
        ts_tree_delete(result->cached_tree);
        result->cached_tree = NULL;
    }
    cbm_arena_destroy(&result->arena);
    free(result);
}

void cbm_free_tree(CBMFileResult *result) {
    if (result && result->cached_tree) {
        ts_tree_delete(result->cached_tree);
        result->cached_tree = NULL;
    }
}

void cbm_free_tree_ptr(TSTree *tree) {
    if (tree) {
        ts_tree_delete(tree);
    }
}
