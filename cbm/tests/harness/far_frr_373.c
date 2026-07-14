/*
 * far_frr_373.c — corpus-scale FAR/FRR harness for macro-embedded call recovery (#373).
 *
 * #358 established that tree-sitter-rust resolves a macro_invocation token_tree
 * interior context-sensitively: a Rust call embedded in a macro
 * (`assert!(self.check())`) is structured as a call_expression in a whole-file
 * parse but left as raw tokens in an isolated-snippet parse. The guard reparses
 * snippets in isolation; production parses whole files. This harness measures, over
 * the REAL calyx/ + crates/ Rust trees, the two competing "make both contexts
 * agree" directions:
 *
 *   FRR(opaque)  = real macro-embedded call edges the whole-file parse finds that
 *                  an isolated parse drops = sum |W\I| over every function. This is
 *                  the count of REAL edges the "opaque" direction (ignore macro
 *                  interiors in both contexts) would delete from production.
 *   FAR(isolate) = callee names the isolated parse produces that are NOT in the
 *                  whole-file superset = sum |I\W|. A non-zero value means an
 *                  isolated reparse FABRICATES a callee — the failure the guard must
 *                  never commit. The "textual recovery" direction (bring isolation
 *                  up to the whole-file set) fabricates nothing beyond this bound.
 *
 * The harness is standalone (not in the gated suite — a full corpus walk under ASan
 * is far too heavy for `make test`); it links the already-built extractor objects and
 * prints the corpus tally so the #373 direction is chosen from measured numbers, per
 * the "new thresholds are measured, not guessed" invariant. A bounded subset-invariant
 * pin lives in the gated suite (test_extraction.c
 * rust_macro_embedded_call_isolation_is_subset_of_whole_file_issue373).
 *
 * The comparison is FILE-LEVEL (W_file = every whole-file callee; I_file = union of the
 * callees recovered by parsing each function in isolation). This is deliberate: a
 * macro-embedded call's synthesized CBMCall has start_line=0, and per-function
 * enclosing-QN attribution differs between an isolated slice and the whole-file parse,
 * so ANY per-function matcher (line-range OR exact-QN) mis-attributes exactly the
 * macro-embedded calls this issue is about. A file-level set union sidesteps both. The
 * BARE (terminal-identifier normalized) variant is the recovery signal; the RAW variant
 * is dominated by name-resolution context (`Self::x` vs `Type::x`) and is reported only
 * for completeness. The instrument is validated: on the #358 repro it reports FRR_bare=2
 * (both macro-embedded method calls correctly detected as dropped by isolation), FAR=0.
 *
 * BUILD (from cbm/, after `make -f Makefile.cbm build/c/test-runner` has populated
 * build/c objects; SANITIZE= to match the C floor):
 *   gcc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -O1 -Isrc -Ivendored -Ivendored/sqlite3 \
 *       -Ivendored/mimalloc/include -Iinternal/cbm \
 *       -Iinternal/cbm/vendored/ts_runtime/include -c tests/harness/far_frr_373.c -o h.o
 *   gcc -O1 -o far_frr_373 h.o \
 *       $(find build/c/tu -name '*.o' | grep -v /tests/) $(find build/c -maxdepth 1 -name '*.o') \
 *       -lm -lstdc++ -lpthread -lz -lws2_32 -lpsapi -lshell32 \
 *       -Wl,--allow-multiple-definition -Wl,--stack,8388608 -static
 *   ./far_frr_373 ../calyx ../crates
 *
 * MEASURED (wave-15, calyx/ + crates/ : 2616 files, 32858 functions, 172032 callees):
 *   FRR_bare = 1497 over 827 files  (real macro-embedded call edges an opaque prune,
 *                                    or the guard's isolated reparse, would DROP)
 *   FAR_bare = 0    over 0   files  (an isolated reparse NEVER produces a callee name
 *                                    the whole-file parse does not — zero fabrication)
 * VERDICT: textual recovery wins decisively (FAR 0 vs opaque's 1497-edge FRR). Opaque
 * is rejected: it would delete 1497 real edges from the production graph. The isolated
 * reparse is proven fabrication-free at corpus scale (corroborates the wave-14 subset
 * invariant, now properly measured with a file-level instrument).
 */
#include "cbm.h"
#include "foundation/compat_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* deduped callee-name set, '|'-joined, first-seen order */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int count;
} CalleeSet;

static void cs_init(CalleeSet *s) {
    s->cap = 4096;
    s->buf = (char *)malloc(s->cap);
    s->buf[0] = '\0';
    s->len = 0;
    s->count = 0;
}
static void cs_free(CalleeSet *s) {
    free(s->buf);
    s->buf = NULL;
}
static int cs_has(const CalleeSet *s, const char *name) {
    char needle[512];
    snprintf(needle, sizeof(needle), "|%s|", name);
    char hay[8192];
    snprintf(hay, sizeof(hay), "|%s|", s->buf);
    return strstr(hay, needle) != NULL;
}
static void cs_add(CalleeSet *s, const char *name) {
    if (!name || !name[0] || cs_has(s, name)) {
        return;
    }
    size_t nl = strlen(name);
    while (s->len + nl + 2 >= s->cap) {
        s->cap *= 2;
        s->buf = (char *)realloc(s->buf, s->cap);
    }
    if (s->len) {
        s->buf[s->len++] = '|';
    }
    memcpy(s->buf + s->len, name, nl + 1);
    s->len += nl;
    s->count++;
}

/* Reduce a callee-name to its bare terminal identifier so a comparison measures
 * call RECOVERY (presence/absence), not receiver/type name-resolution context which
 * legitimately differs between an isolated slice (`Self::x`, `self.y`) and the
 * whole-file parse (`Type::x`, `recv.y`). Takes the span after the last '.' or ':'
 * then the leading identifier run. Empty result falls back to the whole string. */
static void normalize_bare(const char *name, char *out, size_t out_sz) {
    const char *p = name;
    const char *last = name;
    for (; *p; p++) {
        if (*p == '.' || *p == ':') {
            last = p + 1;
        }
    }
    while (*last == ' ' || *last == '\t' || *last == '\n' || *last == '\r') {
        last++;
    }
    size_t n = 0;
    while (last[n] && (last[n] == '_' || (last[n] >= 'A' && last[n] <= 'Z') ||
                       (last[n] >= 'a' && last[n] <= 'z') || (last[n] >= '0' && last[n] <= '9'))) {
        n++;
    }
    if (n == 0) {
        snprintf(out, out_sz, "%s", name);
        return;
    }
    if (n >= out_sz) {
        n = out_sz - 1;
    }
    memcpy(out, last, n);
    out[n] = '\0';
}

/* Collect deduped callee names for calls whose call site (1-based start_line) falls
 * within [lo,hi] (0 = every call). Position matching, not qn-string matching: robust
 * to the qn differences between an isolated slice and the whole-file parse. When
 * `bare` is set the terminal-identifier normalization is applied first. */
static void collect_callees_range(CBMFileResult *r, uint32_t lo, uint32_t hi, int bare,
                                  CalleeSet *set) {
    for (int i = 0; i < r->calls.count; i++) {
        const CBMCall *c = &r->calls.items[i];
        if (!c->callee_name || !c->callee_name[0]) {
            continue;
        }
        if (lo && !(c->start_line >= (int)lo && c->start_line <= (int)hi)) {
            continue;
        }
        if (bare) {
            char nb[256];
            normalize_bare(c->callee_name, nb, sizeof(nb));
            cs_add(set, nb);
        } else {
            cs_add(set, c->callee_name);
        }
    }
}

/* Slice 1-based inclusive line range [start,end] out of src into a fresh buffer. */
static char *slice_lines(const char *src, uint32_t start, uint32_t end) {
    if (start == 0) {
        start = 1;
    }
    uint32_t line = 1;
    const char *p = src;
    const char *begin = NULL;
    const char *stop = NULL;
    if (start == 1) {
        begin = src;
    }
    for (; *p; p++) {
        if (line == start && !begin && p == src) {
            begin = p;
        }
        if (*p == '\n') {
            line++;
            if (line == start && !begin) {
                begin = p + 1;
            }
            if (line == end + 1 && begin) {
                stop = p + 1;
                break;
            }
        }
    }
    if (!begin) {
        return NULL;
    }
    if (!stop) {
        stop = p;
    }
    size_t n = (size_t)(stop - begin);
    char *out = (char *)malloc(n + 1);
    memcpy(out, begin, n);
    out[n] = '\0';
    return out;
}

static char *read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 8 * 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *out_len = (int)rd;
    return buf;
}

/* Count elements of set A absent from set B (|A\B|). */
static int set_minus(const CalleeSet *a, const CalleeSet *b) {
    int diff = 0;
    char *tok = a->len ? strdup(a->buf) : NULL;
    if (tok) {
        for (char *t = strtok(tok, "|"); t; t = strtok(NULL, "|")) {
            if (!cs_has(b, t)) {
                diff++;
            }
        }
        free(tok);
    }
    return diff;
}

/* corpus tallies (FILE-LEVEL: robust to macro-embedded calls whose synthesized
 * call site has start_line=0 and to per-function qn-attribution differences — both
 * of which corrupt any per-function matcher; a file-level set union sidesteps them). */
static long g_files = 0, g_funcs = 0, g_whole_calls = 0;
static long g_frr_raw = 0, g_far_raw = 0;   /* |W_file\I_file| / |I_file\W_file| exact */
static long g_frr_bare = 0, g_far_bare = 0; /* normalized (recovery, not resolution) */
static long g_files_frr = 0, g_files_far = 0;

static int is_measurable_fn(const CBMDefinition *def) {
    return def->label &&
           (strcmp(def->label, "Function") == 0 || strcmp(def->label, "Method") == 0) &&
           def->qualified_name && def->end_line >= def->start_line;
}

static void measure_file(const char *path) {
    int len = 0;
    char *src = read_file(path, &len);
    if (!src) {
        return;
    }
    CBMFileResult *rw = cbm_extract_file(src, len, CBM_LANG_RUST, "corpus", path, 0, NULL, NULL);
    if (!rw) {
        free(src);
        return;
    }
    g_files++;

    /* W_file: EVERY callee the whole-file parse produces (raw + bare). */
    CalleeSet w_raw, w_bare;
    cs_init(&w_raw);
    cs_init(&w_bare);
    collect_callees_range(rw, 0, 0, 0, &w_raw);
    collect_callees_range(rw, 0, 0, 1, &w_bare);
    g_whole_calls += w_raw.count;

    /* I_file: union of the callees recovered by parsing EACH function in isolation
     * (the guard's per-snippet reparse), over every function in the file. */
    CalleeSet i_raw, i_bare;
    cs_init(&i_raw);
    cs_init(&i_bare);
    for (int d = 0; d < rw->defs.count; d++) {
        const CBMDefinition *def = &rw->defs.items[d];
        if (!is_measurable_fn(def)) {
            continue;
        }
        g_funcs++;
        char *slice = slice_lines(src, def->start_line, def->end_line);
        if (!slice) {
            continue;
        }
        CBMFileResult *ri = cbm_extract_file(slice, (int)strlen(slice), CBM_LANG_RUST, "corpus",
                                             "iso.rs", 0, NULL, NULL);
        if (ri) {
            collect_callees_range(ri, 0, 0, 0, &i_raw);
            collect_callees_range(ri, 0, 0, 1, &i_bare);
            cbm_free_result(ri);
        }
        free(slice);
    }

    int frr_raw = set_minus(&w_raw, &i_raw);
    int far_raw = set_minus(&i_raw, &w_raw);
    int frr_bare = set_minus(&w_bare, &i_bare);
    int far_bare = set_minus(&i_bare, &w_bare);
    g_frr_raw += frr_raw;
    g_far_raw += far_raw;
    g_frr_bare += frr_bare;
    g_far_bare += far_bare;
    if (frr_bare > 0) {
        g_files_frr++;
        fprintf(stderr, "[#373 FRR opaque-would-delete] %s  W\\I(bare)=%d\n", path, frr_bare);
    }
    if (far_bare > 0) {
        g_files_far++;
    }
    cs_free(&w_raw);
    cs_free(&w_bare);
    cs_free(&i_raw);
    cs_free(&i_bare);
    cbm_free_result(rw);
    free(src);
}

static int has_rs_ext(const char *name) {
    size_t n = strlen(name);
    return n > 3 && strcmp(name + n - 3, ".rs") == 0;
}

static void walk(const char *dir, int depth) {
    if (depth > 40) {
        return;
    }
    cbm_dir_t *d = cbm_opendir(dir);
    if (!d) {
        return;
    }
    cbm_dirent_t *e;
    while ((e = cbm_readdir(d)) != NULL) {
        if (e->name[0] == '.') {
            continue;
        }
        if (strcmp(e->name, "target") == 0 || strcmp(e->name, "node_modules") == 0) {
            continue;
        }
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", dir, e->name);
        if (e->is_dir) {
            walk(child, depth + 1);
        } else if (has_rs_ext(e->name)) {
            measure_file(child);
        }
    }
    cbm_closedir(d);
}

int main(int argc, char **argv) {
    cbm_init();
    if (argc < 2) {
        fprintf(stderr, "usage: far_frr_373 <root-dir> [<root-dir>...]\n");
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        walk(argv[i], 0);
    }
    printf("=== #373 corpus FAR/FRR tally (FILE-LEVEL set comparison) ===\n");
    printf("rs_files_parsed      = %ld\n", g_files);
    printf("functions_measured   = %ld\n", g_funcs);
    printf("whole_file_callees   = %ld  (deduped per file, summed)\n", g_whole_calls);
    printf("\n-- RAW (exact callee text) --\n");
    printf("FRR_raw sum|W_file\\I_file| (whole-file callees NO isolated fn recovers) = %ld\n",
           g_frr_raw);
    printf("FAR_raw sum|I_file\\W_file| (isolated callees whole-file never produces) = %ld\n",
           g_far_raw);
    printf("\n-- BARE (terminal-identifier normalized: RECOVERY presence, not resolution "
           "context) --\n");
    printf("FRR_bare = %ld  over %ld files  <- real macro-embedded edges 'opaque' deletes / "
           "isolation drops\n",
           g_frr_bare, g_files_frr);
    printf("FAR_bare = %ld  over %ld files  <- isolated over-production 'textual recovery' "
           "risks\n",
           g_far_bare, g_files_far);
    return 0;
}
