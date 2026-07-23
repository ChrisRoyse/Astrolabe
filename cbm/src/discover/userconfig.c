/*
 * userconfig.c — User-defined extension→language mappings.
 *
 * Reads extra_extensions from:
 *   Global:  $XDG_CONFIG_HOME/codebase-memory-mcp/config.json
 *            (falls back to ~/.config/codebase-memory-mcp/config.json)
 *   Project: {repo_root}/.codebase-memory.json
 *
 * Project config wins over global. Missing files are optional; present
 * invalid/unreadable inputs fail closed.
 */
#include "discover/userconfig.h"
#include "cbm.h" /* CBMLanguage, CBM_LANG_* */
#include "foundation/constants.h"
#include "foundation/platform.h" /* cbm_safe_getenv */
#include "foundation/compat_fs.h"

#include "foundation/log.h"

#include <yyjson/yyjson.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Process-global user config pointer ──────────────────────────── */

static const cbm_userconfig_t *g_userconfig = NULL;

void cbm_set_user_lang_config(const cbm_userconfig_t *cfg) {
    g_userconfig = cfg;
}

const cbm_userconfig_t *cbm_get_user_lang_config(void) {
    return g_userconfig;
}

/* ── Language name → enum table ──────────────────────────────────── */

/*
 * Reverse-mapping from lowercase language name strings to CBMLanguage.
 * Covers all names exposed by cbm_language_name() plus common aliases.
 */
typedef struct {
    const char *name; /* lowercase */
    CBMLanguage lang;
} lang_name_entry_t;

static const lang_name_entry_t LANG_NAME_TABLE[] = {
    {"go", CBM_LANG_GO},
    {"python", CBM_LANG_PYTHON},
    {"javascript", CBM_LANG_JAVASCRIPT},
    {"typescript", CBM_LANG_TYPESCRIPT},
    {"tsx", CBM_LANG_TSX},
    {"rust", CBM_LANG_RUST},
    {"java", CBM_LANG_JAVA},
    {"c++", CBM_LANG_CPP},
    {"cpp", CBM_LANG_CPP},
    {"c#", CBM_LANG_CSHARP},
    {"csharp", CBM_LANG_CSHARP},
    {"php", CBM_LANG_PHP},
    {"lua", CBM_LANG_LUA},
    {"scala", CBM_LANG_SCALA},
    {"kotlin", CBM_LANG_KOTLIN},
    {"ruby", CBM_LANG_RUBY},
    {"c", CBM_LANG_C},
    {"bash", CBM_LANG_BASH},
    {"sh", CBM_LANG_BASH},
    {"zig", CBM_LANG_ZIG},
    {"elixir", CBM_LANG_ELIXIR},
    {"haskell", CBM_LANG_HASKELL},
    {"ocaml", CBM_LANG_OCAML},
    {"objective-c", CBM_LANG_OBJC},
    {"objc", CBM_LANG_OBJC},
    {"swift", CBM_LANG_SWIFT},
    {"dart", CBM_LANG_DART},
    {"perl", CBM_LANG_PERL},
    {"groovy", CBM_LANG_GROOVY},
    {"erlang", CBM_LANG_ERLANG},
    {"r", CBM_LANG_R},
    {"html", CBM_LANG_HTML},
    {"css", CBM_LANG_CSS},
    {"scss", CBM_LANG_SCSS},
    {"yaml", CBM_LANG_YAML},
    {"toml", CBM_LANG_TOML},
    {"hcl", CBM_LANG_HCL},
    {"terraform", CBM_LANG_HCL},
    {"sql", CBM_LANG_SQL},
    {"dockerfile", CBM_LANG_DOCKERFILE},
    {"clojure", CBM_LANG_CLOJURE},
    {"f#", CBM_LANG_FSHARP},
    {"fsharp", CBM_LANG_FSHARP},
    {"julia", CBM_LANG_JULIA},
    {"vimscript", CBM_LANG_VIMSCRIPT},
    {"nix", CBM_LANG_NIX},
    {"common lisp", CBM_LANG_COMMONLISP},
    {"commonlisp", CBM_LANG_COMMONLISP},
    {"lisp", CBM_LANG_COMMONLISP},
    {"elm", CBM_LANG_ELM},
    {"fortran", CBM_LANG_FORTRAN},
    {"cuda", CBM_LANG_CUDA},
    {"cobol", CBM_LANG_COBOL},
    {"verilog", CBM_LANG_VERILOG},
    {"emacs lisp", CBM_LANG_EMACSLISP},
    {"emacslisp", CBM_LANG_EMACSLISP},
    {"json", CBM_LANG_JSON},
    {"xml", CBM_LANG_XML},
    {"markdown", CBM_LANG_MARKDOWN},
    {"makefile", CBM_LANG_MAKEFILE},
    {"cmake", CBM_LANG_CMAKE},
    {"protobuf", CBM_LANG_PROTOBUF},
    {"graphql", CBM_LANG_GRAPHQL},
    {"vue", CBM_LANG_VUE},
    {"svelte", CBM_LANG_SVELTE},
    {"meson", CBM_LANG_MESON},
    {"glsl", CBM_LANG_GLSL},
    {"ini", CBM_LANG_INI},
    {"matlab", CBM_LANG_MATLAB},
    {"lean", CBM_LANG_LEAN},
    {"form", CBM_LANG_FORM},
    {"magma", CBM_LANG_MAGMA},
    {"wolfram", CBM_LANG_WOLFRAM},
};

#define LANG_NAME_TABLE_SIZE (sizeof(LANG_NAME_TABLE) / sizeof(LANG_NAME_TABLE[0]))

/*
 * Parse a language string (case-insensitive) to a CBMLanguage enum.
 * Returns CBM_LANG_COUNT if the string is not recognized.
 */
static CBMLanguage lang_from_string(const char *s) {
    if (!s || !s[0]) {
        return CBM_LANG_COUNT;
    }

    /* Build a lowercase copy for comparison */
    char lower[CBM_SZ_64];
    size_t i;
    for (i = 0; i < sizeof(lower) - SKIP_ONE && s[i]; i++) {
        lower[i] = (char)tolower((unsigned char)s[i]);
    }
    lower[i] = '\0';

    for (size_t j = 0; j < LANG_NAME_TABLE_SIZE; j++) {
        if (strcmp(LANG_NAME_TABLE[j].name, lower) == 0) {
            return LANG_NAME_TABLE[j].lang;
        }
    }
    return CBM_LANG_COUNT;
}

/* ── Config directory helper ─────────────────────────────────────── */

/* cbm_app_config_dir() is now in platform.c (cross-platform). */

/* ── JSON parsing ────────────────────────────────────────────────── */

/*
 * Parse extra_extensions from a yyjson object root.
 * Appends valid entries to *entries / *count (growing via realloc).
 * Project-level entries (from_project=true) are appended after global
 * entries so that a later dedup pass can prefer project values.
 *
 * Returns 0 on success, -1 on alloc failure.
 */
static int parse_extra_extensions(yyjson_val *root, cbm_userext_t **entries, int *count,
                                  const char *source_label) {
    if (!yyjson_is_obj(root)) {
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_ROOT_INVALID", "path",
                      source_label, "message", "the configuration root is not a JSON object",
                      "remediation", "provide a JSON object and retry indexing");
        return CBM_NOT_FOUND;
    }

    yyjson_val *extra = yyjson_obj_get(root, "extra_extensions");
    if (!extra) {
        return 0; /* key absent — fine */
    }
    if (!yyjson_is_obj(extra)) {
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_EXTENSIONS_INVALID", "path",
                      source_label, "message", "extra_extensions is not a JSON object",
                      "remediation", "map extension keys to language names and retry indexing");
        return CBM_NOT_FOUND;
    }

    int source_start = *count;
    yyjson_obj_iter iter;
    yyjson_obj_iter_init(extra, &iter);
    yyjson_val *key;
    while ((key = yyjson_obj_iter_next(&iter)) != NULL) {
        yyjson_val *val = yyjson_obj_iter_get_val(key);

        const char *ext_str = yyjson_get_str(key);
        const char *lang_str = yyjson_get_str(val);

        if (!ext_str || !lang_str) {
            cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_ENTRY_INVALID", "path",
                          source_label, "message",
                          "an extension mapping does not contain string key and value data",
                          "remediation", "map each extension string to a language string");
            return CBM_NOT_FOUND;
        }

        /* Extension must start with '.' */
        size_t ext_len = strlen(ext_str);
        bool ext_valid = ext_len > SKIP_ONE && ext_str[0] == '.';
        for (size_t i = SKIP_ONE; ext_valid && i < ext_len; i++) {
            if (ext_str[i] == '/' || ext_str[i] == '\\' || isspace((unsigned char)ext_str[i])) {
                ext_valid = false;
            }
        }
        if (!ext_valid) {
            cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_EXTENSION_INVALID", "path",
                          source_label, "extension", ext_str, "message",
                          "a configured extension is not a valid explicit suffix", "remediation",
                          "correct the extension key and retry indexing");
            return CBM_NOT_FOUND;
        }

        CBMLanguage lang = lang_from_string(lang_str);
        if (lang == CBM_LANG_COUNT) {
            cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_LANGUAGE_UNKNOWN", "path",
                          source_label, "language", lang_str, "message",
                          "a configured extension names an unsupported language", "remediation",
                          "use a registered language name and retry indexing");
            return CBM_NOT_FOUND;
        }

        for (int i = source_start; i < *count; i++) {
            if (strcmp((*entries)[i].ext, ext_str) == 0) {
                cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_EXTENSION_DUPLICATE",
                              "path", source_label, "extension", ext_str, "message",
                              "the configuration defines one extension more than once",
                              "remediation", "retain exactly one mapping for the extension");
                return CBM_NOT_FOUND;
            }
        }

        /* Grow the array */
        if (*count == INT_MAX) {
            return CBM_NOT_FOUND;
        }
        cbm_userext_t *tmp = realloc(*entries, (size_t)(*count + SKIP_ONE) * sizeof(cbm_userext_t));
        if (!tmp) {
            return CBM_NOT_FOUND;
        }
        *entries = tmp;

        char *ext_copy = strdup(ext_str);
        if (!ext_copy) {
            return CBM_NOT_FOUND;
        }

        (*entries)[*count].ext = ext_copy;
        (*entries)[*count].lang = lang;
        (*count)++;
    }
    return 0;
}

/*
 * Read a JSON file and parse extra_extensions from it.
 * Missing files are optional. Present files are complete-or-error.
 */
static int load_config_file(const char *path, cbm_userext_t **entries, int *count) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_OPEN_FAILED", "path", path,
                      "message", "a present configuration file could not be opened", "remediation",
                      "restore file access and retry indexing");
        return CBM_NOT_FOUND;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_SEEK_FAILED", "path", path,
                      "message", "the configuration length could not be measured", "remediation",
                      "stabilize the file and retry indexing");
        return CBM_NOT_FOUND;
    }
    long len = ftell(f);
    if (fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_SEEK_FAILED", "path", path,
                      "message", "the configuration stream could not be rewound", "remediation",
                      "stabilize the file and retry indexing");
        return CBM_NOT_FOUND;
    }

    if (len <= 0) {
        (void)fclose(f);
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_SIZE_INVALID", "path", path,
                      "message", "the configuration is empty", "remediation",
                      "provide a non-empty JSON configuration");
        return CBM_NOT_FOUND;
    }

    char *buf = malloc((size_t)len + SKIP_ONE);
    if (!buf) {
        (void)fclose(f);
        return CBM_NOT_FOUND;
    }

    size_t nread = fread(buf, SKIP_ONE, (size_t)len, f);
    bool read_ok = nread == (size_t)len && ferror(f) == 0;
    if (fclose(f) != 0) {
        read_ok = false;
    }
    if (!read_ok) {
        free(buf);
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_READ_FAILED", "path", path,
                      "message", "the complete configuration bytes could not be read",
                      "remediation", "stabilize the file and retry indexing");
        return CBM_NOT_FOUND;
    }
    buf[nread] = '\0';

    yyjson_doc *doc = yyjson_read(buf, nread, 0);
    free(buf);

    if (!doc) {
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_JSON_INVALID", "path", path,
                      "message", "the configuration is not valid JSON", "remediation",
                      "correct the JSON and retry indexing");
        return CBM_NOT_FOUND;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    int rc = parse_extra_extensions(root, entries, count, path);
    yyjson_doc_free(doc);
    return rc;
}

/* ── Public API ──────────────────────────────────────────────────── */

int cbm_userconfig_load_checked(const char *repo_path, cbm_userconfig_t **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    cbm_userconfig_t *cfg = calloc(CBM_ALLOC_ONE, sizeof(cbm_userconfig_t));
    if (!cfg) {
        return CBM_NOT_FOUND;
    }

    cbm_userext_t *entries = NULL;
    int count = 0;

    /* ── Step 1: Load global config ── */
    const char *cfg_base = cbm_app_config_dir();
    if (!cfg_base) {
        free(cfg);
        cbm_log_error("userconfig.failed", "code", "CBM_USERCONFIG_BASE_UNAVAILABLE", "message",
                      "the application configuration root could not be resolved", "remediation",
                      "restore the native user configuration environment and retry");
        return CBM_NOT_FOUND;
    }
    const char global_suffix[] = "/codebase-memory-mcp/config.json";
    size_t global_size = strlen(cfg_base) + sizeof(global_suffix);
    char *global_path = malloc(global_size);
    if (!global_path) {
        free(cfg);
        return CBM_NOT_FOUND;
    }
    snprintf(global_path, global_size, "%s%s", cfg_base, global_suffix);

    if (load_config_file(global_path, &entries, &count) != 0) {
        for (int i = 0; i < count; i++) {
            free(entries[i].ext);
        }
        free(entries);
        free(cfg);
        free(global_path);
        return CBM_NOT_FOUND;
    }
    free(global_path);

    int global_count = count; /* entries[0..global_count) are from global */

    /* ── Step 2: Load project config ── */
    if (repo_path && repo_path[0]) {
        const char project_suffix[] = "/.codebase-memory.json";
        size_t project_size = strlen(repo_path) + sizeof(project_suffix);
        char *project_path = malloc(project_size);
        if (!project_path) {
            for (int i = 0; i < count; i++) {
                free(entries[i].ext);
            }
            free(entries);
            free(cfg);
            return CBM_NOT_FOUND;
        }
        snprintf(project_path, project_size, "%s%s", repo_path, project_suffix);

        if (load_config_file(project_path, &entries, &count) != 0) {
            /* Free already-allocated entries */
            for (int i = 0; i < count; i++) {
                free(entries[i].ext);
            }
            free(entries);
            free(cfg);
            free(project_path);
            return CBM_NOT_FOUND;
        }
        free(project_path);
    }

    /*
     * ── Step 3: Dedup — project entries win over global ──
     *
     * For any extension that appears in both global (indices 0..global_count)
     * and project (indices global_count..count), remove the global entry by
     * replacing it with the last global entry (order-insensitive dedup).
     */
    for (int p = global_count; p < count; p++) {
        for (int g = 0; g < global_count; g++) {
            if (entries[g].ext && strcmp(entries[g].ext, entries[p].ext) == 0) {
                /* Remove global entry: overwrite with last global entry */
                free(entries[g].ext);
                entries[g] = entries[global_count - SKIP_ONE];
                entries[global_count - SKIP_ONE].ext = NULL; /* mark as consumed */
                global_count--;
                break;
            }
        }
    }

    /*
     * Compact: remove any NULL-ext slots left by the dedup step.
     * (Those are the consumed "last global" entries.)
     */
    int write_idx = 0;
    for (int i = 0; i < count; i++) {
        if (entries[i].ext != NULL) {
            entries[write_idx++] = entries[i];
        }
    }
    count = write_idx;

    cfg->entries = entries;
    cfg->count = count;
    *out = cfg;
    return 0;
}

bool cbm_userconfig_equal(const cbm_userconfig_t *left, const cbm_userconfig_t *right) {
    if (left == right) {
        return true;
    }
    if (!left || !right || left->count != right->count) {
        return false;
    }
    for (int i = 0; i < left->count; i++) {
        bool found = false;
        for (int j = 0; j < right->count; j++) {
            if (strcmp(left->entries[i].ext, right->entries[j].ext) == 0 &&
                left->entries[i].lang == right->entries[j].lang) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

CBMLanguage cbm_userconfig_lookup(const cbm_userconfig_t *cfg, const char *ext) {
    if (!cfg || !ext || !ext[0]) {
        return CBM_LANG_COUNT;
    }
    for (int i = 0; i < cfg->count; i++) {
        if (cfg->entries[i].ext && strcmp(cfg->entries[i].ext, ext) == 0) {
            return cfg->entries[i].lang;
        }
    }
    return CBM_LANG_COUNT;
}

void cbm_userconfig_free(cbm_userconfig_t *cfg) {
    if (!cfg) {
        return;
    }
    for (int i = 0; i < cfg->count; i++) {
        free(cfg->entries[i].ext);
    }
    free(cfg->entries);
    free(cfg);
}
