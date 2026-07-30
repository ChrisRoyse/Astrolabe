/*
 * discover.h — File discovery, language detection, and gitignore matching.
 *
 * Provides:
 *   - Language detection from filename/extension (CBM_SZ_64 languages)
 *   - .m file disambiguation (Objective-C vs Magma vs MATLAB)
 *   - Gitignore-style pattern parsing and matching
 *   - Recursive directory walk with hardcoded + gitignore filtering
 *
 * Depends on: foundation (platform.h for file ops), cbm.h (CBMLanguage enum)
 */
#ifndef CBM_DISCOVER_H
#define CBM_DISCOVER_H

#include <stdbool.h>
#include <stdint.h>

/* Use the existing CBMLanguage enum from extraction layer */
#include "cbm.h"

/* ── Language detection ──────────────────────────────────────────── */

/* Detect language from a filename (basename only, not full path).
 * Checks special filenames first (Makefile, CMakeLists.txt, etc.),
 * then falls back to extension-based lookup.
 * Returns CBM_LANG_COUNT if unknown. */
CBMLanguage cbm_language_for_filename(const char *filename);

/* Detect language from a file extension (including the dot, e.g. ".go").
 * Returns CBM_LANG_COUNT if unknown. */
CBMLanguage cbm_language_for_extension(const char *ext);

/* Get the human-readable name for a language enum value.
 * Returns "Unknown" for CBM_LANG_COUNT or out-of-range values. */
const char *cbm_language_name(CBMLanguage lang);

/* Disambiguate .m files by reading the first 4KB completely. Read failures
 * are terminal; ambiguity is classified as MATLAB only after a successful read. */
int cbm_disambiguate_m_checked(const char *path, CBMLanguage *out);

/* ── Gitignore pattern matching ──────────────────────────────────── */

typedef struct cbm_gitignore cbm_gitignore_t;

/* Load gitignore patterns with complete-or-error semantics. A missing path is
 * accepted only when optional is true. Caller owns *out on success. */
int cbm_gitignore_load_checked(const char *path, bool optional, cbm_gitignore_t **out);

/* Parse gitignore patterns from a string.
 * Caller must call cbm_gitignore_free(). */
cbm_gitignore_t *cbm_gitignore_parse(const char *content);

/* Check if a relative path matches any gitignore pattern.
 * rel_path should use '/' separators. is_dir indicates if path is a directory. */
bool cbm_gitignore_matches(const cbm_gitignore_t *gi, const char *rel_path, bool is_dir);

/* Free a gitignore matcher. NULL-safe. */
void cbm_gitignore_free(cbm_gitignore_t *gi);

/* Append all patterns from src into dst. dst takes ownership of deep copies
 * of each src pattern; src is unchanged and must still be freed by the caller.
 * NULL-safe on either argument.
 * Returns true on success (or when there is nothing to merge). Returns false on
 * allocation failure, in which case dst is left exactly as it was (atomic) — no
 * partial merge — so a failed merge degrades to "as if src was absent". */
bool cbm_gitignore_merge(cbm_gitignore_t *dst, const cbm_gitignore_t *src);

/* ── Directory skip / suffix filters ─────────────────────────────── */

/* Index mode controls filtering aggressiveness.
 * IMPORTANT: these values MUST match pipeline.h exactly.  A previous
 * mismatch (this header had FAST=1, pipeline.h has FAST=2) caused
 * fast-mode filtering to silently no-op depending on include order —
 * the pipeline passed value 2, discover.c compared against 1, and no
 * files got filtered. */
#ifndef CBM_INDEX_MODE_T_DEFINED
#define CBM_INDEX_MODE_T_DEFINED
typedef enum {
    CBM_MODE_FULL = 0,     /* parse everything supported */
    CBM_MODE_MODERATE = 1, /* aggressive filtering + similarity/semantic edges */
    CBM_MODE_FAST = 2,     /* aggressive filtering + no similarity/semantic edges */
} cbm_index_mode_t;
#endif

/* Check if a directory name should always be skipped (e.g. .git, node_modules).
 * Only invariant cache/vendor/build basenames are skipped; mode never adds
 * semantic-role guesses that could hide imported production source. */
bool cbm_should_skip_dir(const char *dirname, cbm_index_mode_t mode);

/* Check if a file has a suffix that should be skipped (e.g. .pyc, .png). */
bool cbm_has_ignored_suffix(const char *filename, cbm_index_mode_t mode);

/* Check if a specific filename should be skipped in fast mode (e.g. LICENSE, go.sum). */
bool cbm_should_skip_filename(const char *filename, cbm_index_mode_t mode);

/* Check if a path matches fast-mode substring patterns (e.g. .d.ts, .pb.go). */
bool cbm_matches_fast_pattern(const char *filename, cbm_index_mode_t mode);

/* ── File discovery ──────────────────────────────────────────────── */

typedef struct {
    char *path;           /* immutable snapshot path after capture (heap-allocated) */
    char *live_path;      /* original absolute path; never used by extraction passes */
    char *rel_path;       /* relative to repo root (heap-allocated) */
    CBMLanguage language; /* detected language */
    int64_t size;         /* exact captured byte count */
    int64_t mtime_ns;     /* handle-bound source mtime captured with the bytes */
    char sha256[65];      /* lowercase SHA-256 of the exact captured bytes */
    uint64_t source_volume_serial;
    uint8_t source_file_id[16];
    int64_t source_change_time_100ns;
    bool auxiliary;            /* interpretation input with no registered source language */
    bool interpretation_input; /* changes can affect resolution beyond this file */
    char structured_classification[16];
    char structured_classification_provenance[128];
    uint8_t structured_classification_rank;
} cbm_file_info_t;

/* True for files that affect source interpretation even when they are not
 * themselves code atoms (package manifests, alias config, ignore/config
 * policy, and environment manifests). */
bool cbm_is_auxiliary_input_name(const char *filename);

typedef struct {
    cbm_index_mode_t mode;   /* CBM_MODE_FULL or CBM_MODE_FAST */
    const char *ignore_file; /* path to .cbmignore file, or NULL */
    int64_t max_file_size;   /* 0 = no limit */
} cbm_discover_opts_t;

/* Walk a repository directory tree and discover all source files.
 * Applies hardcoded filters, gitignore patterns, and language detection.
 * Returns 0 on success, -1 on error.
 * Caller must call cbm_discover_free() on the results. */
int cbm_discover(const char *repo_path, const cbm_discover_opts_t *opts, cbm_file_info_t **out,
                 int *count);

/* Like cbm_discover(), but also reports the directory subtrees that were
 * skipped during the walk (hardcoded ALWAYS_SKIP/FAST_SKIP dirs + gitignore
 * matches), so callers can surface which subtrees were dropped (#411).
 * On success, *excluded_out receives a heap-allocated array of strdup'd
 * relative directory paths and *excluded_count_out its length; the caller
 * owns it and must free via cbm_discover_free_excluded(). Pass NULL for
 * excluded_out (and/or excluded_count_out) to discard the list — the internal
 * accumulator is freed in that case (no leak).
 * Returns 0 on success, -1 on error. */
int cbm_discover_ex(const char *repo_path, const cbm_discover_opts_t *opts, cbm_file_info_t **out,
                    int *count, char ***excluded_out, int *excluded_count_out);

/* Free an array of file info results. NULL-safe. */
void cbm_discover_free(cbm_file_info_t *files, int count);

/* Free the excluded-directory list returned by cbm_discover_ex(). NULL-safe. */
void cbm_discover_free_excluded(char **excluded, int count);

#endif /* CBM_DISCOVER_H */
