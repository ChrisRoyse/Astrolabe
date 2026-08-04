#ifndef CBM_PREPROCESSOR_H
#define CBM_PREPROCESSOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CBM_PREPROCESS_NO_DIRECTIVES = 0,
    CBM_PREPROCESS_OK = 1,
    CBM_PREPROCESS_FAILED = 2,
} CBMPreprocessStatus;

typedef struct CBMPreprocessContext CBMPreprocessContext;

// Preprocess C/C++ source: expand macros, evaluate #ifdef, resolve #include.
// Returns malloc-allocated expanded source when status is CBM_PREPROCESS_OK.
// Returns NULL with CBM_PREPROCESS_NO_DIRECTIVES when the source has no
// preprocessor branch/macro directives worth expanding. Returns NULL with
// CBM_PREPROCESS_FAILED and a malloc-allocated diagnostic on preprocessing
// failure; callers must log or surface that diagnostic rather than treating it
// as a clean "no expansion" case.
// extra_defines: NULL-terminated array of "NAME=VALUE" strings (can be NULL).
// include_paths: NULL-terminated array of directory paths for #include resolution (can be NULL).
// primary_source_lines_out receives one entry per physical line in the returned
// expanded buffer. Entry N maps expanded line N+1 to the physical line in the
// primary input where the outermost expansion occurred. Zero marks a generated
// directive or an invalid/out-of-range origin; UINT32_MAX marks a token line
// owned by an included file. The caller must never persist an expanded line
// directly and must free the map with cbm_preprocess_line_map_free().
// The returned string must be freed with cbm_preprocess_free().
char *cbm_preprocess(const char *focus_source, int focus_source_len, const char *focus_filename,
                     const CBMPreprocessContext *context,
                     CBMPreprocessStatus *status_out, char **diagnostic_out,
                     uint32_t **primary_source_lines_out, size_t *expanded_line_count_out);

// Free preprocessed source returned by cbm_preprocess.
void cbm_preprocess_free(char *expanded);

// Free the expansion-location map returned by cbm_preprocess.
void cbm_preprocess_line_map_free(uint32_t *primary_source_lines);

// Free diagnostic strings returned via cbm_preprocess.
void cbm_preprocess_diagnostic_free(char *diagnostic);

#ifdef __cplusplus
}
#endif

#endif // CBM_PREPROCESSOR_H
