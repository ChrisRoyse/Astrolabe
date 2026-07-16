#ifndef CBM_PREPROCESSOR_H
#define CBM_PREPROCESSOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CBM_PREPROCESS_NO_DIRECTIVES = 0,
    CBM_PREPROCESS_OK = 1,
    CBM_PREPROCESS_FAILED = 2,
} CBMPreprocessStatus;

// Preprocess C/C++ source: expand macros, evaluate #ifdef, resolve #include.
// Returns malloc-allocated expanded source when status is CBM_PREPROCESS_OK.
// Returns NULL with CBM_PREPROCESS_NO_DIRECTIVES when the source has no
// preprocessor branch/macro directives worth expanding. Returns NULL with
// CBM_PREPROCESS_FAILED and a malloc-allocated diagnostic on preprocessing
// failure; callers must log or surface that diagnostic rather than treating it
// as a clean "no expansion" case.
// extra_defines: NULL-terminated array of "NAME=VALUE" strings (can be NULL).
// include_paths: NULL-terminated array of directory paths for #include resolution (can be NULL).
// The returned string must be freed with cbm_preprocess_free().
char *cbm_preprocess(const char *source, int source_len, const char *filename,
                     const char **extra_defines, const char **include_paths, int cpp_mode,
                     CBMPreprocessStatus *status_out, char **diagnostic_out);

// Free preprocessed source returned by cbm_preprocess.
void cbm_preprocess_free(char *expanded);

// Free diagnostic strings returned via cbm_preprocess.
void cbm_preprocess_diagnostic_free(char *diagnostic);

#ifdef __cplusplus
}
#endif

#endif // CBM_PREPROCESSOR_H
