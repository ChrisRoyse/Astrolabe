#ifndef CBM_PIPELINE_STRUCTURED_DATA_H
#define CBM_PIPELINE_STRUCTURED_DATA_H

#include "discover/discover.h"

/* Resolve repository-owned structured-data classification attributes against
 * the immutable source snapshot. Absence is an explicit no-override result;
 * any present but unevaluable policy is terminal. */
int cbm_structured_classify_files(const char *repo_path, const char *snapshot_root,
                                  cbm_file_info_t *files, int file_count);

#endif /* CBM_PIPELINE_STRUCTURED_DATA_H */
