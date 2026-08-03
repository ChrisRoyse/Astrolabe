#ifndef CBM_FOUNDATION_LOG_INTERNAL_H
#define CBM_FOUNDATION_LOG_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Emit the opt-in pipeline phase probe through the same serialized sink as
 * ordinary libcbm diagnostics while deliberately bypassing the runtime log
 * floor. The explicit phase-trace switch is an independent measurement
 * channel used to diagnose a worker even when a fleet run raises the general
 * floor to WARN or ERROR.
 *
 * This is an internal C boundary, not part of the Rust FFI surface.
 */
void cbm_log_pipeline_phase_trace(const char *boundary, const char *phase, uint64_t pid,
                                  int mode, bool row_sink_active, bool row_sink_completed,
                                  int nodes, int edges, bool memory_valid,
                                  uint64_t working_set_bytes, uint64_t private_bytes,
                                  uint64_t peak_working_set_bytes,
                                  uint64_t peak_private_bytes);

#endif /* CBM_FOUNDATION_LOG_INTERNAL_H */
