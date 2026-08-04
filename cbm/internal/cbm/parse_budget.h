/* parse_budget.h — private measured Tree-sitter budget registry (#978).
 *
 * This scheduler contract is deliberately not part of cbm.h or the Rust FFI.
 * Each file receives a total budget derived from its captured byte length;
 * Tree-sitter's progress callback separately enforces forward-progress and
 * final-tree-balancing budgets. */
#ifndef CBM_PARSE_BUDGET_H
#define CBM_PARSE_BUDGET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *registry_version;
    const char *measurement_source;
    uint64_t base_micros;
    uint64_t minimum_forward_bytes_per_second;
    uint64_t forward_stall_micros;
    uint64_t final_balance_micros;
    uint64_t maximum_total_micros;
} cbm_parse_budget_policy_t;

const cbm_parse_budget_policy_t *cbm_parse_budget_policy(void);

/* Exact total wall budget for one captured source.  Returns a positive value
 * representable by the extraction API or zero only when the private registry
 * itself is invalid. */
int64_t cbm_parse_budget_micros(size_t source_bytes);

#endif /* CBM_PARSE_BUDGET_H */
