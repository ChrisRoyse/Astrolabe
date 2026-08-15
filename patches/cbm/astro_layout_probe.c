#include "astro_ffi.h"

#include <string.h>

CBM_API int cbm_abi_layout_size(const char *type_name, size_t *size_out, size_t *align_out) {
    if (!type_name || !size_out || !align_out) {
        return -1;
    }

#define ASTRO_LAYOUT_SIZE_CASE(type)         \
    do {                                     \
        if (strcmp(type_name, #type) == 0) { \
            *size_out = sizeof(type);        \
            *align_out = _Alignof(type);     \
            return 0;                        \
        }                                    \
    } while (0)

    ASTRO_LAYOUT_SIZE_CASE(CBMExtractionError);
    ASTRO_LAYOUT_SIZE_CASE(CBMFileResult);
    ASTRO_LAYOUT_SIZE_CASE(cbm_gbuf_row_node_t);
    ASTRO_LAYOUT_SIZE_CASE(cbm_gbuf_row_edge_t);
    ASTRO_LAYOUT_SIZE_CASE(cbm_pipeline_row_file_hash_t);
    ASTRO_LAYOUT_SIZE_CASE(cbm_index_capability_t);
    ASTRO_LAYOUT_SIZE_CASE(cbm_pipeline_row_manifest_t);
    ASTRO_LAYOUT_SIZE_CASE(cbm_pipeline_row_sink_v2_t);

#undef ASTRO_LAYOUT_SIZE_CASE

    return -1;
}

CBM_API int cbm_abi_layout_offset(const char *type_name, const char *field_name,
                                  size_t *offset_out) {
    if (!type_name || !field_name || !offset_out) {
        return -1;
    }

#define ASTRO_LAYOUT_OFFSET_CASE(type, field)                                   \
    do {                                                                        \
        if (strcmp(type_name, #type) == 0 && strcmp(field_name, #field) == 0) { \
            *offset_out = offsetof(type, field);                                \
            return 0;                                                           \
        }                                                                       \
    } while (0)

    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, code);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, operation);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, phase);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, message);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, remediation);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, requested);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, outcome_class);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, content_defect_recorded);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, discarded_atom_facts);
    ASTRO_LAYOUT_OFFSET_CASE(CBMExtractionError, discarded_relationship_facts);

    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, arena);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, defs);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, calls);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, imports);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, usages);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, throws);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, rw);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, type_refs);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, env_accesses);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, type_assigns);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, impl_traits);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, resolved_calls);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, string_refs);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, infra_bindings);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, channels);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, diagnostics);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, module_qn);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, namespace_name);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, exports);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, constants);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, global_vars);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, macros);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, has_error);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, error_msg);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, error);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, is_test_file);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, imports_count);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cached_tree);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cached_lang);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, source);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, source_len);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cross_lsp_accounting_present);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cross_lsp_seeded_rows);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cross_lsp_source_rows);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cross_lsp_duplicate_rows);
    ASTRO_LAYOUT_OFFSET_CASE(CBMFileResult, cross_lsp_appended_rows);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, id);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, project);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, label);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, name);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, qualified_name);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, file_path);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, start_line);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, end_line);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_node_t, properties_json);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, id);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, project);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, source_id);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, target_id);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, type);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, properties_json);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, url_path_gen);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_gbuf_row_edge_t, local_name_gen);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_file_hash_t, project);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_file_hash_t, rel_path);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_file_hash_t, sha256);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_file_hash_t, mtime_ns);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_file_hash_t, size);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, project);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, node_count);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, edge_count);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, file_hash_count);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, graph_schema_version);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_manifest_t, index_capability);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, index_mode);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, semantic_state);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, vector_dimension);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, eligible_node_count);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, node_vector_count);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_index_capability_t, token_vector_count);

    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, abi_version);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, struct_size);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, node);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, edge);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, file_hash);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, complete);
    ASTRO_LAYOUT_OFFSET_CASE(cbm_pipeline_row_sink_v2_t, ctx);

#undef ASTRO_LAYOUT_OFFSET_CASE

    return -1;
}
