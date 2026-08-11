//! Sextant-local fail-closed error helpers.

use calyx_core::CalyxError;
pub use calyx_core::{
    CALYX_TEMPORAL_AP60_VIOLATION, CALYX_TEMPORAL_INVALID_BOOST_CONFIG,
    CALYX_TEMPORAL_INVALID_PERIOD, CALYX_TEMPORAL_INVALID_WINDOW, CALYX_TEMPORAL_WEIGHT_SUM,
};

pub const CALYX_SEXTANT_PLAN_UNBOUNDED: &str = "CALYX_SEXTANT_PLAN_UNBOUNDED";
pub const CALYX_SEXTANT_PLAN_COST_EXCEEDED: &str = "CALYX_SEXTANT_PLAN_COST_EXCEEDED";
pub const CALYX_PLANNER_COST_CAP: &str = "CALYX_PLANNER_COST_CAP";
pub const CALYX_SEXTANT_RERANKER_TIMEOUT: &str = "CALYX_SEXTANT_RERANKER_TIMEOUT";
pub const CALYX_SEXTANT_RERANKER_ENDPOINT: &str = "CALYX_SEXTANT_RERANKER_ENDPOINT";
pub const CALYX_SEXTANT_RERANKER_PROTOCOL: &str = "CALYX_SEXTANT_RERANKER_PROTOCOL";
pub const CALYX_SEXTANT_RERANKER_NO_CANDIDATES: &str = "CALYX_SEXTANT_RERANKER_NO_CANDIDATES";
pub const CALYX_SEXTANT_NO_LENSES: &str = "CALYX_SEXTANT_NO_LENSES";
pub const CALYX_SEXTANT_SLOT_ALREADY_REGISTERED: &str = "CALYX_SEXTANT_SLOT_ALREADY_REGISTERED";
pub const CALYX_SEXTANT_SLOT_MISSING: &str = "CALYX_SEXTANT_SLOT_MISSING";
pub const CALYX_SEXTANT_SLOT_INACTIVE: &str = "CALYX_SEXTANT_SLOT_INACTIVE";
pub const CALYX_SEXTANT_INDEX_EMPTY: &str = "CALYX_SEXTANT_INDEX_EMPTY";
pub const CALYX_SEXTANT_EF_TOO_SMALL: &str = "CALYX_SEXTANT_EF_TOO_SMALL";
pub const CALYX_SEXTANT_DIM_MISMATCH: &str = "CALYX_SEXTANT_DIM_MISMATCH";
pub const CALYX_SEXTANT_VECTOR_SHAPE: &str = "CALYX_SEXTANT_VECTOR_SHAPE";
pub const CALYX_SEXTANT_QUERY_SHAPE: &str = "CALYX_SEXTANT_QUERY_SHAPE";
pub const CALYX_INVALID_ARGUMENT: &str = "CALYX_INVALID_ARGUMENT";
pub const CALYX_ANSWER_UNGROUNDED: &str = "CALYX_ANSWER_UNGROUNDED";
pub const CALYX_ANSWER_SYNTHESIS_UNAVAILABLE: &str = "CALYX_ANSWER_SYNTHESIS_UNAVAILABLE";
pub const CALYX_LENS_NOT_FOUND: &str = "CALYX_LENS_NOT_FOUND";
pub const CALYX_SEXTANT_GPU_PARITY_UNAVAILABLE: &str = "CALYX_SEXTANT_GPU_PARITY_UNAVAILABLE";
pub const CALYX_SEXTANT_HNSW_CONSTRUCTION_STATE: &str = "CALYX_SEXTANT_HNSW_CONSTRUCTION_STATE";
pub const CALYX_SEXTANT_HNSW_ARTIFACT_CORRUPT: &str = "CALYX_SEXTANT_HNSW_ARTIFACT_CORRUPT";
pub const CALYX_SEXTANT_HNSW_ARTIFACT_IO: &str = "CALYX_SEXTANT_HNSW_ARTIFACT_IO";
pub const CALYX_SEXTANT_HNSW_ARTIFACT_STALE: &str = "CALYX_SEXTANT_HNSW_ARTIFACT_STALE";
pub const CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED: &str = "CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED";
pub const CALYX_SEXTANT_HNSW_POINTER_CORRUPT: &str = "CALYX_SEXTANT_HNSW_POINTER_CORRUPT";
pub const CALYX_SEXTANT_HNSW_POINTER_IO: &str = "CALYX_SEXTANT_HNSW_POINTER_IO";
pub const CALYX_SEXTANT_HNSW_POINTER_STALE: &str = "CALYX_SEXTANT_HNSW_POINTER_STALE";
pub const CALYX_SEXTANT_HNSW_POINTER_UNSTAGED: &str = "CALYX_SEXTANT_HNSW_POINTER_UNSTAGED";
pub const CALYX_SEXTANT_POSTINGS_CORRUPT: &str = "CALYX_SEXTANT_POSTINGS_CORRUPT";
pub const CALYX_SEXTANT_POSTINGS_NOT_SORTED: &str = "CALYX_SEXTANT_POSTINGS_NOT_SORTED";
pub const CALYX_SEXTANT_PROVENANCE_MISSING: &str = "CALYX_SEXTANT_PROVENANCE_MISSING";
pub const CALYX_SEXTANT_RECURRENCE_READ_ERROR: &str = "CALYX_SEXTANT_RECURRENCE_READ_ERROR";
pub const CALYX_SEXTANT_CX_MISSING: &str = "CALYX_SEXTANT_CX_MISSING";
pub const CALYX_SEXTANT_CONSENSUS_INSUFFICIENT_LENSES: &str =
    "CALYX_SEXTANT_CONSENSUS_INSUFFICIENT_LENSES";
pub const CALYX_SEXTANT_ASSOC_GRAPH_MISSING: &str = "CALYX_SEXTANT_ASSOC_GRAPH_MISSING";
pub const CALYX_SEXTANT_GRAPH_HOP_KIND_UNKNOWN: &str = "CALYX_SEXTANT_GRAPH_HOP_KIND_UNKNOWN";
pub const CALYX_SEXTANT_VECTOR_FUSION_UNWIRED: &str = "CALYX_SEXTANT_VECTOR_FUSION_UNWIRED";
pub const CALYX_SEXTANT_TRAVERSE_HOPS: &str = "CALYX_SEXTANT_TRAVERSE_HOPS";
pub const CALYX_SEXTANT_SKILL_UNKNOWN: &str = "CALYX_SEXTANT_SKILL_UNKNOWN";
pub const CALYX_SEXTANT_SKILL_PARAMS: &str = "CALYX_SEXTANT_SKILL_PARAMS";
pub const CALYX_SEXTANT_SKILL_BUDGET_EXCEEDED: &str = "CALYX_SEXTANT_SKILL_BUDGET_EXCEEDED";
pub const CALYX_SEXTANT_SKILL_PAIR_NO_OVERLAP: &str = "CALYX_SEXTANT_SKILL_PAIR_NO_OVERLAP";
pub const CALYX_TEMPORAL_WINDOW_BUDGET_EXHAUSTED: &str = "CALYX_TEMPORAL_WINDOW_BUDGET_EXHAUSTED";
pub const CALYX_INDEX_CORRUPT: &str = "CALYX_INDEX_CORRUPT";
pub const CALYX_INDEX_IO: &str = "CALYX_INDEX_IO";
pub const CALYX_INDEX_LEGACY_FORMAT: &str = "CALYX_INDEX_LEGACY_FORMAT";
pub const CALYX_INDEX_PAYLOAD_DIGEST: &str = "CALYX_INDEX_PAYLOAD_DIGEST";
pub const CALYX_INDEX_NONFINITE: &str = "CALYX_INDEX_NONFINITE";
pub const CALYX_INDEX_NONCANONICAL_I8: &str = "CALYX_INDEX_NONCANONICAL_I8";
pub const CALYX_INDEX_MANIFEST_DB_MISSING: &str = "CALYX_INDEX_MANIFEST_DB_MISSING";
pub const CALYX_INDEX_MANIFEST_DB_INVALID: &str = "CALYX_INDEX_MANIFEST_DB_INVALID";
pub const CALYX_INDEX_MANIFEST_DB_MISMATCH: &str = "CALYX_INDEX_MANIFEST_DB_MISMATCH";
pub const CALYX_INDEX_DIM_MISMATCH: &str = "CALYX_INDEX_DIM_MISMATCH";
pub const CALYX_INDEX_INVALID_PARAMS: &str = "CALYX_INDEX_INVALID_PARAMS";
pub const CALYX_INDEX_DIRECTION_UNAVAILABLE: &str = "CALYX_INDEX_DIRECTION_UNAVAILABLE";
pub const CALYX_INDEX_FUNNEL_VAULT_TOO_SMALL: &str = "CALYX_INDEX_FUNNEL_VAULT_TOO_SMALL";
pub const CALYX_INDEX_KERNEL_UNAVAILABLE: &str = "CALYX_INDEX_KERNEL_UNAVAILABLE";
pub const CALYX_ANNEAL_UNAVAILABLE: &str = "CALYX_ANNEAL_UNAVAILABLE";
pub fn sextant_error(code: &'static str, message: impl Into<String>) -> CalyxError {
    let remediation = match code {
        CALYX_SEXTANT_PLAN_UNBOUNDED => "tighten k/ef/slot limits or raise operator cap",
        CALYX_SEXTANT_PLAN_COST_EXCEEDED => "reduce k, ef, participating slots, or index scope",
        CALYX_PLANNER_COST_CAP => {
            "reduce the cross-model query scope, add a selective index, or raise cost_cap_ms"
        }
        CALYX_SEXTANT_RERANKER_TIMEOUT => "retry after reranker health is restored",
        CALYX_SEXTANT_RERANKER_ENDPOINT => {
            "configure a resolvable http:// reranker endpoint (resident TEI :8089)"
        }
        CALYX_SEXTANT_RERANKER_PROTOCOL => {
            "inspect the reranker response; the server must return one finite score per candidate"
        }
        CALYX_SEXTANT_RERANKER_NO_CANDIDATES => {
            "supply at least one request-scoped candidate text to rerank"
        }
        CALYX_SEXTANT_NO_LENSES => "register at least one slot index before planning or searching",
        CALYX_SEXTANT_SLOT_ALREADY_REGISTERED => {
            "use a distinct SlotId or rebuild the existing slot"
        }
        CALYX_SEXTANT_SLOT_MISSING => "register or rebuild the requested slot index",
        CALYX_SEXTANT_SLOT_INACTIVE => "unpark the slot before measuring or searching it",
        CALYX_SEXTANT_INDEX_EMPTY => "insert or rebuild at least one vector before searching",
        CALYX_SEXTANT_EF_TOO_SMALL => "set ef greater than or equal to requested result count",
        CALYX_SEXTANT_DIM_MISMATCH => "submit a query vector matching the slot dimension",
        CALYX_SEXTANT_VECTOR_SHAPE => "submit a vector matching the slot index shape",
        CALYX_SEXTANT_QUERY_SHAPE => {
            "submit a query with finite vectors, valid limits, and non-conflicting predicates"
        }
        CALYX_INVALID_ARGUMENT => "submit a non-empty ASK question and valid query arguments",
        CALYX_ANSWER_UNGROUNDED => {
            "seed ASK with at least one visible grounded constellation candidate"
        }
        CALYX_ANSWER_SYNTHESIS_UNAVAILABLE => {
            "wire a real answer synthesis/oracle implementation before enabling ASK answers"
        }
        CALYX_LENS_NOT_FOUND => "register or load a visible lens slot for ASK retrieval",
        CALYX_SEXTANT_GPU_PARITY_UNAVAILABLE => {
            "wire a real Forge GPU path before claiming Sextant CPU/GPU parity"
        }
        CALYX_SEXTANT_HNSW_CONSTRUCTION_STATE => {
            "discard the derived HNSW graph and rebuild it from the authoritative packed rows"
        }
        CALYX_SEXTANT_HNSW_ARTIFACT_CORRUPT => {
            "rebuild the packed HNSW artifact from the authoritative vault; never serve these bytes"
        }
        CALYX_SEXTANT_HNSW_ARTIFACT_IO => {
            "repair the exact artifact path or permissions, then rebuild and independently read it back"
        }
        CALYX_SEXTANT_HNSW_ARTIFACT_STALE => {
            "rebuild and activate an HNSW artifact at the current authoritative sequence"
        }
        CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED => {
            "use the exact codec/layout version requested by the serving manifest or perform an explicit measured migration"
        }
        CALYX_SEXTANT_HNSW_POINTER_CORRUPT => {
            "restore the last verified active pointer or rebuild it from a fully validated HNSW artifact"
        }
        CALYX_SEXTANT_HNSW_POINTER_IO => {
            "repair the active-pointer path or permissions, then atomically publish and reopen it"
        }
        CALYX_SEXTANT_HNSW_POINTER_STALE => {
            "reload current Anneal state and stage an artifact for the exact incumbent and candidate config hashes"
        }
        CALYX_SEXTANT_HNSW_POINTER_UNSTAGED => {
            "build, measure, persist, and stage the exact candidate artifact before requesting promotion"
        }
        CALYX_SEXTANT_POSTINGS_CORRUPT => "discard/rebuild the sparse postings block",
        CALYX_SEXTANT_POSTINGS_NOT_SORTED => "sort postings by increasing document id",
        CALYX_SEXTANT_PROVENANCE_MISSING => {
            "attach the stored constellation before requiring provenance"
        }
        CALYX_SEXTANT_RECURRENCE_READ_ERROR => {
            "repair the recurrence frequency scalar or recurrence CF rows"
        }
        CALYX_SEXTANT_CX_MISSING => {
            "ingest and index the constellation before navigating from or to it"
        }
        CALYX_SEXTANT_CONSENSUS_INSUFFICIENT_LENSES => {
            "expose at least two active dense lenses on the anchor for cross-lens consensus"
        }
        CALYX_SEXTANT_ASSOC_GRAPH_MISSING => {
            "persist the vault association graph before traversing"
        }
        CALYX_SEXTANT_GRAPH_HOP_KIND_UNKNOWN => {
            "use an edge type present in the persisted association graph"
        }
        CALYX_SEXTANT_VECTOR_FUSION_UNWIRED => {
            "wire PlanStep::VectorFusion to real slot indexes before serving vector fusion"
        }
        CALYX_SEXTANT_TRAVERSE_HOPS => "set traverse hops within 1..=10",
        CALYX_SEXTANT_SKILL_UNKNOWN => "call skills() and use one of the returned skill names",
        CALYX_SEXTANT_SKILL_PARAMS => "set min_cluster_size >= 2 and min_samples >= 1",
        CALYX_SEXTANT_SKILL_BUDGET_EXCEEDED => {
            "reduce the constellation count or raise max_constellations"
        }
        CALYX_SEXTANT_SKILL_PAIR_NO_OVERLAP => {
            "ensure every clustered constellation shares at least one dense lens with the others"
        }
        CALYX_TEMPORAL_WINDOW_BUDGET_EXHAUSTED => {
            "raise max_candidates or use the exhaustive window recall policy"
        }
        CALYX_INDEX_CORRUPT => {
            "rebuild the on-disk index from the vault; do not trust partial reads"
        }
        CALYX_INDEX_IO => "inspect disk/permissions on the index path, then rebuild",
        CALYX_INDEX_LEGACY_FORMAT => {
            "re-export the vector file with the current authenticated v2 writer \
             (assay stream-fbin / fbin-export); legacy bytes are never reinterpreted"
        }
        CALYX_INDEX_PAYLOAD_DIGEST => {
            "the payload bytes do not match the sealed header digest; regenerate the vector \
             file from its source and never trust the corrupt copy"
        }
        CALYX_INDEX_NONFINITE => {
            "reject the producing lens output; exact vector sources must be finite F32"
        }
        CALYX_INDEX_NONCANONICAL_I8 => {
            "re-encode the int8 vector file with the canonical per-row-scale v2 writer"
        }
        CALYX_INDEX_MANIFEST_DB_MISSING => {
            "rebuild or migrate the partitioned vault so the manifest is a Calyx/Aster Graph CF row"
        }
        CALYX_INDEX_MANIFEST_DB_INVALID => {
            "discard the corrupt partitioned manifest row and rebuild the partitioned vault"
        }
        CALYX_INDEX_MANIFEST_DB_MISMATCH => {
            "rebuild the partitioned vault; manifest DB readback changed after write"
        }
        CALYX_INDEX_DIM_MISMATCH => "submit a query vector matching the DiskANN graph dimension",
        CALYX_INDEX_INVALID_PARAMS => {
            "supply non-empty vectors with dense ids and dim/m_max/ef/alpha within bounds"
        }
        CALYX_INDEX_DIRECTION_UNAVAILABLE => {
            "rebuild both asymmetric graph directions before serving directional search"
        }
        CALYX_INDEX_FUNNEL_VAULT_TOO_SMALL => {
            "route small vaults through direct HNSW/DiskANN instead of the kernel-first funnel"
        }
        CALYX_INDEX_KERNEL_UNAVAILABLE => {
            "build or load the Lodestar kernel index before using KernelFirst search"
        }
        CALYX_ANNEAL_UNAVAILABLE => {
            "run the tuner in standalone mode and reconnect the Anneal observer when available"
        }
        CALYX_TEMPORAL_AP60_VIOLATION => {
            "keep temporal signals post-retrieval only and never dominant"
        }
        CALYX_TEMPORAL_INVALID_BOOST_CONFIG => {
            "set post-retrieval alpha and causal multipliers within their valid ranges"
        }
        CALYX_TEMPORAL_INVALID_PERIOD => "set target_hour 0..=23 and day_of_week 0..=6",
        CALYX_TEMPORAL_INVALID_WINDOW => "set a non-empty temporal window within i64 bounds",
        CALYX_TEMPORAL_WEIGHT_SUM => "normalize recency + sequence + periodic to exactly 1.0",
        _ => "inspect Sextant query/index state",
    };
    CalyxError {
        code,
        message: message.into(),
        remediation,
    }
}
