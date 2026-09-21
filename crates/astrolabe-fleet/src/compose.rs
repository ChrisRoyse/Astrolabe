//! Kernel-of-kernels composition (issue #456): compose per-repo kernels into
//! the growing language-level fleet kernel (`fleet:rust:v1`).
//!
//! # Design (research-grounded)
//!
//! This is the **composable core-sets** pattern (Indyk/Mahdian/Mirrokni et al.,
//! PODS'14 / STOC'15): solve per-partition (the per-repo FVS kernels already
//! persisted by the pipeline), then run the same optimization over the *union*
//! of the per-partition solutions. Coverage-style objectives are known to lose
//! their guarantees under plain composition. The per-repo radius measurement
//! below is therefore retained only as explicitly diagnostic graph coverage;
//! it is never relabeled as retrieval recall or used to admit a fleet kernel.
//!
//! # The fleet graph
//!
//! - **Nodes** = per-repo kernel members, merged into one node per #455
//!   content-equivalence class (`blake3(frame(label) ‖ frame(language) ‖
//!   frame(snippet))`) — same content = same node, weighted by repo count.
//!   Content-free members (`File` label or explicitly source-absent atom) never
//!   merge: each stays a unique per-(project, member)
//!   node, explicitly counted.
//! - **Edges** = cross-member S20 name-semantic cosine similarity over member
//!   centroids (top-k + declared min-similarity knob, both registry-declared
//!   in [`FLEET_COMPOSE_KNOBS`] — invariant 4), deterministic ordering.
//! - **Groundedness** = any-occurrence anchor rollup: a fleet node carries a
//!   Trusted anchor iff some constituent member was grounded in its home repo.
//! - **Frequency** = summed occurrence frequency (repo count and per-repo heat
//!   both weigh in, declared in the sidecar).
//!
//! The existing `build_kernel` FVS pipeline runs over that graph at the fleet
//! scope. Publication is one content-addressed atomic generation containing
//! the exact repository roster, graph, complete S20 vectors, artifact, member
//! provenance/HNSW bindings, genuine external-query corpus, routed-recall
//! report, manifest, current pointer, and physical Ledger entry. The historical
//! three-row artifact/sidecar is retained only for explicit history diagnosis.
//!
//! # Growth semantics
//!
//! The compose input hash is `blake3` over each repository's exact current
//! generation/source identity, complete member metadata and S20 bits, plus all
//! composition/build knobs. An unchanged hash is a topology-preserving no-op
//! (explicit `unchanged` verdict, no writes); any consumed-input change is a
//! structural [`GraphDelta`] and escalates to an explicit full rebuild — the
//! LSM/segment doctrine: incremental until structural debt, then rebuild, both
//! explicit and recorded.
//!
//! # Exact content contract
//!
//! Content keys derive from the retained canonical input's exact source bytes.
//! Source-absent structural atoms remain explicitly labeled and never collapse
//! into an empty-content equivalence class.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use astrolabe_domain::{TrustTag, cx_id_from_canonical, frame};
use astrolabe_ingest::{
    GraphProjectionKind, GraphProjectionReadBinding, kernel_graph_from_projection_csr,
    read_graph_projection_csr_bound_at, read_persisted_kernel_artifact_at,
};
use astrolabe_kernel::kernel_graph::IndexedGraph;
use astrolabe_kernel::{
    GraphDelta, KERNEL_BUILD_KNOB_REGISTRY_VERSION, KernelArtifact, KernelBuildConfig, KernelGraph,
    KernelGraphEdge, KernelGraphNode, U64KnobDeclaration, build_kernel, kernel_source_identity,
    members_hash,
};
use astrolabe_weave::search::SLOT_NAME_SEMANTIC;
use astrolabe_weave::{
    KernelGenerationManifest, KernelGenerationPointer, WeaveSlotBinding, WeaveSlotSource,
    read_current_kernel_generation, read_current_kernel_generation_header,
};
use calyx_aster::cf::{ColumnFamily, base_key};
use calyx_aster::vault::encode::decode_constellation_base;
use calyx_aster::vault::input_store;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, CxId, LedgerRef, SlotVector, VaultId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::catalog::FleetCatalog;
use crate::dedup::{AtomFrames, parse_atom_frames};
use crate::kernel_generation::{
    CurrentFleetKernelGeneration, FLEET_KERNEL_PROVENANCE_SCHEMA,
    FLEET_KERNEL_SOURCE_ROSTER_SCHEMA, FleetKernelAdmissionInput,
    FleetKernelGenerationPublishRequest, FleetKernelGraphRecord, FleetKernelSourceRoster,
    FleetMemberOccurrenceProvenance, FleetMemberProvenance, FleetMemberProvenanceRoster,
    FleetRepoSourceBinding, FleetVectorRoster, finalize_fleet_member_provenance,
    finalize_fleet_source_roster, persist_fleet_kernel_generation,
    read_current_fleet_kernel_generation, read_current_fleet_kernel_generation_header,
    verify_fleet_source_roster_exact,
};
use crate::orchestrator::{
    ASTRO_FLEET_PROJECT_IDENTITY, RepoStoreIdentity, SHADOW_VAULT_ID, catalog_store_identities,
    kernel_scope_id, project_name, repo_store_identity, shadow_vault_salt,
};

/// History-only report kind used by pre-#1151 fixed-row fleet artifacts.
pub(crate) const FLEET_KERNEL_REPORT_KIND: &str = "fleet-kernel";
/// Sidecar artifact schema tag. Version 4 binds atomic repository generation,
/// physical Ledger/source, and complete S20 input contracts in addition to the
/// declared candidacy policy and fleet-output identity.
pub(crate) const FLEET_KERNEL_SIDECAR_SCHEMA: &str = "fleet-kernel-compose/v4";
/// Knob registry version for fleet composition.
pub const FLEET_COMPOSE_KNOB_REGISTRY_VERSION: &str = "astro.fleet.compose_knobs.v2";
/// Framing tag for a fleet node identity preimage.
pub const FLEET_NODE_CANONICAL_TAG: &[u8] = b"astrolabe.fleet.node.v2";

/// Refusal: no repo contributed a persisted kernel to compose over.
pub const ASTRO_FLEET_COMPOSE_NO_KERNELS: &str = "ASTRO_FLEET_COMPOSE_NO_KERNELS";
/// Refusal: a per-repo kernel member has no stored #446 input record.
pub const ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED: &str = "ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED";
/// Refusal: S20 vectors disagree on dimension across members.
pub const ASTRO_FLEET_COMPOSE_DIM_MISMATCH: &str = "ASTRO_FLEET_COMPOSE_DIM_MISMATCH";
/// Refusal: a repository current generation no longer matches its physical
/// graph/anchor source identity.
pub const ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH: &str = "ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH";
/// Refusal: repository generations do not share one exact S20 panel contract.
pub const ASTRO_FLEET_COMPOSE_SEMANTIC_MISMATCH: &str = "ASTRO_FLEET_COMPOSE_SEMANTIC_MISMATCH";
/// Refusal: one required universal S20 member vector is absent or invalid.
pub const ASTRO_FLEET_COMPOSE_VECTOR_INVALID: &str = "ASTRO_FLEET_COMPOSE_VECTOR_INVALID";
/// Refusal: a compose knob is outside its declared bounds.
pub const ASTRO_FLEET_COMPOSE_KNOB_RANGE: &str = "ASTRO_FLEET_COMPOSE_KNOB_RANGE";
/// Refusal: a semantic fleet weight or coverage census cannot be represented
/// exactly. Saturation would silently change the graph/kernel contract.
pub const ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW: &str = "ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW";
/// Refusal: an inner kernel/ingest/domain operation failed (message carries it).
pub const ASTRO_FLEET_COMPOSE_INNER: &str = "ASTRO_FLEET_COMPOSE_INNER";
/// Refusal: no fleet kernel artifact persisted at the requested scope.
pub const ASTRO_FLEET_KERNEL_MISSING: &str = "ASTRO_FLEET_KERNEL_MISSING";
/// Refusal: only the historical provisional fleet artifact exists; production
/// reads require the complete atomic generation owned by #1151.
pub const ASTRO_FLEET_KERNEL_ATOMIC_GENERATION_REQUIRED: &str =
    "ASTRO_FLEET_KERNEL_ATOMIC_GENERATION_REQUIRED";
/// Refusal: fleet kernel readback diverged (members-hash / ledger pairing).
pub const ASTRO_FLEET_KERNEL_READBACK: &str = "ASTRO_FLEET_KERNEL_READBACK";
/// Refusal: provenance verification found a sidecar claim reality contradicts.
pub const ASTRO_FLEET_PROVENANCE_MISMATCH: &str = "ASTRO_FLEET_PROVENANCE_MISMATCH";
/// Refusal: provenance verification requires a positive, explicit sample.
pub const ASTRO_FLEET_PROVENANCE_SAMPLE_INVALID: &str = "ASTRO_FLEET_PROVENANCE_SAMPLE_INVALID";
/// Refusal: the declared candidacy policy excluded every fleet node, so there
/// is no code-bearing candidate to compose a kernel from.
pub const ASTRO_FLEET_COMPOSE_NO_CANDIDATES: &str = "ASTRO_FLEET_COMPOSE_NO_CANDIDATES";

// Knob names.
pub const KNOB_SIMILARITY_MIN: &str = "fleet.compose.similarity_min_permille";
pub const KNOB_SIMILARITY_TOP_K: &str = "fleet.compose.similarity_top_k";
pub const KNOB_PER_REPO_GRAPH_COVERAGE_MIN: &str =
    "fleet.compose.per_repo_graph_coverage_min_permille";
pub const KNOB_CROSS_REPO_SUPPORT_WEIGHT: &str =
    "fleet.candidacy.cross_repo_support_weight_permille";

const SOURCE: &str = "https://github.com/ChrisRoyse/Astrolabe/issues/456";

/// All fleet compose knobs with their declared bounds (invariant 4).
pub const FLEET_COMPOSE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_SIMILARITY_MIN,
        default: 800,
        min: 0,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "minimum S20 cosine similarity for a cross-member fleet edge; \
                    high-precision cutoff, distribution measured on the pilot fleet (#456 FSV)",
    },
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_SIMILARITY_TOP_K,
        default: 8,
        min: 1,
        max: 64,
        unit: "neighbors",
        source: SOURCE,
        rationale: "per-node cap on similarity neighbors, bounding fleet-graph degree",
    },
    U64KnobDeclaration {
        registry_version: FLEET_COMPOSE_KNOB_REGISTRY_VERSION,
        name: KNOB_PER_REPO_GRAPH_COVERAGE_MIN,
        default: 950,
        min: 1,
        max: 1000,
        unit: "permille",
        source: SOURCE,
        rationale: "diagnostic per-repo undirected graph coverage floor at the declared radius; \
                    this is not query retrieval recall and does not admit the fleet kernel",
    },
    U64KnobDeclaration {
        registry_version: FLEET_CANDIDACY_KNOB_REGISTRY_VERSION,
        name: KNOB_CROSS_REPO_SUPPORT_WEIGHT,
        default: 1000,
        min: 0,
        max: 10_000,
        unit: "permille",
        source: SOURCE_477,
        rationale: "cross-repo support up-weight (#477): a surviving candidate present in \
                    K distinct repos scales its frequency weight by (1 + w·(K−1)); direct \
                    fleet-wide-relevance evidence, so shared code outranks single-repo code \
                    in the FVS frequency bonus. Bounded so no single hub saturates the graph",
    },
];

/// Knob registry version for fleet candidacy (#477).
pub const FLEET_CANDIDACY_KNOB_REGISTRY_VERSION: &str = "astro.fleet.candidacy_knobs.v1";
/// Declared candidacy policy version, recorded in every compose sidecar so
/// consumers can distinguish the member-set semantics (#477). This is the
/// *policy* version; the scope id (`fleet:rust:v1`) is an operator-chosen
/// corpus/lineage identifier and is intentionally NOT bumped by a policy change.
pub const FLEET_CANDIDACY_POLICY_VERSION: &str = "astro.fleet.candidacy.v1";

/// Candidacy exclusion rule: the class carries no snippet fingerprint at all.
pub const CANDIDACY_RULE_EMPTY_FINGERPRINT: &str = "empty_fingerprint";
/// Candidacy exclusion rule: the class label is a declared structural label.
pub const CANDIDACY_RULE_STRUCTURAL_LABEL: &str = "structural_label";

/// Declared structural / content-free labels excluded from fleet kernel
/// candidacy (#477). These labels name atoms that carry no reusable code body,
/// so they crowd the member set without contributing code-graph value:
/// - `File`   — a filesystem node; its "snippet" is only the #413 name+extension
///   property fingerprint (content-free; already `content_free` in dedup #455).
/// - `Decorator` — an attribute/annotation marker (`<decorator:test>`,
///   `<decorator:#[cfg>`); no body, no path, `lang=unknown`.
/// - `Section` — a documentation heading (`README.License`); prose navigation,
///   not code.
///
/// Measured motivation (fleet:rust:v1, 67 members before this policy): File 5,
/// Decorator 5, Section 10 — 20/67 (30%) content-free structural members, all at
/// or near the score floor. The denylist is a declared categorical policy (not a
/// tunable threshold), mirroring the dedup census's `content_free` predicate.
pub const FLEET_STRUCTURAL_LABELS: &[&str] = &["File", "Decorator", "Section"];

const SOURCE_477: &str = "https://github.com/ChrisRoyse/Astrolabe/issues/477";

/// Fully resolved fleet compose knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeConfig {
    /// Minimum cosine similarity for an edge, in permille.
    pub similarity_min_permille: u64,
    /// Per-node similarity neighbor cap.
    pub similarity_top_k: u64,
    /// Per-repo diagnostic graph-coverage floor in permille.
    pub per_repo_graph_coverage_min_permille: u64,
    /// Cross-repo support up-weight in permille (#477 candidacy policy): a
    /// surviving candidate present in K distinct repos scales its frequency
    /// weight by `(1000 + w·(K−1)) / 1000`.
    pub cross_repo_support_weight_permille: u64,
}

impl ComposeConfig {
    /// Returns the registry-default configuration.
    pub fn with_registry_defaults() -> Self {
        Self {
            similarity_min_permille: knob_default(KNOB_SIMILARITY_MIN),
            similarity_top_k: knob_default(KNOB_SIMILARITY_TOP_K),
            per_repo_graph_coverage_min_permille: knob_default(KNOB_PER_REPO_GRAPH_COVERAGE_MIN),
            cross_repo_support_weight_permille: knob_default(KNOB_CROSS_REPO_SUPPORT_WEIGHT),
        }
    }

    /// Validates every knob against its declared bounds, fail-closed.
    pub fn validate(&self) -> Result<(), CalyxError> {
        check_range(KNOB_SIMILARITY_MIN, self.similarity_min_permille)?;
        check_range(KNOB_SIMILARITY_TOP_K, self.similarity_top_k)?;
        check_range(
            KNOB_PER_REPO_GRAPH_COVERAGE_MIN,
            self.per_repo_graph_coverage_min_permille,
        )?;
        check_range(
            KNOB_CROSS_REPO_SUPPORT_WEIGHT,
            self.cross_repo_support_weight_permille,
        )?;
        Ok(())
    }
}

fn knob_default(name: &str) -> u64 {
    FLEET_COMPOSE_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet compose knob is declared")
        .default
}

fn check_range(name: &str, value: u64) -> Result<(), CalyxError> {
    let knob = FLEET_COMPOSE_KNOBS
        .iter()
        .find(|knob| knob.name == name)
        .expect("fleet compose knob is declared");
    if value < knob.min || value > knob.max {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_KNOB_RANGE,
            message: format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            remediation: "set the fleet compose knob within its registered bounds",
        });
    }
    Ok(())
}

fn inner_err(what: &str, error: impl std::fmt::Display) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_COMPOSE_INNER,
        message: format!("{what}: {error}"),
        remediation: "the inner error carries its own code; fix that condition and re-run compose",
    }
}

/// One per-repo kernel member resolved against its vault's stores.
#[derive(Clone, Debug)]
pub struct MemberOccurrence {
    /// Catalog project (`org__repo`).
    pub project: String,
    /// The member's per-repo CxId.
    pub cx: CxId,
    /// Qualified symbol name (from the stored canonical frames).
    pub qualified_name: String,
    /// Repo-relative file path.
    pub rel_file_path: String,
    /// Symbol label.
    pub label: String,
    /// Language tag.
    pub language: String,
    /// #455 content-only key.
    pub content_key: [u8; 32],
    /// True for File-label or source-absent atoms — never merged.
    pub content_free: bool,
    /// True when the atom explicitly carries no source. Distinct
    /// from `content_free`, which also folds in the `File` label; kept separate
    /// so the candidacy policy can attribute each exclusion to exactly one
    /// declared rule.
    pub source_absent: bool,
    /// Whether the member was grounded (Trusted anchor within hop limit) at home.
    pub grounded: bool,
    /// Per-repo measured member stats, carried for provenance and fleet weighting.
    pub score_permille: u64,
    pub degree: u64,
    pub betweenness_permille: u64,
    pub groundedness_permille: u64,
    pub frequency: u64,
    pub in_fvs: bool,
    /// Persisted universal S20 name-semantic vector. Every member must carry
    /// one; a partial roster refuses before fleet graph construction.
    pub vector: Vec<f32>,
}

/// One repo's loaded kernel, resolved and vector-joined.
#[derive(Clone, Debug)]
pub struct RepoKernelLoad {
    /// Catalog project.
    pub project: String,
    /// Inner CBM/shadow project identity used by the repository generation.
    pub index_project: String,
    /// Exact repository kernel scope selected by its current pointer.
    pub kernel_scope: String,
    /// The repo kernel's members-hash (composition input identity).
    pub members_hash: String,
    /// Source-graph node count of the repo kernel build.
    pub node_count: usize,
    /// Repo kernel diagnostic graph coverage in permille.
    pub graph_coverage_permille: u64,
    /// Exact per-repo kernel source graph/config identity.
    pub source_identity_hash: String,
    /// Atomic composite generation selected by the current pointer.
    pub generation_id: String,
    /// Stable identity of every row/source bound into that generation.
    pub source_generation_identity: String,
    /// Exact pointer+manifest header identity selected by the cold read.
    pub kernel_header_blake3: String,
    /// Durable content generations for the Base and Blob families consumed by
    /// the member-resolution pass.
    pub base_content_generation: u64,
    pub blob_content_generation: u64,
    /// Frozen panel version that produced the S20 vector space.
    pub panel_version: u32,
    /// Complete S20 vector dimension.
    pub semantic_dim: u32,
    /// Exact universal-S20 Slot/Compression representation and its verification
    /// epochs from the repository generation.
    pub s20_source_binding_seq: u64,
    pub s20_source_final_verification_seq: u64,
    pub s20_source_binding: WeaveSlotBinding,
    /// Exact hash of every materialized value consumed by fleet composition.
    pub compose_source_hash: String,
    /// Whether the repo build's betweenness was exact.
    pub betweenness_exact: bool,
    /// Resolved members.
    pub occurrences: Vec<MemberOccurrence>,
}

fn open_shadow_vault(
    store_root: &Path,
    store_key: &str,
    index_project: &str,
    selected_cfs: Vec<ColumnFamily>,
) -> Result<AsterVault, CalyxError> {
    let vault_dir = store_root
        .join(store_key)
        .join(format!("{index_project}.astrolabe-vault"));
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID).map_err(|error| CalyxError {
        code: ASTRO_FLEET_COMPOSE_INNER,
        message: format!("shadow vault id failed to parse: {error:?}"),
        remediation: "internal defect: SHADOW_VAULT_ID must be a valid ULID",
    })?;
    AsterVault::open(
        &vault_dir,
        vault_id,
        shadow_vault_salt(index_project).into_bytes(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )
}

fn fixed_kernel_json_key(scope: &str) -> Vec<u8> {
    fixed_kernel_artifact_key(scope, b"kernel.json")
}

fn fixed_kernel_artifact_key(scope: &str, leaf: &[u8]) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX);
    key.extend_from_slice(scope.as_bytes());
    key.push(b':');
    key.extend_from_slice(leaf);
    key
}

/// Reads one member's Cx-addressed Base row and its exact retained canonical
/// input at the caller's snapshot. The persisted panel version, never a
/// hard-coded historical version, owns the CxId re-derivation.
fn read_member_atom_at(
    vault: &AsterVault,
    project: &str,
    cx: CxId,
    expected_panel_version: u32,
    snapshot: u64,
) -> Result<AtomFrames, CalyxError> {
    let base_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Base, &base_key(cx))?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "current composite kernel member {cx} of project {project:?} has no Cx-addressed Base row at sequence {snapshot}"
            ),
            remediation: "repair the current graph/Base generation and rebuild the complete repository kernel before composing the fleet",
        })?;
    let constellation = decode_constellation_base(&base_bytes)?;
    constellation.validate_schema()?;
    if constellation.cx_id != cx || constellation.panel_version != expected_panel_version {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "member Base identity differs from the current composite generation: requested_cx={cx}, observed_cx={}, expected_panel_version={expected_panel_version}, observed_panel_version={}",
                constellation.cx_id, constellation.panel_version
            ),
            remediation: "preserve the vault and rebuild one atomic graph/Base/S20/kernel generation from the unchanged source",
        });
    }
    if constellation.input_ref.redacted {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "current composite kernel member {cx} of project {project:?} has a redacted canonical input"
            ),
            remediation: "re-index with input retention enabled and rebuild the complete repository kernel before composing the fleet",
        });
    }
    let input_hash = constellation.input_ref.hash;
    let expected_pointer = input_store::input_pointer(&input_hash);
    if constellation.input_ref.pointer.as_deref() != Some(expected_pointer.as_str()) {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "member {cx} input pointer {:?} differs from its content address {expected_pointer:?}",
                constellation.input_ref.pointer
            ),
            remediation: "repair the Base/input-store pairing and rebuild the complete repository kernel",
        });
    }
    let bytes = input_store::reassemble_and_verify(&input_hash, |key| {
        vault.read_cf_at(snapshot, ColumnFamily::Blob, key)
    })?;
    let salt = astrolabe_domain::vault_salt(project)
        .map_err(|error| inner_err("derive domain identity salt", error))?
        .into_bytes();
    let rederived = cx_id_from_canonical(&bytes, constellation.panel_version, &salt)
        .map_err(|error| inner_err("derive member CxId from retained canonical input", error))?;
    if rederived != cx {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "member Base key {cx} re-derives as {rederived} from panel {} canonical input bytes",
                constellation.panel_version
            ),
            remediation: "preserve the vault and repair the Base/input-store identity pairing before recomposing",
        });
    }
    let frames = parse_atom_frames(&bytes)?;
    let exact_metadata = [
        ("project", frames.project.as_str()),
        ("qualified_name", frames.qualified_name.as_str()),
        ("label", frames.label.as_str()),
        ("file_path", frames.rel_file_path.as_str()),
        ("language", frames.language.as_str()),
    ];
    if frames.project != project
        || exact_metadata.iter().any(|(key, expected)| {
            constellation.metadata.get(*key).map(String::as_str) != Some(*expected)
        })
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_MEMBER_UNRESOLVED,
            message: format!(
                "member {cx} canonical frames differ from its Base metadata or requested project {project:?}: frame_project={:?}, frame_name={:?}, frame_label={:?}, frame_path={:?}, frame_language={:?}",
                frames.project,
                frames.qualified_name,
                frames.label,
                frames.rel_file_path,
                frames.language
            ),
            remediation: "preserve the divergent Base and Blob rows, repair import identity publication, and rebuild the complete generation",
        });
    }
    Ok(frames)
}

fn dense_s20_member_vector(
    project: &str,
    cx: CxId,
    expected_dim: u32,
    vector: Option<SlotVector>,
) -> Result<Vec<f32>, CalyxError> {
    let vector = vector.ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
        message: format!("current composite member {project}:{cx} has no persisted S20 row"),
        remediation: "re-index the repository so universal S20 covers every graph node, then rebuild the complete kernel generation",
    })?;
    vector.validate_schema()?;
    let SlotVector::Dense { dim, data } = vector else {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!(
                "current composite member {project}:{cx} S20 row is not one dense vector"
            ),
            remediation: "repair the universal S20 lens output and rebuild the complete kernel generation",
        });
    };
    if dim != expected_dim
        || data.len() != expected_dim as usize
        || data.iter().any(|value| !value.is_finite())
        || !data.iter().any(|value| *value != 0.0)
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!(
                "current composite member {project}:{cx} has invalid S20: expected_dim={expected_dim}, observed_dim={dim}, observed_len={}, finite={}, nonzero={}",
                data.len(),
                data.iter().all(|value| value.is_finite()),
                data.iter().any(|value| *value != 0.0)
            ),
            remediation: "repair the exact persisted S20 row and rebuild the complete kernel generation",
        });
    }
    Ok(data)
}

/// Loads one repo's atomic current kernel generation and resolves every member
/// by exact CxId against its Base/input-store row and universal S20 binding.
///
/// Returns `Ok(None)` only when the repo has no kernel state at all. Fleet
/// composition refuses an explicitly requested roster containing that state;
/// it never silently omits the repo. A legacy fixed alias without a composite
/// current pointer is a hard stale-state error, never a compatibility fallback.
///
/// # Cost contract (#1064)
///
/// At the measured 2026-08-20 production size `N=192,873`, `E=328,899`, this
/// performs one `O(N+E)` current projection/source verification, one `O(A)`
/// anchor/promotion rollup, `O(K*D)` exact S20 member resolution, and `O(K)`
/// Cx-addressed Base/input reads. `A`, `K`, and `D` are read from the persisted
/// production generation rather than guessed. The retained sequence, current
/// generation, projection, anchor roster, member roster, panel version, S20
/// binding, and dimension are invariant for the complete pass
/// (PC-03/04/07/14/15/28/35/37/41/43).
pub fn load_repo_kernel(
    store_root: &Path,
    store_key: &str,
    index_project: &str,
) -> Result<Option<RepoKernelLoad>, CalyxError> {
    let vault_dir = store_root
        .join(store_key)
        .join(format!("{index_project}.astrolabe-vault"));
    match vault_dir.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) => {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "cannot classify per-repository vault path {}: {error}",
                    vault_dir.display()
                ),
                remediation: "repair the named repository vault path so its physical presence can be read exactly before composing a fleet kernel",
            });
        }
    }
    let vault = open_shadow_vault(
        store_root,
        store_key,
        index_project,
        vec![
            ColumnFamily::Base,
            ColumnFamily::Blob,
            ColumnFamily::Graph,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::Kernel,
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::slot(SLOT_NAME_SEMANTIC),
        ],
    )?;
    let scope = kernel_scope_id(index_project);
    let source_lease = vault.retain_latest_snapshot();
    let snapshot = source_lease.seq();
    let base_content_generation = vault
        .cf_content_generation(ColumnFamily::Base)
        .map_err(|error| inner_err("read repository Base content generation", error))?;
    let blob_content_generation = vault
        .cf_content_generation(ColumnFamily::Blob)
        .map_err(|error| inner_err("read repository Blob content generation", error))?;
    let generation = read_current_kernel_generation(&vault, index_project, &scope)
        .map_err(|error| inner_err("read current composite per-repo kernel generation", error))?;
    let Some(generation) = generation else {
        if vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Kernel,
                &fixed_kernel_json_key(&scope),
            )?
            .is_some()
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "project {index_project:?} has a fixed kernel.json alias but no atomic composite current pointer at sequence {snapshot}"
                ),
                remediation: "rebuild and publish one complete atomic repository kernel generation; fleet composition never consumes the legacy fixed alias",
            });
        }
        return Ok(None);
    };
    source_lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "project {index_project:?} moved while reading its current composite generation: retained_seq={snapshot}, observed_seq={}",
                vault.latest_seq()
            ),
            remediation: "discard the mixed read and retry against one stable current generation",
        });
    }
    let projection = read_graph_projection_csr_bound_at(
        &vault,
        GraphProjectionKind::KernelGraph,
        snapshot,
        &GraphProjectionReadBinding {
            graph_content_generation: generation
                .manifest
                .generation_source_binding
                .graph_content_generation,
            manifest: generation
                .manifest
                .generation_source_binding
                .projection_manifest
                .clone(),
        },
    )
    .map_err(|error| inner_err("read current composite graph projection", error))?;
    source_lease.record_progress();
    let anchor_trust = astrolabe_anchors::effective_anchor_trust_map_at(&vault, snapshot)
        .map_err(|error| inner_err("read current anchor trust roster", error))?;
    source_lease.record_progress();
    let source_graph = kernel_graph_from_projection_csr(&projection, &anchor_trust)
        .map_err(|error| inner_err("adapt current composite graph projection", error))?;
    let observed_source_identity =
        kernel_source_identity(&source_graph, &generation.artifact.config)
            .map_err(|error| inner_err("recompute current kernel source identity", error))?;
    if observed_source_identity != generation.artifact.source_identity {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "current projection/anchor/config source identity differs from generation {:?}: expected={}, observed={}",
                generation.manifest.generation_id,
                generation.artifact.source_identity.combined_hash,
                observed_source_identity.combined_hash
            ),
            remediation: "rebuild the complete repository kernel from the current projection and anchor rows before fleet composition",
        });
    }

    let member_ids = generation
        .artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let binding_ids = generation
        .index
        .bindings
        .iter()
        .map(|binding| binding.cx_id)
        .collect::<Vec<_>>();
    if member_ids != binding_ids || member_ids.len() != generation.artifact.member_count {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "current generation member/index roster differs: artifact_count={}, binding_count={}, declared_count={}",
                member_ids.len(),
                binding_ids.len(),
                generation.artifact.member_count
            ),
            remediation: "preserve the composite generation and repair its atomic member binding publication",
        });
    }
    let semantic_dim = generation
        .index
        .descriptor
        .semantic_dim
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: "current complete member index has no S20 dimension".to_string(),
            remediation: "rebuild the complete S20-backed repository kernel generation",
        })?;
    let panel_version = generation.index.descriptor.panel_version;
    let s20_source_binding_seq = generation.index.descriptor.source_binding_seq;
    let s20_source_final_verification_seq =
        generation.index.descriptor.source_final_verification_seq;
    let s20_source_binding = generation.index.descriptor.source_binding.clone();
    let slot_source = WeaveSlotSource::open(snapshot, Some(&vault_dir), Some(panel_version))
        .map_err(|error| inner_err("open current S20 interpretation source", error))?;
    let resolved = slot_source
        .resolve_many_bound_at(
            &vault,
            snapshot,
            &generation.index.descriptor.source_binding,
            &member_ids,
        )
        .map_err(|error| inner_err("resolve current complete S20 member roster", error))?;
    source_lease.record_progress();
    if resolved.len() != member_ids.len() {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!(
                "S20 resolver returned {} rows for {} current kernel members",
                resolved.len(),
                member_ids.len()
            ),
            remediation: "repair the exact S20 representation and rebuild the complete repository kernel",
        });
    }
    let mut vectors = BTreeMap::new();
    for (&expected_cx, (observed_cx, vector)) in member_ids.iter().zip(resolved) {
        if expected_cx != observed_cx {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
                message: format!(
                    "S20 resolver changed the current member order: expected {expected_cx}, observed {observed_cx}"
                ),
                remediation: "repair the slot resolver ordering contract and rebuild the complete repository kernel",
            });
        }
        vectors.insert(
            expected_cx,
            dense_s20_member_vector(index_project, expected_cx, semantic_dim, vector)?,
        );
    }

    let artifact = &generation.artifact;
    let mut occurrences = Vec::with_capacity(artifact.members.len());
    for member in &artifact.members {
        let frames =
            read_member_atom_at(&vault, index_project, member.id, panel_version, snapshot)?;
        let vector = vectors.remove(&member.id).ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!("member {} disappeared from the exact S20 roster", member.id),
            remediation: "preserve the generation and repair its member/vector binding before recomposing",
        })?;
        occurrences.push(MemberOccurrence {
            project: store_key.to_string(),
            cx: member.id,
            qualified_name: frames.qualified_name,
            rel_file_path: frames.rel_file_path,
            label: frames.label.clone(),
            language: frames.language,
            content_key: frames.content_key,
            content_free: frames.source_absent || frames.label == "File",
            source_absent: frames.source_absent,
            grounded: member.grounded,
            score_permille: member.score_permille,
            degree: member.degree,
            betweenness_permille: member.betweenness_permille,
            groundedness_permille: member.groundedness_permille,
            frequency: member.frequency,
            in_fvs: member.in_fvs,
            vector,
        });
    }
    source_lease.record_progress();
    let final_base_content_generation = vault
        .cf_content_generation(ColumnFamily::Base)
        .map_err(|error| inner_err("re-read repository Base content generation", error))?;
    let final_blob_content_generation = vault
        .cf_content_generation(ColumnFamily::Blob)
        .map_err(|error| inner_err("re-read repository Blob content generation", error))?;
    if !vectors.is_empty()
        || vault.latest_seq() != snapshot
        || final_base_content_generation != base_content_generation
        || final_blob_content_generation != blob_content_generation
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "current generation changed or retained extra vectors during fleet load: extra_vectors={}, retained_seq={snapshot}, observed_seq={}, base_generation={base_content_generation}->{final_base_content_generation}, blob_generation={blob_content_generation}->{final_blob_content_generation}",
                vectors.len(),
                vault.latest_seq()
            ),
            remediation: "discard the mixed load and retry against one stable complete repository generation",
        });
    }
    let kernel_header_blake3 =
        repo_kernel_header_blake3(&generation.manifest, &generation.pointer)?;

    Ok(Some(RepoKernelLoad {
        project: store_key.to_string(),
        index_project: index_project.to_string(),
        kernel_scope: scope,
        members_hash: artifact.members_hash.clone(),
        node_count: artifact.node_count,
        graph_coverage_permille: artifact.graph_coverage.permille,
        source_identity_hash: artifact.source_identity.combined_hash.clone(),
        generation_id: generation.manifest.generation_id.clone(),
        source_generation_identity: generation.manifest.source_generation_identity.clone(),
        kernel_header_blake3: kernel_header_blake3.clone(),
        base_content_generation,
        blob_content_generation,
        panel_version,
        semantic_dim,
        s20_source_binding_seq,
        s20_source_final_verification_seq,
        s20_source_binding: s20_source_binding.clone(),
        compose_source_hash: repo_compose_source_hash(
            &generation.manifest.generation_id,
            &kernel_header_blake3,
            base_content_generation,
            blob_content_generation,
            &artifact.source_identity.combined_hash,
            &generation.manifest.source_generation_identity,
            &artifact.members_hash,
            panel_version,
            semantic_dim,
            s20_source_binding_seq,
            s20_source_final_verification_seq,
            &s20_source_binding,
            &occurrences,
        )?,
        betweenness_exact: artifact.betweenness_exact,
        occurrences,
    }))
}

fn repo_compose_source_hash(
    generation_id: &str,
    kernel_header_blake3: &str,
    base_content_generation: u64,
    blob_content_generation: u64,
    source_identity_hash: &str,
    source_generation_identity: &str,
    members_hash: &str,
    panel_version: u32,
    semantic_dim: u32,
    s20_source_binding_seq: u64,
    s20_source_final_verification_seq: u64,
    s20_source_binding: &WeaveSlotBinding,
    occurrences: &[MemberOccurrence],
) -> Result<String, CalyxError> {
    let mut sorted = occurrences.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|occurrence| occurrence.cx);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&frame(b"astrolabe.fleet.repo-compose-source.v4"));
    preimage.extend_from_slice(&frame(generation_id.as_bytes()));
    preimage.extend_from_slice(&frame(kernel_header_blake3.as_bytes()));
    preimage.extend_from_slice(&frame(&base_content_generation.to_be_bytes()));
    preimage.extend_from_slice(&frame(&blob_content_generation.to_be_bytes()));
    preimage.extend_from_slice(&frame(source_identity_hash.as_bytes()));
    preimage.extend_from_slice(&frame(source_generation_identity.as_bytes()));
    preimage.extend_from_slice(&frame(members_hash.as_bytes()));
    preimage.extend_from_slice(&frame(&panel_version.to_be_bytes()));
    preimage.extend_from_slice(&frame(&semantic_dim.to_be_bytes()));
    preimage.extend_from_slice(&frame(&s20_source_binding_seq.to_be_bytes()));
    preimage.extend_from_slice(&frame(&s20_source_final_verification_seq.to_be_bytes()));
    let source_binding_bytes = serde_json::to_vec(s20_source_binding).map_err(|error| {
        CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!("serialize exact repository S20 source binding: {error}"),
            remediation: "preserve the repository generation and repair the source-binding serializer before fleet composition",
        }
    })?;
    preimage.extend_from_slice(&frame(&source_binding_bytes));
    preimage.extend_from_slice(&frame(&(sorted.len() as u64).to_be_bytes()));
    for occurrence in sorted {
        preimage.extend_from_slice(&frame(occurrence.cx.as_bytes()));
        preimage.extend_from_slice(&frame(occurrence.project.as_bytes()));
        preimage.extend_from_slice(&frame(occurrence.qualified_name.as_bytes()));
        preimage.extend_from_slice(&frame(occurrence.rel_file_path.as_bytes()));
        preimage.extend_from_slice(&frame(occurrence.label.as_bytes()));
        preimage.extend_from_slice(&frame(occurrence.language.as_bytes()));
        preimage.extend_from_slice(&frame(&occurrence.content_key));
        preimage.extend_from_slice(&frame(&[
            u8::from(occurrence.content_free),
            u8::from(occurrence.source_absent),
            u8::from(occurrence.grounded),
            u8::from(occurrence.in_fvs),
        ]));
        for value in [
            occurrence.score_permille,
            occurrence.degree,
            occurrence.betweenness_permille,
            occurrence.groundedness_permille,
            occurrence.frequency,
        ] {
            preimage.extend_from_slice(&frame(&value.to_be_bytes()));
        }
        preimage.extend_from_slice(&frame(b"dense-s20"));
        preimage.extend_from_slice(&frame(&(occurrence.vector.len() as u64).to_be_bytes()));
        for value in &occurrence.vector {
            preimage.extend_from_slice(&frame(&value.to_bits().to_be_bytes()));
        }
    }
    Ok(blake3::hash(&preimage).to_hex().to_string())
}

fn repo_kernel_header_blake3(
    manifest: &KernelGenerationManifest,
    pointer: &KernelGenerationPointer,
) -> Result<String, CalyxError> {
    let bytes = serde_json::to_vec(&(manifest, pointer)).map_err(|error| CalyxError {
        code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
        message: format!("serialize exact repository kernel header: {error}"),
        remediation: "preserve the repository generation and repair its canonical pointer/manifest serializer before fleet composition",
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&frame(b"astrolabe.fleet.repository-kernel-header.v1"));
    hasher.update(&frame(&bytes));
    Ok(hasher.finalize().to_hex().to_string())
}

/// Reads only one repository's atomic current Kernel artifact.
///
/// This is the narrow postcondition for operations such as explicit WAL
/// migration that need to prove the durable generation, physical Ledger row,
/// complete member HNSW, and S20 source binding still reopen. It never consumes
/// a fixed legacy alias as the repository generation.
///
/// At production `N=192,873`, `E=328,899` (2026-08-20), this performs
/// `O(N+E+A+B+K)`: one current projection traversal, one anchor/promotion
/// rollup `A`, checksum-bound composite bytes `B`, the `K`-member roster, and
/// current/previous physical Ledger point reads. Retained sequence, current
/// pointer/generation, projection, anchor roster, member roster,
/// panel/dimension, and S20 source binding are invariant
/// (PC-03/04/07/14/15/28/32/35/37/41/43; #1064).
pub fn read_repo_kernel_artifact(
    store_root: &Path,
    store_key: &str,
    index_project: &str,
) -> Result<Option<KernelArtifact>, CalyxError> {
    let vault_dir = store_root
        .join(store_key)
        .join(format!("{index_project}.astrolabe-vault"));
    match vault_dir.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) => {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "cannot classify per-repository vault path {}: {error}",
                    vault_dir.display()
                ),
                remediation: "repair the named repository vault path so its physical presence can be read exactly before reading the current kernel generation",
            });
        }
    }
    let vault = open_shadow_vault(
        store_root,
        store_key,
        index_project,
        vec![
            ColumnFamily::Graph,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::Kernel,
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
            ColumnFamily::slot(SLOT_NAME_SEMANTIC),
        ],
    )?;
    let scope = kernel_scope_id(index_project);
    let source_lease = vault.retain_latest_snapshot();
    let snapshot = source_lease.seq();
    let current = read_current_kernel_generation(&vault, index_project, &scope)
        .map_err(|error| inner_err("read narrow current per-repo kernel generation", error))?;
    source_lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "repository kernel generation moved during narrow read: retained_seq={snapshot}, observed_seq={}",
                vault.latest_seq()
            ),
            remediation: "retry the read against one stable current composite generation",
        });
    }
    let artifact = match current {
        Some(current) => {
            let projection = read_graph_projection_csr_bound_at(
                &vault,
                GraphProjectionKind::KernelGraph,
                snapshot,
                &GraphProjectionReadBinding {
                    graph_content_generation: current
                        .manifest
                        .generation_source_binding
                        .graph_content_generation,
                    manifest: current
                        .manifest
                        .generation_source_binding
                        .projection_manifest
                        .clone(),
                },
            )
            .map_err(|error| inner_err("read current repository KernelGraph projection", error))?;
            source_lease.record_progress();
            let anchor_trust = astrolabe_anchors::effective_anchor_trust_map_at(&vault, snapshot)
                .map_err(|error| {
                inner_err("read current repository anchor trust roster", error)
            })?;
            source_lease.record_progress();
            let source_graph = kernel_graph_from_projection_csr(&projection, &anchor_trust)
                .map_err(|error| {
                    inner_err("adapt current repository KernelGraph projection", error)
                })?;
            let observed_source_identity =
                kernel_source_identity(&source_graph, &current.artifact.config).map_err(
                    |error| inner_err("recompute current repository kernel source identity", error),
                )?;
            if observed_source_identity != current.artifact.source_identity {
                return Err(CalyxError {
                    code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                    message: format!(
                        "repository {index_project:?} current projection/anchor/config identity differs from generation {:?}: expected={}, observed={}",
                        current.manifest.generation_id,
                        current.artifact.source_identity.combined_hash,
                        observed_source_identity.combined_hash
                    ),
                    remediation: "rebuild the complete repository kernel from the current projection and anchor rows before using it in fleet state",
                });
            }
            Some(current.artifact)
        }
        None => {
            if vault
                .read_cf_at(
                    snapshot,
                    ColumnFamily::Kernel,
                    &fixed_kernel_json_key(&scope),
                )?
                .is_some()
            {
                return Err(CalyxError {
                    code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                    message: format!(
                        "repository {index_project:?} has a fixed kernel alias but no composite current pointer"
                    ),
                    remediation: "publish one complete atomic repository kernel generation; fixed aliases are not a serving source",
                });
            }
            None
        }
    };
    source_lease.record_progress();
    if vault.latest_seq() != snapshot {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "repository kernel state moved during narrow alias/current readback: retained_seq={snapshot}, observed_seq={}",
                vault.latest_seq()
            ),
            remediation: "discard the mixed result and retry against one stable current composite generation",
        });
    }
    Ok(artifact)
}

/// One fleet-graph node: a content-equivalence class of per-repo members.
#[derive(Clone, Debug)]
struct FleetNode {
    fleet_cx: CxId,
    content_key: Option<[u8; 32]>,
    occurrences: Vec<MemberOccurrence>,
    grounded_any: bool,
    frequency_sum: u64,
    centroid: Vec<f32>,
}

fn fleet_node_cx(scope: &str, key_bytes: &[u8], panel_version: u32) -> Result<CxId, CalyxError> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&frame(FLEET_NODE_CANONICAL_TAG));
    canonical.extend_from_slice(&frame(scope.as_bytes()));
    canonical.extend_from_slice(&frame(key_bytes));
    let salt = format!("astrolabe-fleet-v1:{scope}");
    cx_id_from_canonical(&canonical, panel_version, salt.as_bytes())
        .map_err(|error| inner_err("derive fleet node CxId", error))
}

fn unit_vector(vector: &[f32], identity: impl std::fmt::Display) -> Result<Vec<f32>, CalyxError> {
    let norm: f32 = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!("S20 vector for {identity} has non-finite or zero norm {norm}"),
            remediation: "repair the exact universal S20 row and rebuild the complete repository kernel",
        });
    }
    Ok(vector.iter().map(|value| value / norm).collect())
}

fn checked_fleet_frequency_add(sum: u64, addend: u64) -> Result<u64, CalyxError> {
    sum.checked_add(addend).ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
        message: format!("fleet frequency addition overflowed u64: {sum} + {addend}"),
        remediation: "widen the fleet frequency representation before composing; no saturated sum is permitted",
    })
}

fn checked_fleet_weighted_frequency(
    frequency_sum: u64,
    repo_count: u64,
    weight_permille: u64,
) -> Result<u64, CalyxError> {
    let extra = repo_count.checked_sub(1).ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
        message: "fleet weighted frequency has zero repository support".to_string(),
        remediation: "repair the empty fleet equivalence class before composition",
    })?;
    let scale = u128::from(weight_permille)
        .checked_mul(u128::from(extra))
        .and_then(|extra_scale| 1000_u128.checked_add(extra_scale))
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
            message: format!(
                "fleet support scale overflowed: weight_permille={weight_permille} extra_repositories={extra}"
            ),
            remediation: "reduce the admitted support-weight/roster or widen the graph-weight representation; no saturated scale is published",
        })?;
    let scaled = u128::from(frequency_sum)
        .checked_mul(scale)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
            message: format!(
                "fleet weighted frequency overflowed u128: frequency={frequency_sum} scale={scale}"
            ),
            remediation: "widen the weighted-frequency representation before composing; no saturated graph weight is published",
        })?
        / 1000;
    Ok(u64::try_from(scaled)
        .map_err(|_| CalyxError {
            code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
            message: format!("fleet weighted frequency {scaled} exceeds u64"),
            remediation: "widen the kernel graph frequency representation before composing; no u64 clamp is permitted",
        })?
        .max(1))
}

fn checked_fleet_coverage_permille(covered: u64, total: u64) -> Result<u64, CalyxError> {
    covered
        .checked_mul(1000)
        .and_then(|numerator| numerator.checked_div(total))
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
            message: format!(
                "fleet coverage ratio is not exactly representable: covered={covered} total={total}"
            ),
            remediation: "repair the zero/overflowing repository coverage census before publishing the fleet generation",
        })
}

/// Manual-FSV edge driver for the same checked arithmetic used by production
/// fleet node and coverage construction. This creates no query/evaluator data.
#[cfg(feature = "manual-fsv")]
pub fn manual_fsv_arithmetic_overflow_edges() -> Result<Value, CalyxError> {
    let require_overflow = |edge: &'static str, result: Result<u64, CalyxError>| match result {
        Err(error) => Ok(error),
        Ok(value) => Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_INNER,
            message: format!("manual FSV arithmetic edge {edge:?} unexpectedly returned {value}"),
            remediation: "restore checked production arithmetic before recording FSV evidence",
        }),
    };
    let frequency = require_overflow("frequency_add", checked_fleet_frequency_add(u64::MAX, 1))?;
    let weighted = require_overflow(
        "weighted_frequency",
        checked_fleet_weighted_frequency(u64::MAX, 2, 1000),
    )?;
    let coverage = require_overflow(
        "coverage_permille",
        checked_fleet_coverage_permille(u64::MAX, 1),
    )?;
    if [frequency.code, weighted.code, coverage.code]
        .into_iter()
        .any(|code| code != ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW)
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_INNER,
            message: "manual FSV arithmetic edge returned a non-overflow refusal code".to_string(),
            remediation: "restore the exact checked production arithmetic refusal contract before recording FSV evidence",
        });
    }
    Ok(json!({
        "schema": "astrolabe.issue_1151.arithmetic_edges.v1",
        "frequency_add": frequency.code,
        "weighted_frequency": weighted.code,
        "coverage_permille": coverage.code,
        "saturation_used": false,
    }))
}

/// Builds the fleet nodes: content-bearing members merge per content key
/// (`same content = same node`); content-free members stay unique per
/// (project, member) — their explicit source absence makes them content-free, so merging them
/// would fabricate equivalence (the degenerate `mod.rs` class found on #455).
fn build_fleet_nodes(
    scope: &str,
    loads: &[RepoKernelLoad],
    panel_version: u32,
) -> Result<Vec<FleetNode>, CalyxError> {
    let mut grouped: BTreeMap<Vec<u8>, Vec<MemberOccurrence>> = BTreeMap::new();
    for load in loads {
        for occurrence in &load.occurrences {
            let key = if occurrence.content_free {
                let mut key = vec![0x02_u8];
                key.extend_from_slice(&frame(occurrence.project.as_bytes()));
                key.extend_from_slice(occurrence.cx.as_bytes());
                key
            } else {
                let mut key = vec![0x01_u8];
                key.extend_from_slice(&occurrence.content_key);
                key
            };
            grouped.entry(key).or_default().push(occurrence.clone());
        }
    }

    let mut nodes = Vec::with_capacity(grouped.len());
    let mut dim: Option<usize> = None;
    for (key, mut occurrences) in grouped {
        occurrences.sort_by(|left, right| {
            left.project
                .cmp(&right.project)
                .then_with(|| left.cx.cmp(&right.cx))
        });
        let fleet_cx = fleet_node_cx(scope, &key, panel_version)?;
        let grounded_any = occurrences.iter().any(|occurrence| occurrence.grounded);
        let frequency_sum = occurrences.iter().try_fold(0_u64, |sum, occurrence| {
            checked_fleet_frequency_add(sum, occurrence.frequency).map_err(|_| CalyxError {
                code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
                message: format!(
                    "fleet equivalence class {fleet_cx} frequency sum overflowed u64 while adding {}:{} frequency {} to {sum}",
                    occurrence.project, occurrence.cx, occurrence.frequency,
                ),
                remediation: "preserve the exact source generations and widen the fleet kernel frequency representation; no saturated weight is published",
            })
        })?.max(1);
        let mut sum: Option<Vec<f32>> = None;
        for occurrence in &occurrences {
            let unit = unit_vector(
                &occurrence.vector,
                format_args!("{}:{}", occurrence.project, occurrence.cx),
            )?;
            match dim {
                None => dim = Some(unit.len()),
                Some(expected) if expected != unit.len() => {
                    return Err(CalyxError {
                        code: ASTRO_FLEET_COMPOSE_DIM_MISMATCH,
                        message: format!(
                            "S20 vector dimension {} for {}:{} disagrees with fleet dimension {expected}",
                            unit.len(),
                            occurrence.project,
                            occurrence.qualified_name
                        ),
                        remediation: "re-index the divergent repo with the same frozen panel so every S20 vector shares one dimension",
                    });
                }
                Some(_) => {}
            }
            match &mut sum {
                None => sum = Some(unit),
                Some(sum) => {
                    for (slot, value) in sum.iter_mut().zip(unit.iter()) {
                        *slot += value;
                    }
                }
            }
        }
        let mut centroid = sum.ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_VECTOR_INVALID,
            message: format!("fleet equivalence class {fleet_cx} has no S20 member vectors"),
            remediation: "repair the complete S20 roster before composing the fleet graph",
        })?;
        for value in &mut centroid {
            *value /= occurrences.len() as f32;
        }
        let centroid = unit_vector(&centroid, fleet_cx)?;
        let content_key = if key[0] == 0x01 {
            let mut content_key = [0_u8; 32];
            content_key.copy_from_slice(&key[1..33]);
            Some(content_key)
        } else {
            None
        };
        nodes.push(FleetNode {
            fleet_cx,
            content_key,
            occurrences,
            grounded_any,
            frequency_sum,
            centroid,
        });
    }
    nodes.sort_by_key(|node| node.fleet_cx);
    Ok(nodes)
}

impl FleetNode {
    /// The class label. Every occurrence of a content-equivalence class shares
    /// one label (the content key frames it); a content-free node holds a single
    /// occurrence.
    fn label(&self) -> &str {
        self.occurrences
            .first()
            .map(|occurrence| occurrence.label.as_str())
            .unwrap_or("")
    }

    /// Distinct repos supporting this node (cross-repo support).
    fn repo_count(&self) -> Result<u64, CalyxError> {
        u64::try_from(
            self.occurrences
            .iter()
            .map(|occurrence| occurrence.project.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        )
        .map_err(|_| CalyxError {
            code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
            message: format!(
                "fleet node {} repository-support count cannot be represented as u64",
                self.fleet_cx,
            ),
            remediation: "widen the fleet support-count representation before composing; no clamped weight is published",
        })
    }

    /// Cross-repo-support-weighted frequency (#477): `freq · (1000 + w·(K−1))/1000`,
    /// with the declared minimum-one convention. `w` is the support-weight
    /// knob. Every semantic operation is checked; overflow refuses instead of
    /// changing the graph weight through saturation.
    fn weighted_frequency(&self, weight_permille: u64) -> Result<u64, CalyxError> {
        checked_fleet_weighted_frequency(self.frequency_sum, self.repo_count()?, weight_permille)
            .map_err(|error| CalyxError {
                code: error.code,
                message: format!("fleet node {}: {}", self.fleet_cx, error.message),
                remediation: error.remediation,
            })
    }

    /// Declared candidacy verdict (#477): `Some(rule)` = excluded by that rule,
    /// `None` = eligible. Rules are evaluated in a fixed order; each excluded
    /// node is attributed to exactly the first matching rule.
    fn candidacy_exclusion(&self) -> Option<&'static str> {
        if self
            .occurrences
            .iter()
            .all(|occurrence| occurrence.source_absent)
        {
            return Some(CANDIDACY_RULE_EMPTY_FINGERPRINT);
        }
        if FLEET_STRUCTURAL_LABELS.contains(&self.label()) {
            return Some(CANDIDACY_RULE_STRUCTURAL_LABEL);
        }
        None
    }
}

/// Per-rule tally of the declared candidacy policy (#477), recorded verbatim in
/// the compose sidecar so every exclusion is counted (invariant 3) and the
/// before/after member-set shift is auditable.
#[derive(Default)]
struct CandidacyCensus {
    total_nodes: usize,
    candidates: usize,
    excluded_total: usize,
    excluded_by_rule: BTreeMap<&'static str, u64>,
    excluded_by_label: BTreeMap<String, u64>,
    surviving_by_label: BTreeMap<String, u64>,
}

impl CandidacyCensus {
    /// The declared candidacy policy block for the sidecar: every rule named,
    /// its per-rule exclusion count, and the surviving/excluded label tallies.
    fn to_sidecar(&self, weight_permille: u64) -> Value {
        let rule_count = |rule: &str| self.excluded_by_rule.get(rule).copied().unwrap_or(0);
        json!({
            "policy_version": FLEET_CANDIDACY_POLICY_VERSION,
            "knob_registry_version": FLEET_CANDIDACY_KNOB_REGISTRY_VERSION,
            "rules": [
                {
                    "rule": CANDIDACY_RULE_EMPTY_FINGERPRINT,
                    "kind": "exclusion",
                    "description": "class carries no exact retained source bytes; \
                                    no content to reuse — mirrors the dedup census content_free predicate",
                    "excluded": rule_count(CANDIDACY_RULE_EMPTY_FINGERPRINT),
                },
                {
                    "rule": CANDIDACY_RULE_STRUCTURAL_LABEL,
                    "kind": "exclusion",
                    "description": "class label is a declared structural/content-free label: no reusable code body",
                    "structural_labels": FLEET_STRUCTURAL_LABELS,
                    "excluded": rule_count(CANDIDACY_RULE_STRUCTURAL_LABEL),
                },
                {
                    "rule": "cross_repo_support_weight",
                    "kind": "weight",
                    "description": "surviving candidates' graph frequency up-weighted by distinct-repo \
                                    support: freq·(1000 + w·(K−1))/1000 (not an exclusion)",
                    "weight_permille": weight_permille,
                    "excluded": 0,
                },
            ],
            "nodes_before_policy": self.total_nodes,
            "candidates": self.candidates,
            "excluded_total": self.excluded_total,
            "excluded_by_rule": self.excluded_by_rule,
            "excluded_by_label": self.excluded_by_label,
            "surviving_by_label": self.surviving_by_label,
        })
    }
}

/// Applies the declared candidacy policy (#477): every fleet node is classified
/// eligible or excluded; excluded nodes are dropped from the kernel graph — so
/// they can be neither kernel members nor coverage targets nor similarity hubs —
/// and counted per declared rule. Content-bearing code atoms survive; content-
/// free structural atoms (File/Decorator/Section labels, snippetless classes)
/// do not. The census is returned for verbatim persistence in the sidecar.
fn apply_candidacy_policy(nodes: Vec<FleetNode>) -> (Vec<FleetNode>, CandidacyCensus) {
    let mut census = CandidacyCensus {
        total_nodes: nodes.len(),
        ..CandidacyCensus::default()
    };
    let mut candidates = Vec::with_capacity(nodes.len());
    for node in nodes {
        let label = node.label().to_string();
        match node.candidacy_exclusion() {
            Some(rule) => {
                *census.excluded_by_rule.entry(rule).or_default() += 1;
                *census.excluded_by_label.entry(label).or_default() += 1;
                census.excluded_total += 1;
            }
            None => {
                *census.surviving_by_label.entry(label).or_default() += 1;
                candidates.push(node);
            }
        }
    }
    census.candidates = candidates.len();
    (candidates, census)
}

/// Builds deterministic top-k min-thresholded cosine similarity edges over the
/// node centroids. Returns `(edges, similarity_permille_histogram)`.
fn build_similarity_edges(
    nodes: &[FleetNode],
    config: &ComposeConfig,
) -> (Vec<KernelGraphEdge>, BTreeMap<u64, u64>) {
    // Each node retains only its declared top-k while the all-pairs stream is
    // evaluated. This keeps resident candidate state O(V_f*T), never O(V_f²),
    // while preserving the exact deterministic ranking for every node
    // (PC-09/16/24/26/38; #1064).
    let top_k = config.similarity_top_k as usize;
    let mut candidates = vec![Vec::<(u64, usize)>::new(); nodes.len()];
    let mut histogram: BTreeMap<u64, u64> = BTreeMap::new();
    for a in 0..nodes.len() {
        let centroid_a = &nodes[a].centroid;
        for b in (a + 1)..nodes.len() {
            let centroid_b = &nodes[b].centroid;
            let dot: f32 = centroid_a
                .iter()
                .zip(centroid_b.iter())
                .map(|(left, right)| left * right)
                .sum();
            let permille = (dot.clamp(0.0, 1.0) * 1000.0).floor() as u64;
            *histogram.entry(permille / 100 * 100).or_default() += 1;
            if permille >= config.similarity_min_permille {
                retain_similarity_candidate(&mut candidates[a], (permille, b), top_k, nodes);
                retain_similarity_candidate(&mut candidates[b], (permille, a), top_k, nodes);
            }
        }
    }
    let mut weights: BTreeMap<(CxId, CxId), u64> = BTreeMap::new();
    for (index, list) in candidates.into_iter().enumerate() {
        for (permille, other) in list {
            let src = nodes[index].fleet_cx;
            let dst = nodes[other].fleet_cx;
            let entry = weights.entry((src, dst)).or_default();
            *entry = (*entry).max(permille);
            let entry = weights.entry((dst, src)).or_default();
            *entry = (*entry).max(permille);
        }
    }
    let edges = weights
        .into_iter()
        .map(|((src, dst), permille)| KernelGraphEdge::new(src, dst, permille as f32 / 1000.0))
        .collect();
    (edges, histogram)
}

fn retain_similarity_candidate(
    candidates: &mut Vec<(u64, usize)>,
    candidate: (u64, usize),
    top_k: usize,
    nodes: &[FleetNode],
) {
    candidates.push(candidate);
    candidates.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| nodes[left.1].fleet_cx.cmp(&nodes[right.1].fleet_cx))
    });
    candidates.truncate(top_k);
}

/// Marks every node within `radius` undirected hops of any member index.
/// Mirrors the kernel crate's graph-coverage BFS so the per-repo diagnostic
/// measures the identical topology property the artifact carries.
fn coverage_from(indexed: &IndexedGraph, members: &BTreeSet<usize>, radius: u64) -> Vec<bool> {
    let n = indexed.len();
    let mut covered = vec![false; n];
    let mut depth = vec![0_u64; n];
    let mut queue = std::collections::VecDeque::new();
    for &member in members {
        if !covered[member] {
            covered[member] = true;
            queue.push_back(member);
        }
    }
    while let Some(node) = queue.pop_front() {
        if depth[node] >= radius {
            continue;
        }
        for &neighbor in indexed.undirected_neighbors(node) {
            if !covered[neighbor] {
                covered[neighbor] = true;
                depth[neighbor] = depth[node] + 1;
                queue.push_back(neighbor);
            }
        }
    }
    covered
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn elapsed_us(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Exact compose-input hash over every per-repo value and configuration field
/// consumed by fleet graph construction. A change in topology, member metadata,
/// S20 vector bits, candidacy, similarity geometry, or kernel build config is a
/// structural [`GraphDelta`] even when the member roster itself is unchanged.
pub fn compose_input_hash(
    sources: &[(String, String)],
    policy_version: &str,
    compose_config: &ComposeConfig,
    kernel_config: &KernelBuildConfig,
) -> String {
    let mut sorted = sources.iter().collect::<Vec<_>>();
    sorted.sort();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&frame(b"astrolabe.fleet.atomic-compose-input.v1"));
    preimage.extend_from_slice(&frame(FLEET_KERNEL_SOURCE_ROSTER_SCHEMA.as_bytes()));
    preimage.extend_from_slice(&frame(FLEET_COMPOSE_KNOB_REGISTRY_VERSION.as_bytes()));
    preimage.extend_from_slice(&frame(KERNEL_BUILD_KNOB_REGISTRY_VERSION.as_bytes()));
    preimage.extend_from_slice(&frame(policy_version.as_bytes()));
    for value in [
        compose_config.similarity_min_permille,
        compose_config.similarity_top_k,
        compose_config.per_repo_graph_coverage_min_permille,
        compose_config.cross_repo_support_weight_permille,
        kernel_config.weight_degree_permille,
        kernel_config.weight_betweenness_permille,
        kernel_config.weight_groundedness_permille,
        kernel_config.groundedness_hop_limit,
        kernel_config.groundedness_freq_cap,
        kernel_config.groundedness_freq_bonus_permille,
        kernel_config.betweenness_exact_max_nodes,
        kernel_config.betweenness_sample_pivots,
        kernel_config.betweenness_sample_seed,
        kernel_config.graph_coverage_min_permille,
        kernel_config.graph_coverage_radius_hops,
        kernel_config.max_member_fraction_permille,
    ] {
        preimage.extend_from_slice(&frame(&value.to_be_bytes()));
    }
    for (project, source_hash) in sorted {
        preimage.extend_from_slice(&frame(project.as_bytes()));
        preimage.extend_from_slice(&frame(source_hash.as_bytes()));
    }
    blake3::hash(&preimage).to_hex().to_string()
}

fn source_roster_from_loads(
    scope: &str,
    compose_config: ComposeConfig,
    kernel_config: KernelBuildConfig,
    panel_version: u32,
    semantic_dim: u32,
    loads: &[RepoKernelLoad],
) -> Result<FleetKernelSourceRoster, CalyxError> {
    finalize_fleet_source_roster(FleetKernelSourceRoster {
        schema: FLEET_KERNEL_SOURCE_ROSTER_SCHEMA.to_string(),
        scope_id: scope.to_string(),
        compose_input_hash: String::new(),
        candidacy_policy_version: FLEET_CANDIDACY_POLICY_VERSION.to_string(),
        panel_version,
        semantic_dim,
        compose_config,
        kernel_config,
        repositories: loads
            .iter()
            .map(|load| FleetRepoSourceBinding {
                catalog_project: load.project.clone(),
                store_key: load.project.clone(),
                index_project: load.index_project.clone(),
                kernel_scope: load.kernel_scope.clone(),
                generation_id: load.generation_id.clone(),
                source_generation_identity: load.source_generation_identity.clone(),
                kernel_header_blake3: load.kernel_header_blake3.clone(),
                base_content_generation: load.base_content_generation,
                blob_content_generation: load.blob_content_generation,
                compose_source_hash: load.compose_source_hash.clone(),
                artifact_source_identity_hash: load.source_identity_hash.clone(),
                members_hash: load.members_hash.clone(),
                member_count: load.occurrences.len(),
                panel_version: load.panel_version,
                semantic_dim: load.semantic_dim,
                s20_source_binding_seq: load.s20_source_binding_seq,
                s20_source_final_verification_seq: load.s20_source_final_verification_seq,
                s20_source_binding: load.s20_source_binding.clone(),
            })
            .collect(),
        source_roster_hash: String::new(),
    })
}

fn similarity_pair_count(node_count: usize) -> Result<u128, CalyxError> {
    (node_count as u128)
        .checked_mul(node_count.saturating_sub(1) as u128)
        .map(|pairs| pairs / 2)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_KNOB_RANGE,
            message: "fleet similarity-pair count overflowed u128".to_string(),
            remediation: "reduce the explicit fleet roster; pair-work overflow refuses before any similarity computation",
        })
}

fn enforce_similarity_pair_ceiling(node_count: usize, ceiling: u64) -> Result<u128, CalyxError> {
    let pairs = similarity_pair_count(node_count)?;
    if ceiling == 0 || pairs > u128::from(ceiling) {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_KNOB_RANGE,
            message: format!(
                "fleet similarity work requires {pairs} unordered pair evaluations, above explicit admission ceiling {ceiling}"
            ),
            remediation: "supply a measured explicit ceiling sufficient for this exact fleet generation or reduce the source roster; no truncated or approximate fallback is permitted",
        });
    }
    Ok(pairs)
}

fn member_provenance_from_nodes(
    artifact: &KernelArtifact,
    nodes: &[FleetNode],
) -> Result<FleetMemberProvenanceRoster, CalyxError> {
    let node_by_cx = nodes
        .iter()
        .map(|node| (node.fleet_cx, node))
        .collect::<BTreeMap<_, _>>();
    finalize_fleet_member_provenance(FleetMemberProvenanceRoster {
        schema: FLEET_KERNEL_PROVENANCE_SCHEMA.to_string(),
        members_hash: artifact.members_hash.clone(),
        members: artifact
            .members
            .iter()
            .map(|member| {
                let node = node_by_cx.get(&member.id).ok_or_else(|| CalyxError {
                    code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                    message: format!(
                        "fleet artifact member {} is absent from the independently rebuilt fleet projection",
                        member.id
                    ),
                    remediation: "preserve the fleet generation and recompose it from the exact current repository roster",
                })?;
                Ok(FleetMemberProvenance {
                    fleet_cx: member.id,
                    content_key_hex: node.content_key.as_ref().map(hex32),
                    grounded: node.grounded_any,
                    occurrences: node
                        .occurrences
                        .iter()
                        .map(|occurrence| FleetMemberOccurrenceProvenance {
                            project: occurrence.project.clone(),
                            cx_id: occurrence.cx,
                            qualified_name: occurrence.qualified_name.clone(),
                            rel_file_path: occurrence.rel_file_path.clone(),
                            label: occurrence.label.clone(),
                            language: occurrence.language.clone(),
                            content_key_hex: hex32(&occurrence.content_key),
                            grounded: occurrence.grounded,
                            score_permille: occurrence.score_permille,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, CalyxError>>()?,
        provenance_hash: String::new(),
    })
}

fn missing_catalog_inventory_identity(store_key: &str) -> CalyxError {
    CalyxError {
        code: ASTRO_FLEET_PROJECT_IDENTITY,
        message: format!(
            "fleet catalog pass-level inventory omitted requested stable store key {store_key:?}"
        ),
        remediation: "preserve the catalog bytes and retry only after one complete catalog inventory can resolve every requested repository exactly once",
    }
}

fn load_generation_source_roster(
    catalog: &FleetCatalog,
    store_root: &Path,
    expected: &FleetKernelSourceRoster,
) -> Result<Vec<RepoKernelLoad>, CalyxError> {
    let catalog_seq = catalog.vault().latest_seq();
    let catalog_inventory = catalog_store_identities(
        catalog,
        expected
            .repositories
            .iter()
            .map(|binding| binding.catalog_project.as_str()),
    )?;
    let catalog_identities = catalog_inventory.identities;
    let mut loads = Vec::with_capacity(expected.repositories.len());
    for binding in &expected.repositories {
        let catalog_identity = catalog_identities
            .get(&binding.catalog_project)
            .ok_or_else(|| missing_catalog_inventory_identity(&binding.catalog_project))?;
        if catalog_identity.store_key != binding.store_key
            || catalog_identity.index_project != binding.index_project
            || catalog_identity.kernel_scope != binding.kernel_scope
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "fleet catalog identity drifted for {:?}: persisted=({:?},{:?},{:?}) observed=({:?},{:?},{:?})",
                    binding.catalog_project,
                    binding.store_key,
                    binding.index_project,
                    binding.kernel_scope,
                    catalog_identity.store_key,
                    catalog_identity.index_project,
                    catalog_identity.kernel_scope,
                ),
                remediation: "do not serve the stale fleet generation; restore the exact catalog/repository identity or explicitly recompose from the new complete roster",
            });
        }
        let load = load_repo_kernel(
            store_root,
            &catalog_identity.store_key,
            &catalog_identity.index_project,
        )?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet source repository {:?} no longer has one complete current atomic kernel generation",
                binding.store_key
            ),
            remediation: "rebuild the missing repository generation, then explicitly recompose the fleet; no stale fleet fallback is served",
        })?;
        loads.push(load);
    }
    loads.sort_by(|left, right| left.project.cmp(&right.project));
    let observed = source_roster_from_loads(
        &expected.scope_id,
        expected.compose_config,
        expected.kernel_config,
        expected.panel_version,
        expected.semantic_dim,
        &loads,
    )?;
    if catalog.vault().latest_seq() != catalog_seq {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet catalog moved while resolving the repository source roster: retained_seq={catalog_seq} observed_seq={}",
                catalog.vault().latest_seq(),
            ),
            remediation: "discard the mixed multi-repository read and retry against one stable catalog/source roster",
        });
    }
    verify_fleet_source_roster_exact(expected, &observed)?;
    Ok(loads)
}

/// Point-checks one persisted repository source binding without reconstructing
/// its graph, anchors, member roster, Base rows, Blob payloads, or S20 vectors.
/// The Aster content generations are durable logical identities, so equality
/// of the exact current pointer/manifest header plus Base+Blob generations is
/// sufficient for a warm consumer of an already cold-verified fleet cell.
fn verify_generation_source_headers_once(
    catalog: &FleetCatalog,
    store_root: &Path,
    expected: &FleetKernelSourceRoster,
) -> Result<FleetKernelSourceVerificationPass, CalyxError> {
    let catalog_inventory = catalog_store_identities(
        catalog,
        expected
            .repositories
            .iter()
            .map(|binding| binding.catalog_project.as_str()),
    )?;
    let catalog_rows_scanned = catalog_inventory.catalog_rows_scanned;
    let catalog_identities = catalog_inventory.identities;
    let mut repository_bindings_checked = 0usize;
    for binding in &expected.repositories {
        let catalog_identity = catalog_identities
            .get(&binding.catalog_project)
            .ok_or_else(|| missing_catalog_inventory_identity(&binding.catalog_project))?;
        if catalog_identity.store_key != binding.store_key
            || catalog_identity.index_project != binding.index_project
            || catalog_identity.kernel_scope != binding.kernel_scope
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "fleet catalog identity drifted during narrow warm verification for {:?}: persisted=({:?},{:?},{:?}) observed=({:?},{:?},{:?})",
                    binding.catalog_project,
                    binding.store_key,
                    binding.index_project,
                    binding.kernel_scope,
                    catalog_identity.store_key,
                    catalog_identity.index_project,
                    catalog_identity.kernel_scope,
                ),
                remediation: "discard the cached fleet generation and explicitly recompose from the new complete repository roster",
            });
        }
        let vault = open_shadow_vault(
            store_root,
            &binding.store_key,
            &binding.index_project,
            vec![
                ColumnFamily::Base,
                ColumnFamily::Blob,
                ColumnFamily::Kernel,
                ColumnFamily::Ledger,
            ],
        )
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "open repository {:?} for narrow warm source verification: underlying_code={} message={:?}",
                binding.store_key, error.code, error.message,
            ),
            remediation: "restore the exact repository vault or explicitly recompose; no cached fleet fallback is served",
        })?;
        let lease = vault.retain_latest_snapshot();
        let snapshot = lease.seq();
        let base_content_generation = vault
            .cf_content_generation(ColumnFamily::Base)
            .map_err(|error| inner_err("read warm Base content generation", error))?;
        let blob_content_generation = vault
            .cf_content_generation(ColumnFamily::Blob)
            .map_err(|error| inner_err("read warm Blob content generation", error))?;
        let header = read_current_kernel_generation_header(
            &vault,
            &binding.index_project,
            &binding.kernel_scope,
        )
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "repository {:?} current kernel header failed narrow verification: underlying_code={} message={:?}",
                binding.store_key,
                error.code(),
                error.message(),
            ),
            remediation: "preserve the divergent repository generation and explicitly recompose before serving the fleet cache",
        })?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "repository {:?} no longer has a current atomic kernel header",
                binding.store_key,
            ),
            remediation: "rebuild the repository generation and explicitly recompose; no stale fleet cache is served",
        })?;
        lease.record_progress();
        let final_base_content_generation = vault
            .cf_content_generation(ColumnFamily::Base)
            .map_err(|error| inner_err("re-read warm Base content generation", error))?;
        let final_blob_content_generation = vault
            .cf_content_generation(ColumnFamily::Blob)
            .map_err(|error| inner_err("re-read warm Blob content generation", error))?;
        let header_blake3 = repo_kernel_header_blake3(&header.manifest, &header.pointer)?;
        if vault.latest_seq() != snapshot
            || final_base_content_generation != base_content_generation
            || final_blob_content_generation != blob_content_generation
            || header.manifest.generation_id != binding.generation_id
            || header.manifest.source_generation_identity != binding.source_generation_identity
            || header.manifest.artifact_source_identity.combined_hash
                != binding.artifact_source_identity_hash
            || header.manifest.members_hash != binding.members_hash
            || header.manifest.member_count != binding.member_count
            || header.manifest.panel_version != binding.panel_version
            || header.manifest.semantic_dim != binding.semantic_dim
            || header.manifest.source_binding != binding.s20_source_binding
            || header_blake3 != binding.kernel_header_blake3
            || base_content_generation != binding.base_content_generation
            || blob_content_generation != binding.blob_content_generation
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "repository {:?} narrow source binding drifted: retained_seq={snapshot} observed_seq={} expected_generation={} observed_generation={} expected_header={} observed_header={} expected_base_generation={} observed_base_generation={} expected_blob_generation={} observed_blob_generation={}",
                    binding.store_key,
                    vault.latest_seq(),
                    binding.generation_id,
                    header.manifest.generation_id,
                    binding.kernel_header_blake3,
                    header_blake3,
                    binding.base_content_generation,
                    base_content_generation,
                    binding.blob_content_generation,
                    blob_content_generation,
                ),
                remediation: "discard the cached fleet generation and explicitly recompose from the exact new repository sources",
            });
        }
        repository_bindings_checked = repository_bindings_checked.checked_add(1).ok_or_else(|| {
            CalyxError {
                code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
                message: "fleet warm source-verification binding count overflowed usize"
                    .to_string(),
                remediation: "reduce the explicit fleet roster; no uncounted source binding is admitted",
            }
        })?;
    }
    Ok(FleetKernelSourceVerificationPass {
        catalog_scans: 1,
        catalog_rows_scanned,
        repository_bindings_checked,
        repository_vault_opens: repository_bindings_checked,
        selected_column_families: vec![
            ColumnFamily::Base.name(),
            ColumnFamily::Blob.name(),
            ColumnFamily::Kernel.name(),
            ColumnFamily::Ledger.name(),
        ],
    })
}

fn verify_generation_projection_exact(
    current: &CurrentFleetKernelGeneration,
    loads: &[RepoKernelLoad],
) -> Result<(), CalyxError> {
    if current.source_roster.candidacy_policy_version != FLEET_CANDIDACY_POLICY_VERSION {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet generation candidacy policy {:?} is not the sole supported policy {:?}",
                current.source_roster.candidacy_policy_version, FLEET_CANDIDACY_POLICY_VERSION,
            ),
            remediation: "recompose the complete fleet generation with the current declared candidacy policy",
        });
    }
    let all_nodes = build_fleet_nodes(
        &current.source_roster.scope_id,
        loads,
        current.source_roster.panel_version,
    )?;
    let (nodes, _) = apply_candidacy_policy(all_nodes);
    if nodes.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_NO_CANDIDATES,
            message: "the independently rebuilt fleet projection has no eligible nodes".to_string(),
            remediation: "do not serve the stale generation; repair repository inputs and explicitly recompose",
        });
    }
    enforce_similarity_pair_ceiling(
        nodes.len(),
        current.admission.max_fleet_similarity_pair_evaluations,
    )?;
    let (edges, _) = build_similarity_edges(&nodes, &current.source_roster.compose_config);
    let graph_nodes = nodes
        .iter()
        .map(|node| {
            Ok(KernelGraphNode::new(
                node.fleet_cx,
                node.weighted_frequency(
                    current
                        .source_roster
                        .compose_config
                        .cross_repo_support_weight_permille,
                )?,
                node.grounded_any.then_some(TrustTag::Trusted),
            ))
        })
        .collect::<Result<Vec<_>, CalyxError>>()?;
    let graph = KernelGraph::new(graph_nodes, edges)
        .map_err(|error| inner_err("rebuild fleet graph during cold read", error))?;
    let graph_record = FleetKernelGraphRecord::from_graph(&graph)?;
    let artifact = build_kernel(
        &graph,
        &current.source_roster.scope_id,
        &current.source_roster.kernel_config,
    )
    .map_err(|error| inner_err("rebuild fleet kernel during cold read", error))?;
    let vectors = nodes
        .iter()
        .map(|node| (node.fleet_cx, node.centroid.clone()))
        .collect::<BTreeMap<_, _>>();
    let vector_roster = FleetVectorRoster::from_vectors(
        current.source_roster.panel_version,
        current.source_roster.semantic_dim,
        &vectors,
    )?;
    let provenance = member_provenance_from_nodes(&artifact, &nodes)?;
    if graph_record != current.graph_record
        || artifact != current.artifact
        || vector_roster.vector_roster_hash != current.manifest.vector_roster_hash
        || provenance != current.provenance
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "independent fleet projection differs from atomic generation {}: graph_match={} artifact_match={} vectors_match={} provenance_match={}",
                current.manifest.generation_id,
                graph_record == current.graph_record,
                artifact == current.artifact,
                vector_roster.vector_roster_hash == current.manifest.vector_roster_hash,
                provenance == current.provenance,
            ),
            remediation: "preserve the divergent fleet and repository generations; explicitly recompose from the exact current source roster before serving",
        });
    }
    Ok(())
}

/// Classifies exact pre-#1151 fixed-row names without decoding or returning a
/// legacy artifact. Production uses this only to distinguish absence from
/// retained historical bytes; malformed or partial history is still reported
/// as non-serving state and can never enter a fleet response.
fn classify_historical_fleet_kernel_presence(
    catalog: &FleetCatalog,
    scope: &str,
) -> Result<Option<Value>, CalyxError> {
    let snapshot = catalog.vault().latest_seq();
    let keys = [
        fixed_kernel_artifact_key(scope, b"kernel.json"),
        fixed_kernel_artifact_key(scope, b"index.json"),
        fixed_kernel_artifact_key(scope, b"members-hash"),
    ];
    let rows = catalog.vault().read_cf_batch_at(
        snapshot,
        keys.iter().cloned().map(|key| (ColumnFamily::Kernel, key)),
    )?;
    let sidecar = catalog.read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?;
    if catalog.vault().latest_seq() != snapshot {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "fleet catalog moved while classifying historical fixed-row presence: retained_seq={snapshot} observed_seq={}",
                catalog.vault().latest_seq(),
            ),
            remediation: "discard the mixed historical-presence classification and retry against one stable catalog snapshot",
        });
    }
    if rows.iter().all(Option::is_none) && sidecar.is_none() {
        return Ok(None);
    }
    let leaves = ["kernel.json", "index.json", "members-hash"];
    let row_evidence = leaves
        .into_iter()
        .zip(keys)
        .zip(rows)
        .map(|((leaf, key), bytes)| {
            json!({
                "leaf": leaf,
                "key_hex": key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "present": bytes.is_some(),
                "bytes": bytes.as_ref().map_or(0, Vec::len),
                "blake3": bytes.as_ref().map(|value| blake3::hash(value).to_hex().to_string()),
            })
        })
        .collect::<Vec<_>>();
    Ok(Some(json!({
        "schema": "astrolabe.fleet_kernel_history_presence.v1",
        "scope": scope,
        "snapshot": snapshot,
        "fixed_rows": row_evidence,
        "sidecar": {
            "kind": FLEET_KERNEL_REPORT_KIND,
            "present": sidecar.is_some(),
            "bytes": sidecar.as_ref().map_or(0, Vec::len),
            "blake3": sidecar.as_ref().map(|value| blake3::hash(value).to_hex().to_string()),
        },
        "decoded": false,
        "serving_eligible": false,
    })))
}

/// Loads the atomic fleet generation and independently rebuilds its exact
/// repository roster, graph projection, vector roster, kernel source identity,
/// artifact, and member provenance before returning any serving state.
///
/// The measured production repository is `N=192,873/E=328,899` (2026-08-20).
/// Fleet totals `V_f/E_f/M_f/D/Q` remain unknown until a real generation is
/// published. A cold read brackets projection with two complete passes over
/// the exact repository-generation roster, then pays `O(V_f^2*D + E_f)` for
/// projection reconstruction and `O(Q*V_f*D)` exact recall readback plus its
/// persisted route-work ceilings. Pair/query work is explicitly bounded by the
/// immutable admission; warm serving must cache only by immutable
/// generation id and recheck the current pointer (PC-02/03/04/07/14/16/24/28/
/// 35/37/38/41/43; #1064).
pub fn read_verified_fleet_kernel_generation(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
) -> Result<CurrentFleetKernelGeneration, CalyxError> {
    let current = read_current_fleet_kernel_generation(catalog.vault(), scope)?;
    let Some(current) = current else {
        return match classify_historical_fleet_kernel_presence(catalog, scope)? {
            Some(presence) => Err(CalyxError {
                code: ASTRO_FLEET_KERNEL_ATOMIC_GENERATION_REQUIRED,
                message: format!(
                    "fleet scope {scope:?} has exact pre-#1151 fixed-row names but no atomic generation; presence={presence}"
                ),
                remediation: "retain those bytes as history and publish one independently verified complete #1151 fleet generation; production never decodes or serves the fixed-row state",
            }),
            None => Err(CalyxError {
                code: ASTRO_FLEET_KERNEL_MISSING,
                message: format!("no atomic fleet kernel generation exists at scope {scope:?}"),
                remediation: "compose the exact complete repository roster with an explicit genuine external-query admission capture",
            }),
        };
    };
    let catalog_seq = catalog.vault().latest_seq();
    let loads = load_generation_source_roster(catalog, store_root, &current.source_roster)?;
    verify_generation_projection_exact(&current, &loads)?;
    // The fleet V_f^2 projection can be long. Re-read the complete external
    // source roster after it finishes so a repository transition during that
    // work cannot be labeled fresh by the cold reader (PC-03/35; #1064).
    drop(load_generation_source_roster(
        catalog,
        store_root,
        &current.source_roster,
    )?);
    if catalog.vault().latest_seq() != catalog_seq {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet catalog moved during independent projection rebuild: retained_seq={catalog_seq} observed_seq={}",
                catalog.vault().latest_seq(),
            ),
            remediation: "discard the mixed read and retry against one stable atomic fleet generation",
        });
    }
    let selected = read_current_fleet_kernel_generation_header(catalog.vault(), scope)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("fleet current pointer disappeared after verification for {scope:?}"),
            remediation: "retry only after one complete atomic fleet generation is current",
        })?;
    if selected.manifest != current.manifest || selected.pointer != current.pointer {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet current pointer moved during independent readback: selected={} observed={}",
                current.manifest.generation_id, selected.manifest.generation_id,
            ),
            remediation: "discard the mixed read and retry against one stable atomic fleet generation",
        });
    }
    Ok(current)
}

/// Revalidates every external repository-generation binding for an already
/// cold-verified fleet generation using only current pointer/manifest/Ledger
/// point reads and durable Base+Blob content generations. It deliberately
/// performs two exact `O(C log C + sum(open_i) + R)` metadata passes — one
/// canonical latest-row merge over the `C` catalog rows, then one latest-state
/// vault open plus point-bound header/generation read for each of the `R`
/// selected repositories — so a repository cannot move behind an earlier
/// member of the multi-vault read. No repository `N/E/K*D` source
/// reconstruction and no fleet `V_f²*D` projection occurs on this warm path
/// (PC-02/03/35; #1064).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FleetKernelSourceVerificationPass {
    /// Exact number of catalog Base-CF scans performed by this pass.
    pub catalog_scans: u64,
    /// Catalog rows decoded by the ordered scan.
    pub catalog_rows_scanned: usize,
    /// Selected repository bindings checked byte-for-byte.
    pub repository_bindings_checked: usize,
    /// Selected repository vaults opened for latest-state header checks.
    pub repository_vault_opens: usize,
    /// Exact per-repository CF selection used by every open.
    pub selected_column_families: Vec<String>,
}

/// Measured two-pass warm source verification receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FleetKernelSourceVerificationReport {
    /// The two complete pass receipts, in execution order.
    pub passes: Vec<FleetKernelSourceVerificationPass>,
}

pub fn verify_fleet_kernel_generation_sources(
    catalog: &FleetCatalog,
    store_root: &Path,
    generation: &CurrentFleetKernelGeneration,
) -> Result<FleetKernelSourceVerificationReport, CalyxError> {
    generation.source_roster.canonical_json_bytes()?;
    let catalog_seq = catalog.vault().latest_seq();
    let first =
        verify_generation_source_headers_once(catalog, store_root, &generation.source_roster)?;
    let second =
        verify_generation_source_headers_once(catalog, store_root, &generation.source_roster)?;
    if catalog.vault().latest_seq() != catalog_seq {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet catalog moved during narrow warm source verification: retained_seq={catalog_seq} observed_seq={}",
                catalog.vault().latest_seq(),
            ),
            remediation: "discard the mixed warm read and retry against one stable catalog/repository roster",
        });
    }
    Ok(FleetKernelSourceVerificationReport {
        passes: vec![first, second],
    })
}

/// Composes the fleet kernel over `projects` and atomically publishes the
/// complete content-addressed generation at `scope` in the fleet catalog.
/// Returns the strict decoded/readback summary the CLI prints.
///
/// At measured per-repository production `N=192,873/E=328,899` (2026-08-20),
/// composition brackets `O(sum(N_i+E_i+A_i+B_i+K_i*D_i))` source loading with
/// two exact passes, performs the explicitly admitted `V_f*(V_f-1)/2`
/// similarity evaluations at `O(D)` each, and evaluates `Q` external queries
/// under their persisted exact/route ceilings. Global fleet production totals
/// remain unknown; this function reports only the exact selected generation.
/// Source roster/config/admission/panel/dimension stay invariant until the
/// conditional pointer commit (PC-03/04/07/14/15/16/24/28/35/37/38/41/43;
/// #1064).
#[allow(clippy::too_many_lines)]
pub fn compose_fleet_kernel(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    projects: &[String],
    compose_config: &ComposeConfig,
    admission: &FleetKernelAdmissionInput,
) -> Result<Value, CalyxError> {
    compose_config.validate()?;
    admission.validate()?;
    let kernel_config = KernelBuildConfig::with_registry_defaults();
    kernel_config
        .validate()
        .map_err(|error| inner_err("kernel build config", error))?;

    // Load every explicitly requested repo. A missing current kernel invalidates
    // the fleet input roster; partial composition is not a substitute.
    let catalog_inventory = catalog_store_identities(catalog, projects.iter().map(String::as_str))?;
    let catalog_identities = catalog_inventory.identities;
    let mut loads: Vec<RepoKernelLoad> = Vec::new();
    let mut missing: Vec<(String, String, String)> = Vec::new();
    for project in projects {
        let identity = catalog_identities
            .get(project)
            .ok_or_else(|| missing_catalog_inventory_identity(project))?;
        match load_repo_kernel(store_root, &identity.store_key, &identity.index_project)? {
            Some(load) => loads.push(load),
            None => missing.push((
                project.clone(),
                identity.index_project.clone(),
                identity.kernel_scope.clone(),
            )),
        }
    }
    if !missing.is_empty() {
        missing.sort();
        let missing_json = serde_json::to_string(&missing).map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("encode missing fleet-kernel roster: {error}"),
            remediation: "repair the fleet identity serializer before retrying composition",
        })?;
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!(
                "fleet scope {scope:?} requested {} repositories, but {} have no complete current kernel generation: {missing_json}",
                projects.len(),
                missing.len(),
            ),
            remediation: "build and independently verify one complete current kernel generation for every named repository, then retry the unchanged complete roster",
        });
    }
    if loads.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_NO_KERNELS,
            message: format!(
                "none of the {} named repos carries a persisted kernel artifact",
                projects.len()
            ),
            remediation: "kernel at least one repo through the fleet pipeline before composing",
        });
    }
    loads.sort_by(|left, right| left.project.cmp(&right.project));
    let panel_version = loads[0].panel_version;
    let semantic_dim = loads[0].semantic_dim;
    if let Some(divergent) = loads
        .iter()
        .find(|load| load.panel_version != panel_version || load.semantic_dim != semantic_dim)
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SEMANTIC_MISMATCH,
            message: format!(
                "repository S20 contracts are not comparable: baseline_project={:?} baseline_panel={panel_version} baseline_dim={semantic_dim}; divergent_project={:?} divergent_panel={} divergent_dim={}",
                loads[0].project,
                divergent.project,
                divergent.panel_version,
                divergent.semantic_dim
            ),
            remediation: "re-index every repository with one identical frozen semantic panel and rebuild each complete kernel generation before fleet composition",
        });
    }

    let source_roster = source_roster_from_loads(
        scope,
        *compose_config,
        kernel_config,
        panel_version,
        semantic_dim,
        &loads,
    )?;
    let input_hash = source_roster.compose_input_hash.clone();
    let admission_input_blake3 = admission.identity_blake3()?;

    // Growth semantics: unchanged input is a topology-preserving no-op; any
    // change is structural and escalates to an explicit full rebuild (the
    // GraphDelta doctrine of astrolabe-kernel::incremental).
    // Retain the catalog sequence before selecting the current predecessor.
    // The eventual conditional commit uses this same value so an intervening
    // fleet/catalog write cannot be silently overwritten by long projection
    // work (PC-03/35; #1064).
    let base_seq = catalog.vault().latest_seq();
    let previous = read_current_fleet_kernel_generation(catalog.vault(), scope)?;
    if catalog.vault().latest_seq() != base_seq {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
            message: format!(
                "fleet catalog moved while selecting the compose predecessor: retained_seq={base_seq} observed_seq={}",
                catalog.vault().latest_seq(),
            ),
            remediation: "discard the mixed predecessor selection and retry the unchanged composition request",
        });
    }
    let previous_input_hash = previous
        .as_ref()
        .map(|generation| generation.manifest.compose_input_hash.clone());
    let delta = GraphDelta {
        structural: previous_input_hash.as_deref() != Some(input_hash.as_str()),
        ..GraphDelta::default()
    };
    if let Some(existing) = previous.as_ref()
        && delta.is_topology_preserving()
        && existing.manifest.admission_input_blake3 == admission_input_blake3
        && existing.admission == *admission
    {
        verify_fleet_source_roster_exact(&existing.source_roster, &source_roster)?;
        verify_generation_projection_exact(existing, &loads)?;
        drop(load_generation_source_roster(
            catalog,
            store_root,
            &existing.source_roster,
        )?);
        let selected = read_current_fleet_kernel_generation_header(catalog.vault(), scope)?
            .ok_or_else(|| CalyxError {
                code: ASTRO_FLEET_KERNEL_MISSING,
                message: format!(
                    "fleet current pointer disappeared during no-op verification for {scope:?}"
                ),
                remediation: "retry only after one complete atomic fleet generation is current",
            })?;
        if selected.manifest != existing.manifest || selected.pointer != existing.pointer {
            return Err(CalyxError {
                code: ASTRO_FLEET_COMPOSE_SOURCE_MISMATCH,
                message: format!(
                    "fleet current pointer moved during no-op verification: expected={} observed={}",
                    existing.manifest.generation_id, selected.manifest.generation_id,
                ),
                remediation: "discard the stale no-op result and retry against one stable atomic fleet generation",
            });
        }
        let similarity_pairs = similarity_pair_count(existing.graph_record.nodes.len())?;
        return Ok(json!({
            "verb": "compose",
            "scope": scope,
            "verdict": "unchanged",
            "reason": "repository source roster and explicit genuine-query admission identity match the independently decoded atomic current generation; no rows or Ledger entry were written",
            "compose_input_hash": input_hash,
            "admission_input_blake3": admission_input_blake3,
            "generation_id": existing.manifest.generation_id,
            "source_generation_identity": existing.manifest.source_generation_identity,
            "generation_base_seq": existing.manifest.base_seq,
            "members_hash": existing.artifact.members_hash,
            "member_count": existing.artifact.member_count,
            "repos": loads.len(),
            "ledger_ref": existing.manifest.ledger_ref,
            "rows_readback_verified": existing.rows_verified,
            "production_cost_contract": {
                "measurement_date": "2026-08-20",
                "measured_repository_n": 192_873,
                "measured_repository_e": 328_899,
                "global_fleet_production_totals": "unknown; selected-generation values are persisted observations, not an extrapolation",
                "selected_generation": {
                    "repositories": existing.source_roster.repositories.len(),
                    "fleet_nodes": existing.manifest.graph_node_count,
                    "fleet_edges": existing.manifest.graph_edge_count,
                    "kernel_members": existing.manifest.member_count,
                    "semantic_dimension": existing.manifest.semantic_dim,
                    "external_queries": existing.query_corpus.queries.len(),
                    "similarity_pair_evaluations": similarity_pairs.to_string(),
                },
                "pc_classes": ["PC-03", "PC-04", "PC-07", "PC-14", "PC-15", "PC-28", "PC-35", "PC-37", "PC-38", "PC-41", "PC-43"],
            },
        }));
    }

    // Fleet graph. The declared candidacy policy (#477) filters content-free
    // structural atoms out of the graph before the kernel is built, so they can
    // be neither members nor coverage targets; every exclusion is counted per
    // rule in `candidacy` and the surviving graph is code-bearing only.
    let all_nodes = build_fleet_nodes(scope, &loads, panel_version)?;
    let (nodes, candidacy) = apply_candidacy_policy(all_nodes);
    if nodes.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_COMPOSE_NO_CANDIDATES,
            message: format!(
                "the {} candidacy policy excluded all {} fleet nodes ({} content-free structural): \
                 no code-bearing candidate remains to compose a kernel",
                FLEET_CANDIDACY_POLICY_VERSION, candidacy.total_nodes, candidacy.excluded_total
            ),
            remediation: "index at least one repo carrying content-bearing symbols \
                          (functions/structs/methods), then re-run compose",
        });
    }
    let similarity_pairs = enforce_similarity_pair_ceiling(
        nodes.len(),
        admission.max_fleet_similarity_pair_evaluations,
    )?;
    let (edges, sim_histogram) = build_similarity_edges(&nodes, compose_config);
    let graph_nodes: Vec<KernelGraphNode> = nodes
        .iter()
        .map(|node| {
            Ok(KernelGraphNode::new(
                node.fleet_cx,
                node.weighted_frequency(compose_config.cross_repo_support_weight_permille)?,
                if node.grounded_any {
                    Some(TrustTag::Trusted)
                } else {
                    None
                },
            ))
        })
        .collect::<Result<Vec<_>, CalyxError>>()?;
    let edge_count = edges.len();
    let graph = KernelGraph::new(graph_nodes, edges)
        .map_err(|error| inner_err("assemble fleet kernel graph", error))?;

    let single_repo = loads.len() == 1;
    let artifact = build_kernel(&graph, scope, &kernel_config)
        .map_err(|error| inner_err("build fleet kernel", error))?;
    let verdict_kind = if single_repo {
        "single_repo_full_rebuild"
    } else {
        "composed_full_rebuild"
    };

    // Per-repo undirected radius coverage over the composed graph. This is an
    // explicit topology diagnostic, never held-out query recall or admission.
    let indexed = graph
        .compile()
        .map_err(|error| inner_err("compile fleet graph", error))?;
    let member_indices: BTreeSet<usize> = artifact
        .members
        .iter()
        .filter_map(|member| indexed.ids().binary_search(&member.id).ok())
        .collect();
    let covered = coverage_from(
        &indexed,
        &member_indices,
        kernel_config.graph_coverage_radius_hops,
    );
    let node_by_cx: BTreeMap<CxId, &FleetNode> =
        nodes.iter().map(|node| (node.fleet_cx, node)).collect();
    let mut per_repo_total: BTreeMap<&str, u64> = BTreeMap::new();
    let mut per_repo_covered: BTreeMap<&str, u64> = BTreeMap::new();
    for (index, id) in indexed.ids().iter().enumerate() {
        let node = node_by_cx[id];
        let mut projects_here: BTreeSet<&str> = BTreeSet::new();
        for occurrence in &node.occurrences {
            projects_here.insert(occurrence.project.as_str());
        }
        for project in projects_here {
            let total = per_repo_total.entry(project).or_default();
            *total = total.checked_add(1).ok_or_else(|| CalyxError {
                code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
                message: format!(
                    "fleet graph coverage node census overflowed u64 for repository {project:?}"
                ),
                remediation: "widen the per-repository coverage census before composing; no saturated diagnostic is published",
            })?;
            if covered[index] {
                let covered_count = per_repo_covered.entry(project).or_default();
                *covered_count = covered_count.checked_add(1).ok_or_else(|| CalyxError {
                    code: ASTRO_FLEET_COMPOSE_ARITHMETIC_OVERFLOW,
                    message: format!(
                        "fleet graph covered-node census overflowed u64 for repository {project:?}"
                    ),
                    remediation: "widen the per-repository coverage census before composing; no saturated diagnostic is published",
                })?;
            }
        }
    }
    let mut per_repo_graph_coverage: BTreeMap<String, u64> = BTreeMap::new();
    let mut min_graph_coverage = 1000_u64;
    for (project, total) in &per_repo_total {
        let covered = per_repo_covered.get(project).copied().unwrap_or(0);
        let permille =
            checked_fleet_coverage_permille(covered, *total).map_err(|error| CalyxError {
                code: error.code,
                message: format!("repository {project:?}: {}", error.message),
                remediation: error.remediation,
            })?;
        min_graph_coverage = min_graph_coverage.min(permille);
        per_repo_graph_coverage.insert((*project).to_string(), permille);
    }
    let meets_diagnostic_floor =
        min_graph_coverage >= compose_config.per_repo_graph_coverage_min_permille;
    let fleet_label = if artifact.anchor_grounded {
        "verified"
    } else {
        "provisional"
    };
    let mut trust_reasons = vec![
        "exact brute-force full-corpus retrieval and bounded graph-routed retrieval are admission inputs of the atomic generation"
            .to_string(),
    ];
    if !artifact.anchor_grounded {
        trust_reasons.push(
            "no Trusted anchor rollup among any constituent member (external repos are \
             provisional until anchors upgrade)"
                .to_string(),
        );
    }

    let provenance = member_provenance_from_nodes(&artifact, &nodes)?;
    let complete_vectors = nodes
        .iter()
        .map(|node| (node.fleet_cx, node.centroid.clone()))
        .collect::<BTreeMap<_, _>>();
    let cross_repo_nodes = nodes
        .iter()
        .filter(|node| {
            node.occurrences
                .iter()
                .map(|occurrence| occurrence.project.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        })
        .count();
    // Bracket the expensive fleet projection with a second exact repository
    // generation read. Equality of the content-complete roster proves no
    // graph/Base/S20/kernel source moved between initial materialization and
    // publication; a changed source refuses before the catalog transaction.
    drop(load_generation_source_roster(
        catalog,
        store_root,
        &source_roster,
    )?);
    let persist = persist_fleet_kernel_generation(
        catalog.vault(),
        FleetKernelGenerationPublishRequest {
            scope_id: scope,
            source_roster: &source_roster,
            graph: &graph,
            complete_vectors: &complete_vectors,
            artifact: &artifact,
            provenance: &provenance,
            admission,
            base_seq,
        },
    )?;

    Ok(json!({
        "verb": "compose",
        "scope": scope,
        "verdict": verdict_kind,
        "compose_input_hash": input_hash,
        "admission_input_blake3": admission_input_blake3,
        "generation_id": persist.generation_id,
        "source_generation_identity": persist.source_generation_identity,
        "generation_base_seq": persist.manifest.base_seq,
        "repos": loads.len(),
        "nodes_total": nodes.len(),
        "nodes_before_candidacy": candidacy.total_nodes,
        "excluded_by_candidacy": candidacy.excluded_total,
        "candidacy_policy_version": FLEET_CANDIDACY_POLICY_VERSION,
        "cross_repo_nodes": cross_repo_nodes,
        "similarity_edges_directed": edge_count,
        "similarity_pair_evaluations": similarity_pairs.to_string(),
        "max_similarity_pair_evaluations": admission.max_fleet_similarity_pair_evaluations,
        "similarity_permille_histogram_by_100": sim_histogram,
        "member_count": artifact.member_count,
        "members_hash": artifact.members_hash,
        "graph_coverage_permille": artifact.graph_coverage.permille,
        "per_repo_graph_coverage_min_permille": min_graph_coverage,
        "per_repo_graph_coverage": per_repo_graph_coverage,
        "graph_coverage_meets_diagnostic_floor": meets_diagnostic_floor,
        "query_count": persist.query_count,
        "graph_routed_recall_permille": persist.recall_permille,
        "graph_routed_report_hash": persist.graph_routed_report_hash,
        "vector_roster_hash": persist.vector_roster_hash,
        "trust_evaluation": { "label": fleet_label, "reasons": trust_reasons },
        "generation_commit_seq": persist.commit_seq,
        "ledger_ref": persist.ledger_ref,
        "rows_readback_verified": persist.rows_readback_verified,
        "source_roster_final_readback": "exact_match_before_publication",
        "retired_generation_id": persist.retired_generation_id,
        "retention": persist.manifest.retention,
        "production_cost_contract": {
            "measurement_date": "2026-08-20",
            "measured_repository_n": 192_873,
            "measured_repository_e": 328_899,
            "global_fleet_production_totals": "unknown; selected-generation values are persisted observations, not an extrapolation",
            "selected_generation": {
                "repositories": loads.len(),
                "fleet_nodes": nodes.len(),
                "fleet_edges": edge_count,
                "kernel_members": artifact.member_count,
                "semantic_dimension": semantic_dim,
                "external_queries": persist.query_count,
                "similarity_pair_evaluations": similarity_pairs.to_string(),
            },
            "pc_classes": ["PC-03", "PC-04", "PC-07", "PC-14", "PC-15", "PC-28", "PC-35", "PC-37", "PC-38", "PC-41", "PC-43"],
        },
    }))
}

/// Internal historical fleet-kernel readback: re-reads the
/// persisted kernel.json row, re-derives the members-hash from the persisted
/// member set, verifies the paired members-hash ledger discipline via the
/// sidecar, and returns the summary plus exact historical kernel.json bytes.
/// The result is available only to in-crate history/retirement logic and is
/// never a serving generation.
#[allow(dead_code)]
fn read_historical_fleet_kernel(
    catalog: &FleetCatalog,
    scope: &str,
) -> Result<(Value, Vec<u8>), CalyxError> {
    let vault = catalog.vault();
    let snapshot = vault.latest_seq();
    let artifact = read_persisted_kernel_artifact_at(vault, scope, snapshot)
        .map_err(|error| inner_err("validate fleet kernel artifact rows", error))?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("no fleet kernel artifact persisted at scope {scope:?}"),
            remediation: "run compose for the scope before reading it back",
        })?;
    // Mirror of astrolabe-ingest::kernel_artifact::artifact_key (the prefix is
    // its exported contract) — read the raw row independently of the parser.
    let mut key = Vec::new();
    key.extend_from_slice(astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX);
    key.extend_from_slice(scope.as_bytes());
    key.push(b':');
    key.extend_from_slice(b"kernel.json");
    let raw = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("no fleet kernel artifact persisted at scope {scope:?}"),
            remediation: "run compose for the scope before reading it back",
        })?;
    if artifact.kernel_json_bytes() != raw {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "validated fleet kernel artifact differs from the raw kernel.json row at the retained snapshot".to_string(),
            remediation: "preserve the catalog vault and inspect the exact Kernel CF generation before recomposing",
        });
    }
    let member_ids: Vec<CxId> = artifact.members.iter().map(|member| member.id).collect();
    let rederived = members_hash(&member_ids);
    if rederived != artifact.members_hash {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "re-derived members-hash {rederived} differs from persisted {}",
                artifact.members_hash
            ),
            remediation: "the persisted member set was tampered or torn; recompose",
        });
    }
    // One-serializer check: the parsed artifact must re-serialize to the exact
    // persisted bytes.
    let reserialized = artifact.kernel_json_bytes();
    let serializer_stable = reserialized == raw;
    if !serializer_stable {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message:
                "persisted fleet kernel.json is not byte-stable under its canonical serializer"
                    .to_string(),
            remediation: "preserve the catalog vault and repair canonical kernel serialization before serving",
        });
    }

    let sidecar = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?
        .map(|bytes| {
            serde_json::from_slice::<Value>(&bytes).map_err(|error| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: format!("fleet-kernel sidecar did not parse: {error}"),
                remediation: "recompose the fleet kernel to rewrite the sidecar",
            })
        })
        .transpose()?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("fleet kernel scope {scope:?} has no fleet-kernel sidecar"),
            remediation: "recompose the fleet kernel so its provenance and diagnostic sidecar is paired with the artifact",
        })?;
    let ledger_ref: LedgerRef = serde_json::from_value(
        sidecar
            .get("kernel")
            .and_then(|value| value.get("ledger_ref"))
            .cloned()
            .ok_or_else(|| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: "fleet-kernel sidecar does not bind the exact Kernel ledger_ref"
                    .to_string(),
                remediation: "recompose the fleet kernel; a ledger scan is never substituted for a missing exact reference",
            })?,
    )
    .map_err(|error| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!("fleet-kernel sidecar ledger_ref did not parse: {error}"),
        remediation: "recompose the fleet kernel from its exact Kernel ledger transaction",
    })?;

    // Independent members-hash ledger pairing (invariant 5): the Kernel CF
    // members-hash row and the sidecar-bound physical Kernel ledger entry must
    // carry the same bytes, and that entry's identity must match the artifact.
    // The exact point read is O(1) in ledger length; no Ledger scan is allowed.
    let mut members_key = Vec::new();
    members_key.extend_from_slice(astrolabe_ingest::KERNEL_ARTIFACT_CF_PREFIX);
    members_key.extend_from_slice(scope.as_bytes());
    members_key.push(b':');
    members_key.extend_from_slice(b"members-hash");
    let members_row = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &members_key)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("no members-hash row persisted at scope {scope:?}"),
            remediation: "recompose the fleet kernel; the artifact row set is torn",
        })?;
    let subject = format!("astrolabe-kernel:{scope}").into_bytes();
    let wanted = BTreeSet::from([ledger_ref.seq]);
    let (physical_rows, ledger_trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let physical_row = physical_rows.get(&ledger_ref.seq).ok_or_else(|| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!(
            "sidecar-bound physical Kernel ledger sequence {} is absent",
            ledger_ref.seq
        ),
        remediation: "preserve the catalog vault and repair the exact ledger generation before recomposing",
    })?;
    let entry = calyx_ledger::decode(&physical_row.bytes)?;
    if physical_row.seq != ledger_ref.seq
        || entry.seq != ledger_ref.seq
        || entry.entry_hash != ledger_ref.hash
        || !entry.verify()
        || entry.kind != calyx_ledger::EntryKind::Kernel
        || entry.actor
            != calyx_ledger::ActorId::Service(astrolabe_ingest::KERNEL_ARTIFACT_ACTOR.to_string())
        || !matches!(&entry.subject, calyx_ledger::SubjectId::Query(value) if value.as_slice() == subject.as_slice())
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "physical Kernel ledger identity differs from sidecar: expected_seq={}, expected_hash={}, observed_seq={}, observed_hash={}",
                ledger_ref.seq,
                hex32(&ledger_ref.hash),
                entry.seq,
                hex32(&entry.entry_hash)
            ),
            remediation: "preserve the catalog vault and repair the exact fleet Kernel ledger pairing",
        });
    }
    if entry.payload != members_row {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "Kernel ledger payload ({} bytes) differs from the members-hash row ({} bytes) for scope {scope:?}",
                entry.payload.len(),
                members_row.len()
            ),
            remediation: "recompose the fleet kernel; row and ledger diverged",
        });
    }
    let ledger_entry: astrolabe_kernel::KernelLedgerEntry = serde_json::from_slice(&entry.payload)
        .map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("Kernel ledger payload did not parse: {error}"),
            remediation: "recompose the fleet kernel; the ledger payload is corrupt",
        })?;
    if ledger_entry != artifact.ledger_entry() {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "ledger kernel identity differs from persisted kernel.json: ledger_members_hash={} artifact_members_hash={} ledger_source_identity={} artifact_source_identity={} ledger_fvs_hash={} artifact_fvs_hash={}",
                ledger_entry.members_hash,
                artifact.members_hash,
                ledger_entry.source_identity.combined_hash,
                artifact.source_identity.combined_hash,
                ledger_entry.fvs_validity.residual_topological_order_hash,
                artifact.fvs_validity.residual_topological_order_hash,
            ),
            remediation: "recompose the fleet kernel; the member/source/FVS/graph-coverage/compactness row and ledger identities diverged",
        });
    }

    let expected_source_identity =
        serde_json::to_value(&artifact.source_identity).map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("serialize expected fleet source identity: {error}"),
            remediation: "repair the kernel source-identity serializer before serving the fleet artifact",
        })?;
    let expected_fvs =
        serde_json::to_value(&artifact.fvs_validity).map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("serialize expected fleet FVS validity: {error}"),
            remediation: "repair the kernel FVS-validity serializer before serving the fleet artifact",
        })?;
    let expected_compactness =
        serde_json::to_value(artifact.compactness).map_err(|error| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!("serialize expected fleet compactness: {error}"),
            remediation: "repair the kernel compactness serializer before serving the fleet artifact",
        })?;
    let sidecar_kernel = sidecar.get("kernel").and_then(Value::as_object);
    let sidecar_coverage = sidecar.get("graph_coverage").and_then(Value::as_object);
    let sidecar_trust = sidecar.get("trust_evaluation").and_then(Value::as_object);
    let sidecar_semantic = sidecar.get("semantic_contract").and_then(Value::as_object);
    if sidecar.get("artifact").and_then(Value::as_str) != Some(FLEET_KERNEL_SIDECAR_SCHEMA)
        || sidecar.get("scope").and_then(Value::as_str) != Some(scope)
        || sidecar_kernel
            .and_then(|value| value.get("members_hash"))
            .and_then(Value::as_str)
            != Some(artifact.members_hash.as_str())
        || sidecar_kernel
            .and_then(|value| value.get("member_count"))
            .and_then(Value::as_u64)
            != u64::try_from(artifact.member_count).ok()
        || sidecar_kernel
            .and_then(|value| value.get("node_count"))
            .and_then(Value::as_u64)
            != u64::try_from(artifact.node_count).ok()
        || sidecar_kernel.and_then(|value| value.get("source_identity"))
            != Some(&expected_source_identity)
        || sidecar_kernel.and_then(|value| value.get("fvs_validity")) != Some(&expected_fvs)
        || sidecar_kernel.and_then(|value| value.get("compactness")) != Some(&expected_compactness)
        || sidecar_coverage
            .and_then(|value| value.get("admission_role"))
            .and_then(Value::as_str)
            != Some("diagnostic_only_not_retrieval_recall")
        || sidecar_trust
            .and_then(|value| value.get("label"))
            .and_then(Value::as_str)
            != Some("provisional")
        || sidecar
            .get("repository_input_contract")
            .and_then(Value::as_str)
            != Some(
                "atomic_composite_current_with_physical_ledger_projection_anchor_and_complete_s20_readback",
            )
        || sidecar_semantic
            .and_then(|value| value.get("panel_version"))
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0)
        || sidecar_semantic
            .and_then(|value| value.get("slot"))
            .and_then(Value::as_u64)
            != Some(u64::from(SLOT_NAME_SEMANTIC.get()))
        || sidecar_semantic
            .and_then(|value| value.get("dimension"))
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0)
        || sidecar_semantic
            .and_then(|value| value.get("complete_member_vectors_required"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "fleet-kernel sidecar for scope {scope:?} does not bind the exact v4 member/source/FVS/compactness identity or honest diagnostic-only trust contract"
            ),
            remediation: "preserve the catalog vault and recompose from the exact current repository composite generations and S20 sources",
        });
    }
    if vault.latest_seq() != snapshot {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: format!(
                "fleet catalog moved during independent readback: retained_seq={snapshot}, observed_seq={}",
                vault.latest_seq()
            ),
            remediation: "discard the mixed readback and retry against one stable catalog generation",
        });
    }

    let summary = json!({
        "verb": "kernel-read",
        "scope": scope,
        "kernel_json_bytes": raw.len(),
        "kernel_json_blake3": blake3::hash(&raw).to_hex().as_str(),
        "members_hash_persisted": artifact.members_hash,
        "members_hash_rederived": rederived,
        "serializer_stable": serializer_stable,
        "ledger_paired": true,
        "ledger_ref": ledger_ref,
        "ledger_physical_tiers": ledger_trace.tiers,
        "ledger_members_hash": ledger_entry.members_hash,
        "ledger_member_count": ledger_entry.member_count,
        "member_count": artifact.member_count,
        "node_count": artifact.node_count,
        "graph_coverage_permille": artifact.graph_coverage.permille,
        "graph_coverage_meets_floor": artifact.graph_coverage.meets_coverage_floor,
        "source_identity_hash": artifact.source_identity.combined_hash,
        "residual_topological_order_hash": artifact.fvs_validity.residual_topological_order_hash,
        "compactness_admitted": artifact.compactness.admitted,
        "trust": artifact.trust,
        "anchor_grounded": artifact.anchor_grounded,
        "sidecar": {
            "compose_input_hash": sidecar.get("compose_input_hash"),
            "verdict": sidecar.get("verdict"),
            "graph_coverage": sidecar.get("graph_coverage"),
            "trust_evaluation": sidecar.get("trust_evaluation"),
            "semantic_contract": sidecar.get("semantic_contract"),
            "repository_input_contract": sidecar.get("repository_input_contract"),
            "candidacy": sidecar.get("candidacy"),
            "nodes": sidecar.get("nodes"),
            "edges": sidecar.get("edges"),
            "skipped_no_kernel_count": sidecar.get("skipped_no_kernel_count"),
        },
    });
    Ok((summary, raw))
}

/// Returns only a fully decoded and independently source-rebuilt atomic fleet
/// generation. Historical fixed-row artifacts are classified but never
/// returned as serving bytes.
pub fn read_fleet_kernel(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
) -> Result<(Value, Vec<u8>), CalyxError> {
    let generation = read_verified_fleet_kernel_generation(catalog, store_root, scope)?;
    fleet_kernel_read_output(&generation)
}

fn fleet_kernel_read_output(
    generation: &CurrentFleetKernelGeneration,
) -> Result<(Value, Vec<u8>), CalyxError> {
    let raw = generation.artifact.kernel_json_bytes();
    let similarity_pairs = similarity_pair_count(generation.manifest.graph_node_count)?;
    let summary = json!({
        "verb": "kernel-read",
        "scope": generation.manifest.scope_id,
        "generation_contract": "atomic_content_addressed_fleet_generation_v1",
        "generation_id": generation.manifest.generation_id,
        "source_generation_identity": generation.manifest.source_generation_identity,
        "generation_base_seq": generation.manifest.base_seq,
        "compose_input_hash": generation.manifest.compose_input_hash,
        "source_roster_hash": generation.manifest.source_roster_hash,
        "repository_generation_count": generation.source_roster.repositories.len(),
        "graph_hash": generation.manifest.graph_hash,
        "graph_node_count": generation.manifest.graph_node_count,
        "graph_edge_count": generation.manifest.graph_edge_count,
        "vector_roster_hash": generation.manifest.vector_roster_hash,
        "panel_version": generation.manifest.panel_version,
        "semantic_dimension": generation.manifest.semantic_dim,
        "members_hash": generation.manifest.members_hash,
        "member_count": generation.manifest.member_count,
        "provenance_hash": generation.manifest.provenance_hash,
        "member_index": generation.index.descriptor,
        "admission": {
            "input_blake3": generation.manifest.admission_input_blake3,
            "source_kind": generation.admission.source_kind,
            "capture_id": generation.admission.capture_id,
            "query_count": generation.query_corpus.queries.len(),
            "query_encoder_identity_hash": generation.manifest.query_encoder_identity_hash,
            "query_corpus_hash": generation.manifest.query_corpus_hash,
            "graph_routed_report_hash": generation.manifest.graph_routed_report_hash,
            "recall_permille": generation.graph_routed_report.recall_permille,
            "params": generation.admission.params,
            "index_knobs": generation.admission.index_knobs,
            "max_fleet_similarity_pair_evaluations": generation.admission.max_fleet_similarity_pair_evaluations,
        },
        "kernel_json_bytes": raw.len(),
        "kernel_json_blake3": blake3::hash(&raw).to_hex().as_str(),
        "ledger_ref": generation.manifest.ledger_ref,
        "ledger_physical_tiers": generation.ledger_physical_tiers,
        "rows_readback_verified": generation.rows_verified,
        "current_pointer": generation.pointer.current,
        "previous_pointer": generation.pointer.previous,
        "retention": generation.manifest.retention,
        "source_recomputed": true,
        "fleet_projection_recomputed": true,
        "artifact_recomputed": true,
        "production_cost_contract": {
            "measurement_date": "2026-08-20",
            "measured_repository_n": 192_873,
            "measured_repository_e": 328_899,
            "global_fleet_production_totals": "unknown; selected-generation values are persisted observations, not an extrapolation",
            "selected_generation": {
                "repositories": generation.source_roster.repositories.len(),
                "fleet_nodes": generation.manifest.graph_node_count,
                "fleet_edges": generation.manifest.graph_edge_count,
                "kernel_members": generation.manifest.member_count,
                "semantic_dimension": generation.manifest.semantic_dim,
                "external_queries": generation.query_corpus.queries.len(),
                "similarity_pair_evaluations": similarity_pairs.to_string(),
            },
            "pc_classes": ["PC-02", "PC-03", "PC-04", "PC-07", "PC-14", "PC-16", "PC-24", "PC-28", "PC-35", "PC-37", "PC-38", "PC-41", "PC-43"],
        },
        "selected_cfs": {
            "catalog": [
                ColumnFamily::Base.name(),
                ColumnFamily::Blob.name(),
                ColumnFamily::Kernel.name(),
                ColumnFamily::Ledger.name(),
            ],
            "repository_generation": [
                ColumnFamily::Graph.name(),
                ColumnFamily::Anchors.name(),
                ColumnFamily::Kv.name(),
                ColumnFamily::Kernel.name(),
                ColumnFamily::Compression.name(),
                ColumnFamily::Ledger.name(),
                ColumnFamily::slot(SLOT_NAME_SEMANTIC).name(),
            ],
            "repository_provenance": [
                ColumnFamily::Base.name(),
                ColumnFamily::Blob.name(),
            ],
            "repository_vault_exact_union": [
                ColumnFamily::Base.name(),
                ColumnFamily::Blob.name(),
                ColumnFamily::Graph.name(),
                ColumnFamily::Anchors.name(),
                ColumnFamily::Kv.name(),
                ColumnFamily::Kernel.name(),
                ColumnFamily::Compression.name(),
                ColumnFamily::Ledger.name(),
                ColumnFamily::slot(SLOT_NAME_SEMANTIC).name(),
            ],
        },
    });
    Ok((summary, raw))
}

/// Reads and verifies one atomic fleet generation once, then derives both the
/// kernel-read result and a bounded provenance sample from that same immutable
/// object. Sampling limits response bytes only; source/projection verification
/// remains complete.
pub fn read_fleet_kernel_with_provenance(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    sample_n: usize,
) -> Result<(Value, Vec<u8>, Value), CalyxError> {
    validate_provenance_sample_count(sample_n)?;
    let generation = read_verified_fleet_kernel_generation(catalog, store_root, scope)?;
    let provenance = provenance_verification_value(&generation, scope, sample_n);
    let (summary, raw) = fleet_kernel_read_output(&generation)?;
    Ok((summary, raw, provenance))
}

/// Verifies `sample_n` fleet members' provenance against reality: for each
/// sampled occurrence, its exact Cx-addressed Base row supplies the persisted
/// input-store hash, then that one retained input is read and recomputed. CxId,
/// qualified name, path, and content key must all match the sidecar claim.
/// Fail-closed on any divergence.
#[allow(dead_code)]
fn verify_historical_member_provenance(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    sample_n: usize,
) -> Result<Value, CalyxError> {
    let total_started = std::time::Instant::now();
    if sample_n == 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_PROVENANCE_SAMPLE_INVALID,
            message: "provenance sample count must be greater than zero".to_string(),
            remediation: "pass a positive --verify-provenance count; use the member count to verify all members",
        });
    }
    let requested_sample_n = sample_n;
    let sidecar_bytes = catalog
        .read_fleet_report(FLEET_KERNEL_REPORT_KIND, scope)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_MISSING,
            message: format!("no fleet-kernel sidecar persisted at scope {scope:?}"),
            remediation: "run compose before verifying provenance",
        })?;
    let sidecar: Value = serde_json::from_slice(&sidecar_bytes).map_err(|error| CalyxError {
        code: ASTRO_FLEET_KERNEL_READBACK,
        message: format!("fleet-kernel sidecar did not parse: {error}"),
        remediation: "recompose the fleet kernel to rewrite the sidecar",
    })?;
    let semantic_contract = sidecar
        .get("semantic_contract")
        .and_then(Value::as_object)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "fleet-kernel sidecar has no exact semantic_contract".to_string(),
            remediation: "recompose from atomic current repository generations",
        })?;
    let panel_version = semantic_contract
        .get("panel_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "fleet-kernel semantic_contract has no positive panel_version".to_string(),
            remediation: "recompose from atomic current repository generations",
        })?;
    if sidecar.get("artifact").and_then(Value::as_str) != Some(FLEET_KERNEL_SIDECAR_SCHEMA)
        || semantic_contract.get("slot").and_then(Value::as_u64)
            != Some(u64::from(SLOT_NAME_SEMANTIC.get()))
        || semantic_contract
            .get("dimension")
            .and_then(Value::as_u64)
            .is_none_or(|dimension| dimension == 0)
        || semantic_contract
            .get("complete_member_vectors_required")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "fleet-kernel sidecar is not the current complete universal-S20 contract"
                .to_string(),
            remediation: "recompose from atomic current repository generations; obsolete non-S20 or partial sidecars are never verified as current",
        });
    }
    let members = sidecar
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "sidecar carries no members array".to_string(),
            remediation: "recompose the fleet kernel",
        })?;
    if members.is_empty() {
        return Err(CalyxError {
            code: ASTRO_FLEET_KERNEL_READBACK,
            message: "sidecar members array is empty".to_string(),
            remediation: "recompose the fleet kernel",
        });
    }
    let sample_n = sample_n.min(members.len());
    let mut sampled: Vec<&Value> = Vec::with_capacity(sample_n);
    for slot in 0..sample_n {
        sampled.push(&members[slot * members.len() / sample_n]);
    }

    // Group sampled occurrences by project so each vault opens once.
    let mut by_project: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
    for member in &sampled {
        let fleet_cx = member
            .get("fleet_cx")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: "sampled sidecar member carries no fleet_cx".to_string(),
                remediation: "recompose the fleet kernel",
            })?
            .to_string();
        let occurrences = member
            .get("occurrences")
            .and_then(Value::as_array)
            .filter(|occurrences| !occurrences.is_empty())
            .ok_or_else(|| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: format!(
                    "sampled sidecar member {fleet_cx} carries no provenance occurrences"
                ),
                remediation: "recompose the fleet kernel",
            })?;
        for occurrence in occurrences {
            let project = occurrence
                .get("project")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| CalyxError {
                    code: ASTRO_FLEET_KERNEL_READBACK,
                    message: format!(
                        "sampled sidecar member {fleet_cx} carries an occurrence with no project"
                    ),
                    remediation: "recompose the fleet kernel",
                })?
                .to_string();
            by_project
                .entry(project)
                .or_default()
                .push((fleet_cx.clone(), occurrence.clone()));
        }
    }

    let mut project_identities = BTreeMap::<String, RepoStoreIdentity>::new();
    for row in catalog.query(None, None)? {
        let project = project_name(&row.record.full_name);
        if !by_project.contains_key(&project) {
            continue;
        }
        let identity = repo_store_identity(&row)?;
        if project_identities
            .insert(project.clone(), identity)
            .is_some()
        {
            return Err(CalyxError {
                code: ASTRO_FLEET_PROJECT_IDENTITY,
                message: format!(
                    "fleet project identity for {project} is inconsistent: stable store key maps to more than one fleet catalog row"
                ),
                remediation: "preserve the catalog and store bytes; resolve the duplicate durable project identity before verifying provenance",
            });
        }
    }
    for project in by_project.keys() {
        if !project_identities.contains_key(project) {
            return Err(CalyxError {
                code: ASTRO_FLEET_PROJECT_IDENTITY,
                message: format!(
                    "fleet project identity for {project} is inconsistent: stable store key has no matching fleet catalog row"
                ),
                remediation: "preserve the catalog and store bytes; re-run index_repository and bind only its durable returned project",
            });
        }
    }

    let mut verified = 0_usize;
    let mut input_body_reads = 0_usize;
    let mut input_body_read_us = 0_u64;
    let mut claim_compare_us = 0_u64;
    let mut project_open_diagnostics = Vec::new();
    for (project, claims) in &by_project {
        let identity = &project_identities[project];
        let project_open_started = std::time::Instant::now();
        let vault = open_shadow_vault(
            store_root,
            &identity.store_key,
            &identity.index_project,
            vec![ColumnFamily::Base, ColumnFamily::Blob],
        )
        .map_err(|error| CalyxError {
            code: error.code,
            message: format!(
                "open sampled provenance project vault {project} at {} failed: {}",
                store_root
                    .join(&identity.store_key)
                    .join(format!("{}.astrolabe-vault", identity.index_project))
                    .display(),
                error.message
            ),
            remediation: error.remediation,
        })?;
        let project_open_wall_us = elapsed_us(project_open_started);
        let open = vault.open_diagnostics();
        project_open_diagnostics.push(json!({
            "project": project,
            "wall_us": project_open_wall_us,
            "read_snapshot_lock_us": open.read_snapshot_lock_us,
            "read_snapshot_lock_usage": phase_usage_json(open.read_snapshot_lock_usage),
            "recovery_us": open.recovery_us,
            "recovery_usage": phase_usage_json(open.recovery_usage),
            "ledger_hook_us": open.ledger_hook_us,
            "ledger_hook_usage": phase_usage_json(open.ledger_hook_usage),
            "router_us": open.router_us,
            "router_usage": phase_usage_json(open.router_usage),
            "total_us": open.total_us,
            "total_usage": phase_usage_json(open.total_usage),
        }));
        let snapshot = vault.latest_seq();
        for (fleet_cx, claim) in claims {
            let cx_str = claim.get("cx").and_then(Value::as_str).unwrap_or("");
            let cx = CxId::from_str(cx_str).map_err(|error| CalyxError {
                code: ASTRO_FLEET_KERNEL_READBACK,
                message: format!("sidecar occurrence cx {cx_str:?} did not parse: {error:?}"),
                remediation: "recompose the fleet kernel",
            })?;
            let claimed_panel = claim
                .get("panel_version")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
            if claimed_panel != Some(panel_version) {
                return Err(CalyxError {
                    code: ASTRO_FLEET_PROVENANCE_MISMATCH,
                    message: format!(
                        "fleet member {fleet_cx} occurrence {cx} in {project} claims panel {claimed_panel:?}, but the sidecar semantic contract is panel {panel_version}"
                    ),
                    remediation: "recompose the fleet kernel from one exact shared panel generation",
                });
            }
            let read_started = std::time::Instant::now();
            let frames =
                read_member_atom_at(&vault, &identity.index_project, cx, panel_version, snapshot)?;
            input_body_read_us = input_body_read_us.saturating_add(elapsed_us(read_started));
            input_body_reads += 1;
            let compare_started = std::time::Instant::now();
            let claimed_name = claim.get("qualified_name").and_then(Value::as_str);
            let claimed_path = claim.get("rel_file_path").and_then(Value::as_str);
            let claimed_label = claim.get("label").and_then(Value::as_str);
            let claimed_language = claim.get("language").and_then(Value::as_str);
            let claimed_key = claim.get("content_key").and_then(Value::as_str);
            if claimed_name != Some(frames.qualified_name.as_str())
                || claimed_path != Some(frames.rel_file_path.as_str())
                || claimed_label != Some(frames.label.as_str())
                || claimed_language != Some(frames.language.as_str())
                || claimed_key != Some(hex32(&frames.content_key).as_str())
            {
                return Err(CalyxError {
                    code: ASTRO_FLEET_PROVENANCE_MISMATCH,
                    message: format!(
                        "fleet member {fleet_cx} occurrence {cx} in {project}: sidecar claims \
                         name={claimed_name:?} path={claimed_path:?} label={claimed_label:?} \
                         language={claimed_language:?} key={claimed_key:?} but the vault holds \
                         name={:?} path={:?} label={:?} language={:?} key={:?}",
                        frames.qualified_name,
                        frames.rel_file_path,
                        frames.label,
                        frames.language,
                        hex32(&frames.content_key)
                    ),
                    remediation: "the sidecar diverged from the project vault; recompose",
                });
            }
            claim_compare_us = claim_compare_us.saturating_add(elapsed_us(compare_started));
            verified += 1;
        }
        if vault.latest_seq() != snapshot {
            return Err(CalyxError {
                code: ASTRO_FLEET_PROVENANCE_MISMATCH,
                message: format!(
                    "project {project} vault moved during provenance readback: retained_seq={snapshot}, observed_seq={}",
                    vault.latest_seq()
                ),
                remediation: "discard the mixed provenance read and retry against one stable project state",
            });
        }
    }

    Ok(json!({
        "verb": "kernel-read",
        "provenance_verified": true,
        "requested_sample_members": requested_sample_n,
        "sampled_members": sampled.len(),
        "occurrences_verified": verified,
        "projects_scanned": by_project.len(),
        "performance": {
            "total_us": elapsed_us(total_started),
            "project_vault_opens": project_open_diagnostics,
            "input_body_reads": input_body_reads,
            "input_body_read_us": input_body_read_us,
            "claim_compare_us": claim_compare_us,
            "full_blob_scan": false,
            "blob_scan_rows": 0,
            "blob_scan_us": 0,
        },
    }))
}

/// Verifies the full atomic source roster/projection first, then reports a
/// deterministic sample of the already source-recomputed immutable member
/// provenance. Sampling affects only the response size, never verification.
pub fn verify_member_provenance(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
    sample_n: usize,
) -> Result<Value, CalyxError> {
    validate_provenance_sample_count(sample_n)?;
    let generation = read_verified_fleet_kernel_generation(catalog, store_root, scope)?;
    Ok(provenance_verification_value(&generation, scope, sample_n))
}

fn validate_provenance_sample_count(sample_n: usize) -> Result<(), CalyxError> {
    if sample_n == 0 {
        return Err(CalyxError {
            code: ASTRO_FLEET_PROVENANCE_SAMPLE_INVALID,
            message: "provenance sample count must be greater than zero".to_string(),
            remediation: "pass a positive --verify-provenance count; sampling limits only returned rows because the complete source roster is always rebuilt",
        });
    }
    Ok(())
}

fn provenance_verification_value(
    generation: &CurrentFleetKernelGeneration,
    scope: &str,
    sample_n: usize,
) -> Value {
    let sample_count = sample_n.min(generation.provenance.members.len());
    let sampled = (0..sample_count)
        .map(|slot| {
            generation.provenance.members[slot * generation.provenance.members.len() / sample_count]
                .clone()
        })
        .collect::<Vec<_>>();
    let occurrences_verified = generation
        .provenance
        .members
        .iter()
        .map(|member| member.occurrences.len())
        .sum::<usize>();
    json!({
        "verb": "kernel-read",
        "scope": scope,
        "generation_id": generation.manifest.generation_id,
        "provenance_hash": generation.provenance.provenance_hash,
        "provenance_verified": true,
        "verification_scope": "complete_exact_repository_roster_and_fleet_projection",
        "requested_sample_members": sample_n,
        "sampled_members": sampled.len(),
        "total_members_verified": generation.provenance.members.len(),
        "occurrences_verified": occurrences_verified,
        "sample": sampled,
    })
}

fn phase_usage_json(usage: calyx_aster::vault::VaultPhaseUsage) -> Value {
    json!({
        "kernel_time_100ns": usage.kernel_time_100ns,
        "user_time_100ns": usage.user_time_100ns,
        "read_operations": usage.read_operations,
        "read_bytes": usage.read_bytes,
        "write_operations": usage.write_operations,
        "write_bytes": usage.write_bytes,
        "page_faults": usage.page_faults,
        "working_set_bytes_after": usage.working_set_bytes_after,
        "peak_working_set_bytes_after": usage.peak_working_set_bytes_after,
        "private_bytes_after": usage.private_bytes_after,
        "peak_private_bytes_after": usage.peak_private_bytes_after,
    })
}
