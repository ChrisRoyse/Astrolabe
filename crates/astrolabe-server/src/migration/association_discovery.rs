//! Production `discover_associations` surface for the complete association
//! discovery generation (#1012).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::Path;

use astrolabe_domain::{EdgeKind, TrustTag};
use astrolabe_kernel::{
    AssociationCompletenessWitness, AssociationDiscoveryBudgets, AssociationDiscoveryConfig,
    AssociationDiscoveryInput, AssociationSourceManifest, AssociationSourcePhysicalBinding,
    DISCOVERY_PREPARED_SCHEMA, DiscoveryConceptInput, DiscoveryTypedEdgeInput,
    EvaluatorDeclaration, EvaluatorReceipt, FinalAssociationDiscoveryEnvelope,
    PreparedAssociationDiscoveryEnvelope, association_source_generation_sha256,
    derive_association_source_manifest, finalize_association_discovery,
    prepare_association_discovery,
};
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::PhysicalCommitRowDigest;
use calyx_core::{Seq, SlotId};
use serde::{Deserialize, Serialize};

use super::*;

const DISCOVERY_TOOL_SCHEMA: &str = "astrolabe.discover_associations.v4";
const DISCOVERY_PERSISTED_SCHEMA: &str = "astrolabe.association_discovery.persisted.v3";
const DISCOVERY_POINTER_SCHEMA: &str = "astrolabe.association_discovery.pointer.v1";
const DISCOVERY_COMPACT_HEADER_SCHEMA: &str = "astrolabe.association_discovery.compact_header.v1";
const DISCOVERY_CHUNK_DESCRIPTOR_SCHEMA: &str =
    "astrolabe.association_discovery.chunk_descriptor.v1";
const DISCOVERY_PREFIX: &[u8] = b"astrolabe:association-discovery:v3:";
const DISCOVERY_ACTOR: &str = "astrolabe-association-discovery";
const DISCOVERY_RETENTION_CONTRACT: &str = "bounded_current_plus_previous; retired immutable rows are tombstoned in the same pointer/manifest/Ledger transaction";
// Calyx's default memtable admits rows up to 8 MiB. Keep every physical
// discovery value below half that ceiling so keys and future framing overhead
// cannot turn a valid logical artifact into an unwriteable physical row.
const MAX_DISCOVERY_PHYSICAL_VALUE_BYTES: usize = 4 * 1024 * 1024;

const PREPARED_STAGE_FIELDS: [(&str, &str, ColumnFamily); 9] = [
    ("source_manifest", "source_manifest", ColumnFamily::Kernel),
    ("normalized_concepts", "concept_map", ColumnFamily::Kernel),
    ("typed_edges", "typed_edges", ColumnFamily::Kernel),
    ("latent", "latent", ColumnFamily::Kernel),
    ("spectral", "spectral", ColumnFamily::Kernel),
    ("walks", "walks", ColumnFamily::Kernel),
    ("candidates", "candidates", ColumnFamily::Assay),
    (
        "evaluation_roster",
        "evaluation_roster",
        ColumnFamily::Assay,
    ),
    ("validation", "validation", ColumnFamily::Assay),
];

const FINAL_STAGE_FIELDS: [(&str, &str, ColumnFamily); 6] = [
    ("source_manifest", "source_manifest", ColumnFamily::Kernel),
    (
        "evaluation_roster",
        "evaluation_roster",
        ColumnFamily::Assay,
    ),
    (
        "evaluator_receipts",
        "evaluator_receipts",
        ColumnFamily::Assay,
    ),
    ("evaluator", "evaluator", ColumnFamily::Assay),
    ("ranked", "ranked", ColumnFamily::Kernel),
    ("reasoning_kernel", "reasoning_kernel", ColumnFamily::Kernel),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedStage {
    cf: String,
    name: String,
    key_hex: String,
    sha256: String,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDiscoveryManifest {
    schema: String,
    kind: String,
    project: String,
    source_generation_sha256: String,
    prepared_artifact_sha256: String,
    artifact_sha256: String,
    request_identity_sha256: String,
    stages: Vec<PersistedStage>,
    ledger_ref: PersistedLedgerRef,
    ledger_payload_sha256: String,
    previous_artifact_sha256: Option<String>,
    retired_artifact_sha256: Option<String>,
    retention: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLedgerRef {
    seq: u64,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDiscoveryPointerTarget {
    artifact_sha256: String,
    manifest_key_hex: String,
    manifest_sha256: String,
    commit_seq: Seq,
    ledger_ref: PersistedLedgerRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDiscoveryPointer {
    schema: String,
    kind: String,
    project: String,
    pointer_commit_seq: Seq,
    current: PersistedDiscoveryPointerTarget,
    previous: Option<PersistedDiscoveryPointerTarget>,
    retained_generation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedArtifactHeader {
    schema: String,
    artifact_sha256: String,
    artifact_fields: serde_json::Map<String, Value>,
    staged_artifact_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalStageChunk {
    ordinal: usize,
    key_hex: String,
    sha256: String,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalStageDescriptor {
    schema: String,
    logical_name: String,
    logical_sha256: String,
    logical_bytes: usize,
    chunks: Vec<LogicalStageChunk>,
}

#[derive(Clone, Debug)]
struct StageRow {
    cf: ColumnFamily,
    name: String,
    key: Vec<u8>,
    bytes: Vec<u8>,
}

struct CrossKindRetention {
    retired_artifact_sha256: String,
    pointer: PersistedDiscoveryPointer,
    pointer_key: Vec<u8>,
    pointer_bytes: Vec<u8>,
    retired_keys: Vec<(ColumnFamily, Vec<u8>)>,
}

#[derive(Serialize)]
struct DiscoveryLedgerPayload<'a> {
    schema: &'static str,
    kind: &'a str,
    project: &'a str,
    source_generation_sha256: &'a str,
    prepared_artifact_sha256: &'a str,
    artifact_sha256: &'a str,
    request_identity_sha256: &'a str,
    stages: &'a [PersistedStage],
    previous_artifact_sha256: Option<&'a str>,
    retired_artifact_sha256: Option<&'a str>,
    cross_kind_retired_artifact_sha256: Option<&'a str>,
}

struct PersistGenerationRequest<'a> {
    vault_dir: &'a Path,
    vault_id: &'a str,
    vault_salt: &'a str,
    expected_seq: Seq,
    kind: &'a str,
    project: &'a str,
    source_generation_sha256: &'a str,
    prepared_hash: &'a str,
    artifact_hash: &'a str,
    request_identity_sha256: &'a str,
    budgets: &'a AssociationDiscoveryBudgets,
    stages: Vec<StageRow>,
}

struct PreparedReadback {
    envelope: PreparedAssociationDiscoveryEnvelope,
    snapshot: Seq,
    manifest: PersistedDiscoveryManifest,
    manifest_stage: PersistedStage,
    ledger: LedgerRef,
}

pub(crate) fn discover_associations_json_at(
    cache_dir: &Path,
    project: &str,
    mode: &str,
    prepared_hash: Option<&str>,
    section: Option<&str>,
    config: AssociationDiscoveryConfig,
    evaluator_receipts: Option<Value>,
) -> Result<Value, DynError> {
    if read_dial_at(cache_dir, project)? != MigrationDial::Shadow {
        return Ok(discovery_refusal(
            "ASTRO_DISCOVERY_SHADOW_REQUIRED",
            format!("project {project:?} is not using Calyx shadow indexing"),
            "run index_repository with calyx=\"shadow\" and wait for exact association completion",
        ));
    }
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    match mode {
        "prepare" => {
            let (input, source_read_snapshot) =
                load_discovery_input(&vault_dir, &vault_id, &vault_salt, project, &config)?;
            let request_identity_sha256 =
                prepared_request_identity(project, &input.source_generation_sha256, &config)?;
            let cached = read_cached_prepared(
                &vault_dir,
                &vault_id,
                &vault_salt,
                project,
                &input.source_generation_sha256,
                &config,
                &request_identity_sha256,
            )?;
            let prepared_cache_hit = cached.is_some();
            let (prepared, persistence) = match cached {
                Some(cached) => {
                    if cached.snapshot != source_read_snapshot {
                        return Err(ToolFault::new(
                            "ASTRO_DISCOVERY_SOURCE_CHANGED",
                            format!(
                                "prepare cache read crossed vault generations: source_read={source_read_snapshot} cache_read={}",
                                cached.snapshot
                            ),
                            "rerun prepare so current source verification and immutable prepared readback occur at one unchanged vault generation",
                        )
                        .into());
                    }
                    let persistence = cached_prepared_persistence(&cached)?;
                    (cached.envelope, persistence)
                }
                None => {
                    let prepared =
                        prepare_association_discovery(&input, &config).map_err(domain_fault)?;
                    let persistence = persist_prepared(
                        &vault_dir,
                        &vault_id,
                        &vault_salt,
                        source_read_snapshot,
                        &request_identity_sha256,
                        &prepared,
                    )?;
                    (prepared, persistence)
                }
            };
            Ok(json!({
                "schema": DISCOVERY_TOOL_SCHEMA,
                "status": "prepared",
                "project": project,
                "source_generation_sha256": prepared.artifact.source_generation_sha256,
                "prepared_artifact_sha256": prepared.artifact_sha256,
                "candidate_count": prepared.artifact.candidates.len(),
                "candidates": prepared.artifact.candidates,
                "evaluation_roster": prepared.artifact.evaluation_roster,
                "spectral": {
                    "community_count": prepared.artifact.spectral.report.communities.len(),
                    "partition_gap_lambda3_minus_lambda2": prepared.artifact.spectral.partition_gap_lambda3_minus_lambda2,
                    "partition_stability": prepared.artifact.spectral.partition_stability,
                },
                "walks": {
                    "accepted": prepared.artifact.gate_counts.accepted,
                    "refused": prepared.artifact.gate_counts.refused,
                    "hypotheses": prepared.artifact.walks.hypothesis_count,
                },
                "validation": prepared.artifact.validation,
                "performance": {
                    "graph_compile_count": prepared.artifact.graph_compile_count,
                    "graph_compiles_this_call": usize::from(!prepared_cache_hit),
                    "prepared_cache_hit": prepared_cache_hit,
                    "worker_pool_reused": prepared.telemetry.worker_pool_reused,
                    "workers": prepared.artifact.config.workers,
                },
                "trust": prepared.artifact.trust,
                "persistence": persistence,
            }))
        }
        "publish" => {
            let prepared_hash = prepared_hash.filter(|value| !value.is_empty()).ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_PREPARED_HASH_REQUIRED",
                    "publish requires prepared_artifact_sha256",
                    "pass the hash returned by mode=\"prepare\" and evaluator receipts bound to its evidence ids",
                )
            })?;
            let prepared_readback =
                read_prepared(&vault_dir, &vault_id, &vault_salt, project, prepared_hash)?;
            let prepared = prepared_readback.envelope;
            let read_snapshot = prepared_readback.snapshot;
            let source_verified_snapshot = verify_current_source_binding(
                &vault_dir,
                &vault_id,
                &vault_salt,
                &prepared.artifact.source_manifest,
                &prepared.artifact.config,
                "evaluator-admission",
            )?;
            if source_verified_snapshot != read_snapshot {
                return Err(ToolFault::new(
                    "ASTRO_DISCOVERY_SOURCE_CHANGED",
                    format!(
                        "evaluator admission crossed vault generations: prepared_read={read_snapshot} source_verified={source_verified_snapshot}"
                    ),
                    "rerun publish so immutable prepared readback and exact current-source verification occur at one unchanged vault generation",
                )
                .into());
            }
            let evaluator_receipts_value = evaluator_receipts.ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_REQUIRED",
                    "publish requires the complete exact evaluator_receipts roster",
                    "invoke every prepared evaluator binding and return one exact byte/hash-bound receipt per invocation",
                )
            })?;
            let budgets = prepared.artifact.config.budgets.as_ref().ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_BUDGETS_REQUIRED",
                    "prepared artifact has no mandatory evaluator/persistence budgets",
                    "prepare a new generation with every caller-owned budget",
                )
            })?;
            let evaluator_receipts = decode_bounded_evaluator_receipts(
                evaluator_receipts_value,
                budgets,
                prepared.artifact.evaluation_roster.binding_count,
            )?;
            let final_artifact = finalize_association_discovery(&prepared, &evaluator_receipts)
                .map_err(domain_fault)?;
            let persistence = persist_final(
                &vault_dir,
                &vault_id,
                &vault_salt,
                read_snapshot,
                &prepared,
                &final_artifact,
            )?;
            Ok(json!({
                "schema": DISCOVERY_TOOL_SCHEMA,
                "status": "published",
                "project": project,
                "source_generation_sha256": prepared.artifact.source_generation_sha256,
                "prepared_artifact_sha256": prepared.artifact_sha256,
                "artifact_sha256": final_artifact.artifact_sha256,
                "trust": final_artifact.artifact.trust,
                "ranked": final_artifact.artifact.ranked,
                "reasoning_kernel": final_artifact.artifact.reasoning_kernel,
                "persistence": persistence,
            }))
        }
        "read" => read_discovery(
            &vault_dir,
            &vault_id,
            &vault_salt,
            project,
            prepared_hash,
            section.unwrap_or("all"),
        ),
        other => Ok(discovery_refusal(
            "ASTRO_DISCOVERY_MODE_UNSUPPORTED",
            format!("discover_associations mode {other:?} is unsupported"),
            "pass mode as prepare, publish, or read",
        )),
    }
}

fn decode_bounded_evaluator_receipts(
    value: Value,
    budgets: &AssociationDiscoveryBudgets,
    expected_count: usize,
) -> Result<Vec<EvaluatorReceipt>, DynError> {
    let receipts = value.as_array().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
            "evaluator_receipts must be an array",
            "submit the exact one-per-binding receipt array returned by the trusted external capture step",
        )
    })?;
    if receipts.len() != expected_count || receipts.len() > budgets.max_evaluation_bindings {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_EXCEEDED",
            format!(
                "receipt count is {}, exact roster is {expected_count}, caller budget is {}",
                receipts.len(),
                budgets.max_evaluation_bindings
            ),
            "submit exactly the prepared receipt roster within its identity-bound caller budget",
        )
        .into());
    }
    let mut request_total = 0usize;
    let mut response_total = 0usize;
    for (ordinal, receipt) in receipts.iter().enumerate() {
        let object = receipt.as_object().ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
                format!("receipt {ordinal} is not an object"),
                "submit receipts matching the exact tool schema",
            )
        })?;
        let request = object
            .get("request_utf8")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
                    format!("receipt {ordinal} lacks string request_utf8"),
                    "submit the exact prepared request bytes",
                )
            })?;
        let response = object
            .get("response_utf8")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
                    format!("receipt {ordinal} lacks string response_utf8"),
                    "submit the exact captured response bytes",
                )
            })?;
        if request.len() > budgets.max_request_bytes_per_binding
            || response.len() > budgets.max_response_bytes_per_binding
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_EXCEEDED",
                format!(
                    "receipt {ordinal} bytes exceed a per-binding budget: request={}/{} response={}/{}",
                    request.len(),
                    budgets.max_request_bytes_per_binding,
                    response.len(),
                    budgets.max_response_bytes_per_binding,
                ),
                "preserve the capture and prepare a new generation with explicitly measured larger budgets",
            )
            .into());
        }
        request_total = request_total.checked_add(request.len()).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_OVERFLOW",
                "receipt request byte total overflow",
                "narrow the evaluator roster",
            )
        })?;
        response_total = response_total.checked_add(response.len()).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_OVERFLOW",
                "receipt response byte total overflow",
                "narrow the evaluator roster",
            )
        })?;
        if request_total > budgets.max_request_bytes_total
            || response_total > budgets.max_response_bytes_total
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_EXCEEDED",
                format!(
                    "receipt totals exceed caller budgets: request={request_total}/{} response={response_total}/{}",
                    budgets.max_request_bytes_total, budgets.max_response_bytes_total
                ),
                "preserve the captures and prepare a new generation with explicitly measured larger budgets",
            )
            .into());
        }
    }
    serde_json::from_value(value).map_err(|error| {
        ToolFault::new(
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
            format!("evaluator_receipts do not match the exact schema: {error}"),
            "submit one exact receipt for every prepared binding",
        )
        .into()
    })
}

/// Explicit generation-bound source verification. Cost is O(N+E+X): every
/// Graph concept/typed edge plus every current Base/Slot/Compression/XTerm
/// constellation is logically rederived because the producers expose no
/// Merkle root. Production N=192,873 and E=328,899 (#1064, 2026-08-08);
/// production X remains an explicitly unknown measurement gap. This operation
/// is called only by prepare, publish admission, and final read, never by an
/// ordinary association query path.
fn load_discovery_input(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
    config: &AssociationDiscoveryConfig,
) -> Result<(AssociationDiscoveryInput, Seq), DynError> {
    // Slot families are dynamic (`Slot { id, kind }`), so the retained source
    // read opens the complete CF roster rather than pretending one scalar
    // `Slot` family exists.
    let vault = open_shadow_vault_read_only(vault_dir, vault_id, vault_salt, Vec::new())?;
    let snapshot = vault.latest_seq();
    let csr = astrolabe_ingest::read_graph_projection_csr_at(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        snapshot,
    )?
    .ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_PROJECTION_MISSING",
            "the exact retained source has no composite kernel_graph projection",
            "complete indexing and association reconciliation before preparing discovery",
        )
    })?;
    let structural = csr.edges.iter().filter(|edge| {
        edge.etype != EdgeKind::SimilarTo.code()
            && edge.etype != EdgeKind::SemanticallyRelated.code()
    });
    let structural_count = structural.count();
    let semantic_count = csr
        .edges
        .iter()
        .filter(|edge| {
            edge.etype == EdgeKind::SimilarTo.code()
                || edge.etype == EdgeKind::SemanticallyRelated.code()
        })
        .count();
    if structural_count == 0 || semantic_count == 0 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_COMPOSITE_REQUIRED",
            format!(
                "composite graph is partial: structural_edges={structural_count} semantic_edges={semantic_count}"
            ),
            "reconcile typed structural and encoded/embedded similarity associations into the same projection",
        )
        .into());
    }
    let graph = astrolabe_ingest::read_cbm_graph_snapshot_at(&vault, project, snapshot)?;
    let verified_complete =
        astrolabe_weave::verify_complete_association_state_at(&vault, snapshot, Some(vault_dir))?;
    let complete = verified_complete.state;
    let anchors = astrolabe_anchors::effective_anchor_trust_map_at(&vault, snapshot)?;
    let nodes = graph
        .nodes
        .iter()
        .filter_map(|node| node.cx_id.map(|cx_id| (cx_id, node)))
        .collect::<BTreeMap<_, _>>();
    let mut concepts = Vec::with_capacity(csr.nodes.len());
    for projection_node in &csr.nodes {
        let node = nodes.get(&projection_node.id).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_NODE_SOURCE_MISSING",
                format!(
                    "projection node {} has no exact CBM source row at snapshot {snapshot}",
                    projection_node.id
                ),
                "reconcile the graph projection and CBM node map at one MVCC sequence",
            )
        })?;
        let source_excerpt = if node.source_bytes.is_empty() {
            String::new()
        } else {
            String::from_utf8(node.source_bytes.clone()).map_err(|error| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_SOURCE_UTF8_INVALID",
                    format!("source bytes for {} are not UTF-8: {error}", node.qualified_name),
                    "repair the persisted source encoding before using it as cited evaluator evidence",
                )
            })?
        };
        let source_sha256 = if node.source_sha256.is_empty() {
            String::new()
        } else {
            node.source_sha256.clone()
        };
        let signature_or_shape = signature_or_shape(node)?;
        if !projection_node.weight.is_finite()
            || projection_node.weight < 1.0
            || projection_node.weight.round() > u64::MAX as f32
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_CONCEPT_FREQUENCY_INVALID",
                format!(
                    "projection node {} has non-positive, non-finite, or overflowing frequency weight {}",
                    projection_node.id, projection_node.weight
                ),
                "repair the exact persisted projection weight; discovery never substitutes frequency=1",
            )
            .into());
        }
        concepts.push(DiscoveryConceptInput {
            cx_id: projection_node.id,
            symbol_kind: node.label.clone(),
            language: language_from_path(&node.file_path),
            qualified_name: node.qualified_name.clone(),
            signature_or_shape,
            file_path: node.file_path.clone(),
            source_sha256,
            source_excerpt,
            frequency: projection_node.weight.round() as u64,
            anchor_trust: anchors.get(&projection_node.id).copied(),
        });
    }
    concepts.sort_by_key(|concept| concept.cx_id);

    let mut typed_edges = Vec::with_capacity(csr.edges.len());
    for (src_index, range) in csr.offsets.windows(2).enumerate() {
        let src = csr.nodes[src_index].id;
        for (offset, edge) in csr.edges[range[0]..range[1]].iter().enumerate() {
            let kind = EdgeKind::ALL
                .iter()
                .copied()
                .find(|kind| kind.code() == edge.etype)
                .ok_or_else(|| {
                    ToolFault::new(
                        "ASTRO_DISCOVERY_EDGE_KIND_UNKNOWN",
                        format!(
                            "projection edge {src}->{} has unknown etype {}",
                            edge.dst, edge.etype
                        ),
                        "repair the typed edge vocabulary/projection mismatch before discovery",
                    )
                })?;
            let ledger_ref = edge.ledger_ref().ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_EDGE_UNATTESTED",
                    format!(
                        "projection edge {src}->{} ({}) has no ledger attestation",
                        edge.dst,
                        kind.as_str()
                    ),
                    "rebuild the projection from ledger-paired typed and similarity rows",
                )
            })?;
            let family = edge_family(kind).to_string();
            typed_edges.push(DiscoveryTypedEdgeInput {
                evidence_id: format!(
                    "edge:{src}:{}:{}:{offset}:{ledger_ref}",
                    edge.dst,
                    kind.as_str()
                ),
                src,
                dst: edge.dst,
                edge_type_code: i64::from(edge.etype),
                edge_type_name: kind.as_str().to_string(),
                family: family.clone(),
                weight: edge.weight,
                trust: if family == "semantic" {
                    TrustTag::Provisional
                } else {
                    TrustTag::Trusted
                },
                temporal_direction: None,
                observed_at_millis: None,
                ledger_ref: ledger_ref.clone(),
                provenance: vec![
                    "projection=kernel_graph".to_string(),
                    format!(
                        "projection_source_fingerprint_blake3={}",
                        hex_lower(&csr.source_fingerprint_blake3)
                    ),
                    format!("edge_kind={}", kind.as_str()),
                    format!("ledger_ref={ledger_ref}"),
                    if family == "semantic" {
                        "cross_term_family=encoded_or_embedded_slot_similarity".to_string()
                    } else {
                        "cross_term_family=not_applicable".to_string()
                    },
                ],
                source_generation_sha256: String::new(),
            });
        }
    }
    typed_edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    let mut maximum_source_ledger_seq = 0_u64;
    for edge in &typed_edges {
        let (seq, hash) = edge.ledger_ref.split_once(':').ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_SOURCE_LEDGER_INVALID",
                format!(
                    "typed edge {} has malformed ledger_ref {:?}",
                    edge.evidence_id, edge.ledger_ref
                ),
                "repair every graph-projection ledger reference before discovery",
            )
        })?;
        let seq = seq.parse::<u64>().map_err(|error| {
            ToolFault::new(
                "ASTRO_DISCOVERY_SOURCE_LEDGER_INVALID",
                format!(
                    "typed edge {} has non-numeric ledger sequence {seq:?}: {error}",
                    edge.evidence_id
                ),
                "repair every graph-projection ledger reference before discovery",
            )
        })?;
        if seq == 0 || hash.is_empty() {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_SOURCE_LEDGER_INVALID",
                format!(
                    "typed edge {} has incomplete ledger_ref {:?}",
                    edge.evidence_id, edge.ledger_ref
                ),
                "repair every graph-projection ledger reference before discovery",
            )
            .into());
        }
        maximum_source_ledger_seq = maximum_source_ledger_seq.max(seq);
    }
    if maximum_source_ledger_seq == 0 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_LEDGER_MISSING",
            "no positive ledger sequence exists in the composite relationship graph",
            "rebuild the projection from ledger-attested association rows",
        )
        .into());
    }
    let completeness = AssociationCompletenessWitness {
        constellation_count: complete.constellation_count as u64,
        source_slot_count: complete.source_slot_count as u64,
        pair_count: complete.completion_row_count as u64,
        completion_witness_state_hash: complete.witness_state_hash,
        xterm_key_stream_hash: complete.pair_key_stream_hash,
        xterm_value_stream_hash: complete.pair_value_stream_hash,
    };
    let mut slot_ids = BTreeSet::new();
    let mut panel_schema_ids = BTreeMap::new();
    let mut panel_manifest_sha256 = BTreeMap::new();
    for panel_version in complete.panel_version_counts.keys().copied() {
        let slots = astrolabe_panel::slots_for_version(panel_version)
            .map_err(|error| ToolFault::new(error.code(), error.message(), error.remediation()))?;
        slot_ids.extend(slots.iter().map(|spec| spec.slot));
        let schema = astrolabe_panel::schema_id_for_version(panel_version)
            .map_err(|error| ToolFault::new(error.code(), error.message(), error.remediation()))?;
        panel_schema_ids.insert(panel_version, schema.to_string());
        let manifest = astrolabe_panel::panel_slot_manifest_sha256(panel_version)
            .map_err(|error| ToolFault::new(error.code(), error.message(), error.remediation()))?;
        panel_manifest_sha256.insert(panel_version, hex_lower(&manifest));
    }
    let slot_cf_generations = slot_ids
        .into_iter()
        .map(|slot| {
            Ok((
                slot,
                vault.cf_content_generation(ColumnFamily::slot(SlotId::new(slot)))?,
            ))
        })
        .collect::<calyx_core::Result<BTreeMap<_, _>>>()?;
    let physical = AssociationSourcePhysicalBinding {
        retained_snapshot_seq: snapshot,
        projection_source_fingerprint_blake3: hex_lower(&csr.source_fingerprint_blake3),
        graph_cf_generation: vault.cf_content_generation(ColumnFamily::Graph)?,
        anchors_cf_generation: vault.cf_content_generation(ColumnFamily::Anchors)?,
        base_cf_generation: vault.cf_content_generation(ColumnFamily::Base)?,
        xterm_cf_generation: vault.cf_content_generation(ColumnFamily::XTerm)?,
        completion_witness_cf_generation: vault.cf_content_generation(ColumnFamily::Kv)?,
        compression_cf_generation: vault.cf_content_generation(ColumnFamily::Compression)?,
        slot_cf_generations,
        panel_schema_ids,
        panel_manifest_sha256,
        completion_pair_block_schema: astrolabe_weave::COMPLETE_PAIR_BLOCK_SCHEMA.to_string(),
        completion_witness_schema: astrolabe_weave::COMPLETE_WITNESS_SCHEMA.to_string(),
        completion_ledger_schema: astrolabe_weave::COMPLETE_ASSOCIATION_LEDGER_SCHEMA.to_string(),
        completion_metric_contract: vec![
            "cosine".to_string(),
            "symmetric_mean_maxsim_cosine".to_string(),
        ],
        completion_incompatibility_contract: vec![
            "absent_slot".to_string(),
            "shape_mismatch".to_string(),
            "zero_norm".to_string(),
        ],
    };
    let post_source_read_seq = vault.latest_seq();
    if post_source_read_seq != snapshot {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_CHANGED",
            format!(
                "prepare source read crossed vault generations: retained_snapshot={snapshot} post_source_read={post_source_read_seq}"
            ),
            "rerun prepare so Graph/Anchors/Base/Slot/Compression/XTerm rows and their source manifest are read within one unchanged retained generation",
        )
        .into());
    }
    let (source_manifest, source_generation_sha256) = derive_association_source_manifest(
        project,
        snapshot,
        &physical,
        &concepts,
        &typed_edges,
        &completeness,
        config,
    )
    .map_err(domain_fault)?;
    for edge in &mut typed_edges {
        edge.source_generation_sha256 = source_generation_sha256.clone();
    }
    Ok((
        AssociationDiscoveryInput {
            project: project.to_string(),
            source_seq: snapshot,
            source_generation_sha256,
            source_manifest,
            concepts,
            typed_edges,
            completeness,
        },
        snapshot,
    ))
}

fn verify_current_source_binding(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    manifest: &AssociationSourceManifest,
    config: &AssociationDiscoveryConfig,
    phase: &str,
) -> Result<Seq, DynError> {
    let expected_generation =
        association_source_generation_sha256(manifest).map_err(domain_fault)?;
    let (current, snapshot) =
        load_discovery_input(vault_dir, vault_id, vault_salt, &manifest.project, config)?;
    if current.source_generation_sha256 != expected_generation {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_CHANGED",
            format!(
                "{phase}: exact current Graph/concept/edge/anchor and verified Base/Slot/Compression/XTerm source rederived {}, expected {expected_generation}",
                current.source_generation_sha256,
            ),
            "discard the stale prepared/final candidate and rerun discovery from the current fully verified logical source; handle-local CF generation floors are diagnostic and never authorize equivalence",
        )
        .into());
    }
    Ok(snapshot)
}

fn persist_prepared(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    expected_seq: Seq,
    request_identity_sha256: &str,
    prepared: &PreparedAssociationDiscoveryEnvelope,
) -> Result<Value, DynError> {
    let hash = &prepared.artifact_sha256;
    let budgets = prepared.artifact.config.budgets.as_ref().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_BUDGETS_REQUIRED",
            "prepared artifact has no caller-owned evaluator/persistence budgets",
            "prepare a new generation with every mandatory budget",
        )
    })?;
    let mut allocation_budget = GenerationAllocationBudget::new(budgets);
    ensure_serialized_allocation_within_budget("prepared envelope", prepared, budgets)?;
    let base = artifact_base("prepared", hash);
    let (header, staged_values) = compact_artifact_header(prepared, hash, &PREPARED_STAGE_FIELDS)?;
    let mut rows = stage_json_rows(
        ColumnFamily::Kernel,
        &base,
        "artifact",
        &header,
        &mut allocation_budget,
    )?;
    for ((_, stage_name, cf), value) in PREPARED_STAGE_FIELDS.iter().zip(staged_values) {
        rows.extend(stage_json_rows(
            *cf,
            &base,
            stage_name,
            &value,
            &mut allocation_budget,
        )?);
    }
    persist_generation(PersistGenerationRequest {
        vault_dir,
        vault_id,
        vault_salt,
        expected_seq,
        kind: "prepared",
        project: &prepared.artifact.project,
        source_generation_sha256: &prepared.artifact.source_generation_sha256,
        prepared_hash: hash,
        artifact_hash: hash,
        request_identity_sha256,
        budgets,
        stages: rows,
    })
}

fn read_cached_prepared(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
    source_generation_sha256: &str,
    config: &AssociationDiscoveryConfig,
    request_identity_sha256: &str,
) -> Result<Option<PreparedReadback>, DynError> {
    let vault = open_shadow_vault_read_only(
        vault_dir,
        vault_id,
        vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Assay,
            ColumnFamily::Ledger,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let Some(pointer) = read_generation_pointer(&vault, snapshot, "prepared", project)? else {
        return Ok(None);
    };
    for target in std::iter::once(&pointer.current).chain(pointer.previous.as_ref()) {
        let manifest =
            read_generation_manifest_target(&vault, snapshot, "prepared", project, target)?;
        if manifest.request_identity_sha256 == request_identity_sha256 {
            let prepared = read_prepared(
                vault_dir,
                vault_id,
                vault_salt,
                project,
                &target.artifact_sha256,
            )?;
            if prepared.envelope.artifact.source_generation_sha256 != source_generation_sha256
                || &prepared.envelope.artifact.config != config
            {
                return Err(ToolFault::new(
                    "ASTRO_DISCOVERY_PREPARED_POINTER_MISMATCH",
                    "prepared retained pointer target disagrees with its source generation or configuration",
                    "preserve the vault and inspect the pointer, manifest, and immutable prepared rows",
                )
                .into());
            }
            return Ok(Some(prepared));
        }
    }
    Ok(None)
}

fn persist_final(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    expected_seq: Seq,
    prepared: &PreparedAssociationDiscoveryEnvelope,
    final_artifact: &FinalAssociationDiscoveryEnvelope,
) -> Result<Value, DynError> {
    verify_nested_kernel_artifact_hash(final_artifact, "before final discovery persistence")?;
    let budgets = prepared.artifact.config.budgets.as_ref().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_BUDGETS_REQUIRED",
            "prepared artifact has no caller-owned evaluator/persistence budgets",
            "prepare a new generation with every mandatory budget",
        )
    })?;
    let mut allocation_budget = GenerationAllocationBudget::new(budgets);
    ensure_serialized_allocation_within_budget("final envelope", final_artifact, budgets)?;
    let hash = &final_artifact.artifact_sha256;
    let base = artifact_base("final", hash);
    let (header, staged_values) =
        compact_artifact_header(final_artifact, hash, &FINAL_STAGE_FIELDS)?;
    let mut rows = stage_json_rows(
        ColumnFamily::Kernel,
        &base,
        "artifact",
        &header,
        &mut allocation_budget,
    )?;
    for ((_, stage_name, cf), value) in FINAL_STAGE_FIELDS.iter().zip(staged_values) {
        rows.extend(stage_json_rows(
            *cf,
            &base,
            stage_name,
            &value,
            &mut allocation_budget,
        )?);
    }
    rows.extend(stage_json_rows(
        ColumnFamily::Assay,
        &base,
        "validation",
        &prepared.artifact.validation,
        &mut allocation_budget,
    )?);
    persist_generation(PersistGenerationRequest {
        vault_dir,
        vault_id,
        vault_salt,
        expected_seq,
        kind: "final",
        project: &prepared.artifact.project,
        source_generation_sha256: &prepared.artifact.source_generation_sha256,
        prepared_hash: &prepared.artifact_sha256,
        artifact_hash: hash,
        request_identity_sha256: &prepared.artifact_sha256,
        budgets,
        stages: rows,
    })
}

fn persist_generation(request: PersistGenerationRequest<'_>) -> Result<Value, DynError> {
    let PersistGenerationRequest {
        vault_dir,
        vault_id,
        vault_salt,
        expected_seq,
        kind,
        project,
        source_generation_sha256,
        prepared_hash,
        artifact_hash,
        request_identity_sha256,
        budgets,
        stages,
    } = request;
    validate_hash(artifact_hash)?;
    validate_hash(prepared_hash)?;
    validate_hash(source_generation_sha256)?;
    validate_hash(request_identity_sha256)?;
    if !matches!(kind, "prepared" | "final") || project.trim().is_empty() {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_GENERATION_KIND_INVALID",
            format!(
                "discovery generation kind/project is invalid: kind={kind:?} project={project:?}"
            ),
            "publish only exact prepared or final generations for a non-empty project",
        )
        .into());
    }
    validate_generation_budget(&stages, budgets, "immutable stages")?;
    let vault = open_shadow_vault_writable_latest_selected(
        vault_dir,
        vault_id,
        vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Assay,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let current_seq = vault.latest_seq();
    if current_seq != expected_seq {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_CHANGED",
            format!("vault advanced from retained snapshot {expected_seq} to {current_seq} before {kind} publication"),
            "rerun the operation against the new exact source; no partial generation was published",
        )
        .into());
    }
    let manifest_key = stage_key(&artifact_base(kind, artifact_hash), "manifest");
    let pointer_before = read_generation_pointer(&vault, current_seq, kind, project)?;
    let mut retained_before = Vec::new();
    if let Some(pointer) = &pointer_before {
        for target in std::iter::once(&pointer.current).chain(pointer.previous.as_ref()) {
            retained_before.push((
                target.clone(),
                read_generation_manifest_target(&vault, current_seq, kind, project, target)?,
            ));
        }
    }
    if let Some((target, manifest)) = retained_before
        .iter()
        .find(|(target, _)| target.artifact_sha256 == artifact_hash)
    {
        if manifest.source_generation_sha256 != source_generation_sha256
            || manifest.prepared_artifact_sha256 != prepared_hash
            || manifest.request_identity_sha256 != request_identity_sha256
            || manifest.stages != stages.iter().map(stage_manifest).collect::<Vec<_>>()
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_RETAINED_IDENTITY_MISMATCH",
                format!("retained {kind} generation {artifact_hash} differs from the exact requested bytes or bindings"),
                "preserve the retained generation and inspect its pointer, manifest, and immutable rows",
            )
            .into());
        }
        let ledger = verify_discovery_ledger(&vault, artifact_hash, manifest)?;
        return persistence_response("unchanged", target.commit_seq, &stages, &ledger, None);
    }
    let existing = stages
        .iter()
        .map(|row| {
            vault
                .read_cf_at(current_seq, row.cf, &row.key)
                .map(|value| (row, value))
        })
        .collect::<calyx_core::Result<Vec<_>>>()?;
    let all_exact = existing
        .iter()
        .all(|(row, value)| value.as_deref() == Some(row.bytes.as_slice()));
    let any_present = existing.iter().any(|(_, value)| value.is_some());
    if any_present && !all_exact {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PERSISTED_PARTIAL_OR_DRIFTED",
            format!("{kind} generation {artifact_hash} has a partial or byte-different persisted row set"),
            "preserve the vault and inspect the stage manifest/readback hashes before retrying",
        )
        .into());
    }
    if all_exact {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_ORPHAN_GENERATION",
            format!("unpointed immutable {kind} rows already exist for {artifact_hash}"),
            "preserve the vault and inspect the interrupted atomic publication; never attach orphan rows with a later pointer write",
        )
        .into());
    }
    if vault
        .read_cf_at(current_seq, ColumnFamily::Kernel, &manifest_key)?
        .is_some()
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_ORPHAN_MANIFEST",
            format!("unpointed {kind} manifest already exists for {artifact_hash}"),
            "preserve the vault and inspect the interrupted or retired generation; never overwrite or resurrect a content-addressed manifest",
        )
        .into());
    }
    let previous_target = pointer_before
        .as_ref()
        .map(|pointer| pointer.current.clone());
    let retired = if let Some(target) = pointer_before
        .as_ref()
        .and_then(|pointer| pointer.previous.clone())
    {
        let manifest = retained_before
            .iter()
            .find(|(candidate, _)| candidate == &target)
            .map(|(_, manifest)| manifest.clone())
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_RETENTION_STATE_MISMATCH",
                    "previous pointer target was not present in the prevalidated retained roster",
                    "preserve the vault and inspect the current+previous pointer transaction",
                )
            })?;
        Some((target, manifest))
    } else {
        None
    };
    let predicted_commit_seq = current_seq.checked_add(1).ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_SEQUENCE_OVERFLOW",
            "discovery commit sequence overflow",
            "preserve the vault; no further generation can be represented",
        )
    })?;
    let cross_kind_retention = plan_cross_kind_retention(
        &vault,
        current_seq,
        predicted_commit_seq,
        kind,
        project,
        retired.as_ref().map(|(target, _)| target),
    )?;
    let stage_bindings = stages.iter().map(stage_manifest).collect::<Vec<_>>();
    let ledger_payload_value = DiscoveryLedgerPayload {
        schema: "astrolabe.association_discovery.ledger_payload.v1",
        kind,
        project,
        source_generation_sha256,
        prepared_artifact_sha256: prepared_hash,
        artifact_sha256: artifact_hash,
        request_identity_sha256,
        stages: &stage_bindings,
        previous_artifact_sha256: previous_target
            .as_ref()
            .map(|target| target.artifact_sha256.as_str()),
        retired_artifact_sha256: retired
            .as_ref()
            .map(|(target, _)| target.artifact_sha256.as_str()),
        cross_kind_retired_artifact_sha256: cross_kind_retention
            .as_ref()
            .map(|retention| retention.retired_artifact_sha256.as_str()),
    };
    ensure_serialized_allocation_within_budget(
        "discovery Ledger payload",
        &ledger_payload_value,
        budgets,
    )?;
    let ledger_payload = serde_json::to_vec(&ledger_payload_value)?;
    let ledger_payload_sha256 = sha256_hex_local(&ledger_payload);
    let placeholder_ref = PersistedLedgerRef {
        // Conservative fixed-width preflight: the physical ledger sequence is
        // known only inside the atomic derived-row callback. u64::MAX makes the
        // allocation budget an upper bound before any mutation is staged.
        seq: u64::MAX,
        hash: "0".repeat(64),
    };
    let preflight_manifest = discovery_manifest(
        kind,
        project,
        source_generation_sha256,
        prepared_hash,
        artifact_hash,
        request_identity_sha256,
        stage_bindings.clone(),
        placeholder_ref.clone(),
        &ledger_payload_sha256,
        previous_target.as_ref(),
        retired.as_ref().map(|(target, _)| target),
    );
    let preflight_manifest_bytes = serde_json::to_vec(&preflight_manifest)?;
    let preflight_target = PersistedDiscoveryPointerTarget {
        artifact_sha256: artifact_hash.to_string(),
        manifest_key_hex: hex_lower(&manifest_key),
        manifest_sha256: sha256_hex_local(&preflight_manifest_bytes),
        commit_seq: predicted_commit_seq,
        ledger_ref: placeholder_ref,
    };
    let preflight_pointer = discovery_pointer(
        kind,
        project,
        predicted_commit_seq,
        preflight_target,
        previous_target.clone(),
    );
    let preflight_pointer_bytes = serde_json::to_vec(&preflight_pointer)?;
    let retired_keys = retired
        .as_ref()
        .map(|(_, manifest)| manifest_generation_keys(manifest))
        .transpose()?
        .unwrap_or_default();
    let cross_kind_rows = cross_kind_retention
        .as_ref()
        .map(|retention| {
            let mut rows = vec![(
                ColumnFamily::Kernel,
                retention.pointer_key.clone(),
                retention.pointer_bytes.clone(),
            )];
            rows.extend(
                retention
                    .retired_keys
                    .iter()
                    .map(|(cf, key)| (*cf, key.clone(), tombstone_value())),
            );
            rows
        })
        .unwrap_or_default();
    validate_complete_generation_budget(
        &stages,
        &manifest_key,
        &preflight_manifest_bytes,
        &generation_pointer_key(kind, project),
        &preflight_pointer_bytes,
        &retired_keys,
        &cross_kind_rows,
        ledger_payload.len(),
        budgets,
    )?;
    let actor = ActorId::Service(DISCOVERY_ACTOR.to_string());
    let subject = SubjectId::Kernel(artifact_hash.as_bytes().to_vec());
    let rows = stages
        .iter()
        .map(|row| (row.cf, row.key.clone(), row.bytes.clone()))
        .collect::<Vec<_>>();
    let callback_stage_bindings = stage_bindings.clone();
    let callback_previous = previous_target.clone();
    let callback_retired = retired.as_ref().map(|(target, _)| target.clone());
    let callback_kind = kind.to_string();
    let callback_project = project.to_string();
    let callback_source = source_generation_sha256.to_string();
    let callback_prepared = prepared_hash.to_string();
    let callback_artifact = artifact_hash.to_string();
    let callback_request = request_identity_sha256.to_string();
    let callback_payload_hash = ledger_payload_sha256.clone();
    let callback_manifest_key = manifest_key.clone();
    let callback_pointer_key = generation_pointer_key(kind, project);
    let callback_retired_keys = retired_keys.clone();
    let callback_cross_kind_rows = cross_kind_rows.clone();
    let (commit, (manifest, pointer)) = vault
        .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
            current_seq,
            rows,
            calyx_ledger::EntryKind::Assay,
            subject,
            ledger_payload,
            actor,
            move |ledger_ref, _source_rows| {
                let persisted_ledger_ref = persisted_ledger_ref(ledger_ref);
                let manifest = discovery_manifest(
                    &callback_kind,
                    &callback_project,
                    &callback_source,
                    &callback_prepared,
                    &callback_artifact,
                    &callback_request,
                    callback_stage_bindings,
                    persisted_ledger_ref.clone(),
                    &callback_payload_hash,
                    callback_previous.as_ref(),
                    callback_retired.as_ref(),
                );
                let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
                    calyx_core::CalyxError::ledger_group_commit_failed(format!(
                        "encode discovery manifest: {error}"
                    ))
                })?;
                let current = PersistedDiscoveryPointerTarget {
                    artifact_sha256: callback_artifact,
                    manifest_key_hex: hex_lower(&callback_manifest_key),
                    manifest_sha256: sha256_hex_local(&manifest_bytes),
                    commit_seq: predicted_commit_seq,
                    ledger_ref: persisted_ledger_ref,
                };
                let pointer = discovery_pointer(
                    &callback_kind,
                    &callback_project,
                    predicted_commit_seq,
                    current,
                    callback_previous,
                );
                let pointer_bytes = serde_json::to_vec(&pointer).map_err(|error| {
                    calyx_core::CalyxError::ledger_group_commit_failed(format!(
                        "encode discovery pointer: {error}"
                    ))
                })?;
                let mut derived = vec![
                    (ColumnFamily::Kernel, callback_manifest_key, manifest_bytes),
                    (ColumnFamily::Kernel, callback_pointer_key, pointer_bytes),
                ];
                derived.extend(
                    callback_retired_keys
                        .into_iter()
                        .map(|(cf, key)| (cf, key, tombstone_value())),
                );
                derived.extend(callback_cross_kind_rows);
                Ok((derived, (manifest, pointer)))
            },
        )?;
    if commit.seq != predicted_commit_seq
        || persisted_ledger_ref(&commit.ledger_ref) != manifest.ledger_ref
        || pointer.current.ledger_ref != manifest.ledger_ref
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_COMMIT_RECEIPT_MISMATCH",
            "atomic discovery commit sequence, manifest, pointer, or LedgerRef differs",
            "preserve the vault and inspect the exact group commit",
        )
        .into());
    }
    vault.flush()?;
    let retention_inventory = if retired_keys.is_empty()
        && cross_kind_retention
            .as_ref()
            .is_none_or(|retention| retention.retired_keys.is_empty())
    {
        None
    } else {
        Some(vault.physical_commit_inventory(
            commit.seq,
            &[
                ColumnFamily::Kernel,
                ColumnFamily::Assay,
                ColumnFamily::Ledger,
                ColumnFamily::TimeIndex,
            ],
        )?)
    };
    let mut physical_commit_rows = BTreeMap::new();
    if let Some(inventory) = &retention_inventory {
        for row in &inventory.rows {
            physical_commit_rows
                .entry(row.cf)
                .or_insert_with(BTreeMap::new)
                .entry(row.key.clone())
                .and_modify(|entry| *entry = None)
                .or_insert(Some(row));
        }
    }
    let observed_pointer =
        read_generation_pointer(&vault, commit.seq, kind, project)?.ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_POINTER_MISSING",
                "atomic discovery pointer is absent after flush",
                "preserve the vault and inspect the group commit",
            )
        })?;
    if observed_pointer != pointer {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_READBACK_MISMATCH",
            "atomic discovery pointer bytes differ after flush",
            "preserve the vault and inspect the physical pointer row",
        )
        .into());
    }
    let observed_manifest =
        read_generation_manifest_target(&vault, commit.seq, kind, project, &pointer.current)?;
    if observed_manifest != manifest {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_READBACK_MISMATCH",
            "atomic discovery manifest bytes differ after flush",
            "preserve the vault and inspect the physical manifest row",
        )
        .into());
    }
    if let Some(previous) = &pointer.previous {
        read_generation_manifest_target(&vault, commit.seq, kind, project, previous)?;
    }
    for (cf, key) in &retired_keys {
        verify_retired_tombstone(&vault, commit.seq, &physical_commit_rows, *cf, key, false)?;
    }
    if let Some(retention) = &cross_kind_retention {
        let observed = read_generation_pointer(&vault, commit.seq, "final", project)?
            .ok_or_else(|| ToolFault::new(
                "ASTRO_DISCOVERY_CROSS_RETENTION_POINTER_MISSING",
                "final pointer is absent after cross-kind retention",
                "preserve the vault and inspect the atomic prepared/final retention transaction",
            ))?;
        if observed != retention.pointer {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_CROSS_RETENTION_POINTER_MISMATCH",
                "final pointer differs after cross-kind retention",
                "preserve the vault and inspect the atomic prepared/final retention transaction",
            )
            .into());
        }
        read_generation_manifest_target(&vault, commit.seq, "final", project, &observed.current)?;
        for (cf, key) in &retention.retired_keys {
            verify_retired_tombstone(&vault, commit.seq, &physical_commit_rows, *cf, key, true)?;
        }
    }
    let ledger = verify_discovery_ledger(&vault, artifact_hash, &manifest)?;
    persistence_response("written", commit.seq, &stages, &ledger, None)
}

fn verify_retired_tombstone<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
    physical_commit_rows: &BTreeMap<
        ColumnFamily,
        BTreeMap<Vec<u8>, Option<&PhysicalCommitRowDigest>>,
    >,
    cf: ColumnFamily,
    key: &[u8],
    cross_kind: bool,
) -> Result<(), DynError>
where
    C: Clock,
{
    let (code, label, remediation) = if cross_kind {
        (
            "ASTRO_DISCOVERY_CROSS_RETENTION_READBACK_MISMATCH",
            "cross-retired",
            "preserve the vault and inspect the atomic prepared/final retention transaction",
        )
    } else {
        (
            "ASTRO_DISCOVERY_RETENTION_READBACK_MISMATCH",
            "retired",
            "preserve the vault and inspect the atomic retention transaction",
        )
    };
    if vault.read_cf_at(commit_seq, cf, key)?.is_some() {
        return Err(ToolFault::new(
            code,
            format!(
                "{label} {cf:?} row {} remains logically visible after its tombstone commit",
                hex_lower(key)
            ),
            remediation,
        )
        .into());
    }
    let physical = physical_commit_rows
        .get(&cf)
        .and_then(|rows| rows.get(key))
        .and_then(|row| *row)
        .ok_or_else(|| {
            ToolFault::new(
                code,
                format!(
                    "{label} {cf:?} row {} is absent or duplicated in the exact physical commit inventory",
                    hex_lower(key)
                ),
                remediation,
            )
        })?;
    let tombstone = tombstone_value();
    let tombstone_len = u64::try_from(tombstone.len()).map_err(|_| {
        ToolFault::new(
            code,
            "exact tombstone length cannot be represented in the physical commit inventory",
            remediation,
        )
    })?;
    if physical.key_sha256_hex() != sha256_hex_local(key)
        || !physical.tombstoned
        || physical.value_length != tombstone_len
        || physical.value_sha256_hex() != sha256_hex_local(&tombstone)
    {
        return Err(ToolFault::new(
            code,
            format!(
                "{label} {cf:?} row {} physical commit digest is not the exact tombstone: ordinal={} tombstoned={} value_bytes={} value_sha256={}",
                hex_lower(key),
                physical.ordinal,
                physical.tombstoned,
                physical.value_length,
                physical.value_sha256_hex(),
            ),
            remediation,
        )
        .into());
    }
    Ok(())
}

fn persisted_ledger_ref(ledger_ref: &LedgerRef) -> PersistedLedgerRef {
    PersistedLedgerRef {
        seq: ledger_ref.seq,
        hash: hex_lower(&ledger_ref.hash),
    }
}

#[allow(clippy::too_many_arguments)]
fn discovery_manifest(
    kind: &str,
    project: &str,
    source_generation_sha256: &str,
    prepared_artifact_sha256: &str,
    artifact_sha256: &str,
    request_identity_sha256: &str,
    stages: Vec<PersistedStage>,
    ledger_ref: PersistedLedgerRef,
    ledger_payload_sha256: &str,
    previous: Option<&PersistedDiscoveryPointerTarget>,
    retired: Option<&PersistedDiscoveryPointerTarget>,
) -> PersistedDiscoveryManifest {
    PersistedDiscoveryManifest {
        schema: DISCOVERY_PERSISTED_SCHEMA.to_string(),
        kind: kind.to_string(),
        project: project.to_string(),
        source_generation_sha256: source_generation_sha256.to_string(),
        prepared_artifact_sha256: prepared_artifact_sha256.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
        request_identity_sha256: request_identity_sha256.to_string(),
        stages,
        ledger_ref,
        ledger_payload_sha256: ledger_payload_sha256.to_string(),
        previous_artifact_sha256: previous.map(|target| target.artifact_sha256.clone()),
        retired_artifact_sha256: retired.map(|target| target.artifact_sha256.clone()),
        retention: DISCOVERY_RETENTION_CONTRACT.to_string(),
    }
}

fn discovery_pointer(
    kind: &str,
    project: &str,
    pointer_commit_seq: Seq,
    current: PersistedDiscoveryPointerTarget,
    previous: Option<PersistedDiscoveryPointerTarget>,
) -> PersistedDiscoveryPointer {
    PersistedDiscoveryPointer {
        schema: DISCOVERY_POINTER_SCHEMA.to_string(),
        kind: kind.to_string(),
        project: project.to_string(),
        pointer_commit_seq,
        current,
        retained_generation_count: usize::from(previous.is_some()) + 1,
        previous,
    }
}

fn validate_generation_budget(
    stages: &[StageRow],
    budgets: &AssociationDiscoveryBudgets,
    phase: &str,
) -> Result<(), DynError> {
    let mut identities = BTreeSet::new();
    let mut bytes = 0usize;
    for row in stages {
        if !identities.insert((row.cf, row.key.as_slice())) {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_DUPLICATE_ROW",
                format!("{phase} repeats {:?} row {}", row.cf, hex_lower(&row.key)),
                "repair the deterministic stage planner before publication",
            )
            .into());
        }
        bytes = bytes
            .checked_add(row.key.len())
            .and_then(|total| total.checked_add(row.bytes.len()))
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                    format!("{phase} byte count overflow"),
                    "narrow the generation before publication",
                )
            })?;
    }
    if stages.len() > budgets.max_generation_rows || bytes > budgets.max_generation_bytes {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_GENERATION_BUDGET_EXCEEDED",
            format!(
                "{phase} requires rows={}/{} key_plus_value_bytes={}/{}",
                stages.len(), budgets.max_generation_rows, bytes, budgets.max_generation_bytes
            ),
            "raise the explicit persistence budget with measured production evidence or narrow the generation",
        )
        .into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_complete_generation_budget(
    stages: &[StageRow],
    manifest_key: &[u8],
    manifest_bytes: &[u8],
    pointer_key: &[u8],
    pointer_bytes: &[u8],
    retired_keys: &[(ColumnFamily, Vec<u8>)],
    additional_rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)],
    ledger_payload_bytes: usize,
    budgets: &AssociationDiscoveryBudgets,
) -> Result<(), DynError> {
    let row_count = stages
        .len()
        .checked_add(2)
        .and_then(|count| count.checked_add(retired_keys.len()))
        .and_then(|count| count.checked_add(additional_rows.len()))
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                "complete generation row count overflow",
                "narrow the generation before publication",
            )
        })?;
    let tombstone_bytes = tombstone_value().len();
    let mut bytes = stages
        .iter()
        .try_fold(0usize, |total, row| {
            total
                .checked_add(row.key.len())
                .and_then(|value| value.checked_add(row.bytes.len()))
        })
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                "complete generation byte count overflow",
                "narrow the generation before publication",
            )
        })?;
    for component in [
        manifest_key.len(),
        manifest_bytes.len(),
        pointer_key.len(),
        pointer_bytes.len(),
        ledger_payload_bytes,
    ] {
        bytes = bytes.checked_add(component).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                "complete generation byte count overflow",
                "narrow the generation before publication",
            )
        })?;
    }
    for (_, key) in retired_keys {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|value| value.checked_add(tombstone_bytes))
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                    "retention tombstone byte count overflow",
                    "narrow the generation before publication",
                )
            })?;
    }
    for (_, key, value) in additional_rows {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                    "cross-kind retention byte count overflow",
                    "narrow the generation before publication",
                )
            })?;
    }
    if row_count > budgets.max_generation_rows || bytes > budgets.max_generation_bytes {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_GENERATION_BUDGET_EXCEEDED",
            format!(
                "complete atomic generation requires rows={row_count}/{} key_plus_value_and_ledger_payload_bytes={bytes}/{}",
                budgets.max_generation_rows, budgets.max_generation_bytes
            ),
            "raise the explicit persistence budget with measured production evidence or narrow the generation",
        )
        .into());
    }
    Ok(())
}

fn manifest_generation_keys(
    manifest: &PersistedDiscoveryManifest,
) -> Result<Vec<(ColumnFamily, Vec<u8>)>, DynError> {
    let mut keys = manifest
        .stages
        .iter()
        .map(|stage| {
            Ok((
                manifest_column_family(&stage.cf)?,
                decode_hex_local(&stage.key_hex)?,
            ))
        })
        .collect::<Result<Vec<_>, DynError>>()?;
    keys.push((
        ColumnFamily::Kernel,
        stage_key(
            &artifact_base(&manifest.kind, &manifest.artifact_sha256),
            "manifest",
        ),
    ));
    Ok(keys)
}

fn plan_cross_kind_retention<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    predicted_commit_seq: Seq,
    kind: &str,
    project: &str,
    retired_prepared: Option<&PersistedDiscoveryPointerTarget>,
) -> Result<Option<CrossKindRetention>, DynError> {
    if kind != "prepared" {
        return Ok(None);
    }
    let Some(retired_prepared) = retired_prepared else {
        return Ok(None);
    };
    let Some(final_pointer) = read_generation_pointer(vault, snapshot, "final", project)? else {
        return Ok(None);
    };
    let current_manifest =
        read_generation_manifest_target(vault, snapshot, "final", project, &final_pointer.current)?;
    if current_manifest.prepared_artifact_sha256 == retired_prepared.artifact_sha256 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_RETENTION_BLOCKED",
            format!(
                "prepared generation {} is still required by current final generation {}",
                retired_prepared.artifact_sha256, final_pointer.current.artifact_sha256
            ),
            "publish the current prepared generation first, then retry prepare so only the superseded final previous generation is retired",
        )
        .into());
    }
    let Some(previous_target) = final_pointer.previous.as_ref() else {
        return Ok(None);
    };
    let previous_manifest =
        read_generation_manifest_target(vault, snapshot, "final", project, previous_target)?;
    if previous_manifest.prepared_artifact_sha256 != retired_prepared.artifact_sha256 {
        return Ok(None);
    }
    let pointer = discovery_pointer(
        "final",
        project,
        predicted_commit_seq,
        final_pointer.current,
        None,
    );
    let pointer_key = generation_pointer_key("final", project);
    let pointer_bytes = serde_json::to_vec(&pointer)?;
    Ok(Some(CrossKindRetention {
        retired_artifact_sha256: previous_target.artifact_sha256.clone(),
        pointer,
        pointer_key,
        pointer_bytes,
        retired_keys: manifest_generation_keys(&previous_manifest)?,
    }))
}

fn read_generation_pointer<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    kind: &str,
    project: &str,
) -> Result<Option<PersistedDiscoveryPointer>, DynError> {
    if !matches!(kind, "prepared" | "final") || project.trim().is_empty() {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_GENERATION_KIND_INVALID",
            format!("discovery pointer kind/project is invalid: kind={kind:?} project={project:?}"),
            "read only exact prepared or final pointers for a non-empty project",
        )
        .into());
    }
    let Some(bytes) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kernel,
        &generation_pointer_key(kind, project),
    )?
    else {
        return Ok(None);
    };
    if is_tombstone_value(&bytes) {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_TOMBSTONED",
            format!("{kind} current pointer is tombstoned"),
            "preserve the vault and inspect the interrupted retention transaction",
        )
        .into());
    }
    let pointer: PersistedDiscoveryPointer = serde_json::from_slice(&bytes).map_err(|error| {
        ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_CORRUPT",
            format!("{kind} current pointer is invalid JSON: {error}"),
            "preserve the vault and inspect the exact physical pointer row",
        )
    })?;
    if pointer.schema != DISCOVERY_POINTER_SCHEMA
        || pointer.kind != kind
        || pointer.project != project
        || pointer.pointer_commit_seq > snapshot
        || pointer.retained_generation_count != usize::from(pointer.previous.is_some()) + 1
        || pointer.previous.as_ref().is_some_and(|previous| {
            previous == &pointer.current
                || previous.artifact_sha256 == pointer.current.artifact_sha256
        })
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_MISMATCH",
            format!(
                "{kind} current pointer violates its exact schema or current+previous contract"
            ),
            "preserve the vault and inspect the physical pointer and manifests",
        )
        .into());
    }
    if vault.seq_for_key_at(
        snapshot,
        ColumnFamily::Kernel,
        &generation_pointer_key(kind, project),
    )? != Some(pointer.pointer_commit_seq)
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_SEQUENCE_MISMATCH",
            format!("{kind} pointer was not last written by its declared current atomic commit"),
            "preserve the vault and inspect the physical pointer history",
        )
        .into());
    }
    Ok(Some(pointer))
}

fn retained_pointer_target<'a>(
    pointer: &'a PersistedDiscoveryPointer,
    artifact_sha256: &str,
) -> Option<&'a PersistedDiscoveryPointerTarget> {
    std::iter::once(&pointer.current)
        .chain(pointer.previous.as_ref())
        .find(|target| target.artifact_sha256 == artifact_sha256)
}

fn read_generation_manifest_target<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    kind: &str,
    project: &str,
    target: &PersistedDiscoveryPointerTarget,
) -> Result<PersistedDiscoveryManifest, DynError> {
    validate_hash(&target.artifact_sha256)?;
    validate_hash(&target.manifest_sha256)?;
    validate_hash(&target.ledger_ref.hash)?;
    let manifest_key = decode_hex_local(&target.manifest_key_hex)?;
    let expected_key = stage_key(&artifact_base(kind, &target.artifact_sha256), "manifest");
    if manifest_key != expected_key
        || target.commit_seq == 0
        || target.commit_seq > snapshot
        || target.ledger_ref.seq == 0
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_POINTER_TARGET_MISMATCH",
            format!("{kind} pointer target has an invalid manifest key or sequence"),
            "preserve the vault and inspect the pointer target identity",
        )
        .into());
    }
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_MISSING",
                format!(
                    "retained {kind} manifest {} is absent",
                    target.manifest_key_hex
                ),
                "preserve the vault and inspect the atomic publication",
            )
        })?;
    if is_tombstone_value(&bytes) || sha256_hex_local(&bytes) != target.manifest_sha256 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_HASH_MISMATCH",
            format!("retained {kind} manifest fails exact pointer byte/hash validation"),
            "preserve the vault and inspect the pointer plus physical manifest row",
        )
        .into());
    }
    if vault.seq_for_key_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        != Some(target.commit_seq)
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_SEQUENCE_MISMATCH",
            format!("retained {kind} manifest was not last written by its declared atomic commit"),
            "preserve the vault and inspect the physical manifest history",
        )
        .into());
    }
    let manifest: PersistedDiscoveryManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema != DISCOVERY_PERSISTED_SCHEMA
        || manifest.kind != kind
        || manifest.project != project
        || manifest.artifact_sha256 != target.artifact_sha256
        || manifest.ledger_ref != target.ledger_ref
        || manifest.ledger_ref.seq == 0
        || !validate_hash_bool(&manifest.source_generation_sha256)
        || !validate_hash_bool(&manifest.prepared_artifact_sha256)
        || !validate_hash_bool(&manifest.request_identity_sha256)
        || !validate_hash_bool(&manifest.ledger_payload_sha256)
        || manifest.retention != DISCOVERY_RETENTION_CONTRACT
        || (kind == "prepared" && manifest.prepared_artifact_sha256 != manifest.artifact_sha256)
        || manifest
            .previous_artifact_sha256
            .as_ref()
            .is_some_and(|hash| !validate_hash_bool(hash) || hash == &manifest.artifact_sha256)
        || manifest
            .retired_artifact_sha256
            .as_ref()
            .is_some_and(|hash| !validate_hash_bool(hash) || hash == &manifest.artifact_sha256)
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_IDENTITY_MISMATCH",
            format!("retained {kind} manifest violates its exact schema/hash/pointer contract"),
            "preserve the vault and inspect the manifest bytes",
        )
        .into());
    }
    verify_manifest_rows(vault, snapshot, target.commit_seq, &manifest)?;
    verify_discovery_ledger(vault, &target.artifact_sha256, &manifest)?;
    Ok(manifest)
}

fn verify_discovery_ledger<C: Clock>(
    vault: &AsterVault<C>,
    artifact_sha256: &str,
    manifest: &PersistedDiscoveryManifest,
) -> Result<LedgerRef, DynError> {
    let wanted = BTreeSet::from([manifest.ledger_ref.seq]);
    let (rows, _) = vault.read_physical_ledger_seqs(&wanted)?;
    let row = rows.get(&manifest.ledger_ref.seq).ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_LEDGER_UNPAIRED",
            format!("physical Ledger row {} is absent", manifest.ledger_ref.seq),
            "preserve the vault and inspect the atomic manifest/pointer/Ledger transaction",
        )
    })?;
    let entry = calyx_ledger::decode(&row.bytes)?;
    if row.seq != manifest.ledger_ref.seq
        || entry.seq != manifest.ledger_ref.seq
        || hex_lower(&entry.entry_hash) != manifest.ledger_ref.hash
        || !entry.verify()
        || entry.kind != calyx_ledger::EntryKind::Assay
        || entry.actor != ActorId::Service(DISCOVERY_ACTOR.to_string())
        || entry.subject != SubjectId::Kernel(artifact_sha256.as_bytes().to_vec())
        || sha256_hex_local(&entry.payload) != manifest.ledger_payload_sha256
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_LEDGER_CORRUPT",
            format!(
                "physical Ledger row {} violates its exact discovery binding",
                manifest.ledger_ref.seq
            ),
            "preserve the vault and inspect the point-read Ledger row plus manifest",
        )
        .into());
    }
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn read_prepared(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
    hash: &str,
) -> Result<PreparedReadback, DynError> {
    validate_hash(hash)?;
    let vault = open_shadow_vault_read_only(
        vault_dir,
        vault_id,
        vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Assay,
            ColumnFamily::Ledger,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let pointer =
        read_generation_pointer(&vault, snapshot, "prepared", project)?.ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_PREPARED_NOT_FOUND",
                format!("project {project:?} has no retained prepared generation"),
                "run mode=\"prepare\" and pass its physical artifact hash",
            )
        })?;
    for retained in std::iter::once(&pointer.current).chain(pointer.previous.as_ref()) {
        read_generation_manifest_target(&vault, snapshot, "prepared", project, retained)?;
    }
    let target = retained_pointer_target(&pointer, hash).ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_NOT_RETAINED",
            format!("prepared generation {hash} is not current or previous"),
            "use one of the bounded retained prepared generations or prepare again",
        )
    })?;
    let manifest = read_generation_manifest_target(&vault, snapshot, "prepared", project, target)?;
    let base = artifact_base("prepared", hash);
    let manifest_key = decode_hex_local(&target.manifest_key_hex)?;
    let manifest_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_PREPARED_NOT_FOUND",
                format!("prepared generation {hash} has no retained manifest"),
                "preserve the vault and inspect the bounded prepared pointer",
            )
        })?;
    if manifest.prepared_artifact_sha256 != hash || manifest.artifact_sha256 != hash {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_MANIFEST_MISMATCH",
            "prepared manifest disagrees with its schema, kind, project, or artifact identity",
            "preserve the vault and inspect the content-addressed prepared manifest",
        )
        .into());
    }
    let envelope_value =
        read_compact_artifact_value(&vault, snapshot, &base, hash, &PREPARED_STAGE_FIELDS)?;
    let prepared: PreparedAssociationDiscoveryEnvelope = serde_json::from_value(envelope_value)?;
    let physical_hash = sha256_hex_local(&canonical_artifact_bytes(&prepared.artifact)?);
    if physical_hash != hash {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_HASH_MISMATCH",
            format!("reconstructed prepared bytes rederive {physical_hash}, expected {hash}"),
            "preserve the vault and inspect the prepared header, descriptors, and chunks",
        )
        .into());
    }
    if prepared.artifact_sha256 != hash || prepared.artifact.project != project {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_IDENTITY_MISMATCH",
            "prepared row disagrees with its requested hash or project",
            "use the exact project/hash pair returned by prepare",
        )
        .into());
    }
    let source_manifest_hash =
        association_source_generation_sha256(&prepared.artifact.source_manifest)
            .map_err(domain_fault)?;
    if prepared.artifact.source_generation_sha256 != manifest.source_generation_sha256
        || source_manifest_hash != manifest.source_generation_sha256
        || prepared.artifact.source_manifest.project != project
        || prepared.artifact.source_manifest.schema
            != astrolabe_kernel::DISCOVERY_SOURCE_MANIFEST_SCHEMA
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_SOURCE_IDENTITY_MISMATCH",
            "prepared artifact and persisted manifest disagree on their exact source identity",
            "preserve the immutable prepared rows and inspect the source-manifest stage",
        )
        .into());
    }
    let ledger = verify_discovery_ledger(&vault, hash, &manifest)?;
    Ok(PreparedReadback {
        envelope: prepared,
        snapshot,
        manifest,
        manifest_stage: PersistedStage {
            cf: format!("{:?}", ColumnFamily::Kernel),
            name: "manifest".to_string(),
            key_hex: hex_lower(&manifest_key),
            sha256: sha256_hex_local(&manifest_bytes),
            bytes: manifest_bytes.len(),
        },
        ledger,
    })
}

fn read_discovery(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
    requested_hash: Option<&str>,
    section: &str,
) -> Result<Value, DynError> {
    let vault = open_shadow_vault_read_only(
        vault_dir,
        vault_id,
        vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Assay,
            ColumnFamily::Ledger,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let pointer =
        read_generation_pointer(&vault, snapshot, "final", project)?.ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_CURRENT_MISSING",
                format!("project {project:?} has no published discovery generation"),
                "prepare, capture genuine provider responses through the trusted operator boundary, and publish a generation first",
            )
        })?;
    for retained in std::iter::once(&pointer.current).chain(pointer.previous.as_ref()) {
        read_generation_manifest_target(&vault, snapshot, "final", project, retained)?;
    }
    let hash = match requested_hash.filter(|value| !value.is_empty()) {
        Some(hash) => {
            validate_hash(hash)?;
            hash.to_string()
        }
        None => pointer.current.artifact_sha256.clone(),
    };
    let target = retained_pointer_target(&pointer, &hash).ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_NOT_RETAINED",
            format!("final discovery generation {hash} is not current or previous"),
            "read one of the bounded retained final generations",
        )
    })?;
    let manifest = read_generation_manifest_target(&vault, snapshot, "final", project, target)?;
    let base = artifact_base("final", &hash);
    if manifest.artifact_sha256 != hash || manifest.project != project {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_IDENTITY_MISMATCH",
            "final artifact, manifest, project, or prepared generation identity disagrees",
            "preserve the vault and inspect the content-addressed final generation",
        )
        .into());
    }
    let envelope_value =
        read_compact_artifact_value(&vault, snapshot, &base, &hash, &FINAL_STAGE_FIELDS)?;
    let final_artifact: FinalAssociationDiscoveryEnvelope = serde_json::from_value(envelope_value)?;
    let nested_kernel_artifact_sha256 =
        verify_nested_kernel_artifact_hash(&final_artifact, "after physical final readback")?;
    if final_artifact.artifact_sha256 != hash
        || final_artifact.artifact.prepared_artifact_sha256 != manifest.prepared_artifact_sha256
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_IDENTITY_MISMATCH",
            "reconstructed final artifact disagrees with its manifest identity",
            "preserve the vault and inspect the final header, descriptors, and chunks",
        )
        .into());
    }
    let physical_hash = sha256_hex_local(&canonical_artifact_bytes(&final_artifact.artifact)?);
    if physical_hash != hash {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_HASH_MISMATCH",
            format!("physical final bytes rederive {physical_hash}, expected {hash}"),
            "preserve the vault and inspect the final artifact row",
        )
        .into());
    }
    let source_manifest_hash =
        association_source_generation_sha256(&final_artifact.artifact.source_manifest)
            .map_err(domain_fault)?;
    if final_artifact.artifact.source_manifest.schema
        != astrolabe_kernel::DISCOVERY_SOURCE_MANIFEST_SCHEMA
        || final_artifact.artifact.source_manifest.project != project
        || source_manifest_hash != manifest.source_generation_sha256
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_SOURCE_IDENTITY_MISMATCH",
            "final artifact source manifest is invalid or disagrees with its project",
            "preserve the immutable final generation and inspect its source-manifest stage",
        )
        .into());
    }
    let prepared_readback = read_prepared(
        vault_dir,
        vault_id,
        vault_salt,
        project,
        &manifest.prepared_artifact_sha256,
    )?;
    if prepared_readback.envelope.artifact.source_manifest
        != final_artifact.artifact.source_manifest
        || prepared_readback.envelope.artifact.evaluation_roster
            != final_artifact.artifact.evaluation_roster
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_PREPARED_BINDING_MISMATCH",
            "final source manifest or evaluator roster does not equal its exact prepared generation",
            "preserve both immutable generations and rebuild final publication from the exact prepared artifact",
        )
        .into());
    }
    let rederived_final = finalize_association_discovery(
        &prepared_readback.envelope,
        &final_artifact.artifact.evaluator_receipts,
    )
    .map_err(domain_fault)?;
    if rederived_final != final_artifact {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_SEMANTIC_READBACK_MISMATCH",
            "full receipt validation/finalization does not byte-for-byte rederive the persisted final envelope",
            "preserve the prepared/final rows and inspect the exact evaluator roster, requests, responses, and reasoning outputs",
        )
        .into());
    }
    let source_verified_snapshot = verify_current_source_binding(
        vault_dir,
        vault_id,
        vault_salt,
        &final_artifact.artifact.source_manifest,
        &prepared_readback.envelope.artifact.config,
        "final-read",
    )?;
    if prepared_readback.snapshot != snapshot || source_verified_snapshot != snapshot {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_CHANGED",
            format!(
                "final read crossed vault generations: final_read={snapshot} prepared_read={} source_verified={source_verified_snapshot}",
                prepared_readback.snapshot,
            ),
            "rerun read so final/prepared physical readback and exact current-source verification occur at one unchanged vault generation",
        )
        .into());
    }
    let ledger = verify_discovery_ledger(&vault, &hash, &manifest)?;
    let section_value = match section {
        "all" => serde_json::to_value(&final_artifact)?,
        "manifest" => serde_json::to_value(&manifest)?,
        "evaluator" => serde_json::to_value(&final_artifact.artifact.evaluator)?,
        "receipts" => serde_json::to_value(&final_artifact.artifact.evaluator_receipts)?,
        "roster" => serde_json::to_value(&final_artifact.artifact.evaluation_roster)?,
        "source" => serde_json::to_value(&final_artifact.artifact.source_manifest)?,
        "ranked" => serde_json::to_value(&final_artifact.artifact.ranked)?,
        "kernel" => serde_json::to_value(&final_artifact.artifact.reasoning_kernel)?,
        other => {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_SECTION_UNSUPPORTED",
                format!("read section {other:?} is unsupported"),
                "pass section as all, manifest, source, roster, receipts, evaluator, ranked, or kernel",
            )
            .into());
        }
    };
    Ok(json!({
        "schema": DISCOVERY_TOOL_SCHEMA,
        "status": "read",
        "project": project,
        "artifact_sha256": hash,
        "physical_readback_sha256": physical_hash,
        "kernel_artifact_sha256_readback": nested_kernel_artifact_sha256,
        "snapshot_seq": snapshot,
        "ledger_ref": {"seq": ledger.seq, "hash": hex_lower(&ledger.hash)},
        "section": section,
        "value": section_value,
    }))
}

fn compact_artifact_header<T: Serialize>(
    envelope: &T,
    expected_hash: &str,
    staged_fields: &[(&str, &str, ColumnFamily)],
) -> Result<(PersistedArtifactHeader, Vec<Value>), DynError> {
    let value = serde_json::to_value(envelope)?;
    let envelope_object = value.as_object().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_ENVELOPE_INVALID",
            "discovery envelope did not serialize as a JSON object",
            "preserve the generation and inspect its typed serialization contract",
        )
    })?;
    let artifact_sha256 = envelope_object
        .get("artifact_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_ENVELOPE_HASH_MISSING",
                "discovery envelope has no string artifact_sha256",
                "preserve the generation and inspect its typed serialization contract",
            )
        })?;
    if artifact_sha256 != expected_hash {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_ENVELOPE_HASH_MISMATCH",
            "discovery envelope hash disagrees with its persistence identity",
            "preserve the generation and inspect the producer hash contract",
        )
        .into());
    }
    let mut artifact_fields = envelope_object
        .get("artifact")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_ARTIFACT_FIELD_MISSING",
                "discovery envelope has no object artifact field",
                "preserve the generation and inspect its typed serialization contract",
            )
        })?;
    let mut values = Vec::with_capacity(staged_fields.len());
    for (field, _, _) in staged_fields {
        values.push(artifact_fields.remove(*field).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_ARTIFACT_STAGE_MISSING",
                format!("discovery artifact has no required staged field {field:?}"),
                "preserve the generation and repair the compact persistence field map",
            )
        })?);
    }
    Ok((
        PersistedArtifactHeader {
            schema: DISCOVERY_COMPACT_HEADER_SCHEMA.to_string(),
            artifact_sha256: expected_hash.to_string(),
            artifact_fields,
            staged_artifact_fields: staged_fields
                .iter()
                .map(|(field, _, _)| (*field).to_string())
                .collect(),
        },
        values,
    ))
}

fn stage_json_rows<T: Serialize>(
    cf: ColumnFamily,
    base: &[u8],
    name: &str,
    value: &T,
    budget: &mut GenerationAllocationBudget<'_>,
) -> Result<Vec<StageRow>, DynError> {
    budget.admit_json(name, value)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    stage_logical_bytes(cf, base, name, bytes)
}

struct CountingWriter {
    bytes: usize,
}

fn ensure_serialized_allocation_within_budget<T: Serialize>(
    name: &str,
    value: &T,
    budgets: &AssociationDiscoveryBudgets,
) -> Result<(), DynError> {
    let mut writer = CountingWriter { bytes: 0 };
    serde_json::to_writer_pretty(&mut writer, value)?;
    if writer.bytes > budgets.max_generation_bytes {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_GENERATION_BUDGET_EXCEEDED",
            format!(
                "{name} serialization would allocate {} bytes, exceeding caller generation budget {}",
                writer.bytes, budgets.max_generation_bytes
            ),
            "raise the explicit measured persistence budget or narrow the generation before retrying",
        )
        .into());
    }
    Ok(())
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized discovery byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct GenerationAllocationBudget<'a> {
    limits: &'a AssociationDiscoveryBudgets,
    admitted_rows: usize,
    admitted_logical_bytes: usize,
}

impl<'a> GenerationAllocationBudget<'a> {
    fn new(limits: &'a AssociationDiscoveryBudgets) -> Self {
        Self {
            limits,
            admitted_rows: 0,
            admitted_logical_bytes: 0,
        }
    }

    fn admit_json<T: Serialize>(&mut self, name: &str, value: &T) -> Result<(), DynError> {
        let mut writer = CountingWriter { bytes: 0 };
        serde_json::to_writer_pretty(&mut writer, value)?;
        let logical_bytes = writer.bytes.checked_add(1).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                format!("logical stage {name:?} byte count overflow"),
                "narrow the generation before persistence allocation",
            )
        })?;
        let physical_rows = if logical_bytes <= MAX_DISCOVERY_PHYSICAL_VALUE_BYTES {
            1
        } else {
            logical_bytes.div_ceil(MAX_DISCOVERY_PHYSICAL_VALUE_BYTES) + 1
        };
        let admitted_rows = self
            .admitted_rows
            .checked_add(physical_rows)
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                    "physical stage row count overflow",
                    "narrow the generation before persistence allocation",
                )
            })?;
        let admitted_bytes = self
            .admitted_logical_bytes
            .checked_add(logical_bytes)
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_GENERATION_BUDGET_OVERFLOW",
                    "logical stage byte count overflow",
                    "narrow the generation before persistence allocation",
                )
            })?;
        if admitted_rows > self.limits.max_generation_rows
            || admitted_bytes > self.limits.max_generation_bytes
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_GENERATION_BUDGET_EXCEEDED",
                format!(
                    "stage {name:?} would allocate rows={admitted_rows}/{} logical_bytes={admitted_bytes}/{}",
                    self.limits.max_generation_rows, self.limits.max_generation_bytes
                ),
                "raise the explicit measured persistence budget or narrow the generation before retrying",
            )
            .into());
        }
        self.admitted_rows = admitted_rows;
        self.admitted_logical_bytes = admitted_bytes;
        Ok(())
    }
}

fn physical_stage_json<T: Serialize>(
    cf: ColumnFamily,
    base: &[u8],
    name: &str,
    value: &T,
) -> Result<StageRow, DynError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_DISCOVERY_PHYSICAL_VALUE_BYTES {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_TOO_LARGE",
            format!(
                "physical stage {name:?} is {} bytes, above the {}-byte discovery row ceiling",
                bytes.len(),
                MAX_DISCOVERY_PHYSICAL_VALUE_BYTES
            ),
            "reduce physical row count per generation or introduce a separately rooted manifest tree",
        )
        .into());
    }
    Ok(StageRow {
        cf,
        name: name.to_string(),
        key: stage_key(base, name),
        bytes,
    })
}

fn stage_logical_bytes(
    cf: ColumnFamily,
    base: &[u8],
    name: &str,
    bytes: Vec<u8>,
) -> Result<Vec<StageRow>, DynError> {
    if bytes.len() <= MAX_DISCOVERY_PHYSICAL_VALUE_BYTES {
        return Ok(vec![StageRow {
            cf,
            name: name.to_string(),
            key: stage_key(base, name),
            bytes,
        }]);
    }
    let logical_bytes = bytes.len();
    let logical_sha256 = sha256_hex_local(&bytes);
    let mut chunks = Vec::with_capacity(logical_bytes.div_ceil(MAX_DISCOVERY_PHYSICAL_VALUE_BYTES));
    let mut chunk_rows = Vec::with_capacity(chunks.capacity());
    let mut bytes = bytes.into_iter();
    for ordinal in 0..chunks.capacity() {
        let chunk = bytes
            .by_ref()
            .take(MAX_DISCOVERY_PHYSICAL_VALUE_BYTES)
            .collect::<Vec<_>>();
        if chunk.is_empty() {
            break;
        }
        let chunk_name = format!("{name}:chunk:{ordinal:08}");
        let key = stage_key(base, &chunk_name);
        chunks.push(LogicalStageChunk {
            ordinal,
            key_hex: hex_lower(&key),
            sha256: sha256_hex_local(&chunk),
            bytes: chunk.len(),
        });
        chunk_rows.push(StageRow {
            cf,
            name: chunk_name,
            key,
            bytes: chunk,
        });
    }
    if bytes.next().is_some() {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_CHUNK_INTERNAL_OVERFLOW",
            format!("logical stage {name:?} was not exhausted by its computed chunk count"),
            "preserve the generation and inspect the discovery chunk planner",
        )
        .into());
    }
    let descriptor = LogicalStageDescriptor {
        schema: DISCOVERY_CHUNK_DESCRIPTOR_SCHEMA.to_string(),
        logical_name: name.to_string(),
        logical_sha256,
        logical_bytes,
        chunks,
    };
    let descriptor_row = physical_stage_json(cf, base, name, &descriptor)?;
    let mut rows = Vec::with_capacity(chunk_rows.len() + 1);
    rows.push(descriptor_row);
    rows.extend(chunk_rows);
    Ok(rows)
}

fn stage_manifest(row: &StageRow) -> PersistedStage {
    PersistedStage {
        cf: format!("{:?}", row.cf),
        name: row.name.to_string(),
        key_hex: hex_lower(&row.key),
        sha256: sha256_hex_local(&row.bytes),
        bytes: row.bytes.len(),
    }
}

fn read_compact_artifact_value<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    base: &[u8],
    expected_hash: &str,
    staged_fields: &[(&str, &str, ColumnFamily)],
) -> Result<Value, DynError> {
    let header_bytes = read_logical_stage(vault, snapshot, ColumnFamily::Kernel, base, "artifact")?;
    let mut header: PersistedArtifactHeader =
        serde_json::from_slice(&header_bytes).map_err(|error| {
            ToolFault::new(
                "ASTRO_DISCOVERY_COMPACT_HEADER_CORRUPT",
                format!("discovery compact header is invalid: {error}"),
                "preserve the vault and inspect the content-addressed artifact header",
            )
        })?;
    let expected_fields = staged_fields
        .iter()
        .map(|(field, _, _)| (*field).to_string())
        .collect::<Vec<_>>();
    if header.schema != DISCOVERY_COMPACT_HEADER_SCHEMA
        || header.artifact_sha256 != expected_hash
        || header.staged_artifact_fields != expected_fields
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_COMPACT_HEADER_MISMATCH",
            "discovery compact header disagrees with its schema, hash, or exact staged-field contract",
            "preserve the vault and inspect the artifact header plus manifest",
        )
        .into());
    }
    for (field, stage_name, cf) in staged_fields {
        if header.artifact_fields.contains_key(*field) {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_COMPACT_HEADER_DUPLICATE_FIELD",
                format!("compact header duplicates separately staged field {field:?}"),
                "preserve the vault and repair the compact persistence field map",
            )
            .into());
        }
        let bytes = read_logical_stage(vault, snapshot, *cf, base, stage_name)?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            ToolFault::new(
                "ASTRO_DISCOVERY_STAGE_JSON_CORRUPT",
                format!("logical stage {stage_name:?} is invalid JSON: {error}"),
                "preserve the vault and inspect the logical descriptor plus its physical chunks",
            )
        })?;
        header.artifact_fields.insert((*field).to_string(), value);
    }
    Ok(json!({
        "artifact_sha256": header.artifact_sha256,
        "artifact": Value::Object(header.artifact_fields),
    }))
}

fn read_logical_stage<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    cf: ColumnFamily,
    base: &[u8],
    name: &str,
) -> Result<Vec<u8>, DynError> {
    let logical_key = stage_key(base, name);
    let physical = vault
        .read_cf_at(snapshot, cf, &logical_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_STAGE_MISSING",
                format!(
                    "logical stage {name:?} is absent at {}",
                    hex_lower(&logical_key)
                ),
                "preserve the vault and inspect the generation manifest",
            )
        })?;
    if physical.len() > MAX_DISCOVERY_PHYSICAL_VALUE_BYTES {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PHYSICAL_STAGE_OVERSIZED",
            format!(
                "logical stage {name:?} has an unchunked {}-byte physical value",
                physical.len()
            ),
            "preserve the vault and republish through bounded logical-stage chunking",
        )
        .into());
    }
    let parsed: Value = serde_json::from_slice(&physical).map_err(|error| {
        ToolFault::new(
            "ASTRO_DISCOVERY_STAGE_JSON_CORRUPT",
            format!("logical stage {name:?} is invalid JSON: {error}"),
            "preserve the vault and inspect the generation manifest plus physical row",
        )
    })?;
    if parsed.get("schema").and_then(Value::as_str) != Some(DISCOVERY_CHUNK_DESCRIPTOR_SCHEMA) {
        return Ok(physical);
    }
    let descriptor: LogicalStageDescriptor = serde_json::from_value(parsed).map_err(|error| {
        ToolFault::new(
            "ASTRO_DISCOVERY_CHUNK_DESCRIPTOR_CORRUPT",
            format!("logical stage {name:?} descriptor is invalid: {error}"),
            "preserve the vault and inspect the descriptor bytes",
        )
    })?;
    let expected_chunk_count = descriptor
        .logical_bytes
        .div_ceil(MAX_DISCOVERY_PHYSICAL_VALUE_BYTES);
    if descriptor.logical_name != name
        || descriptor.logical_bytes <= MAX_DISCOVERY_PHYSICAL_VALUE_BYTES
        || descriptor.chunks.len() != expected_chunk_count
        || descriptor.chunks.is_empty()
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_CHUNK_DESCRIPTOR_MISMATCH",
            format!(
                "logical stage {name:?} descriptor has inconsistent name, size, or chunk count"
            ),
            "preserve the vault and inspect the descriptor/chunk generation",
        )
        .into());
    }
    let mut reconstructed = Vec::with_capacity(descriptor.logical_bytes);
    for (ordinal, chunk) in descriptor.chunks.iter().enumerate() {
        let expected_name = format!("{name}:chunk:{ordinal:08}");
        let expected_key = stage_key(base, &expected_name);
        if chunk.ordinal != ordinal || chunk.key_hex != hex_lower(&expected_key) {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_CHUNK_IDENTITY_MISMATCH",
                format!("logical stage {name:?} chunk {ordinal} has a mismatched ordinal or key"),
                "preserve the vault and inspect the descriptor/chunk identities",
            )
            .into());
        }
        let bytes = vault
            .read_cf_at(snapshot, cf, &expected_key)?
            .ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_CHUNK_MISSING",
                    format!("logical stage {name:?} chunk {ordinal} is absent"),
                    "preserve the vault and inspect the interrupted generation transaction",
                )
            })?;
        let expected_size = if ordinal + 1 == descriptor.chunks.len() {
            descriptor.logical_bytes - ordinal * MAX_DISCOVERY_PHYSICAL_VALUE_BYTES
        } else {
            MAX_DISCOVERY_PHYSICAL_VALUE_BYTES
        };
        if bytes.len() != chunk.bytes
            || bytes.len() != expected_size
            || bytes.len() > MAX_DISCOVERY_PHYSICAL_VALUE_BYTES
            || sha256_hex_local(&bytes) != chunk.sha256
        {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_CHUNK_HASH_MISMATCH",
                format!(
                    "logical stage {name:?} chunk {ordinal} failed size or SHA-256 verification"
                ),
                "preserve the vault and inspect the exact physical chunk row",
            )
            .into());
        }
        reconstructed.extend_from_slice(&bytes);
    }
    if reconstructed.len() != descriptor.logical_bytes
        || sha256_hex_local(&reconstructed) != descriptor.logical_sha256
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_LOGICAL_STAGE_HASH_MISMATCH",
            format!("logical stage {name:?} failed reconstructed size or SHA-256 verification"),
            "preserve the vault and inspect the ordered physical chunk stream",
        )
        .into());
    }
    Ok(reconstructed)
}

fn verify_manifest_rows<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    commit_seq: Seq,
    manifest: &PersistedDiscoveryManifest,
) -> Result<(), DynError> {
    let mut identities = BTreeSet::new();
    for stage in &manifest.stages {
        let cf = manifest_column_family(&stage.cf)?;
        let key = decode_hex_local(&stage.key_hex)?;
        if !identities.insert((cf, key.clone())) {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_DUPLICATE_ROW",
                format!("manifest repeats {} row {}", stage.cf, stage.key_hex),
                "preserve the vault and inspect the persisted manifest",
            )
            .into());
        }
        let bytes = vault.read_cf_at(snapshot, cf, &key)?.ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_ROW_MISSING",
                format!("manifested {} row {} is absent", stage.cf, stage.key_hex),
                "preserve the vault and inspect the interrupted group commit",
            )
        })?;
        if bytes.len() != stage.bytes || sha256_hex_local(&bytes) != stage.sha256 {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_ROW_MISMATCH",
                format!(
                    "manifested {} row {} failed byte/SHA-256 verification",
                    stage.cf, stage.key_hex
                ),
                "preserve the vault and inspect the exact physical row plus manifest",
            )
            .into());
        }
        if vault.seq_for_key_at(snapshot, cf, &key)? != Some(commit_seq) {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_ROW_SEQUENCE_MISMATCH",
                format!(
                    "manifested {} row {} was not last written by atomic commit {commit_seq}",
                    stage.cf, stage.key_hex
                ),
                "preserve the vault and inspect the immutable row history",
            )
            .into());
        }
    }
    Ok(())
}

fn manifest_column_family(name: &str) -> Result<ColumnFamily, DynError> {
    match name {
        "Kernel" => Ok(ColumnFamily::Kernel),
        "Assay" => Ok(ColumnFamily::Assay),
        other => Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_CF_UNSUPPORTED",
            format!("discovery manifest names unsupported column family {other:?}"),
            "preserve the vault and inspect the generation manifest",
        )
        .into()),
    }
}

fn decode_hex_local(value: &str) -> Result<Vec<u8>, DynError> {
    if !value.len().is_multiple_of(2) {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_KEY_INVALID",
            "manifest key hex has odd length",
            "preserve the vault and inspect the generation manifest",
        )
        .into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble_local(pair[0])?;
            let low = hex_nibble_local(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble_local(value: u8) -> Result<u8, DynError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ToolFault::new(
            "ASTRO_DISCOVERY_MANIFEST_KEY_INVALID",
            "manifest key contains non-lowercase-hexadecimal bytes",
            "preserve the vault and inspect the generation manifest",
        )
        .into()),
    }
}

fn artifact_base(kind: &str, hash: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(DISCOVERY_PREFIX.len() + kind.len() + hash.len() + 2);
    key.extend_from_slice(DISCOVERY_PREFIX);
    key.extend_from_slice(kind.as_bytes());
    key.push(b':');
    key.extend_from_slice(hash.as_bytes());
    key.push(b':');
    key
}

fn stage_key(base: &[u8], name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(base.len() + name.len());
    key.extend_from_slice(base);
    key.extend_from_slice(name.as_bytes());
    key
}

fn prepared_request_identity(
    project: &str,
    source_generation_sha256: &str,
    config: &AssociationDiscoveryConfig,
) -> Result<String, DynError> {
    let mut preimage = Vec::new();
    // Schema is a transitive input to every serialized stage. Binding it here
    // prevents a semantically obsolete prepared generation from satisfying a
    // newer request merely because source/config bytes are unchanged (PC-15).
    frame_local(&mut preimage, DISCOVERY_PREPARED_SCHEMA.as_bytes());
    frame_local(&mut preimage, project.as_bytes());
    frame_local(&mut preimage, source_generation_sha256.as_bytes());
    frame_local(&mut preimage, &serde_json::to_vec(config)?);
    Ok(sha256_hex_local(&preimage))
}

fn generation_pointer_key(kind: &str, project: &str) -> Vec<u8> {
    let mut key = DISCOVERY_PREFIX.to_vec();
    key.extend_from_slice(b"pointer:");
    key.extend_from_slice(kind.as_bytes());
    key.push(b':');
    key.extend_from_slice(sha256_hex_local(project.as_bytes()).as_bytes());
    key
}

fn persistence_response(
    state: &str,
    snapshot: Seq,
    stages: &[StageRow],
    ledger: &LedgerRef,
    fsv: Option<&astrolabe_domain::fsv::FsvAck>,
) -> Result<Value, DynError> {
    let readback = stages.iter().map(stage_manifest).collect::<Vec<_>>();
    Ok(json!({
        "schema": DISCOVERY_PERSISTED_SCHEMA,
        "state": state,
        "snapshot_seq": snapshot,
        "rows_read_back_verified": readback.len(),
        "stages": readback,
        "ledger_paired": true,
        "ledger_ref": {"seq": ledger.seq, "hash": hex_lower(&ledger.hash)},
        "fsv": fsv,
    }))
}

fn cached_prepared_persistence(readback: &PreparedReadback) -> Result<Value, DynError> {
    let mut stages = readback.manifest.stages.clone();
    stages.push(readback.manifest_stage.clone());
    Ok(json!({
        "schema": DISCOVERY_PERSISTED_SCHEMA,
        "state": "unchanged",
        "snapshot_seq": readback.snapshot,
        "rows_read_back_verified": stages.len(),
        "stages": stages,
        "ledger_paired": true,
        "ledger_ref": {
            "seq": readback.ledger.seq,
            "hash": hex_lower(&readback.ledger.hash),
        },
        "fsv": Value::Null,
    }))
}

fn signature_or_shape(node: &astrolabe_ingest::CbmGraphNode) -> Result<String, DynError> {
    let properties: Value = serde_json::from_str(&node.properties_json)?;
    let object = properties.as_object().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_NODE_PROPERTIES_INVALID",
            format!(
                "node {} properties are not a JSON object",
                node.qualified_name
            ),
            "repair the persisted node properties before normalization",
        )
    })?;
    for key in ["signature", "shape", "type", "return_type"] {
        if let Some(value) = object.get(key) {
            let value = value.as_str().ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_NODE_PROPERTIES_INVALID",
                    format!(
                        "node {} property {key:?} must be a string when present, observed {}",
                        node.qualified_name,
                        value_type_name(value)
                    ),
                    "repair the persisted node property type before normalization",
                )
            })?;
            if !value.is_empty() {
                return Ok(format!("{key}:{value}"));
            }
        }
    }
    Ok(String::new())
}

fn language_from_path(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!("extension:{extension}"))
        .unwrap_or_default()
}

fn edge_family(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::SimilarTo | EdgeKind::SemanticallyRelated => "semantic",
        EdgeKind::FileChangesWith => "temporal",
        _ => "structural",
    }
}

fn canonical_artifact_bytes<T: Serialize>(artifact: &T) -> Result<Vec<u8>, DynError> {
    let mut canonical = serde_json::to_vec_pretty(artifact)?;
    canonical.push(b'\n');
    Ok(canonical)
}

fn frame_local(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn sha256_hex_local(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn verify_nested_kernel_artifact_hash(
    final_artifact: &FinalAssociationDiscoveryEnvelope,
    stage: &str,
) -> Result<String, DynError> {
    let reasoning_kernel = &final_artifact.artifact.reasoning_kernel;
    let observed = sha256_hex_local(&reasoning_kernel.kernel_artifact.kernel_json_bytes());
    if observed != reasoning_kernel.kernel_artifact_sha256 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_KERNEL_ARTIFACT_HASH_MISMATCH",
            format!(
                "{stage}: nested kernel artifact SHA-256 mismatch: expected={} observed={} scope={} members_hash={}",
                reasoning_kernel.kernel_artifact_sha256,
                observed,
                reasoning_kernel.kernel_artifact.scope_id,
                reasoning_kernel.kernel_artifact.members_hash,
            ),
            "preserve the prepared/final generation and rebuild the compact reasoning kernel from the exact hash-bound source; never publish or serve an envelope whose nested kernel bytes do not match their declared SHA-256",
        )
        .into());
    }
    let member_set = reasoning_kernel
        .member_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let artifact_member_ids = reasoning_kernel
        .kernel_artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let artifact_members = artifact_member_ids.iter().copied().collect::<BTreeSet<_>>();
    let reasoning_roster = final_artifact
        .artifact
        .ranked
        .hypotheses
        .iter()
        .flat_map(|hypothesis| [hypothesis.a, hypothesis.b, hypothesis.c])
        .collect::<BTreeSet<_>>();
    let expected_support = reasoning_roster
        .difference(&member_set)
        .copied()
        .collect::<Vec<_>>();
    let mut expected_edges = reasoning_kernel.retained_typed_edges.clone();
    expected_edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    let edge_ids = expected_edges
        .iter()
        .map(|edge| edge.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let edge_sha256 = sha256_hex_local(&canonical_artifact_bytes(&expected_edges)?);
    let source_generation_sha256 =
        association_source_generation_sha256(&final_artifact.artifact.source_manifest)
            .map_err(domain_fault)?;
    if reasoning_kernel.member_ids != member_set.iter().copied().collect::<Vec<_>>()
        || member_set != artifact_members
        || reasoning_kernel.member_ids != artifact_member_ids
        || reasoning_kernel.members_hash
            != astrolabe_kernel::members_hash(&reasoning_kernel.member_ids)
        || reasoning_kernel.members_hash != reasoning_kernel.kernel_artifact.members_hash
        || !member_set.is_subset(&reasoning_roster)
        || reasoning_kernel.support_ids != expected_support
        || reasoning_kernel.reasoning_roster_hash
            != astrolabe_kernel::discovery_member_roster_hash(
                &reasoning_roster.iter().copied().collect::<Vec<_>>(),
            )
        || expected_edges != reasoning_kernel.retained_typed_edges
        || edge_ids.len() != expected_edges.len()
        || expected_edges.iter().any(|edge| {
            edge.evidence_id.trim().is_empty()
                || !member_set.contains(&edge.src)
                || !member_set.contains(&edge.dst)
                || edge.source_generation_sha256 != source_generation_sha256
        })
        || edge_sha256 != reasoning_kernel.retained_typed_edges_sha256
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_REASONING_CLOSURE_MISMATCH",
            format!(
                "{stage}: final discovery member/core/support/typed-edge closure or hash mismatch"
            ),
            "preserve the final generation and rebuild it so every retained edge endpoint belongs to the exact sorted member roster and every member/edge hash rederives",
        )
        .into());
    }
    Ok(observed)
}

fn validate_hash(hash: &str) -> Result<(), DynError> {
    if !validate_hash_bool(hash) {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_HASH_INVALID",
            "discovery artifact hash must be exactly 64 lowercase hexadecimal characters",
            "copy the physical artifact hash returned by prepare or publish",
        )
        .into());
    }
    Ok(())
}

fn validate_hash_bool(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn domain_fault(error: astrolabe_domain::DomainError) -> ToolFault {
    ToolFault::new(error.code(), error.message(), error.remediation())
}

fn discovery_refusal(code: &str, message: String, remediation: &str) -> Value {
    ToolFault::new(code, message, remediation).envelope()
}

fn discovery_optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, ToolFault> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(value) => Err(ToolFault::new(
            "ASTRO_DISCOVERY_ARGUMENT_TYPE_INVALID",
            format!(
                "discover_associations field {field:?} must be a string when present, observed {}",
                value_type_name(value)
            ),
            "pass the field using the exact type declared by the tool inputSchema",
        )),
    }
}

fn discovery_optional_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, ToolFault> {
    match object.get(field) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_ARGUMENT_TYPE_INVALID",
                format!(
                    "discover_associations field {field:?} must be a non-negative integer when present, observed {}",
                    value_type_name(value)
                ),
                "pass the field using the exact type declared by the tool inputSchema",
            )
        }),
    }
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_u64() => "non-negative integer",
        Value::Number(number) if number.is_i64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn reject_discovery_fields(
    object: &serde_json::Map<String, Value>,
    mode: &str,
    allowed: &[&str],
) -> Result<(), ToolFault> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    let mut unexpected = object
        .keys()
        .map(String::as_str)
        .filter(|field| !allowed.contains(field))
        .collect::<Vec<_>>();
    unexpected.sort_unstable();
    if unexpected.is_empty() {
        return Ok(());
    }
    Err(ToolFault::new(
        "ASTRO_DISCOVERY_ARGUMENT_UNEXPECTED",
        format!("discover_associations mode {mode:?} does not accept fields {unexpected:?}"),
        "remove fields that are not consumed by the selected mode; prepare declares configuration, publish submits only the exact prepared hash and receipts, and read selects only a final hash/section",
    ))
}

pub(crate) fn handle_discover_associations(args_json: &str) -> Result<String, DynError> {
    let args: Value = serde_json::from_str(args_json)?;
    let object = args.as_object().ok_or_else(|| {
        ToolFault::new(
            "ASTRO_DISCOVERY_ARGUMENTS_INVALID",
            "discover_associations arguments must be a JSON object",
            "pass an object matching the tool inputSchema",
        )
    })?;
    let project = discovery_optional_string(object, "project")?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_PROJECT_REQUIRED",
                "discover_associations requires project",
                "pass the exact indexed CBM project name",
            )
        })?;
    let mode = discovery_optional_string(object, "mode")?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_MODE_REQUIRED",
                "discover_associations requires an explicit mode",
                "pass mode as prepare, publish, or read",
            )
        })?;
    match mode {
        "prepare" => reject_discovery_fields(
            object,
            mode,
            &[
                "project",
                "mode",
                "workers",
                "cross_validation_folds",
                "top_k",
                "max_intermediary_degree",
                "min_shared_intermediaries",
                "evaluator_declarations",
                "budgets",
            ],
        )?,
        "publish" => reject_discovery_fields(
            object,
            mode,
            &[
                "project",
                "mode",
                "prepared_artifact_sha256",
                "evaluator_receipts",
            ],
        )?,
        "read" => reject_discovery_fields(
            object,
            mode,
            &["project", "mode", "prepared_artifact_sha256", "section"],
        )?,
        _ => {}
    }
    let prepared_hash = discovery_optional_string(object, "prepared_artifact_sha256")?;
    let section = discovery_optional_string(object, "section")?;
    let mut config = AssociationDiscoveryConfig::default();
    if let Some(value) = object.get("budgets") {
        config.budgets = Some(
            serde_json::from_value::<AssociationDiscoveryBudgets>(value.clone()).map_err(
                |error| {
                    ToolFault::new(
                        "ASTRO_DISCOVERY_BUDGETS_INVALID",
                        format!("budgets do not match the exact mandatory schema: {error}"),
                        "pass every positive evaluator and persistence budget with no extra fields",
                    )
                },
            )?,
        );
    }
    if let Some(value) = object.get("evaluator_declarations") {
        config.evaluator_declarations = serde_json::from_value::<Vec<EvaluatorDeclaration>>(
            value.clone(),
        )
        .map_err(|error| {
            ToolFault::new(
                "ASTRO_DISCOVERY_EVALUATOR_DECLARATIONS_INVALID",
                format!("evaluator_declarations do not match the exact schema: {error}"),
                "pass a non-empty array of exact evaluator/model/prompt/temperature declarations",
            )
        })?;
    }
    if let Some(value) = discovery_optional_u64(object, "workers")? {
        config.workers = usize::try_from(value)?;
    }
    if let Some(value) = discovery_optional_u64(object, "cross_validation_folds")? {
        config.cross_validation_folds = usize::try_from(value)?;
    }
    if let Some(value) = discovery_optional_u64(object, "top_k")? {
        config.latent_top_k = value;
        config.cross_validation_top_k = usize::try_from(value)?;
    }
    if let Some(value) = discovery_optional_u64(object, "max_intermediary_degree")? {
        config.max_intermediary_degree = value;
    }
    if let Some(value) = discovery_optional_u64(object, "min_shared_intermediaries")? {
        config.min_shared_intermediaries = value;
    }
    let evaluator_receipts = object.get("evaluator_receipts").cloned();
    match mode {
        "prepare" if config.evaluator_declarations.is_empty() => {
            return tool_json_error_result(
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_DECLARATIONS_REQUIRED",
                    "prepare requires a non-empty exact evaluator_declarations roster",
                    "declare every evaluator/model/prompt/temperature variant before candidate preparation",
                )
                .envelope(),
            );
        }
        "prepare" if config.budgets.is_none() => {
            return tool_json_error_result(
                ToolFault::new(
                    "ASTRO_DISCOVERY_BUDGETS_REQUIRED",
                    "prepare requires explicit caller-owned evaluator and persistence budgets",
                    "pass max binding, per/total request, per/total response, and generation row/byte budgets; no defaults exist",
                )
                .envelope(),
            );
        }
        "prepare" if evaluator_receipts.is_some() => {
            return tool_json_error_result(
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_UNEXPECTED",
                    "prepare does not accept evaluator_receipts",
                    "prepare first, invoke the returned exact roster, then submit receipts in publish mode",
                )
                .envelope(),
            );
        }
        "publish" if !config.evaluator_declarations.is_empty() => {
            return tool_json_error_result(
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_DECLARATIONS_UNEXPECTED",
                    "publish uses the declarations frozen in the prepared artifact",
                    "remove evaluator_declarations and submit only the exact prepared hash plus receipts",
                )
                .envelope(),
            );
        }
        _ => {}
    }
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match discover_associations_json_at(
        &cache_dir,
        project,
        mode,
        prepared_hash,
        section,
        config,
        evaluator_receipts,
    ) {
        Ok(value) if value.get("status").and_then(Value::as_str) == Some("error") => {
            tool_json_error_result(value)
        }
        Ok(value) => tool_json_result(value),
        Err(error) => {
            if let Some(result) = tool_fault_result_from_error(error.as_ref()) {
                result
            } else {
                Err(error)
            }
        }
    }
}
