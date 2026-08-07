//! Production `discover_associations` surface for the complete association
//! discovery generation (#1012).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use astrolabe_domain::{EdgeKind, TrustTag};
use astrolabe_kernel::{
    AssociationCompletenessWitness, AssociationDiscoveryConfig, AssociationDiscoveryInput,
    DiscoveryConceptInput, DiscoveryTypedEdgeInput, EvaluatorRun,
    FinalAssociationDiscoveryEnvelope, PreparedAssociationDiscoveryEnvelope,
    finalize_association_discovery, prepare_association_discovery,
};
use calyx_core::Seq;
use serde::{Deserialize, Serialize};

use super::*;

const DISCOVERY_TOOL_SCHEMA: &str = "astrolabe.discover_associations.v1";
const DISCOVERY_PERSISTED_SCHEMA: &str = "astrolabe.association_discovery.persisted.v1";
const DISCOVERY_COMPACT_HEADER_SCHEMA: &str = "astrolabe.association_discovery.compact_header.v1";
const DISCOVERY_CHUNK_DESCRIPTOR_SCHEMA: &str =
    "astrolabe.association_discovery.chunk_descriptor.v1";
const DISCOVERY_PREFIX: &[u8] = b"astrolabe:association-discovery:v1:";
const DISCOVERY_ACTOR: &str = "astrolabe-association-discovery";
// Calyx's default memtable admits rows up to 8 MiB. Keep every physical
// discovery value below half that ceiling so keys and future framing overhead
// cannot turn a valid logical artifact into an unwriteable physical row.
const MAX_DISCOVERY_PHYSICAL_VALUE_BYTES: usize = 4 * 1024 * 1024;

const PREPARED_STAGE_FIELDS: [(&str, &str, ColumnFamily); 7] = [
    ("normalized_concepts", "concept_map", ColumnFamily::Kernel),
    ("typed_edges", "typed_edges", ColumnFamily::Kernel),
    ("latent", "latent", ColumnFamily::Kernel),
    ("spectral", "spectral", ColumnFamily::Kernel),
    ("walks", "walks", ColumnFamily::Kernel),
    ("candidates", "candidates", ColumnFamily::Assay),
    ("validation", "validation", ColumnFamily::Assay),
];

const FINAL_STAGE_FIELDS: [(&str, &str, ColumnFamily); 3] = [
    ("evaluator", "evaluator", ColumnFamily::Assay),
    ("ranked", "ranked", ColumnFamily::Kernel),
    ("reasoning_kernel", "reasoning_kernel", ColumnFamily::Kernel),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedStage {
    cf: String,
    name: String,
    key_hex: String,
    sha256: String,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedDiscoveryManifest {
    schema: String,
    kind: String,
    project: String,
    source_generation_sha256: String,
    prepared_artifact_sha256: String,
    artifact_sha256: String,
    stages: Vec<PersistedStage>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct PersistedArtifactHeader {
    schema: String,
    artifact_sha256: String,
    artifact_fields: serde_json::Map<String, Value>,
    staged_artifact_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LogicalStageChunk {
    ordinal: usize,
    key_hex: String,
    sha256: String,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    evaluator_runs: Option<BTreeMap<String, Vec<EvaluatorRun>>>,
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
                load_discovery_input(&vault_dir, &vault_id, &vault_salt, project)?;
            let request_key =
                prepared_request_key(project, &input.source_generation_sha256, &config)?;
            let cached = read_cached_prepared(
                &vault_dir,
                &vault_id,
                &vault_salt,
                project,
                &input.source_generation_sha256,
                &config,
                &request_key,
            )?;
            let prepared_cache_hit = cached.is_some();
            let (prepared, persistence) = match cached {
                Some(cached) => {
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
                        &request_key,
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
                    "worker_pool_reused": prepared.artifact.worker_pool_reused,
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
            let evaluator_runs = evaluator_runs.ok_or_else(|| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_EVALUATOR_REQUIRED",
                    "publish requires independent evaluator_runs",
                    "provide at least two prompt variants and two temperature variants for every evaluated hypothesis, citing only prepared evidence ids",
                )
            })?;
            let final_artifact =
                finalize_association_discovery(&prepared, &evaluator_runs).map_err(domain_fault)?;
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

fn load_discovery_input(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
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
    let complete = astrolabe_weave::read_complete_association_state_at(&vault, snapshot)?;
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
        let structured = format!(
            "kind={} qualified_name={} file={} span={}:{}-{}:{} properties={}",
            node.label,
            node.qualified_name,
            node.file_path,
            node.start_line,
            node.start_byte,
            node.end_line,
            node.end_byte,
            node.properties_json
        );
        let source_excerpt = if node.source_bytes.is_empty() {
            structured.clone()
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
            sha256_hex_local(structured.as_bytes())
        } else {
            node.source_sha256.clone()
        };
        let signature_or_shape = signature_or_shape(node)?;
        concepts.push(DiscoveryConceptInput {
            cx_id: projection_node.id,
            symbol_kind: node.label.clone(),
            language: language_from_path(&node.file_path),
            qualified_name: node.qualified_name.clone(),
            signature_or_shape,
            file_path: if node.file_path.is_empty() {
                format!("<structural:{}>", node.label)
            } else {
                node.file_path.clone()
            },
            source_sha256,
            source_excerpt,
            frequency: projection_node.weight.max(1.0).round() as u64,
            anchor_trust: anchors.get(&projection_node.id).copied(),
        });
    }
    concepts.sort_by_key(|concept| concept.cx_id);

    let mut source_generation_preimage = Vec::new();
    frame_local(
        &mut source_generation_preimage,
        &csr.source_fingerprint_blake3,
    );
    frame_local(
        &mut source_generation_preimage,
        complete.witness_state_hash.as_bytes(),
    );
    frame_local(
        &mut source_generation_preimage,
        complete.pair_key_stream_hash.as_bytes(),
    );
    frame_local(
        &mut source_generation_preimage,
        complete.pair_value_stream_hash.as_bytes(),
    );
    for concept in &concepts {
        frame_local(&mut source_generation_preimage, concept.cx_id.as_bytes());
        frame_local(
            &mut source_generation_preimage,
            concept.source_sha256.as_bytes(),
        );
        frame_local(
            &mut source_generation_preimage,
            concept
                .anchor_trust
                .map(TrustTag::as_str)
                .unwrap_or("absent")
                .as_bytes(),
        );
    }
    let source_generation_sha256 = sha256_hex_local(&source_generation_preimage);
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
                    "edge:{source_generation_sha256}:{src}:{}:{}:{offset}",
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
                temporal_direction: (kind == EdgeKind::FileChangesWith)
                    .then(|| "recurring".to_string()),
                observed_at_millis: None,
                ledger_ref: ledger_ref.clone(),
                provenance: vec![
                    format!("projection=kernel_graph snapshot={snapshot}"),
                    format!("edge_kind={}", kind.as_str()),
                    format!("ledger_ref={ledger_ref}"),
                    if family == "semantic" {
                        "cross_term_family=encoded_or_embedded_slot_similarity".to_string()
                    } else {
                        "cross_term_family=not_applicable".to_string()
                    },
                ],
                source_generation_sha256: source_generation_sha256.clone(),
            });
        }
    }
    typed_edges.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    let source_seq = typed_edges
        .iter()
        .filter_map(|edge| edge.ledger_ref.split_once(':'))
        .filter_map(|(seq, _)| seq.parse::<u64>().ok())
        .max()
        .unwrap_or(0);
    if source_seq == 0 {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_LEDGER_MISSING",
            "no positive ledger sequence exists in the composite relationship graph",
            "rebuild the projection from ledger-attested association rows",
        )
        .into());
    }
    Ok((
        AssociationDiscoveryInput {
            project: project.to_string(),
            source_seq,
            source_generation_sha256,
            concepts,
            typed_edges,
            completeness: AssociationCompletenessWitness {
                constellation_count: complete.constellation_count as u64,
                source_slot_count: complete.source_slot_count as u64,
                pair_count: complete.completion_row_count as u64,
                completion_witness_state_hash: complete.witness_state_hash,
                xterm_key_stream_hash: complete.pair_key_stream_hash,
                xterm_value_stream_hash: complete.pair_value_stream_hash,
            },
        },
        snapshot,
    ))
}

fn persist_prepared(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    expected_seq: Seq,
    request_key: &[u8],
    prepared: &PreparedAssociationDiscoveryEnvelope,
) -> Result<Value, DynError> {
    let hash = &prepared.artifact_sha256;
    let base = artifact_base("prepared", hash);
    let (header, staged_values) = compact_artifact_header(prepared, hash, &PREPARED_STAGE_FIELDS)?;
    let mut rows = stage_json_rows(ColumnFamily::Kernel, &base, "artifact", &header)?;
    for ((_, stage_name, cf), value) in PREPARED_STAGE_FIELDS.iter().zip(staged_values) {
        rows.extend(stage_json_rows(*cf, &base, stage_name, &value)?);
    }
    rows.push(StageRow {
        cf: ColumnFamily::Kernel,
        name: "prepared_request_pointer".to_string(),
        key: request_key.to_vec(),
        bytes: prepared.artifact_sha256.as_bytes().to_vec(),
    });
    persist_generation(
        vault_dir,
        vault_id,
        vault_salt,
        expected_seq,
        "prepared",
        &prepared.artifact.project,
        &prepared.artifact.source_generation_sha256,
        hash,
        hash,
        rows,
        None,
    )
}

fn read_cached_prepared(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    project: &str,
    source_generation_sha256: &str,
    config: &AssociationDiscoveryConfig,
    request_key: &[u8],
) -> Result<Option<PreparedReadback>, DynError> {
    let pointer = {
        let vault = open_shadow_vault_read_only(
            vault_dir,
            vault_id,
            vault_salt,
            vec![ColumnFamily::Kernel],
        )?;
        vault.read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, request_key)?
    };
    let Some(pointer) = pointer else {
        return Ok(None);
    };
    let hash = String::from_utf8(pointer).map_err(|error| {
        ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_POINTER_CORRUPT",
            format!("prepared cache pointer is not UTF-8: {error}"),
            "preserve the vault and inspect the content-addressed prepared pointer",
        )
    })?;
    let prepared = read_prepared(vault_dir, vault_id, vault_salt, project, &hash)?;
    if prepared.envelope.artifact.source_generation_sha256 != source_generation_sha256
        || &prepared.envelope.artifact.config != config
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_POINTER_MISMATCH",
            "prepared cache pointer disagrees with its source generation or configuration",
            "preserve the vault and inspect the request pointer plus prepared artifact bytes",
        )
        .into());
    }
    Ok(Some(prepared))
}

fn persist_final(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    expected_seq: Seq,
    prepared: &PreparedAssociationDiscoveryEnvelope,
    final_artifact: &FinalAssociationDiscoveryEnvelope,
) -> Result<Value, DynError> {
    let hash = &final_artifact.artifact_sha256;
    let base = artifact_base("final", hash);
    let (header, staged_values) =
        compact_artifact_header(final_artifact, hash, &FINAL_STAGE_FIELDS)?;
    let mut rows = stage_json_rows(ColumnFamily::Kernel, &base, "artifact", &header)?;
    for ((_, stage_name, cf), value) in FINAL_STAGE_FIELDS.iter().zip(staged_values) {
        rows.extend(stage_json_rows(*cf, &base, stage_name, &value)?);
    }
    rows.extend(stage_json_rows(
        ColumnFamily::Assay,
        &base,
        "validation",
        &prepared.artifact.validation,
    )?);
    persist_generation(
        vault_dir,
        vault_id,
        vault_salt,
        expected_seq,
        "final",
        &prepared.artifact.project,
        &prepared.artifact.source_generation_sha256,
        &prepared.artifact_sha256,
        hash,
        rows,
        Some(current_key(&prepared.artifact.project)),
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_generation(
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    expected_seq: Seq,
    kind: &str,
    project: &str,
    source_generation_sha256: &str,
    prepared_hash: &str,
    artifact_hash: &str,
    mut stages: Vec<StageRow>,
    current_pointer_key: Option<Vec<u8>>,
) -> Result<Value, DynError> {
    let base = artifact_base(kind, artifact_hash);
    let manifest = PersistedDiscoveryManifest {
        schema: DISCOVERY_PERSISTED_SCHEMA.to_string(),
        kind: kind.to_string(),
        project: project.to_string(),
        source_generation_sha256: source_generation_sha256.to_string(),
        prepared_artifact_sha256: prepared_hash.to_string(),
        artifact_sha256: artifact_hash.to_string(),
        stages: stages.iter().map(stage_manifest).collect(),
    };
    let manifest_row = physical_stage_json(ColumnFamily::Kernel, &base, "manifest", &manifest)?;
    let manifest_bytes = manifest_row.bytes.clone();
    stages.push(manifest_row);
    if let Some(key) = current_pointer_key {
        stages.push(StageRow {
            cf: ColumnFamily::Kernel,
            name: "current_pointer".to_string(),
            key,
            bytes: artifact_hash.as_bytes().to_vec(),
        });
    }
    let vault = open_shadow_vault_writable(vault_dir, vault_id, vault_salt, Vec::new())?;
    let current_seq = vault.latest_seq();
    if current_seq != expected_seq {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_SOURCE_CHANGED",
            format!("vault advanced from retained snapshot {expected_seq} to {current_seq} before {kind} publication"),
            "rerun the operation against the new exact source; no partial generation was published",
        )
        .into());
    }
    let existing = stages
        .iter()
        .map(|row| {
            vault
                .read_cf_at(current_seq, row.cf, &row.key)
                .map(|value| (row, value))
        })
        .collect::<calyx_core::Result<Vec<_>>>()?;
    let immutable = existing
        .iter()
        .filter(|(row, _)| row.name != "current_pointer")
        .collect::<Vec<_>>();
    let all_exact = immutable
        .iter()
        .all(|(row, value)| value.as_deref() == Some(row.bytes.as_slice()));
    let any_present = immutable.iter().any(|(_, value)| value.is_some());
    if any_present && !all_exact {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PERSISTED_PARTIAL_OR_DRIFTED",
            format!("{kind} generation {artifact_hash} has a partial or byte-different persisted row set"),
            "preserve the vault and inspect the stage manifest/readback hashes before retrying",
        )
        .into());
    }
    if all_exact {
        let ledger = find_discovery_ledger(
            &vault,
            current_seq,
            artifact_hash.as_bytes(),
            &manifest_bytes,
        )?;
        return persistence_response("unchanged", current_seq, &stages, &ledger, None);
    }
    let actor = ActorId::Service(DISCOVERY_ACTOR.to_string());
    let subject = SubjectId::Kernel(artifact_hash.as_bytes().to_vec());
    let mut plan = astrolabe_ingest::VaultMutationPlan::new(
        format!("association-discovery:{kind}:{artifact_hash}"),
        calyx_ledger::EntryKind::Assay,
        &actor,
        &subject,
    );
    let rows = stages
        .iter()
        .map(|row| {
            plan.push_content(row.cf, row.key.clone(), &row.bytes);
            (row.cf, row.key.clone(), row.bytes.clone())
        })
        .collect::<Vec<_>>();
    let (commit_seq, ledger) = vault.write_cf_batch_with_ledger_entry_if_seq(
        current_seq,
        rows,
        calyx_ledger::EntryKind::Assay,
        subject,
        manifest_bytes,
        actor,
    )?;
    vault.flush()?;
    let fsv = plan.verify_committed_with_ledger_ref(&vault, commit_seq, &ledger)?;
    persistence_response("written", commit_seq, &stages, &ledger, Some(&fsv))
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
    let base = artifact_base("prepared", hash);
    let manifest_key = stage_key(&base, "manifest");
    let manifest_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_PREPARED_NOT_FOUND",
                format!("prepared generation {hash} has no manifest"),
                "run mode=\"prepare\" and pass its physical artifact hash",
            )
        })?;
    let manifest: PersistedDiscoveryManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema != DISCOVERY_PERSISTED_SCHEMA
        || manifest.kind != "prepared"
        || manifest.project != project
        || manifest.prepared_artifact_sha256 != hash
        || manifest.artifact_sha256 != hash
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_PREPARED_MANIFEST_MISMATCH",
            "prepared manifest disagrees with its schema, kind, project, or artifact identity",
            "preserve the vault and inspect the content-addressed prepared manifest",
        )
        .into());
    }
    verify_manifest_rows(&vault, snapshot, &manifest)?;
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
    let ledger = find_discovery_ledger(&vault, snapshot, hash.as_bytes(), &manifest_bytes)?;
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
    let hash = match requested_hash.filter(|value| !value.is_empty()) {
        Some(hash) => {
            validate_hash(hash)?;
            hash.to_string()
        }
        None => {
            let bytes = vault
                .read_cf_at(snapshot, ColumnFamily::Kernel, &current_key(project))?
                .ok_or_else(|| {
                    ToolFault::new(
                        "ASTRO_DISCOVERY_CURRENT_MISSING",
                        format!("project {project:?} has no published discovery generation"),
                        "prepare, independently evaluate, and publish a generation first",
                    )
                })?;
            String::from_utf8(bytes).map_err(|error| {
                ToolFault::new(
                    "ASTRO_DISCOVERY_CURRENT_CORRUPT",
                    format!("current discovery pointer is not UTF-8: {error}"),
                    "preserve the vault and inspect the current pointer bytes",
                )
            })?
        }
    };
    let base = artifact_base("final", &hash);
    let manifest_key = stage_key(&base, "manifest");
    let manifest_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_MANIFEST_MISSING",
                format!("final discovery generation {hash} has no manifest"),
                "preserve the vault and inspect the interrupted generation transaction",
            )
        })?;
    let manifest: PersistedDiscoveryManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.schema != DISCOVERY_PERSISTED_SCHEMA
        || manifest.kind != "final"
        || manifest.artifact_sha256 != hash
        || manifest.project != project
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_FINAL_IDENTITY_MISMATCH",
            "final artifact, manifest, project, or prepared generation identity disagrees",
            "preserve the vault and inspect the content-addressed final generation",
        )
        .into());
    }
    verify_manifest_rows(&vault, snapshot, &manifest)?;
    let envelope_value =
        read_compact_artifact_value(&vault, snapshot, &base, &hash, &FINAL_STAGE_FIELDS)?;
    let final_artifact: FinalAssociationDiscoveryEnvelope = serde_json::from_value(envelope_value)?;
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
    let ledger = find_discovery_ledger(&vault, snapshot, hash.as_bytes(), &manifest_bytes)?;
    let section_value = match section {
        "all" => serde_json::to_value(&final_artifact)?,
        "manifest" => serde_json::to_value(&manifest)?,
        "evaluator" => serde_json::to_value(&final_artifact.artifact.evaluator)?,
        "ranked" => serde_json::to_value(&final_artifact.artifact.ranked)?,
        "kernel" => serde_json::to_value(&final_artifact.artifact.reasoning_kernel)?,
        other => {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_SECTION_UNSUPPORTED",
                format!("read section {other:?} is unsupported"),
                "pass section as all, manifest, evaluator, ranked, or kernel",
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
) -> Result<Vec<StageRow>, DynError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    stage_logical_bytes(cf, base, name, bytes)
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

fn prepared_request_key(
    project: &str,
    source_generation_sha256: &str,
    config: &AssociationDiscoveryConfig,
) -> Result<Vec<u8>, DynError> {
    let mut preimage = Vec::new();
    frame_local(&mut preimage, project.as_bytes());
    frame_local(&mut preimage, source_generation_sha256.as_bytes());
    frame_local(&mut preimage, &serde_json::to_vec(config)?);
    let mut key = DISCOVERY_PREFIX.to_vec();
    key.extend_from_slice(b"prepared-request:");
    key.extend_from_slice(sha256_hex_local(&preimage).as_bytes());
    Ok(key)
}

fn current_key(project: &str) -> Vec<u8> {
    let mut key = DISCOVERY_PREFIX.to_vec();
    key.extend_from_slice(b"current:");
    key.extend_from_slice(sha256_hex_local(project.as_bytes()).as_bytes());
    key
}

fn find_discovery_ledger<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    subject_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<LedgerRef, DynError> {
    for (key, bytes) in vault
        .scan_cf_at(snapshot, ColumnFamily::Ledger)?
        .into_iter()
        .rev()
    {
        let entry = decode_ledger(&bytes)?;
        if entry.kind != calyx_ledger::EntryKind::Assay
            || !matches!(&entry.actor, ActorId::Service(actor) if actor == DISCOVERY_ACTOR)
            || !matches!(&entry.subject, SubjectId::Kernel(subject) if subject == subject_bytes)
            || entry.payload != manifest_bytes
        {
            continue;
        }
        if !entry.verify() || key != entry.seq.to_be_bytes() {
            return Err(ToolFault::new(
                "ASTRO_DISCOVERY_LEDGER_CORRUPT",
                format!(
                    "matching discovery ledger entry {} failed hash/key verification",
                    entry.seq
                ),
                "preserve the vault and run verify_chain before reading the generation",
            )
            .into());
        }
        return Ok(LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        });
    }
    Err(ToolFault::new(
        "ASTRO_DISCOVERY_LEDGER_UNPAIRED",
        format!("no matching discovery ledger entry exists at snapshot {snapshot}"),
        "preserve the vault and inspect the Assay/Kernel group commit",
    )
    .into())
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
        if let Some(value) = object
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Ok(format!("{key}:{value}"));
        }
    }
    Ok(format!(
        "kind:{};source_bytes:{};span:{}-{}",
        node.label,
        node.source_bytes.len(),
        node.start_byte,
        node.end_byte
    ))
}

fn language_from_path(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!("extension:{extension}"))
        .unwrap_or_else(|| "extension:none".to_string())
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

fn validate_hash(hash: &str) -> Result<(), DynError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolFault::new(
            "ASTRO_DISCOVERY_HASH_INVALID",
            "discovery artifact hash must be exactly 64 lowercase hexadecimal characters",
            "copy the physical artifact hash returned by prepare or publish",
        )
        .into());
    }
    Ok(())
}

fn domain_fault(error: astrolabe_domain::DomainError) -> ToolFault {
    ToolFault::new(error.code(), error.message(), error.remediation())
}

fn discovery_refusal(code: &str, message: String, remediation: &str) -> Value {
    ToolFault::new(code, message, remediation).envelope()
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
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ToolFault::new(
                "ASTRO_DISCOVERY_PROJECT_REQUIRED",
                "discover_associations requires project",
                "pass the exact indexed CBM project name",
            )
        })?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("prepare");
    let prepared_hash = object
        .get("prepared_artifact_sha256")
        .and_then(Value::as_str);
    let section = object.get("section").and_then(Value::as_str);
    let mut config = AssociationDiscoveryConfig::default();
    if let Some(value) = object.get("workers").and_then(Value::as_u64) {
        config.workers = usize::try_from(value)?;
    }
    if let Some(value) = object.get("cross_validation_folds").and_then(Value::as_u64) {
        config.cross_validation_folds = usize::try_from(value)?;
    }
    if let Some(value) = object.get("top_k").and_then(Value::as_u64) {
        config.latent_top_k = value;
        config.cross_validation_top_k = usize::try_from(value)?;
    }
    if let Some(value) = object
        .get("max_intermediary_degree")
        .and_then(Value::as_u64)
    {
        config.max_intermediary_degree = value;
    }
    if let Some(value) = object
        .get("min_shared_intermediaries")
        .and_then(Value::as_u64)
    {
        config.min_shared_intermediaries = value;
    }
    let evaluator_runs = object
        .get("evaluator_runs")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match discover_associations_json_at(
        &cache_dir,
        project,
        mode,
        prepared_hash,
        section,
        config,
        evaluator_runs,
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
