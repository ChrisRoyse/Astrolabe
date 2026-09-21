use super::*;

use astrolabe_domain::EdgeKind;
use astrolabe_oracle::{
    ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED, AttributionConfig, BacktestReport, ConsequenceEdge,
    ConsequenceEdgeKind, ConsequenceGraph, GateConfig, GitChangeInput, OccurrenceRecord,
    OracleCorpusBinding, OracleCorpusPersistReport, OracleCorpusSourceBinding, OracleTimebase,
    PredictConfig, git_change_inputs_from_archaeology, mine_corpus, outcomes_from_anchor_rows,
    persist_corpus, project_git_change_inputs, read_git_change_inputs_at,
    read_oracle_corpus_binding_at, run_backtest,
};
use calyx_aster::cf::{full_content_hash, ledger_key};
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_core::{AnchorKind, CalyxError, CxId, Seq};
use calyx_ledger::{EntryKind, decode as decode_ledger};
use serde::{Deserialize, Serialize};

const ORACLE_CORPUS_ACTOR: &str = "astrolabe-oracle-corpus-generation";
const ORACLE_GATE_ACTOR: &str = "astrolabe-oracle-gate-generation";
pub(crate) const ORACLE_GATE_ATTESTATION_SCHEMA: &str = "astrolabe.oracle_gate_attestation.v1";
const ORACLE_GATE_POINTER_SCHEMA: &str = "astrolabe.oracle_gate_pointer.v1";
const ORACLE_GATE_RUNTIME_SCHEMA: &str = "astrolabe.oracle_runtime_contract.v1";
const ORACLE_GATE_LEDGER_SCHEMA: &str = "astrolabe.oracle_gate_ledger.v1";
const ORACLE_GATE_CURRENT_PREFIX: &[u8] = b"astrolabe:oracle-gate-current:v1:";
const ORACLE_GATE_GENERATION_PREFIX: &[u8] = b"astrolabe:oracle-gate-generation:v1:";

pub(crate) const ASTRO_ORACLE_GATE_ABSENT: &str = "ASTRO_ORACLE_GATE_ABSENT";
pub(crate) const ASTRO_ORACLE_GATE_CORRUPT: &str = "ASTRO_ORACLE_GATE_CORRUPT";
pub(crate) const ASTRO_ORACLE_GATE_STALE: &str = "ASTRO_ORACLE_GATE_STALE";
const ASTRO_ORACLE_INCREMENTAL_BASE_REQUIRED: &str = "ASTRO_ORACLE_INCREMENTAL_BASE_REQUIRED";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OracleProjectionBuild {
    pub(crate) edges_used: usize,
    pub(crate) calls: usize,
    pub(crate) dataflow: usize,
    pub(crate) service: usize,
    pub(crate) tests: usize,
    pub(crate) edges_unresolved: usize,
    pub(crate) edges_untyped: usize,
    pub(crate) edges_self_loop: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OracleGitProjectionBuild {
    compact_node_count: usize,
    source_range_node_count: usize,
    unusable_source_range_node_count: usize,
    finding_count: usize,
    mapped_finding_count: usize,
    unmapped_finding_count: usize,
    multi_symbol_finding_count: usize,
    mapped_change_event_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleRuntimeContract {
    schema: String,
    corpus_layout_schema: String,
    occurrence_row_schema: String,
    precedes_row_schema: String,
    change_row_schema: String,
    attribution_knob_registry: String,
    predict_knob_registry: String,
    gate_knob_registry: String,
    attribution: AttributionConfig,
    predict: PredictConfig,
    gate: GateConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OracleKernelBinding {
    pub(crate) generation_id: String,
    pub(crate) source_generation_identity: String,
    pub(crate) manifest_key_hex: String,
    pub(crate) manifest_blake3: String,
    pub(crate) commit_seq: Seq,
    pub(crate) source_binding: astrolabe_weave::KernelGenerationSourceBinding,
    pub(crate) slot_source_binding: astrolabe_weave::WeaveSlotBinding,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OracleGateBody {
    schema: String,
    project: String,
    generated_at_seconds: u64,
    corpus: OracleCorpusBinding,
    graph_content_generation: Seq,
    anchors_content_generation: Seq,
    projection_manifest: astrolabe_ingest::GraphProjectionManifestIdentity,
    kernel: OracleKernelBinding,
    runtime: OracleRuntimeContract,
    projection: OracleProjectionBuild,
    git_projection: OracleGitProjectionBuild,
    backtest: BacktestReport,
    admitted: bool,
    refusal_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OracleGateAttestation {
    pub(crate) schema: String,
    pub(crate) attestation_id: String,
    pub(crate) body: OracleGateBody,
    pub(crate) ledger_ref: LedgerRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleGatePointerTarget {
    attestation_id: String,
    attestation_key_hex: String,
    attestation_blake3: String,
    commit_seq: Seq,
    ledger_ref: LedgerRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleGatePointer {
    schema: String,
    project: String,
    current: OracleGatePointerTarget,
    retention: String,
}

pub(crate) struct PreparedOracleGeneration {
    corpus_report: OracleCorpusPersistReport,
    occurrences: Vec<OccurrenceRecord>,
    graph: ConsequenceGraph,
    projection: OracleProjectionBuild,
    git_projection: OracleGitProjectionBuild,
    generated_at_seconds: u64,
}

fn runtime_contract(attribution: AttributionConfig) -> OracleRuntimeContract {
    let predict = PredictConfig {
        advertise_grounded: true,
        ..PredictConfig::default()
    };
    OracleRuntimeContract {
        schema: ORACLE_GATE_RUNTIME_SCHEMA.to_string(),
        corpus_layout_schema: astrolabe_oracle::ORACLE_CORPUS_LAYOUT_SCHEMA.to_string(),
        occurrence_row_schema: astrolabe_oracle::ORACLE_OCCURRENCE_ROW_SCHEMA.to_string(),
        precedes_row_schema: astrolabe_oracle::ORACLE_PRECEDES_ROW_SCHEMA.to_string(),
        change_row_schema: astrolabe_oracle::ORACLE_CHANGE_ROW_SCHEMA.to_string(),
        attribution_knob_registry: astrolabe_oracle::ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION
            .to_string(),
        predict_knob_registry: astrolabe_oracle::ORACLE_PREDICT_KNOB_REGISTRY_VERSION.to_string(),
        gate_knob_registry: astrolabe_oracle::ORACLE_GATE_KNOB_REGISTRY_VERSION.to_string(),
        attribution,
        predict,
        gate: GateConfig::default(),
    }
}

fn service_kind(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::HttpCalls
            | EdgeKind::AsyncCalls
            | EdgeKind::GrpcCalls
            | EdgeKind::GraphqlCalls
            | EdgeKind::TrpcCalls
            | EdgeKind::Emits
            | EdgeKind::ListensOn
            | EdgeKind::Handles
            | EdgeKind::InfraMaps
            | EdgeKind::CrossHttpCalls
            | EdgeKind::CrossAsyncCalls
            | EdgeKind::CrossChannel
            | EdgeKind::CrossGrpcCalls
            | EdgeKind::CrossGraphqlCalls
            | EdgeKind::CrossTrpcCalls
    )
}

fn impact_edge(kind: EdgeKind, src: CxId, dst: CxId) -> Option<ConsequenceEdge> {
    match kind {
        EdgeKind::Calls | EdgeKind::ResolvedCalls => Some(ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Calls,
        }),
        EdgeKind::DataFlows => Some(ConsequenceEdge {
            from: src,
            to: dst,
            kind: ConsequenceEdgeKind::DataFlow,
        }),
        EdgeKind::Tests | EdgeKind::TestsFile => Some(ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Tests,
        }),
        kind if service_kind(kind) => Some(ConsequenceEdge {
            from: dst,
            to: src,
            kind: ConsequenceEdgeKind::Service,
        }),
        _ => None,
    }
}

pub(crate) fn consequence_graph_from_compact(
    compact: &CbmCompactGraphSnapshot,
) -> Result<
    (
        ConsequenceGraph,
        BTreeMap<CxId, BTreeSet<CxId>>,
        OracleProjectionBuild,
    ),
    astrolabe_oracle::OracleError,
> {
    let cx_by_node = compact
        .nodes
        .iter()
        .map(|node| (node.source_node_id, node.cx_id))
        .collect::<BTreeMap<_, _>>();
    let mut edges = Vec::new();
    let mut covered_by_test: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    let mut build = OracleProjectionBuild {
        edges_used: 0,
        calls: 0,
        dataflow: 0,
        service: 0,
        tests: 0,
        edges_unresolved: 0,
        edges_untyped: 0,
        edges_self_loop: 0,
    };
    for edge in &compact.edges {
        let (Some(&src), Some(&dst)) = (
            cx_by_node.get(&edge.source_node_id),
            cx_by_node.get(&edge.target_node_id),
        ) else {
            build.edges_unresolved += 1;
            continue;
        };
        let Some(kind) = EdgeKind::from_cbm_type(&edge.edge_type) else {
            build.edges_untyped += 1;
            continue;
        };
        let Some(impact) = impact_edge(kind, src, dst) else {
            build.edges_untyped += 1;
            continue;
        };
        if impact.from == impact.to {
            build.edges_self_loop += 1;
            continue;
        }
        match impact.kind {
            ConsequenceEdgeKind::Calls => build.calls += 1,
            ConsequenceEdgeKind::DataFlow => build.dataflow += 1,
            ConsequenceEdgeKind::Service => build.service += 1,
            ConsequenceEdgeKind::Tests => {
                build.tests += 1;
                // Raw CBM identity is test -> covered. Consequence traversal is
                // deliberately reversed (covered -> test), but outcome
                // attribution must remain keyed by the real test anchor CxId.
                covered_by_test.entry(src).or_default().insert(dst);
            }
            ConsequenceEdgeKind::Drives => {}
        }
        build.edges_used += 1;
        edges.push(impact);
    }
    edges.sort();
    edges.dedup();
    Ok((
        ConsequenceGraph::from_edges(&edges)?,
        covered_by_test,
        build,
    ))
}

#[derive(Clone, Copy)]
struct SourceRange {
    start: u32,
    end: u32,
    cx_id: CxId,
}

struct FileRanges {
    by_start: Vec<SourceRange>,
    by_end: Vec<SourceRange>,
}

struct SourceRangeIndex {
    files: BTreeMap<String, FileRanges>,
    compact_node_count: usize,
    source_range_node_count: usize,
    unusable_source_range_node_count: usize,
}

impl SourceRangeIndex {
    fn from_compact(compact: &CbmCompactGraphSnapshot) -> Result<Self, DynError> {
        let mut files: BTreeMap<String, Vec<SourceRange>> = BTreeMap::new();
        let mut source_range_node_count = 0usize;
        let mut unusable_source_range_node_count = 0usize;
        for node in &compact.nodes {
            if node.file_path.trim().is_empty()
                || node.start_line <= 0
                || node.end_line < node.start_line
            {
                unusable_source_range_node_count =
                    unusable_source_range_node_count.checked_add(1).ok_or_else(
                        || -> DynError { "ASTRO_ORACLE_SOURCE_RANGE_COUNT_OVERFLOW".into() },
                    )?;
                continue;
            }
            let start = u32::try_from(node.start_line)?;
            let end = u32::try_from(node.end_line)?;
            files
                .entry(node.file_path.replace('\\', "/"))
                .or_default()
                .push(SourceRange {
                    start,
                    end,
                    cx_id: node.cx_id,
                });
            source_range_node_count = source_range_node_count
                .checked_add(1)
                .ok_or_else(|| -> DynError { "ASTRO_ORACLE_SOURCE_RANGE_COUNT_OVERFLOW".into() })?;
        }
        let files = files
            .into_iter()
            .map(|(path, mut ranges)| {
                ranges.sort_by_key(|range| (range.start, range.end, range.cx_id));
                ranges.dedup_by_key(|range| (range.start, range.end, range.cx_id));
                let mut by_end = ranges.clone();
                by_end.sort_by_key(|range| (range.end, range.start, range.cx_id));
                (
                    path,
                    FileRanges {
                        by_start: ranges,
                        by_end,
                    },
                )
            })
            .collect();
        Ok(Self {
            files,
            compact_node_count: compact.nodes.len(),
            source_range_node_count,
            unusable_source_range_node_count,
        })
    }

    /// Resolves all requested locations in one deterministic per-file sweep.
    /// Each range enters and leaves the active set once; enumerating active
    /// CxIds is exactly the unavoidable mapped-output cardinality.
    fn subjects_for(
        &self,
        inputs: &[GitChangeInput],
    ) -> Result<BTreeMap<String, BTreeMap<u32, Vec<CxId>>>, DynError> {
        let mut query_lines: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
        for input in inputs {
            query_lines
                .entry(input.path.replace('\\', "/"))
                .or_default()
                .insert(input.line);
        }
        let mut subjects_by_location = BTreeMap::new();
        for (path, lines) in query_lines {
            let Some(file) = self.files.get(&path) else {
                continue;
            };
            let mut active = BTreeMap::<CxId, usize>::new();
            let mut start_index = 0usize;
            let mut end_index = 0usize;
            let mut by_line = BTreeMap::new();
            for line in lines {
                while start_index < file.by_start.len() && file.by_start[start_index].start <= line
                {
                    let cx_id = file.by_start[start_index].cx_id;
                    let count = active.entry(cx_id).or_default();
                    *count = count.checked_add(1).ok_or_else(|| -> DynError {
                        "ASTRO_ORACLE_SOURCE_RANGE_ACTIVE_COUNT_OVERFLOW".into()
                    })?;
                    start_index += 1;
                }
                while end_index < file.by_end.len() && file.by_end[end_index].end < line {
                    let cx_id = file.by_end[end_index].cx_id;
                    let remove = {
                        let count = active.get_mut(&cx_id).ok_or_else(|| -> DynError {
                            "ASTRO_ORACLE_SOURCE_RANGE_SWEEP_INVALID: an ending range was not active"
                                .into()
                        })?;
                        *count = count.checked_sub(1).ok_or_else(|| -> DynError {
                            "ASTRO_ORACLE_SOURCE_RANGE_ACTIVE_COUNT_UNDERFLOW".into()
                        })?;
                        *count == 0
                    };
                    if remove {
                        active.remove(&cx_id);
                    }
                    end_index += 1;
                }
                by_line.insert(line, active.keys().copied().collect());
            }
            subjects_by_location.insert(path, by_line);
        }
        Ok(subjects_by_location)
    }
}

fn merge_incremental_inputs(
    prior: Vec<GitChangeInput>,
    delta: Vec<GitChangeInput>,
    removed_commits: &BTreeSet<&str>,
) -> Result<Vec<GitChangeInput>, DynError> {
    let mut merged: BTreeMap<(String, String, String, u32), GitChangeInput> = BTreeMap::new();
    for input in prior.into_iter().chain(delta) {
        if removed_commits.contains(input.fix_commit.as_str())
            || removed_commits.contains(input.blamed_commit.as_str())
        {
            continue;
        }
        let identity = (
            input.fix_commit.clone(),
            input.blamed_commit.clone(),
            input.path.clone(),
            input.line,
        );
        if let Some(previous) = merged.insert(identity, input.clone())
            && previous != input
        {
            return Err(format!(
                "ASTRO_ORACLE_GIT_CHANGE_CONFLICT: exact SZZ identity carries conflicting timestamp/confidence metadata: previous={previous:?} incoming={input:?}; remediation: preserve the staged generation and repair the archaeology source"
            )
            .into());
        }
    }
    Ok(merged.into_values().collect())
}

/// Builds and persists the exact Oracle corpus before kernel publication. It
/// reuses the already-mined Git report and already-materialized compact graph,
/// so it adds no second Git or vault graph read. The Oracle-specific in-memory
/// projection costs `O(N log N + E log E + S log S + K log K + A + R log R)`
/// for compact nodes/edges `N/E`, source findings `S`, mapped finding-symbol
/// outputs `K`, anchors `A`, and occurrence rows `R`. The batch range sweep
/// removes the former per-finding worst-case `S*N` interval scan.
/// At the measured production shape `N=192,873`, `E=328,899`, the compact
/// snapshot identity and generation remain invariant across that one pass
/// (PC-04/PC-16/PC-38/PC-41).
pub(crate) fn persist_oracle_corpus_generation<C: Clock>(
    vault: &AsterVault<C>,
    project: &str,
    compact: &CbmCompactGraphSnapshot,
    archaeology: Option<&GitArchaeologyImportReport>,
    generation_clock: GenerationClock,
) -> Result<PreparedOracleGeneration, DynError> {
    let source_snapshot = vault.latest_seq();
    let timebase = OracleTimebase::unix_epoch_seconds(generation_clock.observed_at_seconds())?;
    let projection_manifest = astrolabe_ingest::read_graph_projection_manifest_identity_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        source_snapshot,
    )?
    .ok_or_else(|| -> DynError {
        "ASTRO_ORACLE_GRAPH_PROJECTION_REQUIRED: KernelGraph projection manifest is absent; remediation: complete weave projection materialization before Oracle generation"
            .into()
    })?;
    let graph_content_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let anchors_content_generation = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let range_index = SourceRangeIndex::from_compact(compact)?;
    let (git_history, git_mining_mode, change_inputs) = match archaeology {
        Some(report) => {
            let mined = report.oracle_mining.as_ref().ok_or_else(|| -> DynError {
                "ASTRO_ORACLE_ARCHAEOLOGY_RECEIPT_MISSING: Git archaeology discarded its exact mining report; remediation: preserve the staged generation and rerun the one shared archaeology pass"
                    .into()
            })?;
            let delta = git_change_inputs_from_archaeology(mined, &timebase)?;
            let inputs = match report.mode {
                "incremental" => {
                    if astrolabe_oracle::try_read_oracle_corpus_binding_at(vault, source_snapshot)?
                        .is_none()
                    {
                        return Err(format!(
                            "{ASTRO_ORACLE_INCREMENTAL_BASE_REQUIRED}: project {project:?} has incremental archaeology but no current source-bound Oracle corpus; remediation: rerun this generation with full Git archaeology"
                        )
                        .into());
                    }
                    let prior = read_git_change_inputs_at(vault, source_snapshot)?;
                    let removed = mined
                        .force_removed_commits
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>();
                    merge_incremental_inputs(prior, delta, &removed)?
                }
                "full" | "history_absent" => delta,
                other => {
                    return Err(format!(
                        "ASTRO_ORACLE_ARCHAEOLOGY_MODE_INVALID: unsupported shared archaeology mode {other:?}"
                    )
                    .into());
                }
            };
            (report.history.clone(), report.mode, inputs)
        }
        None => (None, "unavailable", Vec::new()),
    };
    let subjects_by_location = range_index.subjects_for(&change_inputs)?;
    let projected = project_git_change_inputs(&change_inputs, &timebase, |path, line| {
        subjects_by_location
            .get(path)
            .and_then(|by_line| by_line.get(&line))
            .cloned()
            .unwrap_or_default()
    })?;
    let git_projection = OracleGitProjectionBuild {
        compact_node_count: range_index.compact_node_count,
        source_range_node_count: range_index.source_range_node_count,
        unusable_source_range_node_count: range_index.unusable_source_range_node_count,
        finding_count: projected.finding_count,
        mapped_finding_count: projected.mapped_finding_count,
        unmapped_finding_count: projected.unmapped_finding_count,
        multi_symbol_finding_count: projected.multi_symbol_finding_count,
        mapped_change_event_count: projected.events.len(),
    };
    let anchor_rows = astrolabe_anchors::read_anchor_rows_at(vault, source_snapshot)?;
    let mut outcomes = outcomes_from_anchor_rows(&anchor_rows, &timebase)?;
    let (graph, covered_by_test, projection) = consequence_graph_from_compact(compact)?;
    for outcome in &mut outcomes {
        if outcome.outcome_kind() == &AnchorKind::TestPass
            && let Some(covered) = covered_by_test.get(&outcome.outcome_subject())
        {
            outcome.bind_test_attribution(covered.iter().copied().collect())?;
        }
    }
    let source_binding = OracleCorpusSourceBinding {
        schema: astrolabe_oracle::ORACLE_CORPUS_SOURCE_BINDING_SCHEMA.to_string(),
        project: project.to_string(),
        timebase,
        git_history,
        git_mining_mode: git_mining_mode.to_string(),
        graph_content_generation,
        anchors_content_generation,
        compact_graph: compact.receipt.clone(),
        projection_manifest,
    };
    let corpus = mine_corpus(
        &projected.inputs,
        &projected.events,
        &outcomes,
        &AttributionConfig::default(),
        source_binding,
    )?;
    let occurrences = corpus.occurrences().to_vec();
    let corpus_report = persist_corpus(vault, &corpus, ORACLE_CORPUS_ACTOR)?;
    Ok(PreparedOracleGeneration {
        corpus_report,
        occurrences,
        graph,
        projection,
        git_projection,
        generated_at_seconds: generation_clock.observed_at_seconds(),
    })
}

fn kernel_binding_from_parts(
    manifest: &astrolabe_weave::KernelGenerationManifest,
    pointer: &astrolabe_weave::KernelGenerationPointer,
) -> Result<OracleKernelBinding, DynError> {
    if manifest.generation_id != pointer.current.generation_id {
        return Err("ASTRO_ORACLE_KERNEL_BINDING_INVALID: kernel manifest/current pointer generation mismatch".into());
    }
    let bytes = serde_json::to_vec(manifest)?;
    Ok(OracleKernelBinding {
        generation_id: manifest.generation_id.clone(),
        source_generation_identity: manifest.source_generation_identity.clone(),
        manifest_key_hex: pointer.current.manifest_key_hex.clone(),
        manifest_blake3: hex_lower(blake3::hash(&bytes).as_bytes()),
        commit_seq: pointer.current.commit_seq,
        source_binding: manifest.generation_source_binding.clone(),
        slot_source_binding: manifest.source_binding.clone(),
    })
}

fn kernel_binding_from_receipt(receipt: &Value) -> Result<OracleKernelBinding, DynError> {
    let manifest: astrolabe_weave::KernelGenerationManifest = serde_json::from_value(
        receipt
            .get("manifest")
            .cloned()
            .ok_or_else(|| -> DynError {
                "ASTRO_ORACLE_KERNEL_BINDING_INVALID: kernel receipt has no manifest".into()
            })?,
    )?;
    let pointer: astrolabe_weave::KernelGenerationPointer =
        serde_json::from_value(receipt.get("pointer").cloned().ok_or_else(|| -> DynError {
            "ASTRO_ORACLE_KERNEL_BINDING_INVALID: kernel receipt has no pointer".into()
        })?)?;
    kernel_binding_from_parts(&manifest, &pointer)
}

fn project_key(prefix: &[u8], project: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(blake3::hash(project.as_bytes()).as_bytes());
    key
}

fn gate_pointer_key(project: &str) -> Vec<u8> {
    project_key(ORACLE_GATE_CURRENT_PREFIX, project)
}

fn gate_attestation_key(project: &str, attestation_id: &str) -> Vec<u8> {
    let mut key = project_key(ORACLE_GATE_GENERATION_PREFIX, project);
    key.extend_from_slice(attestation_id.as_bytes());
    key
}

fn gate_body_bytes(body: &OracleGateBody) -> Result<Vec<u8>, DynError> {
    Ok(serde_json::to_vec(body)?)
}

fn gate_ledger_payload(
    project: &str,
    attestation_id: &str,
    body: &OracleGateBody,
) -> Result<Vec<u8>, DynError> {
    Ok(serde_json::to_vec(&json!({
        "schema": ORACLE_GATE_LEDGER_SCHEMA,
        "project": project,
        "attestation_id": attestation_id,
        "body_blake3": hex_lower(blake3::hash(&gate_body_bytes(body)?).as_bytes()),
        "admitted": body.admitted,
        "refusal_code": body.refusal_code,
    }))?)
}

fn read_pointer_at<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    project: &str,
) -> Result<Option<OracleGatePointer>, DynError> {
    let key = gate_pointer_key(project);
    let Some(value) = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &key)? else {
        return Ok(None);
    };
    if is_tombstone_value(&value) {
        return Ok(None);
    }
    let pointer: OracleGatePointer = serde_json::from_slice(&value)?;
    if pointer.schema != ORACLE_GATE_POINTER_SCHEMA
        || pointer.project != project
        || pointer.current.commit_seq == 0
        || pointer.current.commit_seq > snapshot
        || pointer.retention
            != "current_only; superseded immutable attestation tombstoned atomically"
        || serde_json::to_vec(&pointer)? != value
    {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_CORRUPT}: project {project:?} gate pointer is non-canonical"
        )
        .into());
    }
    Ok(Some(pointer))
}

fn verify_gate_ledger<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    attestation: &OracleGateAttestation,
) -> Result<(), DynError> {
    let value = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(attestation.ledger_ref.seq),
        )?
        .ok_or_else(|| -> DynError {
            format!(
                "{ASTRO_ORACLE_GATE_CORRUPT}: gate Ledger row {} is absent",
                attestation.ledger_ref.seq
            )
            .into()
        })?;
    let entry = decode_ledger(&value)?;
    let payload = gate_ledger_payload(
        &attestation.body.project,
        &attestation.attestation_id,
        &attestation.body,
    )?;
    let subject = SubjectId::Query(
        format!(
            "astrolabe-oracle-gate:{}:{}",
            attestation.body.project, attestation.attestation_id
        )
        .into_bytes(),
    );
    if !entry.verify()
        || entry.seq != attestation.ledger_ref.seq
        || entry.entry_hash != attestation.ledger_ref.hash
        || entry.kind != EntryKind::Score
        || entry.subject != subject
        || entry.actor != ActorId::Service(ORACLE_GATE_ACTOR.to_string())
        || entry.payload != payload
    {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_CORRUPT}: exact gate Ledger binding does not verify"
        )
        .into());
    }
    Ok(())
}

pub(crate) fn read_current_oracle_gate_at<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    project: &str,
) -> Result<Option<OracleGateAttestation>, DynError> {
    let Some(pointer) = read_pointer_at(vault, snapshot, project)? else {
        return Ok(None);
    };
    let key = gate_attestation_key(project, &pointer.current.attestation_id);
    if hex_lower(&key) != pointer.current.attestation_key_hex {
        return Err(
            format!("{ASTRO_ORACLE_GATE_CORRUPT}: gate pointer attestation key mismatch").into(),
        );
    }
    let value = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
        .ok_or_else(|| -> DynError {
            format!("{ASTRO_ORACLE_GATE_CORRUPT}: current gate attestation row is absent").into()
        })?;
    if is_tombstone_value(&value)
        || hex_lower(blake3::hash(&value).as_bytes()) != pointer.current.attestation_blake3
    {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_CORRUPT}: current gate attestation bytes do not match pointer"
        )
        .into());
    }
    let attestation: OracleGateAttestation = serde_json::from_slice(&value)?;
    let body_bytes = gate_body_bytes(&attestation.body)?;
    let expected_id = hex_lower(&full_content_hash([
        b"astrolabe.oracle-gate-body.v1".as_slice(),
        body_bytes.as_slice(),
    ]));
    if attestation.schema != ORACLE_GATE_ATTESTATION_SCHEMA
        || attestation.attestation_id != expected_id
        || attestation.attestation_id != pointer.current.attestation_id
        || attestation.ledger_ref != pointer.current.ledger_ref
        || serde_json::to_vec(&attestation)? != value
    {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_CORRUPT}: current gate attestation identity/bytes are non-canonical"
        )
        .into());
    }
    verify_gate_ledger(vault, snapshot, &attestation)?;
    Ok(Some(attestation))
}

fn persist_gate<C: Clock>(
    vault: &AsterVault<C>,
    body: OracleGateBody,
) -> Result<OracleGateAttestation, DynError> {
    let base_seq = vault.latest_seq();
    let prior = read_pointer_at(vault, base_seq, &body.project)?;
    let body_bytes = gate_body_bytes(&body)?;
    let attestation_id = hex_lower(&full_content_hash([
        b"astrolabe.oracle-gate-body.v1".as_slice(),
        body_bytes.as_slice(),
    ]));
    let ledger_payload = gate_ledger_payload(&body.project, &attestation_id, &body)?;
    let subject = SubjectId::Query(
        format!("astrolabe-oracle-gate:{}:{attestation_id}", body.project).into_bytes(),
    );
    let project = body.project.clone();
    let callback_id = attestation_id.clone();
    let callback_body = body.clone();
    let predicted_commit_seq = base_seq.checked_add(1).ok_or_else(|| -> DynError {
        "ASTRO_ORACLE_GATE_SEQUENCE_OVERFLOW: vault sequence cannot advance".into()
    })?;
    let (commit, attestation) = vault
        .write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
            base_seq,
            Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new(),
            EntryKind::Score,
            subject,
            ledger_payload,
            ActorId::Service(ORACLE_GATE_ACTOR.to_string()),
            move |ledger_ref, _| {
                let attestation = OracleGateAttestation {
                    schema: ORACLE_GATE_ATTESTATION_SCHEMA.to_string(),
                    attestation_id: callback_id.clone(),
                    body: callback_body,
                    ledger_ref: ledger_ref.clone(),
                };
                let attestation_bytes = serde_json::to_vec(&attestation).map_err(|error| {
                    CalyxError::ledger_group_commit_failed(format!(
                        "encode Oracle gate attestation: {error}"
                    ))
                })?;
                let attestation_key = gate_attestation_key(&project, &callback_id);
                let pointer = OracleGatePointer {
                    schema: ORACLE_GATE_POINTER_SCHEMA.to_string(),
                    project: project.clone(),
                    current: OracleGatePointerTarget {
                        attestation_id: callback_id,
                        attestation_key_hex: hex_lower(&attestation_key),
                        attestation_blake3: hex_lower(blake3::hash(&attestation_bytes).as_bytes()),
                        commit_seq: predicted_commit_seq,
                        ledger_ref: ledger_ref.clone(),
                    },
                    retention:
                        "current_only; superseded immutable attestation tombstoned atomically"
                            .to_string(),
                };
                let mut rows = vec![
                    (ColumnFamily::Kernel, attestation_key, attestation_bytes),
                    (
                        ColumnFamily::Kernel,
                        gate_pointer_key(&project),
                        serde_json::to_vec(&pointer).map_err(|error| {
                            CalyxError::ledger_group_commit_failed(format!(
                                "encode Oracle gate pointer: {error}"
                            ))
                        })?,
                    ),
                ];
                if let Some(prior) = prior
                    && prior.current.attestation_id != attestation.attestation_id
                {
                    rows.push((
                        ColumnFamily::Kernel,
                        gate_attestation_key(&project, &prior.current.attestation_id),
                        tombstone_value(),
                    ));
                }
                Ok((rows, attestation))
            },
        )?;
    if commit.seq != predicted_commit_seq || commit.ledger_ref != attestation.ledger_ref {
        return Err(
            format!("{ASTRO_ORACLE_GATE_CORRUPT}: gate commit/ledger receipt mismatch").into(),
        );
    }
    vault.flush()?;
    let readback = read_current_oracle_gate_at(vault, commit.seq, &body.project)?.ok_or_else(
        || -> DynError {
            format!("{ASTRO_ORACLE_GATE_CORRUPT}: gate disappeared after commit").into()
        },
    )?;
    if readback != attestation {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_CORRUPT}: gate readback differs from committed value"
        )
        .into());
    }
    Ok(readback)
}

pub(crate) fn persist_oracle_gate_generation<C: Clock>(
    vault: &AsterVault<C>,
    project: &str,
    prepared: PreparedOracleGeneration,
    kernel_receipt: &Value,
) -> Result<Value, DynError> {
    let config = PredictConfig {
        advertise_grounded: true,
        ..PredictConfig::default()
    };
    let backtest = run_backtest(&prepared.graph, &prepared.occurrences, &config)?;
    let kernel = kernel_binding_from_receipt(kernel_receipt)?;
    let corpus = prepared.corpus_report.binding.clone();
    let body = OracleGateBody {
        schema: ORACLE_GATE_ATTESTATION_SCHEMA.to_string(),
        project: project.to_string(),
        generated_at_seconds: prepared.generated_at_seconds,
        graph_content_generation: corpus.source_binding.graph_content_generation,
        anchors_content_generation: corpus.source_binding.anchors_content_generation,
        projection_manifest: corpus.source_binding.projection_manifest.clone(),
        runtime: runtime_contract(corpus.attribution),
        projection: prepared.projection,
        git_projection: prepared.git_projection,
        admitted: backtest.admitted,
        refusal_code: backtest.refusal_code.clone().or_else(|| {
            (!backtest.admitted).then(|| ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED.to_string())
        }),
        corpus,
        kernel,
        backtest,
    };
    let attestation = persist_gate(vault, body)?;
    Ok(json!({
        "schema": ORACLE_GATE_ATTESTATION_SCHEMA,
        "attestation_id": attestation.attestation_id,
        "admitted": attestation.body.admitted,
        "refusal_code": attestation.body.refusal_code,
        "generated_at_seconds": attestation.body.generated_at_seconds,
        "corpus": attestation.body.corpus,
        "kernel": attestation.body.kernel,
        "projection": attestation.body.projection,
        "git_projection": attestation.body.git_projection,
        "backtest": attestation.body.backtest,
        "ledger_ref": {
            "seq": attestation.ledger_ref.seq,
            "hash": hex_lower(&attestation.ledger_ref.hash),
        },
        "trust": if attestation.body.admitted { "trusted" } else { "provisional" },
        "freshness": "fresh",
        "provenance": [
            "git:shared-exact-archaeology-report",
            "anchors:persisted-boolean-outcomes",
            "backtest:strict-chronological-held-out",
            "vault:Kernel+Ledger atomic gate pointer",
        ],
    }))
}

/// Verifies one current attestation against the exact retained source/kernel
/// generation. It performs bounded point reads only: gate pointer+row+Ledger,
/// corpus layout, projection manifest, and the caller's already-read kernel
/// manifest/pointer. No Graph, Oracle occurrence, or HNSW scan is introduced.
pub(crate) fn validate_current_oracle_gate_at<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    project: &str,
    kernel_manifest: &astrolabe_weave::KernelGenerationManifest,
    kernel_pointer: &astrolabe_weave::KernelGenerationPointer,
) -> Result<OracleGateAttestation, DynError> {
    if vault.latest_seq() != snapshot {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_STALE}: retained gate check requires current sequence {snapshot}, observed {}",
            vault.latest_seq()
        )
        .into());
    }
    let attestation = read_current_oracle_gate_at(vault, snapshot, project)?.ok_or_else(
        || -> DynError {
            format!(
                "{ASTRO_ORACLE_GATE_ABSENT}: project {project:?} has no persisted automatic Oracle gate attestation"
            )
            .into()
        },
    )?;
    let current_corpus = read_oracle_corpus_binding_at(vault, snapshot)?;
    let current_projection = astrolabe_ingest::read_graph_projection_manifest_identity_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        snapshot,
    )?
    .ok_or_else(|| -> DynError {
        format!("{ASTRO_ORACLE_GATE_STALE}: KernelGraph projection manifest is absent").into()
    })?;
    let current_kernel = kernel_binding_from_parts(kernel_manifest, kernel_pointer)?;
    let body = &attestation.body;
    let current_graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let current_anchors_generation = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let current_kv_generation = vault.cf_content_generation(ColumnFamily::Kv)?;
    let current_slot_generation =
        vault.cf_content_generation(ColumnFamily::slot(current_kernel.slot_source_binding.slot))?;
    let current_compression_generation = vault.cf_content_generation(ColumnFamily::Compression)?;
    if body.schema != ORACLE_GATE_ATTESTATION_SCHEMA
        || body.project != project
        || body.corpus != current_corpus
        || body.graph_content_generation != current_graph_generation
        || body.anchors_content_generation != current_anchors_generation
        || body.projection_manifest != current_projection
        || body.kernel != current_kernel
        || body.runtime != runtime_contract(current_corpus.attribution)
        || body.generated_at_seconds
            != current_corpus
                .source_binding
                .timebase
                .observed_through_seconds
        || body.admitted != body.backtest.admitted
        || body.refusal_code != body.backtest.refusal_code
        || !git_projection_matches_corpus(body)
        || body.kernel.source_binding.graph_content_generation != current_graph_generation
        || body.kernel.source_binding.anchors_content_generation != current_anchors_generation
        || body
            .kernel
            .source_binding
            .anchor_metadata_content_generation
            != current_kv_generation
        || body.kernel.source_binding.projection_manifest != current_projection
        || body.kernel.slot_source_binding.slot != astrolabe_weave::search::SLOT_NAME_SEMANTIC
        || body.kernel.slot_source_binding.slot_cf_generation != current_slot_generation
        || body.kernel.slot_source_binding.compression_cf_generation
            != current_compression_generation
    {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_STALE}: gate attestation does not match the exact retained corpus/graph/kernel/runtime generation"
        )
        .into());
    }
    if vault.latest_seq() != snapshot {
        return Err(format!(
            "{ASTRO_ORACLE_GATE_STALE}: vault advanced from retained gate sequence {snapshot} to {} during exact attestation validation",
            vault.latest_seq()
        )
        .into());
    }
    Ok(attestation)
}

pub(crate) fn require_current_oracle_gate_at<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    project: &str,
    kernel_manifest: &astrolabe_weave::KernelGenerationManifest,
    kernel_pointer: &astrolabe_weave::KernelGenerationPointer,
) -> Result<OracleGateAttestation, DynError> {
    let attestation =
        validate_current_oracle_gate_at(vault, snapshot, project, kernel_manifest, kernel_pointer)?;
    if !attestation.body.admitted {
        return Err(format!(
            "{}: automatic held-out Oracle gate refused grounded serving ({:?})",
            attestation
                .body
                .refusal_code
                .as_deref()
                .unwrap_or(ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED),
            attestation.body.backtest
        )
        .into());
    }
    Ok(attestation)
}

/// Bounded exact-no-op predicate. Absence or a well-formed but stale binding is
/// `false` (the normal rebuild path); malformed present bytes still refuse.
pub(crate) fn oracle_generation_is_current<C: Clock>(
    vault: &AsterVault<C>,
    project: &str,
) -> Result<bool, DynError> {
    let snapshot = vault.latest_seq();
    let Some(attestation) = read_current_oracle_gate_at(vault, snapshot, project)? else {
        return Ok(false);
    };
    let Some(corpus) = astrolabe_oracle::try_read_oracle_corpus_binding_at(vault, snapshot)? else {
        return Ok(false);
    };
    let Some(projection) = astrolabe_ingest::read_graph_projection_manifest_identity_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        snapshot,
    )?
    else {
        return Ok(false);
    };
    let Some(kernel) = astrolabe_weave::read_current_kernel_generation_header(
        vault,
        project,
        &kernel_artifact_scope_id(project),
    )?
    else {
        return Ok(false);
    };
    if vault.latest_seq() != snapshot {
        return Ok(false);
    }
    let kernel_binding = kernel_binding_from_parts(&kernel.manifest, &kernel.pointer)?;
    let body = &attestation.body;
    let current_graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let current_anchors_generation = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let current_kv_generation = vault.cf_content_generation(ColumnFamily::Kv)?;
    let current_slot_generation =
        vault.cf_content_generation(ColumnFamily::slot(kernel_binding.slot_source_binding.slot))?;
    let current_compression_generation = vault.cf_content_generation(ColumnFamily::Compression)?;
    Ok(body.project == project
        && body.schema == ORACLE_GATE_ATTESTATION_SCHEMA
        && body.corpus == corpus
        && body.graph_content_generation == current_graph_generation
        && body.anchors_content_generation == current_anchors_generation
        && body.projection_manifest == projection
        && body.kernel == kernel_binding
        && body.runtime == runtime_contract(corpus.attribution)
        && body.generated_at_seconds == corpus.source_binding.timebase.observed_through_seconds
        && body.admitted == body.backtest.admitted
        && body.refusal_code == body.backtest.refusal_code
        && git_projection_matches_corpus(body)
        && body.kernel.source_binding.graph_content_generation == current_graph_generation
        && body.kernel.source_binding.anchors_content_generation == current_anchors_generation
        && body
            .kernel
            .source_binding
            .anchor_metadata_content_generation
            == current_kv_generation
        && body.kernel.source_binding.projection_manifest == projection
        && body.kernel.slot_source_binding.slot == astrolabe_weave::search::SLOT_NAME_SEMANTIC
        && body.kernel.slot_source_binding.slot_cf_generation == current_slot_generation
        && body.kernel.slot_source_binding.compression_cf_generation
            == current_compression_generation)
}

fn git_projection_matches_corpus(body: &OracleGateBody) -> bool {
    let git = &body.git_projection;
    let Ok(compact_node_count) =
        usize::try_from(body.corpus.source_binding.compact_graph.node_count)
    else {
        return false;
    };
    git.compact_node_count == compact_node_count
        && git
            .source_range_node_count
            .checked_add(git.unusable_source_range_node_count)
            == Some(git.compact_node_count)
        && git
            .mapped_finding_count
            .checked_add(git.unmapped_finding_count)
            == Some(git.finding_count)
        && git.multi_symbol_finding_count <= git.mapped_finding_count
        && git.finding_count == body.corpus.change_count
        && git.mapped_change_event_count == body.corpus.mapped_change_event_count
}

pub(crate) fn oracle_gate_summary(attestation: &OracleGateAttestation) -> Value {
    json!({
        "schema": ORACLE_GATE_ATTESTATION_SCHEMA,
        "attestation_id": attestation.attestation_id,
        "admitted": attestation.body.admitted,
        "generated_at_seconds": attestation.body.generated_at_seconds,
        "refusal_code": attestation.body.refusal_code,
        "backtest": attestation.body.backtest,
        "corpus_layout_blake3": attestation.body.corpus.layout_blake3,
        "corpus_content_rows_hash": attestation.body.corpus.content_rows_hash,
        "kernel_generation_id": attestation.body.kernel.generation_id,
        "projection": attestation.body.projection,
        "git_projection": attestation.body.git_projection,
    })
}

pub(crate) fn oracle_gate_projection_matches(
    attestation: &OracleGateAttestation,
    projection: &OracleProjectionBuild,
) -> bool {
    &attestation.body.projection == projection
}
