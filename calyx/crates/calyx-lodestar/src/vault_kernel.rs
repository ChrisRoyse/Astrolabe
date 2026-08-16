//! Build a real Lodestar kernel AND measure its kernel-only recall directly from
//! a live Aster vault — the production Vault→embeddings recall bridge (#1900).
//!
//! Embeddings are read straight from each constellation's content-slot dense
//! vector (the source of truth — no mock, no fabricated recall). Associations
//! are derived as the embedding k-NN graph (concepts the panel measures as
//! close). The kernel is selected by [`build_kernel_pipeline`] and its recall is
//! MEASURED by [`kernel_recall_test`] against the full corpus index. Fails loud
//! on a too-small / unanchored / unembedded vault.

use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver, encode};
use calyx_core::{AnchorKind, Clock, CxId, Seq, SlotId, SlotVector, VaultStore, dense_cosine};
use calyx_paths::AssocGraph;

use crate::error::{LodestarError, Result};
use crate::{
    GroundednessReport, InMemoryAnnIndex, InMemoryCorpus, Kernel, KernelParams, RecallQuery,
    RecallReport, RecallTestParams, build_kernel_index, build_kernel_pipeline, kernel_recall_test,
};

/// A real kernel plus its MEASURED kernel-only recall, both computed from the
/// live vault corpus.
pub struct MeasuredVaultKernel {
    pub kernel: Kernel,
    pub recall: RecallReport,
    /// Number of embedded concepts in the corpus the kernel was measured against.
    pub corpus_size: usize,
    /// Number of concepts visible in the vault Base CF at the measurement snapshot.
    pub vault_corpus_size: usize,
    /// Number of visible concepts skipped because `content_slot` had no dense vector.
    pub skipped_unembedded: usize,
    /// Persisted label anchors captured during the same Base scan.
    pub labels: BTreeMap<CxId, String>,
}

/// Result of selecting and measuring the best dense content column from a
/// caller-ordered candidate list. Equal coverage preserves caller order.
pub struct MeasuredVaultKernelSelection {
    pub content_slot: SlotId,
    pub measured: MeasuredVaultKernel,
    pub contributions: Vec<(CxId, f32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VaultKernelMode {
    Strict,
    WebPartial,
}

/// Build the doc-corpus kernel for `vault` and measure its kernel-only recall.
///
/// `content_slot` is the dense semantic lens slot read per concept. `knn` /
/// `edge_cos_threshold` shape the embedding-proximity association graph that
/// drives kernel-member selection. `recall_params.min_recall_ratio` is the gate
/// (0.95 for the website). Errors (never silent): a vault with <2 embedded
/// concepts, no anchored concepts, or a concept missing the content-slot vector.
pub fn measured_kernel_from_vault<C: Clock>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
) -> Result<MeasuredVaultKernel> {
    measured_kernel_from_vault_resolved(
        vault,
        content_slot,
        kernel_params,
        recall_params,
        knn,
        edge_cos_threshold,
        &StrictRawSlotResolver,
    )
}

/// Compression-aware form of [`measured_kernel_from_vault`]. The resolver is
/// the sole owner of slot interpretation; Base is still read directly from the
/// same Aster snapshot.
pub fn measured_kernel_from_vault_resolved<C, R>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
    resolver: &R,
) -> Result<MeasuredVaultKernel>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let inputs = build_vault_kernel_inputs(
        vault,
        content_slot,
        kernel_params,
        knn,
        edge_cos_threshold,
        VaultKernelMode::Strict,
        resolver,
    )?;
    let kernel_index = build_kernel_index(&inputs.kernel, &inputs.embeddings)?;
    let recall = kernel_recall_test(&kernel_index, &inputs.full, &inputs.corpus, recall_params)?;
    Ok(MeasuredVaultKernel {
        kernel: inputs.kernel,
        recall,
        corpus_size: inputs.corpus_size,
        vault_corpus_size: inputs.vault_corpus_size,
        skipped_unembedded: inputs.skipped_unembedded,
        labels: inputs.labels,
    })
}

/// Build the measured kernel AND each member's **leave-one-out recall
/// contribution** (#1901).
///
/// `contributions[i] = baseline_kernel_only_recall − recall_without(member_i)`:
/// the drop in MEASURED kernel-only recall when that member is removed from the
/// kernel (the retrieval corpus is held fixed — only the kernel index shrinks).
/// A large positive value means the member carries recall the others do not; a
/// value near zero means it is redundant; a negative value means it was hurting.
/// The corpus/full index are built once and reused, so the cost is `n` extra
/// recall tests over the same corpus (the caller caches the result — #1898).
/// The sole-member case reports the full baseline (removing it leaves no kernel
/// to test). NOT fabricated — every value is a real `kernel_recall_test`.
pub fn measured_kernel_with_contributions_from_vault<C: Clock>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
) -> Result<(MeasuredVaultKernel, Vec<(CxId, f32)>)> {
    measured_kernel_with_contributions_from_vault_resolved(
        vault,
        content_slot,
        kernel_params,
        recall_params,
        knn,
        edge_cos_threshold,
        &StrictRawSlotResolver,
    )
}

/// Compression-aware form of
/// [`measured_kernel_with_contributions_from_vault`].
pub fn measured_kernel_with_contributions_from_vault_resolved<C, R>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
    resolver: &R,
) -> Result<(MeasuredVaultKernel, Vec<(CxId, f32)>)>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let inputs = build_vault_kernel_inputs(
        vault,
        content_slot,
        kernel_params,
        knn,
        edge_cos_threshold,
        VaultKernelMode::Strict,
        resolver,
    )?;
    measured_kernel_with_contributions_from_inputs(inputs, recall_params)
}

/// Build the measured kernel for a website-facing vault snapshot while honestly
/// tolerating operationally incomplete historical coverage.
///
/// Unlike the strict functions above, this skips rows missing `content_slot`
/// dense vectors and permits an unanchored vault. The returned kernel carries
/// explicit `warnings`, `groundedFraction`, `vault_corpus_size`, and
/// `skipped_unembedded`; callers must surface those instead of pretending the
/// artifact is fully grounded.
pub fn measured_kernel_with_contributions_from_vault_allow_partial<C: Clock>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
) -> Result<(MeasuredVaultKernel, Vec<(CxId, f32)>)> {
    measured_kernel_with_contributions_from_vault_allow_partial_resolved(
        vault,
        content_slot,
        kernel_params,
        recall_params,
        knn,
        edge_cos_threshold,
        &StrictRawSlotResolver,
    )
}

/// Compression-aware form of
/// [`measured_kernel_with_contributions_from_vault_allow_partial`].
pub fn measured_kernel_with_contributions_from_vault_allow_partial_resolved<C, R>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
    resolver: &R,
) -> Result<(MeasuredVaultKernel, Vec<(CxId, f32)>)>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let inputs = build_vault_kernel_inputs(
        vault,
        content_slot,
        kernel_params,
        knn,
        edge_cos_threshold,
        VaultKernelMode::WebPartial,
        resolver,
    )?;
    measured_kernel_with_contributions_from_inputs(inputs, recall_params)
}

/// Selects the highest-coverage dense content slot and measures the website
/// kernel without rereading Base or the selected slot column.
///
/// Base is decoded once at one sequence. Each distinct candidate column is
/// resolved once through `resolver`; ties preserve `content_slots` order so the
/// caller can encode panel-state preference deterministically.
pub fn measured_kernel_with_contributions_from_vault_candidates_allow_partial_resolved<C, R>(
    vault: &AsterVault<C>,
    content_slots: &[SlotId],
    kernel_params: &KernelParams,
    recall_params: &RecallTestParams,
    knn: usize,
    edge_cos_threshold: f32,
    resolver: &R,
) -> Result<MeasuredVaultKernelSelection>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    if content_slots.is_empty() {
        return Err(LodestarError::KernelInvalidParams {
            detail: "kernel content-slot candidate list is empty".to_string(),
        });
    }
    if content_slots.iter().copied().collect::<BTreeSet<_>>().len() != content_slots.len() {
        return Err(LodestarError::KernelInvalidParams {
            detail: "kernel content-slot candidate list contains duplicates".to_string(),
        });
    }

    let snapshot = vault.snapshot();
    let base_by_id = read_vault_kernel_base(vault, snapshot)?;
    let mut selected: Option<(SlotId, BTreeMap<CxId, SlotVector>, usize)> = None;
    for content_slot in content_slots {
        let vectors =
            resolve_content_vectors(vault, snapshot, *content_slot, resolver, &base_by_id)?;
        let dense_count = vectors
            .values()
            .filter(|vector| vector.as_dense().is_some())
            .count();
        let improves_coverage = match selected.as_ref() {
            Some((_, _, best_count)) => dense_count > *best_count,
            None => true,
        };
        if improves_coverage {
            selected = Some((*content_slot, vectors, dense_count));
        }
    }
    let (content_slot, vectors, _) =
        selected.ok_or_else(|| LodestarError::KernelInvalidParams {
            detail: "kernel content-slot candidate selection produced no column".to_string(),
        })?;
    let inputs = build_vault_kernel_inputs_from_rows(
        &base_by_id,
        vectors,
        content_slot,
        kernel_params,
        knn,
        edge_cos_threshold,
        VaultKernelMode::WebPartial,
    )?;
    let (measured, contributions) =
        measured_kernel_with_contributions_from_inputs(inputs, recall_params)?;
    Ok(MeasuredVaultKernelSelection {
        content_slot,
        measured,
        contributions,
    })
}

fn measured_kernel_with_contributions_from_inputs(
    inputs: VaultKernelInputs,
    recall_params: &RecallTestParams,
) -> Result<(MeasuredVaultKernel, Vec<(CxId, f32)>)> {
    let kernel_index = build_kernel_index(&inputs.kernel, &inputs.embeddings)?;
    let recall = kernel_recall_test(&kernel_index, &inputs.full, &inputs.corpus, recall_params)?;
    let baseline = recall.kernel_only;

    let mut contributions: Vec<(CxId, f32)> = Vec::with_capacity(inputs.kernel.members.len());
    for member in &inputs.kernel.members {
        let drop = if inputs.kernel.members.len() == 1 {
            // Removing the only member leaves nothing to recall-test; the member
            // accounts for the whole baseline by definition.
            baseline
        } else {
            let mut leave_one_out = inputs.kernel.clone();
            leave_one_out.members.retain(|m| m != member);
            let loo_index = build_kernel_index(&leave_one_out, &inputs.embeddings)?;
            let loo_recall =
                kernel_recall_test(&loo_index, &inputs.full, &inputs.corpus, recall_params)?;
            baseline - loo_recall.kernel_only
        };
        contributions.push((*member, drop));
    }

    Ok((
        MeasuredVaultKernel {
            kernel: inputs.kernel,
            recall,
            corpus_size: inputs.corpus_size,
            vault_corpus_size: inputs.vault_corpus_size,
            skipped_unembedded: inputs.skipped_unembedded,
            labels: inputs.labels,
        },
        contributions,
    ))
}

/// The intermediate inputs shared by [`measured_kernel_from_vault`] and
/// [`measured_kernel_with_contributions_from_vault`]: the selected kernel, the
/// per-concept embeddings, and the full-corpus retrieval index/corpus the
/// kernel's recall is measured against.
struct VaultKernelInputs {
    kernel: Kernel,
    embeddings: BTreeMap<CxId, Vec<f32>>,
    full: InMemoryAnnIndex,
    corpus: InMemoryCorpus,
    corpus_size: usize,
    vault_corpus_size: usize,
    skipped_unembedded: usize,
    labels: BTreeMap<CxId, String>,
}

/// Scan the vault's content-slot embeddings, build the embedding k-NN
/// association graph, select the kernel, and build the full-corpus index — the
/// setup common to every measured-kernel call. Fails loud (never silent) on a
/// too-small / unanchored / unembedded vault.
fn build_vault_kernel_inputs<C, R>(
    vault: &AsterVault<C>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    knn: usize,
    edge_cos_threshold: f32,
    mode: VaultKernelMode,
    resolver: &R,
) -> Result<VaultKernelInputs>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let snapshot = vault.snapshot();
    let base_by_id = read_vault_kernel_base(vault, snapshot)?;
    let vectors = resolve_content_vectors(vault, snapshot, content_slot, resolver, &base_by_id)?;
    build_vault_kernel_inputs_from_rows(
        &base_by_id,
        vectors,
        content_slot,
        kernel_params,
        knn,
        edge_cos_threshold,
        mode,
    )
}

fn read_vault_kernel_base<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> Result<BTreeMap<CxId, calyx_core::Constellation>> {
    let mut base_by_id = BTreeMap::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
        let bytes: [u8; 16] =
            key.as_slice()
                .try_into()
                .map_err(|_| LodestarError::KernelInvalidParams {
                    detail: format!("base CF key has {} bytes, expected 16", key.len()),
                })?;
        let cx_id = CxId::from_bytes(bytes);
        let cx = encode::decode_constellation_base(&value)?;
        if cx.cx_id != cx_id {
            return Err(LodestarError::KernelInvalidParams {
                detail: format!(
                    "base CF key {cx_id} differs from embedded constellation {}",
                    cx.cx_id
                ),
            });
        }
        if base_by_id.insert(cx_id, cx).is_some() {
            return Err(LodestarError::KernelInvalidParams {
                detail: format!("base CF contains duplicate constellation {cx_id}"),
            });
        }
    }
    Ok(base_by_id)
}

fn resolve_content_vectors<C, R>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    content_slot: SlotId,
    resolver: &R,
    base_by_id: &BTreeMap<CxId, calyx_core::Constellation>,
) -> Result<BTreeMap<CxId, SlotVector>>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let mut vectors_by_id = BTreeMap::new();
    let mut previous_cx_id = None;
    for (cx_id, vector) in resolver.resolve_slot_column_at(vault, snapshot, content_slot)? {
        if previous_cx_id.is_some_and(|previous| previous >= cx_id) {
            return Err(LodestarError::KernelInvalidParams {
                detail: format!(
                    "content slot {content_slot} resolver column is not strictly ordered at {cx_id}"
                ),
            });
        }
        previous_cx_id = Some(cx_id);
        if !base_by_id
            .get(&cx_id)
            .is_some_and(|cx| cx.slots.contains_key(&content_slot))
        {
            return Err(LodestarError::KernelInvalidParams {
                detail: format!(
                    "content slot {content_slot} resolved orphan or undeclared row {cx_id}"
                ),
            });
        }
        if vectors_by_id.insert(cx_id, vector).is_some() {
            return Err(LodestarError::KernelInvalidParams {
                detail: format!(
                    "content slot {content_slot} resolver returned duplicate row {cx_id}"
                ),
            });
        }
    }
    Ok(vectors_by_id)
}

fn build_vault_kernel_inputs_from_rows(
    base_by_id: &BTreeMap<CxId, calyx_core::Constellation>,
    mut vectors_by_id: BTreeMap<CxId, SlotVector>,
    content_slot: SlotId,
    kernel_params: &KernelParams,
    knn: usize,
    edge_cos_threshold: f32,
    mode: VaultKernelMode,
) -> Result<VaultKernelInputs> {
    let vault_corpus_size = base_by_id.len();
    let mut rows: Vec<RecallQuery> = Vec::new();
    let mut anchors: Vec<CxId> = Vec::new();
    let mut skipped_unembedded = 0usize;
    let labels = base_by_id
        .iter()
        .filter_map(|(cx_id, cx)| {
            cx.anchors.iter().find_map(|anchor| match &anchor.kind {
                AnchorKind::Label(value) => Some((*cx_id, value.clone())),
                _ => None,
            })
        })
        .collect();
    for (cx_id, cx) in base_by_id {
        let dense = vectors_by_id
            .remove(cx_id)
            .and_then(|vector| vector.as_dense().map(ToOwned::to_owned));
        let Some(dense) = dense else {
            match mode {
                VaultKernelMode::Strict => {
                    return Err(LodestarError::KernelInvalidParams {
                        detail: format!(
                            "constellation {cx_id} has no dense vector in content slot {content_slot}; \
                             the kernel needs a per-concept embedding"
                        ),
                    });
                }
                VaultKernelMode::WebPartial => {
                    skipped_unembedded += 1;
                    continue;
                }
            }
        };
        rows.push(RecallQuery {
            cx_id: *cx_id,
            vector: dense,
        });
        if !cx.anchors.is_empty() {
            anchors.push(*cx_id);
        }
    }
    if !vectors_by_id.is_empty() {
        return Err(LodestarError::KernelInvalidParams {
            detail: format!(
                "content slot {content_slot} resolver returned rows not consumed by Base"
            ),
        });
    }
    if rows.len() < 2 {
        return Err(LodestarError::KernelInvalidParams {
            detail: format!(
                "vault has {} embedded concept(s) in slot {content_slot}; need >=2 for a kernel",
                rows.len()
            ),
        });
    }
    if anchors.is_empty() && mode == VaultKernelMode::Strict {
        return Err(LodestarError::KernelInvalidParams {
            detail: "vault has no anchored concepts; anchor at least one before building a kernel"
                .to_string(),
        });
    }

    // Embedding k-NN association graph: an edge for each pair the panel measures
    // as close (cosine >= threshold), up to `knn` neighbours per node.
    let mut builder = AssocGraph::builder();
    for row in &rows {
        builder.add_node(row.cx_id, 1.0)?;
    }
    for (index, src) in rows.iter().enumerate() {
        let mut neighbours: Vec<(CxId, f32)> = rows
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .filter_map(|(_, dst)| {
                dense_cosine(&src.vector, &dst.vector).map(|cosine| (dst.cx_id, cosine))
            })
            .filter(|(_, cosine)| *cosine >= edge_cos_threshold)
            .collect();
        neighbours.sort_by(|left, right| right.1.total_cmp(&left.1));
        for (dst, cosine) in neighbours.into_iter().take(knn) {
            builder.add_edge(src.cx_id, dst, cosine)?;
        }
    }
    let graph = builder.build();

    let mut kernel = build_kernel_pipeline(&graph, &anchors, kernel_params)?;
    // A kernel with no selected members cannot be recall-tested; fall back to the
    // kernel graph (or the full corpus) so recall reflects real data, not an
    // empty set.
    if kernel.members.is_empty() {
        kernel.members = if kernel.kernel_graph.is_empty() {
            rows.iter().map(|row| row.cx_id).collect()
        } else {
            kernel.kernel_graph.clone()
        };
    }
    if anchors.is_empty() {
        kernel.groundedness = GroundednessReport {
            reached_anchor: 0.0,
            unanchored_members: kernel.members.clone(),
        };
        if !kernel
            .warnings
            .iter()
            .any(|warning| warning.starts_with("CALYX_KERNEL_UNGROUNDED"))
        {
            kernel
                .warnings
                .push("CALYX_KERNEL_UNGROUNDED: all kernel members are provisional".to_string());
        }
        kernel.estimator_provenance = format!("{}; trust=provisional", kernel.estimator_provenance);
    }
    if skipped_unembedded > 0 {
        let warning = format!(
            "CALYX_KERNEL_PARTIAL_COVERAGE: content_slot={}; embedded={}; vault_total={vault_corpus_size}; skipped_unembedded={skipped_unembedded}",
            content_slot.get(),
            rows.len()
        );
        kernel.warnings.push(warning.clone());
        kernel.estimator_provenance = format!(
            "{}; partial_coverage={warning}",
            kernel.estimator_provenance
        );
    }

    let embeddings: BTreeMap<CxId, Vec<f32>> = rows
        .iter()
        .map(|row| (row.cx_id, row.vector.clone()))
        .collect();
    let corpus_size = rows.len();
    let full = InMemoryAnnIndex::new(rows.clone())?;
    let corpus = InMemoryCorpus::new("vault-kernel", rows);

    Ok(VaultKernelInputs {
        kernel,
        embeddings,
        full,
        corpus,
        corpus_size,
        vault_corpus_size,
        skipped_unembedded,
        labels,
    })
}
