use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use calyx_aster::base_page_index::{
    read_base_page_index_manifest, read_indexed_base_rows, visit_indexed_base_row_pages,
};
use calyx_aster::cf::{ColumnFamily, compression_manifest_key, slot_key};
use calyx_aster::mvcc::OrderedReadbackMetrics;
use calyx_aster::mvcc::is_tombstone_value;
use calyx_aster::vault::{
    AsterVault, OrderedCfRead, SlotVectorResolver, SstReadSession, VaultOptions, encode,
};
use calyx_core::{
    CalyxError, Constellation, CxId, QuantPolicy, SlotId, SlotVector, SystemClock, VaultId,
};
use calyx_registry::VaultPanelState;

use super::{
    COVERED_SCAN_BATCH_SIZE, CandidateSelectionMode, CoverageSlotReadStats, DenseSlotCoverage,
    DenseSlotCoverageScan, EXAMPLE_MISSING_LIMIT,
};
use crate::bounded_progress::Deadline;
use crate::error::{CliError, CliResult};

type SlotCoverageMaps = BTreeMap<SlotId, HashMap<CxId, Vec<f32>>>;
type SlotCoverageRows = Vec<DenseSlotCoverage>;

#[derive(Clone, Copy)]
enum CoverageSlotReadMode {
    Raw,
    Compressed,
}

impl CoverageSlotReadMode {
    const fn label(&self) -> &'static str {
        match self {
            Self::Raw => "raw_primary",
            Self::Compressed => "compressed_registry",
        }
    }
}

/// One operation-scoped, immutable coverage view. The Aster handle is opened
/// read-only over only Compression, the declared slot columns, and Assay when
/// an MXFP4 slot can require it. The retained session pins one exact latest
/// MVCC sequence from manifest discrimination through the last bounded chunk.
struct CoverageSlotReadSession<'a> {
    vault: &'a AsterVault,
    panel_state: &'a VaultPanelState,
    retained: SstReadSession<'a, SystemClock>,
    modes: BTreeMap<SlotId, CoverageSlotReadMode>,
}

impl<'a> CoverageSlotReadSession<'a> {
    fn open(
        vault: &'a AsterVault,
        panel_state: &'a VaultPanelState,
        slots: &[SlotId],
    ) -> CliResult<Self> {
        let snapshot = vault.latest_seq();
        let retained = vault.sst_read_session_at(snapshot)?;
        let manifest_keys = slots
            .iter()
            .map(|slot| compression_manifest_key(*slot))
            .collect::<Vec<_>>();
        let manifest_reads = manifest_keys
            .iter()
            .enumerate()
            .map(|(ordinal, key)| OrderedCfRead::new(ordinal, ColumnFamily::Compression, key))
            .collect::<Vec<_>>();
        let mut manifests = vec![None; slots.len()];
        retained.visit_ordered_cf_plan::<CliError, _>(
            &manifest_reads,
            |ordinal, _, _, value| {
                manifests[ordinal] = value.map(ToOwned::to_owned);
                Ok(())
            },
        )?;

        let mut modes = BTreeMap::new();
        for ((slot_id, manifest), manifest_key) in
            slots.iter().copied().zip(manifests).zip(manifest_keys)
        {
            if manifest.as_deref().is_none_or(is_tombstone_value) {
                modes.insert(slot_id, CoverageSlotReadMode::Raw);
                continue;
            }
            if panel_state.registry_snapshot.is_none() {
                return Err(CalyxError {
                    code: "CALYX_REGISTRY_CONTEXT_MISSING",
                    message: format!(
                        "weave-loom found live compressed manifest key {} for slot {}, but the vault manifest has no persisted registry snapshot",
                        hex_key(&manifest_key),
                        slot_id.get()
                    ),
                    remediation: "persist the exact panel/registry contract that encoded the generation, then re-commission it; never decode from slot_raw",
                }
                .into());
            }
            let panel_slot = panel_state
                .panel
                .slots
                .iter()
                .find(|slot| slot.slot_id == slot_id)
                .ok_or_else(|| {
                    CalyxError::stale_derived(format!(
                        "weave-loom coverage slot {} is absent from the already-loaded persisted panel state",
                        slot_id.get()
                    ))
                })?;
            let index = panel_state
                .registry
                .compressed_slot_index(vault, panel_slot)?;
            // Authenticate the discriminator under the exact registered
            // slot/lens context before the view becomes reachable to chunks.
            index.generation_identity_at(snapshot)?;
            modes.insert(slot_id, CoverageSlotReadMode::Compressed);
        }
        Ok(Self {
            vault,
            panel_state,
            retained,
            modes,
        })
    }

    const fn snapshot_seq(&self) -> u64 {
        self.retained.snapshot_seq()
    }

    fn mode(&self, slot: SlotId) -> CliResult<&CoverageSlotReadMode> {
        self.modes.get(&slot).ok_or_else(|| {
            CliError::runtime(format!(
                "CALYX_WEAVE_LOOM_SLOT_NOT_PREFLIGHTED: slot {} has no retained coverage read mode",
                slot.get()
            ))
        })
    }

    fn read_primary_rows(
        &self,
        slot: SlotId,
        cx_ids: &[CxId],
    ) -> CliResult<(Vec<Option<Vec<u8>>>, OrderedReadbackMetrics)> {
        let keys = cx_ids
            .iter()
            .map(|cx_id| slot_key(*cx_id))
            .collect::<Vec<_>>();
        let reads = keys
            .iter()
            .enumerate()
            .map(|(ordinal, key)| OrderedCfRead::new(ordinal, ColumnFamily::slot(slot), key))
            .collect::<Vec<_>>();
        let mut values = vec![None; cx_ids.len()];
        let metrics = self.retained.visit_ordered_cf_plan::<CliError, _>(
            &reads,
            |ordinal, _, _, value| {
                values[ordinal] = value.map(ToOwned::to_owned);
                Ok(())
            },
        )?;
        Ok((values, metrics))
    }

    fn resolve_semantic_rows(
        &self,
        slot: SlotId,
        cx_ids: &[CxId],
    ) -> CliResult<Vec<(CxId, SlotVector)>> {
        let resolved = self.panel_state.resolve_slot_vectors_at(
            self.vault,
            self.snapshot_seq(),
            slot,
            cx_ids,
        )?;
        resolved
            .into_iter()
            .map(|(cx_id, vector)| {
                vector.map(|vector| (cx_id, vector)).ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "slot {} semantic resolver omitted physically present current-state row {cx_id}",
                        slot.get()
                    ))
                    .into()
                })
            })
            .collect()
    }
}

pub(crate) fn scan_dense_slot_coverage(
    vault_dir: &Path,
    vault_id: VaultId,
    vault_salt: Vec<u8>,
    panel_state: &VaultPanelState,
    content_slots: &[SlotId],
    requested_slot: Option<SlotId>,
    limit: usize,
    mode: CandidateSelectionMode,
    deadline: &Deadline,
) -> CliResult<DenseSlotCoverageScan> {
    deadline.check("weave-loom", "coverage.base_page_index_manifest", 0)?;
    let measured_slots = measured_slots_for_open(content_slots, requested_slot, mode);
    let mut selected_cfs = vec![ColumnFamily::Compression];
    for slot_id in &measured_slots {
        selected_cfs.push(ColumnFamily::slot(*slot_id));
        if panel_state
            .panel
            .slots
            .iter()
            .find(|slot| slot.slot_id == *slot_id)
            .is_some_and(|slot| matches!(slot.quant, QuantPolicy::MxFp4))
        {
            selected_cfs.push(ColumnFamily::Assay);
        }
    }
    selected_cfs.sort();
    selected_cfs.dedup();
    let read_vault = AsterVault::open(
        vault_dir,
        vault_id,
        vault_salt,
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    let read_session = CoverageSlotReadSession::open(&read_vault, panel_state, &measured_slots)?;
    let manifest = read_base_page_index_manifest(vault_dir)?;
    match mode {
        CandidateSelectionMode::BasePrefix => scan_base_prefix_coverage(
            vault_dir,
            &read_session,
            content_slots,
            limit,
            manifest.live_entries,
            deadline,
        ),
        CandidateSelectionMode::Covered => scan_bounded_covered_coverage(
            vault_dir,
            &read_session,
            requested_slot,
            content_slots,
            limit,
            manifest.live_entries,
            deadline,
        ),
    }
}

fn measured_slots_for_open(
    content_slots: &[SlotId],
    requested_slot: Option<SlotId>,
    mode: CandidateSelectionMode,
) -> Vec<SlotId> {
    let mut slots = if mode == CandidateSelectionMode::Covered {
        requested_slot.map_or_else(|| content_slots.to_vec(), |slot| vec![slot])
    } else {
        content_slots.to_vec()
    };
    slots.sort();
    slots.dedup();
    slots
}

fn scan_base_prefix_coverage(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    content_slots: &[SlotId],
    limit: usize,
    live_entries: usize,
    deadline: &Deadline,
) -> CliResult<DenseSlotCoverageScan> {
    let candidate_limit = if limit == 0 {
        live_entries
    } else {
        limit.min(live_entries)
    };
    let indexed_rows = read_indexed_base_rows(vault_dir, candidate_limit)?;
    let mut candidates = Vec::with_capacity(indexed_rows.len());
    for (index, value) in indexed_rows.values().enumerate() {
        if index == 0 || (index + 1) % 512 == 0 {
            deadline.check(
                "weave-loom",
                "coverage.base_page_index_readback",
                index as u64,
            )?;
        }
        candidates.push(encode::decode_constellation_base(value)?);
    }
    let (slot_maps, coverage) = scan_slots_for_candidates(
        vault_dir,
        read_session,
        content_slots,
        &candidates,
        deadline,
    )?;
    Ok(DenseSlotCoverageScan {
        constellations_in_vault: live_entries,
        candidate_scan_rows: candidates.len(),
        candidate_scan_complete: candidates.len() == live_entries,
        scanned_candidates: candidates,
        slot_maps,
        coverage,
        base_page_index_live_entries: live_entries,
    })
}

fn scan_bounded_covered_coverage(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    requested_slot: Option<SlotId>,
    content_slots: &[SlotId],
    limit: usize,
    live_entries: usize,
    deadline: &Deadline,
) -> CliResult<DenseSlotCoverageScan> {
    if requested_slot.is_none() && limit > 0 {
        return scan_auto_bounded_covered_coverage(
            vault_dir,
            read_session,
            content_slots,
            limit,
            live_entries,
            deadline,
        );
    }
    let measured_slots = requested_slot.map_or_else(|| content_slots.to_vec(), |slot| vec![slot]);
    scan_covered_slots(
        vault_dir,
        read_session,
        &measured_slots,
        limit,
        live_entries,
        deadline,
    )
}

fn scan_auto_bounded_covered_coverage(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    content_slots: &[SlotId],
    limit: usize,
    live_entries: usize,
    deadline: &Deadline,
) -> CliResult<DenseSlotCoverageScan> {
    let target_rows = limit.max(2);
    let mut measured_coverage = Vec::new();
    let mut last_scan = None;
    for &slot in content_slots {
        let mut scan = scan_covered_slots(
            vault_dir,
            read_session,
            &[slot],
            limit,
            live_entries,
            deadline,
        )?;
        let row = scan.coverage.remove(0);
        let reached_target = row.dense_rows >= target_rows;
        measured_coverage.push(row);
        if reached_target {
            scan.coverage = measured_coverage;
            return Ok(scan);
        }
        last_scan = Some(scan);
    }
    let mut scan = last_scan.unwrap_or(DenseSlotCoverageScan {
        constellations_in_vault: live_entries,
        scanned_candidates: Vec::new(),
        slot_maps: BTreeMap::new(),
        coverage: Vec::new(),
        base_page_index_live_entries: live_entries,
        candidate_scan_rows: 0,
        candidate_scan_complete: true,
    });
    scan.coverage = measured_coverage;
    Ok(scan)
}

fn scan_covered_slots(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    measured_slots: &[SlotId],
    limit: usize,
    live_entries: usize,
    deadline: &Deadline,
) -> CliResult<DenseSlotCoverageScan> {
    let target_rows = if limit == 0 { usize::MAX } else { limit.max(2) };
    let mut candidates = Vec::new();
    let mut accumulators = measured_slots
        .iter()
        .map(|&slot| {
            read_session.mode(slot).map(|mode| {
                (
                    slot,
                    SlotAccumulator::new(read_session.snapshot_seq(), mode.label()),
                )
            })
        })
        .collect::<CliResult<BTreeMap<_, _>>>()?;
    let mut stopped_after_target = false;

    visit_indexed_base_row_pages(vault_dir, |_, rows| -> CliResult<bool> {
        for row_chunk in rows.chunks(COVERED_SCAN_BATCH_SIZE) {
            let mut chunk = Vec::with_capacity(row_chunk.len());
            for (_, value) in row_chunk {
                let index = candidates.len() + chunk.len();
                if index == 0 || (index + 1) % 512 == 0 {
                    deadline.check(
                        "weave-loom",
                        "coverage.base_page_index_readback",
                        index as u64,
                    )?;
                }
                chunk.push(encode::decode_constellation_base(value)?);
            }
            for (slot_index, &slot) in measured_slots.iter().enumerate() {
                let accumulator = accumulators.get_mut(&slot).expect("slot accumulator");
                classify_chunk(
                    vault_dir,
                    read_session,
                    slot,
                    &chunk,
                    accumulator,
                    deadline,
                    (slot_index * candidates.len()) as u64,
                )?;
            }
            candidates.extend(chunk);
            if target_rows != usize::MAX
                && accumulators
                    .values()
                    .any(|accumulator| accumulator.map.len() >= target_rows)
            {
                stopped_after_target = true;
                return Ok(false);
            }
        }
        Ok(true)
    })?;

    let mut slot_maps = BTreeMap::new();
    let mut coverage = Vec::new();
    for &slot in measured_slots {
        let accumulator = accumulators.remove(&slot).expect("slot accumulator");
        let (map, row) = summarize_slot_coverage(slot, candidates.len(), accumulator)?;
        slot_maps.insert(slot, map);
        coverage.push(row);
    }
    Ok(DenseSlotCoverageScan {
        constellations_in_vault: live_entries,
        candidate_scan_rows: candidates.len(),
        candidate_scan_complete: !stopped_after_target,
        scanned_candidates: candidates,
        slot_maps,
        coverage,
        base_page_index_live_entries: live_entries,
    })
}

fn scan_slots_for_candidates(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    content_slots: &[SlotId],
    candidates: &[Constellation],
    deadline: &Deadline,
) -> CliResult<(SlotCoverageMaps, SlotCoverageRows)> {
    let mut slot_maps = BTreeMap::new();
    let mut coverage = Vec::new();
    for (slot_index, &slot) in content_slots.iter().enumerate() {
        let mode = read_session.mode(slot)?;
        let mut accumulator = SlotAccumulator::new(read_session.snapshot_seq(), mode.label());
        classify_chunk(
            vault_dir,
            read_session,
            slot,
            candidates,
            &mut accumulator,
            deadline,
            (slot_index * candidates.len()) as u64,
        )?;
        let (map, row) = summarize_slot_coverage(slot, candidates.len(), accumulator)?;
        slot_maps.insert(slot, map);
        coverage.push(row);
    }
    Ok((slot_maps, coverage))
}

/// Per-slot classification state. Every candidate lands in exactly one
/// bucket, so the buckets always sum to the candidate count.
struct SlotAccumulator {
    map: HashMap<CxId, Vec<f32>>,
    non_dense_rows: usize,
    absent_rows: usize,
    tombstoned_rows: usize,
    missing_rows: usize,
    example_missing_cx_ids: Vec<String>,
    read_stats: CoverageSlotReadStats,
}

impl SlotAccumulator {
    fn new(snapshot_seq: u64, storage: &'static str) -> Self {
        Self {
            map: HashMap::new(),
            non_dense_rows: 0,
            absent_rows: 0,
            tombstoned_rows: 0,
            missing_rows: 0,
            example_missing_cx_ids: Vec::new(),
            read_stats: CoverageSlotReadStats {
                snapshot_seq,
                storage: Some(storage),
                ..CoverageSlotReadStats::default()
            },
        }
    }
}

/// Reads and classifies one chunk of candidates against one slot CF. A
/// candidate whose base row lists the slot but has no physical slot row in
/// any resolution stage fails closed as `CALYX_ASTER_CORRUPT_SHARD` — it is
/// never silently counted as missing coverage (issue #1096).
fn classify_chunk(
    vault_dir: &Path,
    read_session: &CoverageSlotReadSession<'_>,
    slot: SlotId,
    chunk: &[Constellation],
    accumulator: &mut SlotAccumulator,
    deadline: &Deadline,
    processed_offset: u64,
) -> CliResult<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    for (candidate_index, _) in chunk.iter().enumerate() {
        if candidate_index == 0 || (candidate_index + 1) % 256 == 0 {
            deadline.check(
                "weave-loom",
                "coverage.slot_point_read",
                processed_offset + candidate_index as u64,
            )?;
        }
    }
    let cx_ids = chunk.iter().map(|cx| cx.cx_id).collect::<Vec<_>>();
    let (values, metrics) = read_session.read_primary_rows(slot, &cx_ids)?;
    accumulate_physical_read_metrics(&mut accumulator.read_stats, metrics)?;
    let mode = *read_session.mode(slot)?;
    let mut present = Vec::new();
    for (cx, value) in chunk.iter().zip(values) {
        let Some(value) = value else {
            if cx.slots.contains_key(&slot) {
                return Err(missing_listed_slot_row_error(
                    vault_dir,
                    cx,
                    slot,
                    &accumulator.read_stats,
                ));
            }
            accumulator.missing_rows += 1;
            if accumulator.example_missing_cx_ids.len() < EXAMPLE_MISSING_LIMIT {
                accumulator
                    .example_missing_cx_ids
                    .push(cx.cx_id.to_string());
            }
            continue;
        };
        if is_tombstone_value(&value) {
            if matches!(mode, CoverageSlotReadMode::Compressed) {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "live compressed generation for slot {} has a tombstoned primary row for cx {} at snapshot {}",
                    slot.get(),
                    cx.cx_id,
                    read_session.snapshot_seq()
                ))
                .into());
            }
            accumulator.tombstoned_rows += 1;
            continue;
        }
        present.push(cx.cx_id);
    }
    if present.is_empty() {
        return Ok(());
    }
    let resolved = read_session.resolve_semantic_rows(slot, &present)?;
    record_semantic_batch(&mut accumulator.read_stats, present.len(), resolved.len())?;
    for ((expected, vector), requested) in resolved.into_iter().zip(present) {
        if expected != requested {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "{} coverage batch for slot {} changed requested cx {requested} into {expected}",
                mode.label(),
                slot.get()
            ))
            .into());
        }
        classify_vector(expected, vector, accumulator);
    }
    Ok(())
}

fn classify_vector(cx_id: CxId, vector: SlotVector, accumulator: &mut SlotAccumulator) {
    match vector {
        SlotVector::Dense { data, .. } => {
            accumulator.map.insert(cx_id, data);
        }
        SlotVector::Absent { .. } => accumulator.absent_rows += 1,
        _ => accumulator.non_dense_rows += 1,
    }
}

fn accumulate_physical_read_metrics(
    stats: &mut CoverageSlotReadStats,
    metrics: OrderedReadbackMetrics,
) -> CliResult<()> {
    if metrics.session_snapshot_seq != stats.snapshot_seq {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "weave coverage physical read changed snapshot from {} to {}",
            stats.snapshot_seq, metrics.session_snapshot_seq
        ))
        .into());
    }
    stats.physical_batches = checked_stat_add(
        stats.physical_batches,
        metrics.read_batches,
        "physical_batches",
    )?;
    stats.physical_requested_rows = checked_stat_add(
        stats.physical_requested_rows,
        metrics.requested_keys,
        "physical_requested_rows",
    )?;
    stats.physical_rows_read_back = checked_stat_add(
        stats.physical_rows_read_back,
        metrics.rows_read_back,
        "physical_rows_read_back",
    )?;
    stats.physical_primary_bytes = checked_stat_add(
        stats.physical_primary_bytes,
        metrics.bytes_read_back,
        "physical_primary_bytes",
    )?;
    stats.physical_source_read_operations = checked_stat_add(
        stats.physical_source_read_operations,
        metrics.source_read_operations,
        "physical_source_read_operations",
    )?;
    stats.physical_sst_files_opened = checked_stat_add(
        stats.physical_sst_files_opened,
        metrics.sst_files_opened,
        "physical_sst_files_opened",
    )?;
    stats.physical_sst_key_probes = checked_stat_add(
        stats.physical_sst_key_probes,
        metrics.sst_key_probes,
        "physical_sst_key_probes",
    )?;
    stats.physical_sst_map_reuses = checked_stat_add(
        stats.physical_sst_map_reuses,
        metrics.sst_map_reuses,
        "physical_sst_map_reuses",
    )?;
    stats.physical_max_readback_batch_bytes = stats
        .physical_max_readback_batch_bytes
        .max(metrics.max_readback_batch_bytes);
    Ok(())
}

fn record_semantic_batch(
    stats: &mut CoverageSlotReadStats,
    requested: usize,
    resolved: usize,
) -> CliResult<()> {
    let requested = u64::try_from(requested)
        .map_err(|_| CliError::runtime("coverage requested row count exceeds u64"))?;
    let resolved = u64::try_from(resolved)
        .map_err(|_| CliError::runtime("coverage resolved row count exceeds u64"))?;
    if requested != resolved {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "coverage semantic batch resolved {resolved} rows for {requested} requests"
        ))
        .into());
    }
    stats.semantic_batches = checked_stat_add(stats.semantic_batches, 1, "semantic_batches")?;
    stats.semantic_requested_rows = checked_stat_add(
        stats.semantic_requested_rows,
        requested,
        "semantic_requested_rows",
    )?;
    stats.semantic_resolved_rows = checked_stat_add(
        stats.semantic_resolved_rows,
        resolved,
        "semantic_resolved_rows",
    )?;
    Ok(())
}

fn checked_stat_add(left: u64, right: u64, field: &str) -> CliResult<u64> {
    left.checked_add(right).ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!("weave coverage read-stat overflow for {field}"))
            .into()
    })
}

fn missing_listed_slot_row_error(
    vault_dir: &Path,
    cx: &Constellation,
    slot: SlotId,
    read_stats: &CoverageSlotReadStats,
) -> CliError {
    CalyxError::aster_corrupt_shard(format!(
        "weave-loom dense coverage fail-closed: base row for cx {} in {} lists slot {} \
         (Base ledger provenance seq {}, not used as an Aster MVCC sequence) but no current-state \
         primary row exists at retained Aster snapshot {}; read stats so far: {:?}",
        cx.cx_id,
        vault_dir.display(),
        slot.get(),
        cx.provenance.seq,
        read_stats.snapshot_seq,
        read_stats,
    ))
    .into()
}

fn hex_key(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn summarize_slot_coverage(
    slot: SlotId,
    candidate_rows: usize,
    accumulator: SlotAccumulator,
) -> CliResult<(HashMap<CxId, Vec<f32>>, DenseSlotCoverage)> {
    let dense_rows = accumulator.map.len();
    let classified = dense_rows
        + accumulator.non_dense_rows
        + accumulator.absent_rows
        + accumulator.tombstoned_rows
        + accumulator.missing_rows;
    if classified != candidate_rows {
        return Err(CliError::io(format!(
            "weave-loom dense coverage accounting bug for slot {}: {classified} classified rows \
             != {candidate_rows} candidate rows (dense={dense_rows} non_dense={} absent={} \
             tombstoned={} missing={})",
            slot.get(),
            accumulator.non_dense_rows,
            accumulator.absent_rows,
            accumulator.tombstoned_rows,
            accumulator.missing_rows,
        )));
    }
    let row = DenseSlotCoverage {
        slot_id: slot.get(),
        candidate_rows,
        dense_rows,
        missing_rows: accumulator.missing_rows,
        non_dense_rows: accumulator.non_dense_rows,
        absent_rows: accumulator.absent_rows,
        tombstoned_rows: accumulator.tombstoned_rows,
        example_missing_cx_ids: accumulator.example_missing_cx_ids,
        read_stats: accumulator.read_stats,
    };
    Ok((accumulator.map, row))
}
