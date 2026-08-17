use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use calyx_aster::cf::{ColumnFamily, anchor_key, base_key};
use calyx_aster::dedup::{AnchorConflictResult, check_anchor_conflict};
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode;
use calyx_aster::vault::input_store::{self, InputRetention};
use calyx_core::{
    Anchor, AnchorKind, CalyxError, Constellation, CxId, Input, InputRef, Modality, VaultStore,
};
use calyx_ledger::EntryKind;
use calyx_registry::{VaultPanelState, load_vault_panel_state};

use super::super::search::{rebuild_persistent_indexes, rebuild_persistent_indexes_with_progress};
use super::super::vault::{ResolvedVault, now_ms};
use super::super::{AnchorArgs, IngestArgs, MeasureArgs, Subcommand};
use super::anchor::{parse_anchor_kind, parse_anchor_value};
use super::batch::{BatchRow, parse_batch_line, retain_batch_file, validate_batch_file};
use super::constellation::{
    ensure_content_panel_floor, input_hash, measure_constellation,
    measure_constellation_microbatch_with_runtime_limit, measure_constellation_with_runtime_limit,
    text_input,
};
use super::ledger::{append_anchor_ledger, append_cli_batch_ledger, append_cli_ledger};
use super::oracle_event::{OracleEvent, append_recurrence_if_absent};
use super::route::{IngestGpuRoute, resolve_ingest_gpu_route};
use super::session::BatchIngestSession;
use super::store::{base_exists, ensure_base_exists, open_vault, resolve_cli_vault};
use super::types::{AnchorReport, BatchIngestSummary, IngestOutput, IngestReport};
use super::verify::{
    read_base_record, read_optional_base_record, verify_base_readback, verify_base_record_readback,
    verify_flushed_base_records,
};
use crate::error::{CliError, CliResult};
use crate::output::print_json;
use crate::raw_media::retain_media_input;

const DEFAULT_ANCHOR_SOURCE: &str = "calyx-cli";

/// Default inputs per real runtime call inside a lens worker. This is a CUDA
/// safety limit, not a file-streaming flush size. Bigger = faster GPU
/// utilization, but peak VRAM scales with the transient attention/MLP activation
/// buffers, which grow with `batch x sequence_len`: a single unlucky microbatch
/// of max-length rows can spike past VRAM and OOM mid-ingest (an ingest crash
/// also desyncs the vault ledger — see #866 — so a crash is expensive, not just a
/// retry). Measured on a 14-lens FP32 panel / RTX 5090: batch=8 peaked ~32 GiB
/// and OOM'd on long medmcqa rows, while batch=4 peaks ~19.6 GiB on the
/// worst-case longest corpus rows (13 GiB headroom). So the default is 4; raise
/// `CALYX_MEASURE_BATCH` on a dedicated GPU / short inputs.
const DEFAULT_MEASURE_BATCH: usize = 4;
/// JSONL rows gathered before measurement. Lenses still receive
/// `CALYX_MEASURE_BATCH`-bounded runtime chunks inside the worker, but a larger
/// window prevents a small ingest from spawning one process per lens per 4 rows.
const DEFAULT_MEASURE_WINDOW: usize = 128;
/// Constellations per WAL commit. Small because ColBERT multi-vectors are large;
/// decoupled from the measure batch so we measure big but commit WAL-safe.
const PUT_CHUNK: usize = 8;
/// Existing-row replay does not stage vector payloads, so it can verify and ledger
/// larger groups without the ColBERT WAL pressure that constrains new puts.
const EXISTING_REPLAY_CHUNK: usize = 128;
const MEASURE_BATCH_ENV: &str = "CALYX_MEASURE_BATCH";
const MEASURE_WINDOW_ENV: &str = "CALYX_INGEST_MEASURE_WINDOW";

#[derive(Clone, Copy)]
struct BatchFlushOptions {
    output: IngestOutput,
    runtime_batch_limit: usize,
    gpu_route: IngestGpuRoute,
    /// Resolved raw-input retention policy for this batch (#446).
    input_retention: InputRetention,
}

pub(crate) fn ingest_runtime_log(args: std::fmt::Arguments<'_>) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "CALYX_INGEST_RUNTIME {args}");
    let _ = stderr.flush();
}

pub(super) fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<unserializable>\"".to_string())
}

/// Stake the durable write-ahead rebuild-required marker (issue #1089) before
/// the first Base/ledger mutation of an ingest-family command. If the process
/// is killed at any later point — including an external CLI timeout during the
/// post-commit index rebuild — the vault carries a first-class record of the
/// partial commit and its remediation instead of a silently stale manifest.
/// The marker is cleared by the rebuild itself after the new manifest is
/// durably published.
pub(super) fn stake_rebuild_required_marker(
    vault_dir: &std::path::Path,
    source: &str,
    detail: String,
    session_id: Option<&str>,
    batch_path: Option<&std::path::Path>,
) -> CliResult<()> {
    // A pre-existing marker means an earlier run's staleness record is still
    // unresolved; it must survive verbatim. The vault is already flagged, and
    // the rebuild this run triggers pins the latest durable seq, covering both
    // commits — so preserving is strictly safer than superseding.
    if let Some(existing) = calyx_search::read_rebuild_required_marker(vault_dir)? {
        ingest_runtime_log(format_args!(
            "phase=derived_rebuild_marker_preserved previous_source={} previous_written_at_unix_ms={} previous_required_base_seq={} previous_session_id={} previous_process_id={}",
            existing.source,
            existing.written_at_unix_ms,
            existing
                .required_base_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "in-flight".to_string()),
            existing.session_id.as_deref().unwrap_or("<none>"),
            existing.process_id
        ));
        return Ok(());
    }
    let mut marker = calyx_search::RebuildRequiredMarker::new(source, detail)?;
    marker.session_id = session_id.map(str::to_string);
    marker.batch_path = batch_path.map(|path| path.display().to_string());
    let path = calyx_search::write_rebuild_required_marker(vault_dir, &marker)?;
    ingest_runtime_log(format_args!(
        "phase=derived_rebuild_marker_written source={source} marker_path={} required_base_seq=in-flight session_id={}",
        path.display(),
        marker.session_id.as_deref().unwrap_or("<none>")
    ));
    Ok(())
}

/// Record the exact durable seq the committed rows reached, so the marker
/// names the precise base seq a completing rebuild must cover. A marker owned
/// by another process is left untouched — its own record stands, and the
/// rebuild pins the latest durable seq, which covers this commit too. Fails
/// closed if the marker staked at ingest start has vanished — that would mean
/// external interference with the vault's crash-recovery state mid-run.
pub(super) fn record_rebuild_required_marker_seq(
    vault_dir: &std::path::Path,
    required_base_seq: u64,
) -> CliResult<()> {
    let Some(mut marker) = calyx_search::read_rebuild_required_marker(vault_dir)? else {
        return Err(CliError::from(calyx_core::CalyxError {
            code: "CALYX_SEARCH_REBUILD_MARKER_MISSING",
            message: format!(
                "rebuild-required marker staked at ingest start is missing from {} before the post-commit index rebuild; rows are committed but the derived-staleness record was removed externally",
                calyx_search::rebuild_required_marker_path(vault_dir).display()
            ),
            remediation: "do not delete idx/search/rebuild-required.json by hand; run `calyx rebuild-search-index <vault>` to rebuild derived indexes and restore a consistent state",
        }));
    };
    if marker.process_id != std::process::id() {
        ingest_runtime_log(format_args!(
            "phase=derived_rebuild_marker_seq_skipped reason=foreign_marker owner_process_id={} required_base_seq={required_base_seq}",
            marker.process_id
        ));
        return Ok(());
    }
    marker.required_base_seq = Some(required_base_seq);
    let path = calyx_search::write_rebuild_required_marker(vault_dir, &marker)?;
    ingest_runtime_log(format_args!(
        "phase=derived_rebuild_marker_seq_recorded marker_path={} required_base_seq={required_base_seq}",
        path.display()
    ));
    Ok(())
}

/// Resolve the runtime microbatch from `CALYX_MEASURE_BATCH` (>=1), else the
/// conservative default. Operator-tunable so the VRAM/throughput trade-off does
/// not require a recompile.
fn measure_batch_size() -> usize {
    positive_env_usize(MEASURE_BATCH_ENV).unwrap_or(DEFAULT_MEASURE_BATCH)
}

fn measure_window_size(runtime_batch_limit: usize) -> usize {
    positive_env_usize(MEASURE_WINDOW_ENV)
        .unwrap_or(DEFAULT_MEASURE_WINDOW)
        .max(runtime_batch_limit.max(1))
}

fn positive_env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|&n| n >= 1)
}

pub(crate) fn run(command: Subcommand) -> CliResult {
    match command {
        Subcommand::Ingest(args) => ingest_command(args),
        Subcommand::IngestStatus(args) => super::session::run_status(args),
        Subcommand::Anchor(args) => anchor_command(args),
        Subcommand::Measure(args) => measure_command(args),
        _ => unreachable!("non-ingest command routed to ingest module"),
    }
}

fn ingest_command(args: IngestArgs) -> CliResult {
    if let Some(batch_path) = args.batch.as_deref() {
        let _batch_file_lease = retain_batch_file(batch_path)?;
        let validation = validate_batch_file(batch_path)?;
        let resolved = resolve_cli_vault(&args.vault)?;
        let gpu_route = resolve_ingest_gpu_route(
            &resolved.path,
            args.resident_addr,
            args.allow_cold_gpu_workers,
        )?;
        let mut session = BatchIngestSession::start(
            &resolved,
            batch_path,
            &validation,
            args.session_id.as_deref(),
        )?;
        ingest_runtime_log(format_args!(
            "phase=batch_session_created session_id={} status_path={}",
            session.session_id(),
            session.status_path().display()
        ));
        eprintln!(
            "CALYX_INGEST_SESSION id={} path={}",
            session.session_id(),
            session.status_path().display()
        );
        let mut emitted_summary = false;
        let result = if validation.row_count == 0 {
            (|| {
                let summary = BatchIngestSummary::empty();
                let vault = open_vault(&resolved)?;
                session.complete(&summary, vault.snapshot())?;
                Ok(summary)
            })()
        } else if args.output == IngestOutput::Summary {
            let mut emit_summary = |summary: &BatchIngestSummary| {
                emitted_summary = true;
                print_json(summary)
            };
            batch_stream::ingest_validated_batch_streaming_with_output(
                &resolved,
                batch_path,
                batch_stream::BatchStreamRequest {
                    output: args.output,
                    validated_row_count: validation.row_count,
                    gpu_route,
                    retention_override: args.input_retention,
                },
                Some(&mut emit_summary),
                Some(&mut session),
            )
        } else {
            batch_stream::ingest_validated_batch_streaming_with_output(
                &resolved,
                batch_path,
                batch_stream::BatchStreamRequest {
                    output: args.output,
                    validated_row_count: validation.row_count,
                    gpu_route,
                    retention_override: args.input_retention,
                },
                None,
                Some(&mut session),
            )
        };
        let summary = match result {
            Ok(summary) => summary,
            Err(error) => {
                session.fail_with_error(&error)?;
                return Err(error);
            }
        };
        if args.output == IngestOutput::Summary && !emitted_summary {
            print_json(&summary)?;
        }
    } else {
        let resolved = resolve_cli_vault(&args.vault)?;
        let gpu_route = resolve_ingest_gpu_route(
            &resolved.path,
            args.resident_addr,
            args.allow_cold_gpu_workers,
        )?;
        if let Some(path) = args.file {
            let modality = args.modality.expect("parser requires modality with --file");
            let retained = retain_media_input(&resolved.path, &path, modality)?;
            let reports = media::ingest_media_with_derived_text(&resolved, retained, gpu_route)?;
            for report in reports {
                print_json(&report)?;
            }
        } else if let Some(text) = args.text {
            for report in
                ingest_texts_with_resident(&resolved, &[text], gpu_route, args.input_retention)?
            {
                print_json(&report)?;
            }
        }
    }
    Ok(())
}

fn anchor_command(args: AnchorArgs) -> CliResult {
    let resolved = resolve_cli_vault(&args.vault)?;
    let vault = open_vault(&resolved)?;
    let state = load_vault_panel_state(&resolved.path)?;
    let cx_id = args
        .cx_id
        .parse::<CxId>()
        .map_err(|err| CliError::usage(format!("parse <cx_id> {}: {err}", args.cx_id)))?;
    ensure_base_exists(&vault, cx_id)?;
    let kind = parse_anchor_kind(&args.kind)?;
    let anchor = Anchor {
        value: parse_anchor_value(&kind, &args.kind, &args.value)?,
        kind: kind.clone(),
        source: args
            .source
            .unwrap_or_else(|| DEFAULT_ANCHOR_SOURCE.to_string()),
        observed_at: now_ms(),
        confidence: args.confidence.unwrap_or(1.0),
    };
    stake_rebuild_required_marker(
        &resolved.path,
        "anchor_command",
        format!("anchor append of kind {} on cx {cx_id}", args.kind),
        None,
        None,
    )?;
    let ledger_seq = append_anchor_ledger(&vault, cx_id, &kind, anchor)?;
    vault.flush()?;
    rebuild_persistent_indexes(&resolved.path, &vault, &state)?;
    print_json(&AnchorReport {
        status: "anchored",
        cx_id: cx_id.to_string(),
        ledger_seq,
    })
}

fn measure_command(args: MeasureArgs) -> CliResult {
    let resolved = resolve_cli_vault(&args.vault)?;
    let vault = open_vault(&resolved)?;
    let state = load_vault_panel_state(&resolved.path)?;
    let cx = measure_constellation(&vault, &state, text_input(args.text), now_ms())?;
    print_json(&cx)
}

fn ingest_texts_with_resident(
    resolved: &ResolvedVault,
    texts: &[String],
    gpu_route: IngestGpuRoute,
    retention_override: Option<InputRetention>,
) -> CliResult<Vec<IngestReport>> {
    let rows = texts
        .iter()
        .map(|text| (text.clone(), BTreeMap::new()))
        .collect();
    ingest_text_rows_with_resident(resolved, rows, gpu_route, retention_override)
}

fn ingest_text_rows_with_resident(
    resolved: &ResolvedVault,
    rows: Vec<(String, BTreeMap<String, String>)>,
    gpu_route: IngestGpuRoute,
    retention_override: Option<InputRetention>,
) -> CliResult<Vec<IngestReport>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let prepared = rows
        .into_iter()
        .map(|(text, metadata)| {
            super::parse::validate_text(&text)?;
            Ok(PreparedInput {
                input: text_input(text),
                metadata,
            })
        })
        .collect::<CliResult<Vec<_>>>()?;
    ingest_prepared_inputs(resolved, prepared, gpu_route, retention_override)
}

/// Resolves the effective raw-input retention policy (#446): the per-ingest
/// CLI override wins, otherwise the vault manifest's declared knob (default
/// [`InputRetention::Persist`]).
pub(crate) fn resolve_input_retention(
    vault: &AsterVault,
    retention_override: Option<InputRetention>,
) -> CliResult<InputRetention> {
    match retention_override {
        Some(policy) => Ok(policy),
        None => Ok(vault.input_retention()?),
    }
}

/// Post-commit FSV of persisted input bytes (#446): reads every stored input
/// back through the fail-closed input-store reader and byte-compares against
/// the canonical bytes that were staged. Any divergence is a structured
/// corruption error — never a silent success.
pub(crate) fn verify_persisted_inputs(
    vault: &AsterVault,
    persisted: &[([u8; 32], Vec<u8>)],
) -> CliResult {
    for (input_hash, bytes) in persisted {
        let readback = input_store::read_input_bytes(vault, input_hash)?;
        if &readback != bytes {
            return Err(CliError::from(CalyxError {
                code: input_store::CALYX_INPUT_STORE_CORRUPT,
                message: format!(
                    "post-commit readback of input {} returned {} bytes that do not match the {} canonical source bytes",
                    hex_hash(input_hash),
                    readback.len(),
                    bytes.len()
                ),
                remediation: "the input store write path is inconsistent; do not trust this vault",
            }));
        }
    }
    Ok(())
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

struct PreparedInput {
    input: Input,
    metadata: BTreeMap<String, String>,
}

fn ingest_prepared_inputs(
    resolved: &ResolvedVault,
    inputs: Vec<PreparedInput>,
    gpu_route: IngestGpuRoute,
    retention_override: Option<InputRetention>,
) -> CliResult<Vec<IngestReport>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let vault = open_vault(resolved)?;
    let retention = resolve_input_retention(&vault, retention_override)?;
    ingest_runtime_log(format_args!(
        "phase=load_vault_panel_state_start vault={}",
        resolved.path.display()
    ));
    let state = load_vault_panel_state(&resolved.path)?;
    ingest_runtime_log(format_args!(
        "phase=load_vault_panel_state_ok vault={} panel_version={} slots={}",
        resolved.path.display(),
        state.panel.version,
        state.panel.slots.len()
    ));

    struct TextPlan {
        input_ref: InputRef,
        modality: Modality,
        metadata: BTreeMap<String, String>,
        existing: Option<encode::BaseRecord>,
    }

    let mut staged = Vec::new();
    let mut staged_inputs: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut new_expected = BTreeMap::<CxId, Constellation>::new();
    let mut plans = BTreeMap::<CxId, TextPlan>::new();
    let mut plan_order = Vec::new();
    let mut prepared = Vec::with_capacity(inputs.len());
    let preflight_lease = vault.retain_latest_snapshot();
    let preflight_snapshot = preflight_lease.seq();
    for PreparedInput { input, metadata } in inputs {
        let cx_id = vault.cx_id_for_input(&input.bytes, state.panel.version);
        let incoming_ref = InputRef {
            hash: input_hash(&input.bytes),
            pointer: input.pointer.clone(),
            redacted: false,
        };
        if let Some(plan) = plans.get(&cx_id) {
            if plan.input_ref != incoming_ref
                || plan.modality != input.modality
                || plan.metadata != metadata
            {
                return Err(CliError::usage(format!(
                    "text ingest contains duplicate cx {cx_id} with changed non-anchor identity: {}",
                    batch_support::identity_mismatch_reason(
                        batch_support::IdentityFields {
                            panel_version: state.panel.version,
                            input_ref: &plan.input_ref,
                            modality: plan.modality,
                            metadata: &plan.metadata,
                        },
                        batch_support::IdentityFields {
                            panel_version: state.panel.version,
                            input_ref: &incoming_ref,
                            modality: input.modality,
                            metadata: &metadata,
                        },
                    )
                )));
            }
            prepared.push((cx_id, false));
            preflight_lease.record_progress();
            continue;
        }

        let existing = read_optional_base_record(&vault, preflight_snapshot, cx_id)?;
        let new = existing.is_none();
        if let Some(record) = existing.as_ref() {
            let stored = record.constellation();
            if stored.panel_version != state.panel.version
                || !batch_support::input_ref_matches_replay(&stored.input_ref, &incoming_ref)
                || stored.modality != input.modality
                || stored.metadata != metadata
            {
                return Err(CliError::usage(format!(
                    "idempotent text replay for cx {cx_id} changed stored non-anchor identity: {}",
                    batch_support::identity_mismatch_reason(
                        batch_support::IdentityFields {
                            panel_version: stored.panel_version,
                            input_ref: &stored.input_ref,
                            modality: stored.modality,
                            metadata: &stored.metadata,
                        },
                        batch_support::IdentityFields {
                            panel_version: state.panel.version,
                            input_ref: &incoming_ref,
                            modality: input.modality,
                            metadata: &metadata,
                        },
                    )
                )));
            }
        } else {
            let mut cx = measure_constellation_with_runtime_limit(
                &vault,
                &state,
                &input,
                now_ms(),
                None,
                gpu_route,
            )?;
            if cx.cx_id != cx_id {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "text measurement returned cx {} after preflight derived {cx_id}",
                    cx.cx_id
                ))
                .into());
            }
            cx.metadata = metadata.clone();
            ensure_content_panel_floor(&cx, &state)?;
            match retention {
                InputRetention::Persist => {
                    cx.input_ref.pointer = Some(input_store::input_pointer(&cx.input_ref.hash));
                    cx.input_ref.redacted = false;
                    staged_inputs.push((cx.input_ref.hash, input.bytes.clone()));
                }
                InputRetention::Redact => {
                    cx.input_ref.redacted = true;
                    cx.flags.redacted_input = true;
                }
            }
            new_expected.insert(cx_id, cx.clone());
            staged.push(cx);
        }
        plan_order.push(cx_id);
        plans.insert(
            cx_id,
            TextPlan {
                input_ref: incoming_ref,
                modality: input.modality,
                metadata,
                existing,
            },
        );
        prepared.push((cx_id, new));
        preflight_lease.record_progress();
    }
    drop(preflight_lease);
    let new_count = staged.len();
    ingest_runtime_log(format_args!(
        "phase=text_base_only_preflight rows={} distinct_cx={} existing={} measurement_calls={} slot_decode_skipped={}",
        prepared.len(),
        plans.len(),
        plans
            .values()
            .filter(|plan| plan.existing.is_some())
            .count(),
        new_count,
        plans.values().any(|plan| plan.existing.is_some())
    ));
    if new_count > 0 {
        stake_rebuild_required_marker(
            &resolved.path,
            "text_ingest",
            format!(
                "text ingest of {} prepared inputs ({} newly staged constellations)",
                prepared.len(),
                new_count
            ),
            None,
            None,
        )?;
    }
    let mut input_rows = Vec::new();
    for (input_hash, bytes) in &staged_inputs {
        input_rows.extend(input_store::encode_input_rows(input_hash, bytes)?);
    }
    let existing_requests = plan_order
        .iter()
        .filter_map(|cx_id| {
            plans
                .get(cx_id)
                .and_then(|plan| plan.existing.clone())
                .map(|expected| calyx_aster::vault::ExistingBaseAnchorMerge {
                    expected,
                    incoming: Vec::new(),
                })
        })
        .collect();
    let commit = vault.put_batch_with_input_rows_and_existing_base_anchor_merges(
        staged,
        input_rows,
        existing_requests,
    )?;
    ingest_runtime_log(format_args!(
        "phase=text_atomic_base_commit distinct_cx={} new={} existing={} readback_seq={} commit_seq={}",
        plans.len(),
        commit.new_records.len(),
        commit.existing_results.len(),
        commit.readback_seq,
        commit
            .commit_seq
            .map(|seq| seq.to_string())
            .unwrap_or_else(|| "none".to_string())
    ));
    let mut final_records = BTreeMap::<CxId, encode::BaseRecord>::new();
    let mut changed_records = BTreeMap::<CxId, encode::BaseRecord>::new();
    for record in commit.new_records {
        let cx_id = record.cx_id();
        let mut expected = new_expected.get(&cx_id).cloned().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "text atomic commit returned unplanned new Base record for cx {cx_id}"
            ))
        })?;
        expected.provenance = record.constellation().provenance.clone();
        if record.encode()? != encode::encode_constellation_base(&expected)? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "text atomic commit returned a different final Base record for new cx {cx_id}"
            ))
            .into());
        }
        if changed_records.insert(cx_id, record.clone()).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "text atomic commit returned duplicate changed Base record for cx {cx_id}"
            ))
            .into());
        }
        if final_records.insert(cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "text atomic commit returned duplicate new Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    for result in commit.existing_results {
        let cx_id = result.record.cx_id();
        if !result.added.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "text atomic commit added anchors to no-anchor replay cx {cx_id}"
            ))
            .into());
        }
        if final_records.insert(cx_id, result.record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "text atomic commit returned duplicate existing Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    if final_records.len() != plans.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "text atomic commit returned {} Base records for {} planned CxIds",
            final_records.len(),
            plans.len()
        ))
        .into());
    }
    if !commit.marker_ledger_receipts.is_empty() {
        return Err(CalyxError::aster_corrupt_shard(
            "text atomic commit returned anchor marker receipts for a no-anchor request",
        )
        .into());
    }
    let readback_lease = vault.retain_snapshot_at(commit.readback_seq);
    let flush_report = vault.flush_with_report()?;
    verify_flushed_base_records(&flush_report, commit.commit_seq, &changed_records)?;
    for (cx_id, record) in &final_records {
        verify_base_record_readback(&vault, commit.readback_seq, record)?;
        if let Some(expected) = new_expected.get(cx_id) {
            verify_base_readback(&vault, commit.readback_seq, expected, *cx_id, &[])?;
        }
        readback_lease.record_progress();
    }
    verify_persisted_inputs(&vault, &staged_inputs)?;
    readback_lease.record_progress();
    drop(readback_lease);
    if new_count > 0 {
        rebuild_persistent_indexes(&resolved.path, &vault, &state)?;
    }

    let mut reports = Vec::with_capacity(prepared.len());
    for (cx_id, new) in prepared {
        let ledger_seq = if new {
            final_records
                .get(&cx_id)
                .ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "text report omitted committed Base record for cx {cx_id}"
                    ))
                })?
                .constellation()
                .provenance
                .seq
        } else {
            append_cli_ledger(&vault, EntryKind::Ingest, cx_id, "cli-idempotent-ingest")?
        };
        reports.push(IngestReport {
            cx_id: cx_id.to_string(),
            new,
            ledger_seq,
        });
    }
    vault.flush()?;
    let final_snapshot = vault.snapshot();
    for record in final_records.values() {
        verify_base_record_readback(&vault, final_snapshot, record)?;
    }
    Ok(reports)
}

mod batch_physical;
mod batch_rebuild;
mod batch_stream;
mod batch_support;
mod media;
mod replay;
