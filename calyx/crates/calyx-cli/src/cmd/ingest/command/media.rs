use std::collections::BTreeMap;

use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::{BaseRecord, encode_constellation_base};
use calyx_core::{Constellation, Modality, SlotState, VaultStore};
use calyx_ledger::{ActorId, SubjectId};
use calyx_registry::{VaultPanelState, load_vault_panel_state};

use super::ingest_runtime_log;
use crate::cmd::ingest::constellation::{
    ensure_content_panel_floor, measure_constellation_with_runtime_limit,
};
use crate::cmd::ingest::route::IngestGpuRoute;
use crate::cmd::ingest::store::open_vault;
use crate::cmd::ingest::types::IngestReport;
use crate::cmd::ingest::verify::{
    read_optional_base_record, verify_base_readback, verify_base_record_readback,
    verify_flushed_base_records,
};
use crate::cmd::search::rebuild_persistent_indexes;
use crate::cmd::vault::{ResolvedVault, now_ms};
use crate::error::CliResult;
use crate::media_derived_text::{
    derivation_ledger_payload, derive_text_for_media, derived_artifact_draft,
};
use crate::raw_media::{RetainedMediaInput, media_metadata};

pub(super) fn ingest_media_with_derived_text(
    resolved: &ResolvedVault,
    retained: RetainedMediaInput,
    gpu_route: IngestGpuRoute,
) -> CliResult<Vec<IngestReport>> {
    let vault = open_vault(resolved)?;
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

    ensure_raw_media_panel_route(retained.input.modality, &state)?;
    let source_cx_id = vault.cx_id_for_input(&retained.input.bytes, state.panel.version);
    let derived = derive_text_for_media(&resolved.path, &retained, source_cx_id)?;

    let mut media_cx = measure_constellation_with_runtime_limit(
        &vault,
        &state,
        &retained.input,
        now_ms(),
        None,
        gpu_route,
    )?;
    media_cx.metadata = media_metadata(&retained);
    let mut text_cx = measure_constellation_with_runtime_limit(
        &vault,
        &state,
        &derived.input,
        now_ms(),
        None,
        gpu_route,
    )?;
    text_cx.metadata = derived.metadata.clone();

    if media_cx.cx_id == text_cx.cx_id {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "raw {:?} media and its derived text resolved to the same cx {}; refusing to publish two incompatible constellation roles under one Base key",
            retained.input.modality, media_cx.cx_id
        ))
        .into());
    }

    let preflight_snapshot = vault.snapshot();
    let media_existing = preflight_existing_media_or_text(&vault, preflight_snapshot, &media_cx)?;
    let text_existing = preflight_existing_media_or_text(&vault, preflight_snapshot, &text_cx)?;
    let media_new = media_existing.is_none();
    let text_new = text_existing.is_none();
    if media_new {
        ensure_content_panel_floor(&media_cx, &state)?;
    }
    if text_new {
        ensure_content_panel_floor(&text_cx, &state)?;
    }
    let payload = derivation_ledger_payload(&retained, &derived, media_cx.cx_id, text_cx.cx_id)?;
    let mut staged = Vec::with_capacity(2);
    if media_new {
        staged.push(media_cx.clone());
    }
    if text_new && text_cx.cx_id != media_cx.cx_id {
        staged.push(text_cx.clone());
    }
    let artifact_draft =
        derived_artifact_draft(&retained, &derived, media_cx.cx_id, text_cx.cx_id)?;
    // The derivation artifact always writes Graph rows, including an
    // existing/existing replay, and Graph participates in derived search.
    super::stake_rebuild_required_marker(
        &resolved.path,
        "media_ingest",
        format!(
            "media ingest of {:?} input with derived text (media cx {}, text cx {})",
            retained.input.modality, media_cx.cx_id, text_cx.cx_id
        ),
        None,
        None,
    )?;
    let commit = vault.put_batch_with_ingest_ledger_and_media_artifact_if_current(
        preflight_snapshot,
        staged,
        SubjectId::Cx(text_cx.cx_id),
        payload,
        ActorId::Service("calyx-cli".to_string()),
        artifact_draft,
    )?;
    let expected_new_ids = [
        media_new.then_some(media_cx.cx_id),
        text_new.then_some(text_cx.cx_id),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if commit.ids != expected_new_ids {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "media artifact commit returned Base ids {:?}, expected {:?}",
            commit.ids, expected_new_ids
        ))
        .into());
    }
    let mut new_records = BTreeMap::new();
    for record in commit.new_records {
        let cx_id = record.cx_id();
        let mut expected = if cx_id == media_cx.cx_id && media_new {
            media_cx.clone()
        } else if cx_id == text_cx.cx_id && text_new {
            text_cx.clone()
        } else {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "media artifact commit returned unplanned new Base record for cx {cx_id}"
            ))
            .into());
        };
        expected.provenance = record.constellation().provenance.clone();
        if record.encode()? != encode_constellation_base(&expected)? {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "media artifact commit returned a different final Base record for cx {cx_id}"
            ))
            .into());
        }
        if new_records.insert(cx_id, record).is_some() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "media artifact commit returned duplicate new Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    if new_records.len() != expected_new_ids.len() {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "media artifact commit returned {} new Base records for {} expected ids",
            new_records.len(),
            expected_new_ids.len()
        ))
        .into());
    }
    let readback = vault.retain_snapshot_at(commit.readback_seq);
    let flush_report = vault.flush_with_report()?;
    verify_flushed_base_records(&flush_report, Some(commit.readback_seq), &new_records)?;
    if let Some(expected) = media_existing.as_ref() {
        verify_base_record_readback(&vault, readback.seq(), expected)?;
    } else {
        let record = new_records.get(&media_cx.cx_id).ok_or_else(|| {
            calyx_core::CalyxError::aster_corrupt_shard(format!(
                "media artifact commit omitted new Base record for cx {}",
                media_cx.cx_id
            ))
        })?;
        verify_base_record_readback(&vault, readback.seq(), record)?;
        let mut expected = media_cx.clone();
        expected.provenance = record.constellation().provenance.clone();
        verify_base_readback(&vault, readback.seq(), &expected, media_cx.cx_id, &[])?;
    }
    readback.record_progress();
    if let Some(expected) = text_existing.as_ref() {
        verify_base_record_readback(&vault, readback.seq(), expected)?;
    } else {
        let record = new_records.get(&text_cx.cx_id).ok_or_else(|| {
            calyx_core::CalyxError::aster_corrupt_shard(format!(
                "media artifact commit omitted new Base record for cx {}",
                text_cx.cx_id
            ))
        })?;
        verify_base_record_readback(&vault, readback.seq(), record)?;
        let mut expected = text_cx.clone();
        expected.provenance = record.constellation().provenance.clone();
        verify_base_readback(&vault, readback.seq(), &expected, text_cx.cx_id, &[])?;
    }
    readback.record_progress();
    verify_media_artifact_readback(&vault, readback.seq(), &commit.artifact)?;
    readback.record_progress();
    drop(readback);
    rebuild_persistent_indexes(&resolved.path, &vault, &state)?;

    let media_ledger_seq = new_records
        .get(&media_cx.cx_id)
        .map(|record| record.constellation().provenance.seq)
        .unwrap_or(commit.artifact.ledger_ref.seq);
    let text_ledger_seq = new_records
        .get(&text_cx.cx_id)
        .map(|record| record.constellation().provenance.seq)
        .unwrap_or(commit.artifact.ledger_ref.seq);
    vault.flush()?;
    Ok(vec![
        IngestReport {
            cx_id: media_cx.cx_id.to_string(),
            new: media_new,
            ledger_seq: media_ledger_seq,
        },
        IngestReport {
            cx_id: text_cx.cx_id.to_string(),
            new: text_new,
            ledger_seq: text_ledger_seq,
        },
    ])
}

fn ensure_raw_media_panel_route(modality: Modality, state: &VaultPanelState) -> CliResult {
    if !matches!(
        modality,
        Modality::Image | Modality::Audio | Modality::Video
    ) {
        return Ok(());
    }
    let has_declared_route = state
        .panel
        .slots
        .iter()
        .any(|slot| slot.state == SlotState::Active && slot.counts_toward_degraded(modality));
    if has_declared_route {
        return Ok(());
    }
    Err(calyx_core::CalyxError {
        code: "CALYX_MEDIA_ROUTE_UNAVAILABLE",
        message: format!(
            "raw {modality:?} ingest requires an active {modality:?} content lens before derived text can be attached"
        ),
        remediation:
            "add or activate an image/audio/video lens for the raw media modality, then re-run ingest so the media constellation is measured instead of empty",
    }
    .into())
}

fn preflight_existing_media_or_text(
    vault: &AsterVault,
    snapshot: u64,
    expected: &Constellation,
) -> CliResult<Option<BaseRecord>> {
    let Some(stored) = read_optional_base_record(vault, snapshot, expected.cx_id)? else {
        return Ok(None);
    };
    let expected_record =
        BaseRecord::decode_for_key(expected.cx_id, &encode_constellation_base(expected)?)?;
    let stored_constellation = stored.constellation();
    if stored.vault_id() != expected.vault_id
        || expected_record.vault_id() != expected.vault_id
        || stored_constellation.panel_version != expected.panel_version
        || stored_constellation.input_ref.hash != expected.input_ref.hash
        || stored_constellation.modality != expected.modality
        || stored.slot_hashes() != expected_record.slot_hashes()
    {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "durable media ingest preflight mismatch for existing cx {}",
            expected.cx_id
        ))
        .into());
    }
    Ok(Some(stored))
}

fn verify_media_artifact_readback(
    vault: &AsterVault,
    snapshot: u64,
    expected: &calyx_aster::media_artifact::DerivedMediaArtifactRecord,
) -> CliResult {
    let stored = vault
        .get_derived_media_artifact(snapshot, &expected.artifact_id)?
        .ok_or_else(|| {
            calyx_core::CalyxError::aster_corrupt_shard(format!(
                "derived media artifact {} missing after commit",
                expected.artifact_id
            ))
        })?;
    if stored != *expected {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} readback mismatch",
            expected.artifact_id
        ))
        .into());
    }
    let source_records =
        vault.derived_media_artifacts_for_source(snapshot, expected.source_cx_id)?;
    if !source_records.iter().any(|record| record == expected) {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} missing from source index",
            expected.artifact_id
        ))
        .into());
    }
    let target_records =
        vault.derived_media_artifacts_for_target(snapshot, expected.target_cx_id)?;
    if !target_records.iter().any(|record| record == expected) {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} missing from target index",
            expected.artifact_id
        ))
        .into());
    }
    Ok(())
}
