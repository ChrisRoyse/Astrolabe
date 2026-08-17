use std::collections::BTreeMap;

use super::*;
use crate::tools::ingest::IngestReport;
use calyx_aster::vault::AsterVault;
use calyx_aster::vault::encode::{BaseRecord, encode_constellation_base};
use calyx_core::{Constellation, CxId};

pub(super) fn ingest_media_with_derived_text(
    resolved: &ResolvedVault,
    retained: RetainedMediaInput,
) -> ToolResult<Vec<IngestReport>> {
    let vault = open_vault(resolved)?;
    let state = calyx_registry::load_vault_panel_state(&resolved.path)?;
    ensure_raw_media_panel_route(retained.input.modality, &state)?;
    let source_cx_id = vault.cx_id_for_input(&retained.input.bytes, state.panel.version);
    let derived = derived_text::derive_text_for_media(&resolved.path, &retained, source_cx_id)?;
    let target_cx_id = vault.cx_id_for_input(&derived.input.bytes, state.panel.version);
    if source_cx_id == target_cx_id {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "raw {:?} media and its derived text resolved to the same cx {source_cx_id}; refusing to publish two incompatible constellation roles under one Base key",
            retained.input.modality
        ))
        .into());
    }

    let mut media =
        measure_constellation(&vault, &state, retained.input.clone(), now_ms())?.constellation;
    media.metadata = retained.metadata.clone();
    let mut text =
        measure_constellation(&vault, &state, derived.input.clone(), now_ms())?.constellation;
    text.metadata = derived.metadata.clone();
    if media.cx_id != source_cx_id || text.cx_id != target_cx_id {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP media measurement changed pre-derived role ids: media {} expected {source_cx_id}, text {} expected {target_cx_id}",
            media.cx_id, text.cx_id
        ))
        .into());
    }

    let preflight = vault.retain_latest_snapshot();
    let preflight_snapshot = preflight.seq();
    let expected_readback_seq = preflight_snapshot.checked_add(1).ok_or_else(|| {
        CalyxError::aster_corrupt_shard(
            "MCP media ingest cannot advance a saturated vault sequence",
        )
    })?;
    let role_ids = [media.cx_id, text.cx_id];
    let mut preflight_records =
        super::super::read_optional_base_record_batch(&vault, preflight_snapshot, &role_ids)?
            .into_iter();
    let media_existing = validate_existing_media_or_text(
        preflight_records.next().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "ordered MCP media preflight omitted the raw-media role",
            )
        })?,
        &media,
    )?;
    let text_existing = validate_existing_media_or_text(
        preflight_records.next().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "ordered MCP media preflight omitted the derived-text role",
            )
        })?,
        &text,
    )?;
    if preflight_records.next().is_some() {
        return Err(CalyxError::aster_corrupt_shard(
            "ordered MCP media preflight returned more than two role records",
        )
        .into());
    }
    preflight.record_progress();
    let media_new = media_existing.is_none();
    let text_new = text_existing.is_none();
    if media_new {
        super::super::ensure_content_panel_floor(&media, &state)?;
    }
    if text_new {
        super::super::ensure_content_panel_floor(&text, &state)?;
    }
    let payload =
        derived_text::derivation_ledger_payload(&retained, &derived, media.cx_id, text.cx_id)?;
    let mut staged = Vec::with_capacity(2);
    if media_new {
        staged.push(media.clone());
    }
    if text_new {
        staged.push(text.clone());
    }
    let artifact_draft =
        derived_text::derived_artifact_draft(&retained, &derived, media.cx_id, text.cx_id)?;
    let expected_artifact_draft = artifact_draft.clone();
    let commit = vault.put_batch_with_ingest_ledger_and_media_artifact_if_current(
        preflight_snapshot,
        staged,
        SubjectId::Cx(text.cx_id),
        payload,
        ActorId::Service("calyx-mcp".to_string()),
        artifact_draft,
    )?;
    preflight.record_progress();
    drop(preflight);
    let expected_new_ids = [
        media_new.then_some(media.cx_id),
        text_new.then_some(text.cx_id),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if commit.ids != expected_new_ids {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP media artifact commit returned Base ids {:?}, expected {:?}",
            commit.ids, expected_new_ids
        ))
        .into());
    }
    if commit.readback_seq != expected_readback_seq {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP media artifact commit returned readback seq {}, expected exactly {expected_readback_seq} after guarded preflight seq {preflight_snapshot}",
            commit.readback_seq
        ))
        .into());
    }
    let expected_artifact =
        expected_artifact_draft.into_record(commit.artifact.ledger_ref.clone())?;
    if commit.artifact != expected_artifact {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP media artifact commit returned a different artifact record for {}",
            expected_artifact.artifact_id
        ))
        .into());
    }
    let mut new_records = BTreeMap::<CxId, BaseRecord>::new();
    for record in commit.new_records {
        let cx_id = record.cx_id();
        let expected = if cx_id == media.cx_id && media_new {
            &mut media
        } else if cx_id == text.cx_id && text_new {
            &mut text
        } else {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media artifact commit returned unplanned new Base record for cx {cx_id}"
            ))
            .into());
        };
        if record.constellation().provenance != commit.artifact.ledger_ref {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media artifact commit returned Base provenance that differs from the artifact Ledger ref for cx {cx_id}"
            ))
            .into());
        }
        expected.provenance = record.constellation().provenance.clone();
        if record.encode()? != encode_constellation_base(expected)? {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media artifact commit returned a different final Base record for cx {cx_id}"
            ))
            .into());
        }
        if new_records.insert(cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media artifact commit returned duplicate new Base record for cx {cx_id}"
            ))
            .into());
        }
    }
    if new_records.len() != expected_new_ids.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "MCP media artifact commit returned {} new Base records for {} expected ids",
            new_records.len(),
            expected_new_ids.len()
        ))
        .into());
    }

    let readback = vault.retain_snapshot_at(commit.readback_seq);
    let flush_report = vault.flush_with_report()?;
    flush_report.verify_commit_base_records(Some(commit.readback_seq), &new_records)?;
    let mut final_records = new_records;
    if let Some(record) = media_existing {
        if final_records.insert(media.cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media readback plan contains duplicate raw-media cx {}",
                media.cx_id
            ))
            .into());
        }
    }
    if let Some(record) = text_existing {
        if final_records.insert(text.cx_id, record).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "MCP media readback plan contains duplicate derived-text cx {}",
                text.cx_id
            ))
            .into());
        }
    }
    super::super::verify_base_record_batch_readback(
        &vault,
        readback.seq(),
        &role_ids,
        &final_records,
    )?;
    readback.record_progress();
    verify_new_media_hydrated_readback(&vault, readback.seq(), &expected_new_ids, &media, &text)?;
    readback.record_progress();
    verify_media_artifact_readback(&vault, readback.seq(), &expected_artifact)?;
    readback.record_progress();
    drop(readback);

    let media_seq = final_records
        .get(&media.cx_id)
        .filter(|_| media_new)
        .map(|record| record.constellation().provenance.seq)
        .unwrap_or(expected_artifact.ledger_ref.seq);
    let text_seq = final_records
        .get(&text.cx_id)
        .filter(|_| text_new)
        .map(|record| record.constellation().provenance.seq)
        .unwrap_or(expected_artifact.ledger_ref.seq);
    Ok(vec![
        IngestReport {
            cx_id: media.cx_id.to_string(),
            new: media_new,
            ledger_seq: media_seq,
        },
        IngestReport {
            cx_id: text.cx_id.to_string(),
            new: text_new,
            ledger_seq: text_seq,
        },
    ])
}

fn validate_existing_media_or_text(
    stored: Option<BaseRecord>,
    expected: &Constellation,
) -> ToolResult<Option<BaseRecord>> {
    let Some(stored) = stored else {
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
        return Err(CalyxError::aster_corrupt_shard(format!(
            "durable MCP media ingest preflight mismatch for existing cx {}",
            expected.cx_id
        ))
        .into());
    }
    Ok(Some(stored))
}

fn verify_new_media_hydrated_readback(
    vault: &AsterVault,
    snapshot: u64,
    expected_new_ids: &[CxId],
    media: &Constellation,
    text: &Constellation,
) -> ToolResult<()> {
    let stored = vault.get_many_at(snapshot, expected_new_ids)?;
    if stored.len() != expected_new_ids.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "ordered MCP media hydration returned {} rows for {} new role ids",
            stored.len(),
            expected_new_ids.len()
        ))
        .into());
    }
    for (cx_id, stored) in expected_new_ids.iter().copied().zip(stored) {
        let expected = if cx_id == media.cx_id {
            media
        } else if cx_id == text.cx_id {
            text
        } else {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "ordered MCP media hydration returned unplanned cx {cx_id}"
            ))
            .into());
        };
        if stored != *expected {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable MCP media ingest hydrated readback mismatch for new cx {cx_id}"
            ))
            .into());
        }
    }
    Ok(())
}

fn ensure_raw_media_panel_route(
    modality: Modality,
    state: &calyx_registry::VaultPanelState,
) -> ToolResult<()> {
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
    Err(CalyxError {
        code: "CALYX_MEDIA_ROUTE_UNAVAILABLE",
        message: format!(
            "raw {modality:?} ingest requires an active {modality:?} content lens before derived text can be attached"
        ),
        remediation:
            "add or activate an image/audio/video lens for the raw media modality, then re-run ingest so the media constellation is measured instead of empty",
    }
    .into())
}

fn verify_media_artifact_readback(
    vault: &calyx_aster::vault::AsterVault,
    snapshot: u64,
    expected: &calyx_aster::media_artifact::DerivedMediaArtifactRecord,
) -> ToolResult<()> {
    let stored = vault
        .get_derived_media_artifact(snapshot, &expected.artifact_id)?
        .ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "derived media artifact {} missing after commit",
                expected.artifact_id
            ))
        })?;
    if stored != *expected {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} readback mismatch",
            expected.artifact_id
        ))
        .into());
    }
    let source_records =
        vault.derived_media_artifacts_for_source(snapshot, expected.source_cx_id)?;
    if !source_records.iter().any(|record| record == expected) {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} missing from source index",
            expected.artifact_id
        ))
        .into());
    }
    let target_records =
        vault.derived_media_artifacts_for_target(snapshot, expected.target_cx_id)?;
    if !target_records.iter().any(|record| record == expected) {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "derived media artifact {} missing from target index",
            expected.artifact_id
        ))
        .into());
    }
    Ok(())
}
