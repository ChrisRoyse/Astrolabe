use calyx_core::{
    CalyxError, Clock, Constellation, CxId, GuardTauProfile, Result, SlotId, VaultStore,
};

use super::audit::DedupRestoreSnapshot;
use super::engine::{DedupEvaluation, check_dedup_without_conflict_write_resolved_at};
use super::ingest_event::{DedupOnlineKind, next_online_prefix, online_event_row, online_kind};
use super::ingest_ledger::{
    LedgerPayload, RecurrenceSignatureLedger, action_name, action_name_for_action, ledger_payload,
};
use super::signature::{SignatureResult, detect_recurrence_signature};
use super::{
    AnchorConflictResult, CALYX_DEDUP_INVALID_EVENT_TIME, ContestedWith, DedupAction,
    DedupDecision, DedupPolicy, DedupResult, EpochSecs, IngestInput, OccurrenceId, TctCosineConfig,
    check_anchor_conflict, contested_with_key, dedup_error, encode_contested_with,
    is_recurrence_series_policy,
};
use crate::cf::{ColumnFamily, base_key};
use crate::recurrence::{OccurrenceContext, RetentionPolicy, build_append_at};
use crate::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver, encode};

pub fn ingest_at<C>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    at: EpochSecs,
    guard_profile: Option<&dyn GuardTauProfile>,
) -> Result<DedupResult>
where
    C: Clock,
{
    ingest_at_resolved(vault, input, at, guard_profile, &StrictRawSlotResolver)
}

pub fn ingest_at_resolved<C, R>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    at: EpochSecs,
    guard_profile: Option<&dyn GuardTauProfile>,
    resolver: &R,
) -> Result<DedupResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    ingest_at_with_retention_resolved(
        vault,
        input,
        at,
        guard_profile,
        RetentionPolicy::default(),
        resolver,
    )
}

pub fn ingest_at_with_retention<C>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    at: EpochSecs,
    guard_profile: Option<&dyn GuardTauProfile>,
    recurrence_retention: RetentionPolicy,
) -> Result<DedupResult>
where
    C: Clock,
{
    ingest_at_with_retention_resolved(
        vault,
        input,
        at,
        guard_profile,
        recurrence_retention,
        &StrictRawSlotResolver,
    )
}

pub fn ingest_at_with_retention_resolved<C, R>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    at: EpochSecs,
    guard_profile: Option<&dyn GuardTauProfile>,
    recurrence_retention: RetentionPolicy,
    resolver: &R,
) -> Result<DedupResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    recurrence_retention.validate()?;
    let policy = vault.dedup_policy().clone();
    if is_recurrence_series_policy(&policy) {
        return vault.with_recurrence_write_lock(|| {
            ingest_at_with_policy(
                vault,
                input,
                at,
                guard_profile,
                &policy,
                recurrence_retention,
                resolver,
            )
        });
    }
    ingest_at_with_policy(
        vault,
        input,
        at,
        guard_profile,
        &policy,
        recurrence_retention,
        resolver,
    )
}

fn ingest_at_with_policy<C, R>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    at: EpochSecs,
    guard_profile: Option<&dyn GuardTauProfile>,
    policy: &DedupPolicy,
    recurrence_retention: RetentionPolicy,
    resolver: &R,
) -> Result<DedupResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let new_cx = input.to_constellation(vault, at)?;
    let evaluation_snapshot = vault.snapshot();
    let snapshot_lease = vault.retain_snapshot_at(evaluation_snapshot);
    let DedupEvaluation {
        decision,
        matched,
        snapshot,
    } = check_dedup_without_conflict_write_resolved_at(
        &new_cx,
        vault,
        policy,
        guard_profile,
        resolver,
        evaluation_snapshot,
    )?;
    snapshot_lease.record_progress();
    match decision {
        DedupDecision::NoMatch => store_new(
            vault,
            new_cx,
            at,
            policy,
            "NoMatch",
            Vec::new(),
            recurrence_retention,
            snapshot,
        ),
        DedupDecision::AnchorConflict { existing } => {
            let existing_cx = matched.ok_or_else(|| {
                CalyxError::aster_corrupt_shard(
                    "dedup anchor-conflict decision omitted its evaluated constellation",
                )
            })?;
            if existing_cx.cx_id != existing {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "dedup anchor-conflict decision names {existing} but retained {}",
                    existing_cx.cx_id
                )));
            }
            let online_rows = contested_rows(&new_cx, &existing_cx)?;
            store_new(
                vault,
                new_cx,
                at,
                policy,
                "AnchorConflict",
                online_rows,
                recurrence_retention,
                snapshot,
            )
        }
        DedupDecision::Match {
            existing,
            per_slot_cos,
        } => match policy {
            DedupPolicy::Exact => exact_duplicate(vault, &new_cx, at, existing, per_slot_cos),
            DedupPolicy::TctCosine(config) => {
                if matched.as_ref().is_some_and(|cx| cx.cx_id != existing) {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "dedup match decision names {existing} but retained a different constellation"
                    )));
                }
                if same_event_exact(new_cx.cx_id, existing, at, matched.as_ref())? {
                    exact_duplicate(vault, &new_cx, at, existing, per_slot_cos)
                } else if config.action == DedupAction::RecurrenceSeries {
                    recurrence_match(
                        vault,
                        RecurrenceMatch {
                            input,
                            new_cx,
                            at,
                            existing,
                            per_slot_cos,
                            config,
                            guard_profile,
                            retention: recurrence_retention,
                            existing_cx: matched.ok_or_else(|| {
                                CalyxError::aster_corrupt_shard(
                                    "dedup match decision omitted its evaluated constellation",
                                )
                            })?,
                            snapshot,
                        },
                        resolver,
                    )
                } else {
                    merge_match(
                        vault,
                        MergeMatch {
                            new_cx,
                            at,
                            existing,
                            per_slot_cos,
                            action: config.action.clone(),
                            signature: None,
                            retention: recurrence_retention,
                            existing_cx: None,
                            snapshot,
                        },
                    )
                }
            }
            DedupPolicy::Off => store_new(
                vault,
                new_cx,
                at,
                policy,
                "NoMatch",
                Vec::new(),
                recurrence_retention,
                snapshot,
            ),
        },
    }
}

pub fn ingest<C>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    clock: &dyn Clock,
    guard_profile: Option<&dyn GuardTauProfile>,
) -> Result<DedupResult>
where
    C: Clock,
{
    ingest_resolved(vault, input, clock, guard_profile, &StrictRawSlotResolver)
}

pub fn ingest_resolved<C, R>(
    vault: &AsterVault<C>,
    input: &IngestInput,
    clock: &dyn Clock,
    guard_profile: Option<&dyn GuardTauProfile>,
    resolver: &R,
) -> Result<DedupResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let now_secs = i64::try_from(clock.now() / 1_000).map_err(|_| {
        dedup_error(
            CALYX_DEDUP_INVALID_EVENT_TIME,
            "clock timestamp does not fit EpochSecs",
        )
    })?;
    ingest_at_resolved(vault, input, EpochSecs(now_secs), guard_profile, resolver)
}

fn store_new<C>(
    vault: &AsterVault<C>,
    mut new_cx: Constellation,
    at: EpochSecs,
    policy: &DedupPolicy,
    decision: &'static str,
    mut online_rows: Vec<(Vec<u8>, Vec<u8>)>,
    recurrence_retention: RetentionPolicy,
    snapshot: calyx_core::Seq,
) -> Result<DedupResult>
where
    C: Clock,
{
    let is_recurrence_series = matches!(
        policy,
        DedupPolicy::TctCosine(config) if config.action == DedupAction::RecurrenceSeries
    );
    let mut recurrence_rows = Vec::new();
    if is_recurrence_series {
        let append = build_append_at(
            vault,
            snapshot,
            new_cx,
            at,
            OccurrenceContext::new(Vec::new())?,
            at,
            recurrence_retention,
        )?;
        let occurrence = append.occurrence_id;
        new_cx = append.updated_base;
        recurrence_rows = append.recurrence_rows;
        online_rows.push(online_event_row(
            DedupOnlineKind::Occurrence,
            new_cx.cx_id,
            new_cx.cx_id,
            occurrence,
            at,
            DedupAction::RecurrenceSeries,
            Vec::new(),
        )?);
    }
    let payload = ledger_payload(LedgerPayload {
        cx: &new_cx,
        at,
        result: "New",
        decision,
        action: action_name(policy),
        into: None,
        occurrence: None,
        per_slot_cos: &[],
        recurrence_signature: None,
        restore: None,
    })?;
    let id = new_cx.cx_id;
    vault.commit_dedup_ingest(
        Some(new_cx),
        None,
        online_rows,
        recurrence_rows,
        id,
        payload,
    )?;
    Ok(DedupResult::New(id))
}

fn exact_duplicate<C>(
    vault: &AsterVault<C>,
    new_cx: &Constellation,
    at: EpochSecs,
    existing: CxId,
    per_slot_cos: Vec<(SlotId, f32)>,
) -> Result<DedupResult>
where
    C: Clock,
{
    let payload = ledger_payload(LedgerPayload {
        cx: new_cx,
        at,
        result: "ExactDuplicate",
        decision: "Match",
        action: Some("Exact"),
        into: Some(existing),
        occurrence: None,
        per_slot_cos: &per_slot_cos,
        recurrence_signature: None,
        restore: None,
    })?;
    vault.commit_dedup_ingest(None, None, Vec::new(), Vec::new(), existing, payload)?;
    Ok(DedupResult::ExactDuplicate(existing))
}

fn merge_match<C>(vault: &AsterVault<C>, matched: MergeMatch) -> Result<DedupResult>
where
    C: Clock,
{
    let kind = online_kind(&matched.action);
    let mut updated_base = None;
    let mut recurrence_rows = Vec::new();
    let mut before_base = None;
    let mut recurrence_tombstones = Vec::new();
    let occurrence = if matched.action == DedupAction::RecurrenceSeries {
        let base_bytes = vault
            .read_cf_at(
                matched.snapshot,
                ColumnFamily::Base,
                &base_key(matched.existing),
            )?
            .ok_or_else(|| {
                CalyxError::stale_derived("dedup recurrence base row disappeared at snapshot")
            })?;
        let mut record = encode::BaseRecord::decode_for_key(matched.existing, &base_bytes)?;
        if record.vault_id() != vault.vault_id() {
            return Err(CalyxError::vault_access_denied(format!(
                "dedup recurrence Base row for cx {} belongs to another vault",
                matched.existing
            )));
        }
        before_base = Some(matched.existing_cx.ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "dedup recurrence merge omitted its resolved existing constellation",
            )
        })?);
        let append = build_append_at(
            vault,
            matched.snapshot,
            record.constellation().clone(),
            matched.at,
            OccurrenceContext::new(Vec::new())?,
            matched.at,
            matched.retention,
        )?;
        record
            .scalars_mut()
            .clone_from(&append.updated_base.scalars);
        updated_base = Some((matched.snapshot, record));
        recurrence_rows = append.recurrence_rows;
        recurrence_tombstones.push(append.occurrence_id);
        append.occurrence_id
    } else {
        next_occurrence_id(vault, matched.snapshot, kind, matched.existing)?
    };
    let online_rows = vec![online_event_row(
        kind,
        matched.existing,
        matched.new_cx.cx_id,
        occurrence,
        matched.at,
        matched.action.clone(),
        matched.per_slot_cos.clone(),
    )?];
    let restore = DedupRestoreSnapshot::new(
        vault.vault_id(),
        matched.existing,
        matched.new_cx.clone(),
        before_base,
        recurrence_tombstones,
    );
    let payload = ledger_payload(LedgerPayload {
        cx: &matched.new_cx,
        at: matched.at,
        result: "DedupMerge",
        decision: "Match",
        action: Some(action_name_for_action(&matched.action)),
        into: Some(matched.existing),
        occurrence: Some(occurrence),
        per_slot_cos: &matched.per_slot_cos,
        recurrence_signature: matched.signature,
        restore: Some(&restore),
    })?;
    let candidate = (matched.action == DedupAction::Link).then_some(matched.new_cx);
    let subject = candidate.as_ref().map_or(matched.existing, |cx| cx.cx_id);
    vault.commit_dedup_ingest(
        candidate,
        updated_base,
        online_rows,
        recurrence_rows,
        subject,
        payload,
    )?;
    Ok(DedupResult::DedupMerge {
        into: matched.existing,
        occurrence,
    })
}

struct MergeMatch {
    new_cx: Constellation,
    at: EpochSecs,
    existing: CxId,
    per_slot_cos: Vec<(SlotId, f32)>,
    action: DedupAction,
    signature: Option<RecurrenceSignatureLedger>,
    retention: RetentionPolicy,
    existing_cx: Option<Constellation>,
    snapshot: calyx_core::Seq,
}

fn recurrence_match<C, R>(
    vault: &AsterVault<C>,
    mut matched: RecurrenceMatch<'_>,
    resolver: &R,
) -> Result<DedupResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    hydrate_remaining_slots(
        vault,
        matched.snapshot,
        matched.config,
        &mut matched.existing_cx,
        resolver,
    )?;
    match detect_recurrence_signature(
        &matched.new_cx,
        &matched.existing_cx,
        matched.config,
        matched.input.temporal_slot_ids(),
        matched.guard_profile,
        matched.at,
    )? {
        SignatureResult::RecurrenceSignature {
            same_action,
            new_time,
        } => merge_match(
            vault,
            MergeMatch {
                new_cx: matched.new_cx,
                at: matched.at,
                existing: matched.existing,
                per_slot_cos: matched.per_slot_cos,
                action: DedupAction::RecurrenceSeries,
                signature: Some(RecurrenceSignatureLedger {
                    same_action,
                    new_time,
                }),
                retention: matched.retention,
                existing_cx: Some(matched.existing_cx),
                snapshot: matched.snapshot,
            },
        ),
        SignatureResult::SameTime => exact_duplicate(
            vault,
            &matched.new_cx,
            matched.at,
            matched.existing,
            matched.per_slot_cos,
        ),
        SignatureResult::NewContent | SignatureResult::ContentMismatch => store_new(
            vault,
            matched.new_cx,
            matched.at,
            &DedupPolicy::TctCosine(matched.config.clone()),
            "ContentMismatch",
            Vec::new(),
            matched.retention,
            matched.snapshot,
        ),
    }
}

struct RecurrenceMatch<'a> {
    input: &'a IngestInput,
    new_cx: Constellation,
    at: EpochSecs,
    existing: CxId,
    per_slot_cos: Vec<(SlotId, f32)>,
    config: &'a TctCosineConfig,
    guard_profile: Option<&'a dyn GuardTauProfile>,
    retention: RetentionPolicy,
    existing_cx: Constellation,
    snapshot: calyx_core::Seq,
}

fn same_event_exact(
    new_id: CxId,
    existing: CxId,
    at: EpochSecs,
    existing_cx: Option<&Constellation>,
) -> Result<bool> {
    if new_id != existing {
        return Ok(false);
    }
    let existing_cx = existing_cx.ok_or_else(|| {
        CalyxError::aster_corrupt_shard(
            "exact dedup match omitted its evaluated existing constellation",
        )
    })?;
    Ok(existing_cx.created_at == at.to_u64()?)
}

fn hydrate_remaining_slots<C, R>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
    config: &TctCosineConfig,
    existing: &mut Constellation,
    resolver: &R,
) -> Result<()>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let already_resolved = config
        .required_slots
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let remaining = existing
        .slots
        .keys()
        .copied()
        .filter(|slot| !already_resolved.contains(slot))
        .collect::<Vec<_>>();
    for slot in remaining {
        let resolved =
            resolver.resolve_slot_vectors_at(vault, snapshot, slot, &[existing.cx_id])?;
        let [(resolved_id, vector)] = resolved.as_slice() else {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "dedup recurrence slot {} did not return its one requested row",
                slot.get()
            )));
        };
        if *resolved_id != existing.cx_id {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "dedup recurrence slot {} resolved CxId {resolved_id} where {} was requested",
                slot.get(),
                existing.cx_id
            )));
        }
        let vector = vector.clone().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "dedup recurrence slot {} row missing for {}",
                slot.get(),
                existing.cx_id
            ))
        })?;
        existing.slots.insert(slot, vector);
    }
    Ok(())
}

fn contested_rows(
    new_cx: &Constellation,
    existing_cx: &Constellation,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let AnchorConflictResult::Conflicting {
        anchor_type,
        reason,
    } = check_anchor_conflict(new_cx, existing_cx)
    else {
        return Err(CalyxError::aster_corrupt_shard(
            "dedup decision reported anchor conflict but anchors are compatible",
        ));
    };
    let new_value = ContestedWith {
        contested_with: existing_cx.cx_id,
        anchor_type: anchor_type.clone(),
        reason: reason.clone(),
    };
    let existing_value = ContestedWith {
        contested_with: new_cx.cx_id,
        anchor_type,
        reason,
    };
    Ok(vec![
        (
            contested_with_key(new_cx.cx_id),
            encode_contested_with(&new_value)?,
        ),
        (
            contested_with_key(existing_cx.cx_id),
            encode_contested_with(&existing_value)?,
        ),
    ])
}

fn next_occurrence_id<C>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
    kind: DedupOnlineKind,
    into: CxId,
) -> Result<OccurrenceId>
where
    C: Clock,
{
    let prefix = next_online_prefix(kind, into);
    let count = vault
        .scan_cf_at(snapshot, ColumnFamily::Online)?
        .into_iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .count();
    Ok(OccurrenceId(count as u64))
}
