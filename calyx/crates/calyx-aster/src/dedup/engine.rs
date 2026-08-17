//! Dedup decision engine for PH41 T02.

use std::collections::BTreeSet;

use crate::cf::{ColumnFamily, base_key};
use crate::dedup::{
    AnchorConflictResult, CALYX_DEDUP_ANCHOR_CONFLICT, CALYX_DEDUP_DPI_EXCEEDED,
    CALYX_DEDUP_INVALID_TAU, CALYX_DEDUP_MISSING_GUARD_PROFILE,
    CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION, CALYX_DEDUP_SLOT_NOT_IN_TAU, ConflictReason,
    ContestedWith, DedupPolicy, TauStrategy, TctCosineConfig, check_anchor_conflict,
    contested_with_key, dedup_error, encode_contested_with,
};
use crate::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver, encode};
use calyx_core::{
    Clock, Constellation, CxId, GuardTauProfile, Result, SlotId, VaultStore, dense_cosine,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DEDUP_DPI_CANDIDATE_LIMIT: usize = 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DedupDecision {
    NoMatch,
    Match {
        existing: CxId,
        per_slot_cos: Vec<(SlotId, f32)>,
    },
    AnchorConflict {
        existing: CxId,
    },
}

pub(crate) struct DedupEvaluation {
    pub decision: DedupDecision,
    pub matched: Option<Constellation>,
    pub snapshot: calyx_core::Seq,
}

pub fn resolve_tau(
    slot_id: SlotId,
    config: &TctCosineConfig,
    guard_profile: Option<&dyn GuardTauProfile>,
) -> Result<f32> {
    let tau = match &config.tau {
        TauStrategy::PerSlot(entries) => entries
            .iter()
            .find_map(|(slot, tau)| (*slot == slot_id).then_some(*tau))
            .ok_or_else(|| {
                dedup_error(
                    CALYX_DEDUP_SLOT_NOT_IN_TAU,
                    format!("required slot {slot_id} is missing a tau threshold"),
                )
            }),
        TauStrategy::Calibrated => guard_profile
            .and_then(|profile| profile.tau_for(&slot_id))
            .ok_or_else(|| {
                dedup_error(
                    CALYX_DEDUP_MISSING_GUARD_PROFILE,
                    format!("guard profile has no tau for required slot {slot_id}"),
                )
            }),
    }?;
    validate_resolved_tau(slot_id, tau)
}

pub fn cosine_passes_all_required(
    new_cx: &Constellation,
    existing_cx: &Constellation,
    config: &TctCosineConfig,
    guard_profile: Option<&dyn GuardTauProfile>,
) -> Result<Option<Vec<(SlotId, f32)>>> {
    config.validate_static()?;
    let mut per_slot = Vec::with_capacity(config.required_slots.len());
    for slot in &config.required_slots {
        let new_dense = required_dense(new_cx, *slot)?;
        let existing_dense = required_dense(existing_cx, *slot)?;
        let tau = resolve_tau(*slot, config, guard_profile)?;
        let cosine = dense_cosine(new_dense, existing_dense).ok_or_else(|| {
            dedup_error(
                CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION,
                format!("required slot {slot} has an invalid dense vector"),
            )
        })?;
        if cosine < tau {
            return Ok(None);
        }
        per_slot.push((*slot, cosine));
    }
    Ok(Some(per_slot))
}

pub fn check_dedup<C>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
) -> Result<DedupDecision>
where
    C: Clock,
{
    check_dedup_resolved(new_cx, vault, policy, guard_profile, &StrictRawSlotResolver)
}

pub fn check_dedup_resolved<C, R>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    resolver: &R,
) -> Result<DedupDecision>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let snapshot = vault.snapshot();
    let snapshot_lease = vault.retain_snapshot_at(snapshot);
    let evaluation = check_dedup_inner(
        new_cx,
        vault,
        policy,
        guard_profile,
        DEFAULT_DEDUP_DPI_CANDIDATE_LIMIT,
        true,
        resolver,
        snapshot,
    )?;
    snapshot_lease.record_progress();
    Ok(evaluation.decision)
}

/// Evaluates one dedup candidate at a caller-pinned snapshot through an
/// explicit slot resolver without persisting anchor-conflict rows.
///
/// Readback surfaces use this entry point with a read-only vault handle so the
/// decision is bound to the manifest-backed slot interpretation while the
/// synthetic candidate can never create Online CF state.
pub fn check_dedup_read_only_resolved_at<C, R>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    resolver: &R,
    snapshot: calyx_core::Seq,
) -> Result<DedupDecision>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let snapshot_lease = vault.retain_snapshot_at(snapshot);
    let evaluation = check_dedup_without_conflict_write_resolved_at(
        new_cx,
        vault,
        policy,
        guard_profile,
        resolver,
        snapshot,
    )?;
    snapshot_lease.record_progress();
    Ok(evaluation.decision)
}

pub fn check_dedup_with_limit<C>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    candidate_limit: usize,
) -> Result<DedupDecision>
where
    C: Clock,
{
    check_dedup_with_limit_resolved(
        new_cx,
        vault,
        policy,
        guard_profile,
        candidate_limit,
        &StrictRawSlotResolver,
    )
}

pub fn check_dedup_with_limit_resolved<C, R>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    candidate_limit: usize,
    resolver: &R,
) -> Result<DedupDecision>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let snapshot = vault.snapshot();
    let snapshot_lease = vault.retain_snapshot_at(snapshot);
    let evaluation = check_dedup_inner(
        new_cx,
        vault,
        policy,
        guard_profile,
        candidate_limit,
        true,
        resolver,
        snapshot,
    )?;
    snapshot_lease.record_progress();
    Ok(evaluation.decision)
}

pub(crate) fn check_dedup_without_conflict_write_resolved_at<C, R>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    resolver: &R,
    snapshot: calyx_core::Seq,
) -> Result<DedupEvaluation>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    check_dedup_inner(
        new_cx,
        vault,
        policy,
        guard_profile,
        DEFAULT_DEDUP_DPI_CANDIDATE_LIMIT,
        false,
        resolver,
        snapshot,
    )
}

fn check_dedup_inner<C, R>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    policy: &DedupPolicy,
    guard_profile: Option<&dyn GuardTauProfile>,
    candidate_limit: usize,
    write_conflict_rows: bool,
    resolver: &R,
    snapshot: calyx_core::Seq,
) -> Result<DedupEvaluation>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    match policy {
        DedupPolicy::Off => Ok(DedupEvaluation {
            decision: DedupDecision::NoMatch,
            matched: None,
            snapshot,
        }),
        DedupPolicy::Exact => {
            let (decision, matched) = exact_match_at(new_cx, vault, snapshot)?;
            Ok(DedupEvaluation {
                decision,
                matched,
                snapshot,
            })
        }
        DedupPolicy::TctCosine(config) => {
            config.validate_static()?;
            let (exact, mut exact_existing) = exact_match_at(new_cx, vault, snapshot)?;
            if matches!(exact, DedupDecision::Match { .. }) {
                if exact_existing
                    .as_ref()
                    .is_some_and(|existing| existing.created_at != new_cx.created_at)
                {
                    let existing = exact_existing.take().ok_or_else(|| {
                        calyx_core::CalyxError::aster_corrupt_shard(
                            "exact TCT match omitted its Base constellation",
                        )
                    })?;
                    let mut hydrated = vec![(existing.cx_id, existing)];
                    hydrate_required_candidates(vault, snapshot, config, resolver, &mut hydrated)?;
                    exact_existing = hydrated.pop().map(|(_, existing)| existing);
                }
                return Ok(DedupEvaluation {
                    decision: exact,
                    matched: exact_existing,
                    snapshot,
                });
            }
            let candidates = vault.scan_cf_at(snapshot, ColumnFamily::Base)?;
            if candidates.len() > candidate_limit {
                return Err(dedup_error(
                    CALYX_DEDUP_DPI_EXCEEDED,
                    format!(
                        "dedup candidate set {} exceeds DPI limit {candidate_limit}",
                        candidates.len()
                    ),
                ));
            }
            let mut decoded = Vec::with_capacity(candidates.len());
            let mut seen = BTreeSet::new();
            for (key, bytes) in candidates {
                let existing_id = cx_id_from_base_key(&key)?;
                if existing_id == new_cx.cx_id {
                    continue;
                }
                let existing = encode::decode_constellation_base(&bytes)?;
                if existing.cx_id != existing_id || !seen.insert(existing_id) {
                    return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "dedup Base scan returned invalid or duplicate CxId {existing_id}"
                    )));
                }
                decoded.push((existing_id, existing));
            }
            hydrate_required_candidates(vault, snapshot, config, resolver, &mut decoded)?;
            for (existing_id, existing) in decoded {
                if let AnchorConflictResult::Conflicting {
                    anchor_type,
                    reason,
                } = check_anchor_conflict(new_cx, &existing)
                {
                    if write_conflict_rows {
                        write_anchor_conflict(
                            vault,
                            new_cx.cx_id,
                            existing_id,
                            anchor_type,
                            reason,
                        )?;
                    }
                    return Ok(DedupEvaluation {
                        decision: DedupDecision::AnchorConflict {
                            existing: existing_id,
                        },
                        matched: Some(existing),
                        snapshot,
                    });
                }
                if let Some(per_slot_cos) =
                    cosine_passes_all_required(new_cx, &existing, config, guard_profile)?
                {
                    return Ok(DedupEvaluation {
                        decision: DedupDecision::Match {
                            existing: existing_id,
                            per_slot_cos,
                        },
                        matched: Some(existing),
                        snapshot,
                    });
                }
            }
            Ok(DedupEvaluation {
                decision: DedupDecision::NoMatch,
                matched: None,
                snapshot,
            })
        }
    }
}

fn hydrate_required_candidates<C, R>(
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
    config: &TctCosineConfig,
    resolver: &R,
    candidates: &mut [(CxId, Constellation)],
) -> Result<()>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    let candidate_ids = candidates
        .iter()
        .map(|(cx_id, _)| *cx_id)
        .collect::<Vec<_>>();
    if candidate_ids.is_empty() {
        return Ok(());
    }
    for slot in config
        .required_slots
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let resolved = resolver.resolve_slot_vectors_at(vault, snapshot, slot, &candidate_ids)?;
        if resolved.len() != candidate_ids.len() {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "dedup slot {} resolved {} rows for {} candidates",
                slot.get(),
                resolved.len(),
                candidate_ids.len()
            )));
        }
        for (index, (expected, (resolved_id, vector))) in
            candidate_ids.iter().copied().zip(resolved).enumerate()
        {
            if expected != resolved_id {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "dedup slot {} resolved CxId {resolved_id} where {expected} was requested",
                    slot.get()
                )));
            }
            let declared = candidates[index].1.slots.contains_key(&slot);
            if vector.is_some() && !declared {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "dedup slot {} resolved an undeclared row for {resolved_id}",
                    slot.get()
                )));
            }
            if let Some(vector) = vector {
                candidates[index].1.slots.insert(slot, vector);
            }
        }
    }
    Ok(())
}

fn exact_match_at<C>(
    new_cx: &Constellation,
    vault: &AsterVault<C>,
    snapshot: calyx_core::Seq,
) -> Result<(DedupDecision, Option<Constellation>)>
where
    C: Clock,
{
    if let Some(bytes) = vault.read_cf_at(snapshot, ColumnFamily::Base, &base_key(new_cx.cx_id))? {
        let existing = encode::decode_constellation_base(&bytes)?;
        if existing.cx_id != new_cx.cx_id {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "dedup Base key {} differs from embedded CxId {}",
                new_cx.cx_id, existing.cx_id
            )));
        }
        reject_exact_anchor_conflict(new_cx, &existing)?;
        Ok((
            DedupDecision::Match {
                existing: new_cx.cx_id,
                per_slot_cos: Vec::new(),
            },
            Some(existing),
        ))
    } else {
        Ok((DedupDecision::NoMatch, None))
    }
}

fn reject_exact_anchor_conflict(new_cx: &Constellation, existing: &Constellation) -> Result<()> {
    if let AnchorConflictResult::Conflicting {
        anchor_type,
        reason,
    } = check_anchor_conflict(new_cx, existing)
    {
        return Err(dedup_error(
            CALYX_DEDUP_ANCHOR_CONFLICT,
            format!(
                "exact duplicate {} has conflicting {anchor_type:?} anchor: {reason:?}",
                new_cx.cx_id
            ),
        ));
    }
    Ok(())
}

fn required_dense(cx: &Constellation, slot: SlotId) -> Result<&[f32]> {
    cx.slots
        .get(&slot)
        .and_then(|vector| vector.as_dense())
        .ok_or_else(|| {
            dedup_error(
                CALYX_DEDUP_SLOT_NOT_IN_CONSTELLATION,
                format!(
                    "constellation {} is missing dense required slot {slot}",
                    cx.cx_id
                ),
            )
        })
}

fn validate_resolved_tau(slot_id: SlotId, tau: f32) -> Result<f32> {
    if tau.is_finite() && (-1.0..=1.0).contains(&tau) {
        Ok(tau)
    } else {
        Err(dedup_error(
            CALYX_DEDUP_INVALID_TAU,
            format!("tau for slot {slot_id} must be finite and in -1.0..=1.0"),
        ))
    }
}

fn cx_id_from_base_key(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        calyx_core::CalyxError::aster_corrupt_shard("base CF key is not a 16-byte CxId")
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn write_anchor_conflict<C>(
    vault: &AsterVault<C>,
    new_id: CxId,
    existing_id: CxId,
    anchor_type: calyx_core::AnchorKind,
    reason: ConflictReason,
) -> Result<()>
where
    C: Clock,
{
    let new_value = ContestedWith {
        contested_with: existing_id,
        anchor_type: anchor_type.clone(),
        reason: reason.clone(),
    };
    let existing_value = ContestedWith {
        contested_with: new_id,
        anchor_type,
        reason,
    };
    vault.commit_online_rows([
        (
            contested_with_key(new_id),
            encode_contested_with(&new_value)?,
        ),
        (
            contested_with_key(existing_id),
            encode_contested_with(&existing_value)?,
        ),
    ])?;
    Ok(())
}
