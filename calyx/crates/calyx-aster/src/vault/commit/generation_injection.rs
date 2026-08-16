//! Fail-closed shape validation for the adversarial/historical
//! generation-state injection path (see
//! [`AsterVault::commit_generation_injection_if_seq`]). The contract proves a
//! batch reconstructs exactly one slot's compressed primary column with a
//! matching raw sidecar and never publishes a manifest or lifecycle record, so
//! injection can only stage a legacy/corrupted/torn-down generation, never forge
//! a manifested one. Membership-proof mutations are not part of this exception.

use crate::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, SlotFamilyKind, parse_compression_lifecycle_key,
};
use crate::mvcc::is_tombstone_value;
use crate::vault::encode;
use calyx_core::{CalyxError, Result, SlotId};
use std::collections::BTreeSet;

/// Fail-closed error code for a batch that does not describe a coherent
/// generation-state injection.
pub const CALYX_ASTER_GENERATION_INJECTION_INVALID: &str =
    "CALYX_ASTER_GENERATION_INJECTION_INVALID";

/// Enforces the generation-injection shape contract on a batch BEFORE it is
/// committed unguarded (see
/// [`AsterVault::commit_generation_injection_if_seq`]). The contract guarantees
/// the batch describes exactly one slot's compressed primary column with a
/// matching raw sidecar, and that it never publishes a manifest or lifecycle
/// record — so it can only reconstruct a legacy column, corrupt an existing
/// generation's rows in place, or tear a generation down, never forge a new
/// manifested generation.
pub(super) fn validate_generation_injection_shape(rows: &[encode::WriteRow]) -> Result<()> {
    if rows.is_empty() {
        return Err(generation_injection_error(
            "generation-injection batch is empty".to_string(),
        ));
    }
    let mut slot: Option<SlotId> = None;
    let mut primary_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut raw_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut bind_slot = |candidate: SlotId| -> Result<()> {
        match slot {
            Some(existing) if existing != candidate => Err(generation_injection_error(format!(
                "generation-injection batch mixes slots {} and {}; reconstruct one slot per batch",
                existing.get(),
                candidate.get()
            ))),
            _ => {
                slot = Some(candidate);
                Ok(())
            }
        }
    };
    for row in rows {
        match row.cf {
            ColumnFamily::Compression => {
                if row.key.len() == 2 {
                    bind_slot(SlotId::new(u16::from_be_bytes([row.key[0], row.key[1]])))?;
                    if !is_tombstone_value(&row.value) {
                        return Err(generation_injection_error(
                            "generation injection may only tombstone a compression manifest, never put one; a manifested generation must be published through the lawful lifecycle API".to_string(),
                        ));
                    }
                } else if let Some((slot_id, _prior)) = parse_compression_lifecycle_key(&row.key) {
                    bind_slot(slot_id)?;
                    if !is_tombstone_value(&row.value) {
                        return Err(generation_injection_error(
                            "generation injection may only tombstone lifecycle records, never put one".to_string(),
                        ));
                    }
                } else {
                    return Err(generation_injection_error(format!(
                        "generation-injection compression key must be a manifest or lifecycle key; membership-proof mutations are refused; got {} bytes",
                        row.key.len()
                    )));
                }
            }
            ColumnFamily::Slot {
                slot: slot_id,
                kind,
            } => {
                bind_slot(slot_id)?;
                if is_tombstone_value(&row.value) {
                    return Err(generation_injection_error(
                        "generation injection writes a full slot column; slot-row tombstones are refused".to_string(),
                    ));
                }
                match kind {
                    SlotFamilyKind::Quantized => {
                        if row.value.first().copied() != Some(COMPRESSED_SLOT_VALUE_TAG) {
                            return Err(generation_injection_error(
                                "generation-injection primary rows must be compressed-tagged envelopes".to_string(),
                            ));
                        }
                        if !primary_keys.insert(row.key.clone()) {
                            return Err(generation_injection_error(
                                "generation-injection batch has duplicate primary keys".to_string(),
                            ));
                        }
                    }
                    SlotFamilyKind::Raw => {
                        if !raw_keys.insert(row.key.clone()) {
                            return Err(generation_injection_error(
                                "generation-injection batch has duplicate raw-sidecar keys"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            other => {
                return Err(generation_injection_error(format!(
                    "generation-injection batch touches unrelated column family {other:?}; only one slot's compression, primary, and raw rows are permitted"
                )));
            }
        }
    }
    if primary_keys.is_empty() {
        return Err(generation_injection_error(
            "generation-injection batch has no compressed primary rows".to_string(),
        ));
    }
    if primary_keys != raw_keys {
        return Err(generation_injection_error(format!(
            "generation-injection primary ({}) and raw-sidecar ({}) key sets differ; a legacy column pairs every compressed row with its raw source",
            primary_keys.len(),
            raw_keys.len()
        )));
    }
    Ok(())
}

fn generation_injection_error(message: String) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_GENERATION_INJECTION_INVALID,
        message,
        remediation: "stage a single slot's compressed primary column, its matching raw sidecar, and tombstones for existing manifest/lifecycle records only when no membership proofs exist — reconstruction never publishes a manifested generation",
    }
}
