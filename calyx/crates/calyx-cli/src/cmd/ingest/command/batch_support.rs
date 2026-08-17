use super::replay::ExistingBatchReplayRow;
use super::*;
use calyx_aster::vault::{ExistingBaseAnchorMerge, ExistingBaseAnchorMergeResult};

pub(crate) struct ExistingBatchAnchorMerge {
    pub(crate) readback_seq: u64,
    pub(crate) commit_seq: Option<u64>,
    pub(crate) results: BTreeMap<CxId, ExistingBaseAnchorMergeResult>,
}

pub(crate) struct IdentityFields<'a> {
    pub(crate) panel_version: u32,
    pub(crate) input_ref: &'a InputRef,
    pub(crate) modality: Modality,
    pub(crate) metadata: &'a BTreeMap<String, String>,
}

/// #446: whether a stored `input_ref` matches an incoming measure-time ref for
/// idempotent replay. The content identity is the `hash`; the stored
/// `pointer`/`redacted` pair may legitimately differ from the measure-time
/// default (`pointer: None, redacted: false`) when the stored record declares
/// its retention outcome — `pointer = cxinput:v1:<hash>` with `redacted: false`
/// (bytes retained in the input store) or `redacted: true` with an unchanged
/// pointer (explicit policy opt-out). Anything else — a hash divergence, a
/// foreign pointer change, an unlabeled redaction flip — is a real identity
/// mismatch and stays fail-closed.
pub(crate) fn input_ref_matches_replay(existing: &InputRef, incoming: &InputRef) -> bool {
    if existing == incoming {
        return true;
    }
    if existing.hash != incoming.hash {
        return false;
    }
    if !existing.redacted
        && !incoming.redacted
        && incoming.pointer.is_none()
        && existing.pointer.as_deref() == Some(input_store::input_pointer(&existing.hash).as_str())
    {
        return true;
    }
    existing.redacted && !incoming.redacted && existing.pointer == incoming.pointer
}
pub(crate) fn append_idempotent_batch_ledger(
    vault: &AsterVault,
    order: &[BatchOrderRow],
) -> CliResult<Option<u64>> {
    let ids = order
        .iter()
        .filter(|row| !row.new)
        .map(|row| row.cx_id)
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(None);
    }
    append_cli_batch_ledger(
        vault,
        EntryKind::Ingest,
        &ids,
        "cli-idempotent-ingest-batch",
    )
    .map(Some)
}

pub(crate) fn verify_existing_batch_replay_identity(
    vault: &AsterVault,
    state: &VaultPanelState,
    row: &ExistingBatchReplayRow,
) -> CliResult<encode::BaseRecord> {
    let existing = read_base_record(vault, vault.snapshot(), row.cx_id)?;
    let stored = existing.constellation();
    if stored.panel_version != state.panel.version
        || !input_ref_matches_replay(&stored.input_ref, &row.input_ref)
        || stored.modality != row.modality
        || stored.metadata != row.metadata
    {
        return Err(CliError::usage(format!(
            "idempotent batch replay for cx {} changed stored non-anchor identity: {}",
            row.cx_id,
            identity_mismatch_reason(
                IdentityFields {
                    panel_version: stored.panel_version,
                    input_ref: &stored.input_ref,
                    modality: stored.modality,
                    metadata: &stored.metadata,
                },
                IdentityFields {
                    panel_version: state.panel.version,
                    input_ref: &row.input_ref,
                    modality: row.modality,
                    metadata: &row.metadata,
                },
            )
        )));
    }
    // Existing replay changes no slot payload. Its persisted Base identity is
    // validated losslessly above; creation-time panel-floor validation remains
    // on freshly measured constellations before their first put.
    Ok(existing)
}

pub(crate) fn ensure_idempotent_batch_replay(
    vault: &AsterVault,
    cx: &calyx_core::Constellation,
) -> CliResult<encode::BaseRecord> {
    let existing = read_base_record(vault, vault.snapshot(), cx.cx_id)?;
    let stored = existing.constellation();
    if stored.panel_version != cx.panel_version
        || !input_ref_matches_replay(&stored.input_ref, &cx.input_ref)
        || stored.modality != cx.modality
        || stored.metadata != cx.metadata
    {
        return Err(CliError::usage(format!(
            "idempotent batch replay for cx {} changed stored non-anchor identity: {}",
            cx.cx_id,
            identity_mismatch_reason(
                IdentityFields {
                    panel_version: stored.panel_version,
                    input_ref: &stored.input_ref,
                    modality: stored.modality,
                    metadata: &stored.metadata,
                },
                IdentityFields {
                    panel_version: cx.panel_version,
                    input_ref: &cx.input_ref,
                    modality: cx.modality,
                    metadata: &cx.metadata,
                },
            )
        )));
    }
    Ok(existing)
}

pub(crate) fn identity_mismatch_reason(
    existing: IdentityFields<'_>,
    incoming: IdentityFields<'_>,
) -> String {
    let mut reasons = Vec::new();
    if existing.panel_version != incoming.panel_version {
        reasons.push(format!(
            "panel_version existing={} incoming={}",
            existing.panel_version, incoming.panel_version
        ));
    }
    if existing.input_ref != incoming.input_ref {
        let mut input_parts = Vec::new();
        if existing.input_ref.hash != incoming.input_ref.hash {
            input_parts.push("hash");
        }
        if existing.input_ref.pointer != incoming.input_ref.pointer {
            input_parts.push("pointer");
        }
        if existing.input_ref.redacted != incoming.input_ref.redacted {
            input_parts.push("redacted");
        }
        reasons.push(format!("input_ref fields={}", input_parts.join(",")));
    }
    if existing.modality != incoming.modality {
        reasons.push(format!(
            "modality existing={:?} incoming={:?}",
            existing.modality, incoming.modality
        ));
    }
    if existing.metadata != incoming.metadata {
        let existing_keys = existing.metadata.keys().cloned().collect::<BTreeSet<_>>();
        let incoming_keys = incoming.metadata.keys().cloned().collect::<BTreeSet<_>>();
        let removed = existing_keys
            .difference(&incoming_keys)
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        let added = incoming_keys
            .difference(&existing_keys)
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        let changed = existing_keys
            .intersection(&incoming_keys)
            .filter(|key| existing.metadata.get(*key) != incoming.metadata.get(*key))
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        reasons.push(format!(
            "metadata removed_keys={removed:?} added_keys={added:?} changed_keys={changed:?}"
        ));
    }
    if reasons.is_empty() {
        "unknown identity mismatch".to_string()
    } else {
        reasons.join("; ")
    }
}

pub(crate) fn merge_existing_batch_anchors(
    vault: &AsterVault,
    rows: impl IntoIterator<Item = (encode::BaseRecord, Vec<Anchor>)>,
) -> CliResult<ExistingBatchAnchorMerge> {
    let requests = plan_existing_batch_anchor_merges(rows)?;
    let commit = vault.merge_existing_base_anchors(requests)?;
    Ok(ExistingBatchAnchorMerge {
        readback_seq: commit.readback_seq,
        commit_seq: commit.commit_seq,
        results: commit
            .results
            .into_iter()
            .map(|result| (result.record.cx_id(), result))
            .collect(),
    })
}

pub(crate) fn plan_existing_batch_anchor_merges(
    rows: impl IntoIterator<Item = (encode::BaseRecord, Vec<Anchor>)>,
) -> CliResult<Vec<ExistingBaseAnchorMerge>> {
    struct PlannedMerge {
        expected: encode::BaseRecord,
        incoming: Vec<Anchor>,
        by_kind: BTreeMap<AnchorKind, usize>,
    }

    let mut planned = BTreeMap::<CxId, PlannedMerge>::new();
    let mut request_order = Vec::new();
    for (expected, incoming) in rows {
        let cx_id = expected.cx_id();
        let entry = match planned.entry(cx_id) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                request_order.push(cx_id);
                entry.insert(PlannedMerge {
                    expected,
                    incoming: Vec::new(),
                    by_kind: BTreeMap::new(),
                })
            }
        };
        for anchor in incoming {
            match entry.by_kind.get(&anchor.kind).copied() {
                Some(index) if same_anchor_observation(&entry.incoming[index], &anchor) => {}
                Some(_) => {
                    return Err(CliError::usage(format!(
                        "batch contains duplicate cx {cx_id} with different observations for anchor kind {:?}",
                        anchor.kind
                    )));
                }
                None => {
                    entry
                        .by_kind
                        .insert(anchor.kind.clone(), entry.incoming.len());
                    entry.incoming.push(anchor);
                }
            }
        }
    }
    let requests = request_order
        .into_iter()
        .map(|cx_id| {
            let plan = planned
                .remove(&cx_id)
                .expect("request order contains every planned CxId");
            ExistingBaseAnchorMerge {
                expected: plan.expected,
                incoming: plan.incoming,
            }
        })
        .collect::<Vec<_>>();
    Ok(requests)
}

pub(crate) fn same_anchor_observation(left: &Anchor, right: &Anchor) -> bool {
    left.kind == right.kind
        && left.value == right.value
        && left.source == right.source
        && left.confidence.to_bits() == right.confidence.to_bits()
}

pub(crate) struct BatchOrderRow {
    pub(crate) cx_id: CxId,
    pub(crate) expected_readback: BatchBaseReadback,
    pub(crate) new: bool,
    pub(crate) marker_anchors: Vec<Anchor>,
    pub(crate) oracle: Option<OracleEvent>,
}

pub(crate) enum BatchBaseReadback {
    Hydrated(calyx_core::Constellation),
    Persisted(encode::BaseRecord),
}

pub(crate) fn verify_batch_base_readback(
    vault: &AsterVault,
    snapshot: u64,
    order: &[BatchOrderRow],
) -> CliResult {
    // Report order is per input row, but persisted readback is one exact final
    // image per distinct CxId. Duplicate rows must agree on that image; marker
    // requirements are unioned so an earlier row's added anchor cannot disappear
    // behind a later row.
    let mut final_rows = BTreeMap::<CxId, (&BatchBaseReadback, BTreeSet<AnchorKind>)>::new();
    for row in order {
        match final_rows.entry(row.cx_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((
                    &row.expected_readback,
                    row.marker_anchors
                        .iter()
                        .map(|anchor| anchor.kind.clone())
                        .collect(),
                ));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if !same_batch_readback(entry.get().0, &row.expected_readback)? {
                    return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "batch rows disagree on final Base readback for cx {}",
                        row.cx_id
                    ))
                    .into());
                }
                entry
                    .get_mut()
                    .1
                    .extend(row.marker_anchors.iter().map(|anchor| anchor.kind.clone()));
            }
        }
    }
    for (cx_id, (expected_readback, required_kinds)) in final_rows {
        match expected_readback {
            BatchBaseReadback::Hydrated(expected) => verify_base_readback(
                vault,
                snapshot,
                expected,
                cx_id,
                &required_kinds.into_iter().collect::<Vec<_>>(),
            )?,
            BatchBaseReadback::Persisted(expected) => {
                verify_base_record_readback(vault, snapshot, expected)?
            }
        }
    }
    for row in order {
        for anchor in &row.marker_anchors {
            let key = anchor_key(row.cx_id, &anchor.kind);
            let bytes = vault
                .read_cf_at(snapshot, ColumnFamily::Anchors, &key)?
                .ok_or_else(|| {
                    calyx_core::CalyxError::aster_corrupt_shard(format!(
                        "durable batch readback is missing Anchors CF row for cx {} kind {:?}",
                        row.cx_id, anchor.kind
                    ))
                })?;
            if bytes != encode::encode_anchor(anchor)? {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "durable batch readback disagrees with the committed anchor for cx {} kind {:?}",
                    row.cx_id, anchor.kind
                ))
                .into());
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_anchor_marker_ledger_readback<'a>(
    vault: &AsterVault,
    snapshot: u64,
    receipts: impl IntoIterator<Item = &'a calyx_aster::vault::AnchorMarkerLedgerReceipt>,
) -> CliResult<()> {
    for receipt in receipts {
        let bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Ledger,
                &calyx_aster::cf::ledger_key(receipt.ledger_ref.seq),
            )?
            .ok_or_else(|| {
                calyx_core::CalyxError::aster_corrupt_shard(format!(
                    "atomic anchor marker Ledger row {} is missing for cx {} kind {:?}",
                    receipt.ledger_ref.seq, receipt.cx_id, receipt.anchor.kind
                ))
            })?;
        let stored = calyx_ledger::decode(&bytes)?;
        if stored.seq != receipt.ledger_ref.seq
            || stored.entry_hash != receipt.ledger_ref.hash
            || stored.kind != receipt.entry.kind
            || stored.subject != receipt.entry.subject
            || stored.payload != receipt.entry.payload
            || stored.actor != receipt.entry.actor
        {
            return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
                "atomic anchor marker Ledger row {} disagrees with its receipt for cx {} kind {:?}",
                receipt.ledger_ref.seq, receipt.cx_id, receipt.anchor.kind
            ))
            .into());
        }
    }
    Ok(())
}

fn same_batch_readback(left: &BatchBaseReadback, right: &BatchBaseReadback) -> CliResult<bool> {
    match (left, right) {
        (BatchBaseReadback::Hydrated(left), BatchBaseReadback::Hydrated(right)) => {
            Ok(left == right)
        }
        (BatchBaseReadback::Persisted(left), BatchBaseReadback::Persisted(right)) => {
            Ok(left.encode()? == right.encode()?)
        }
        (BatchBaseReadback::Hydrated(_), BatchBaseReadback::Persisted(_))
        | (BatchBaseReadback::Persisted(_), BatchBaseReadback::Hydrated(_)) => Ok(false),
    }
}

pub(crate) fn append_oracle_events(vault: &AsterVault, order: &[BatchOrderRow]) -> CliResult<()> {
    for row in order {
        if let Some(event) = &row.oracle {
            append_recurrence_if_absent(vault, row.cx_id, event, now_ms())?;
        }
    }
    Ok(())
}
