use calyx_aster::manifest::{ManifestStore, VaultManifest};
use calyx_registry::{
    CALYX_COMPRESSION_ADMISSION_REFUSED, CompressionAdmissionReadback, CompressionAdmissionStatus,
    CompressionAdmissionVerdict, CompressionCandidateEvaluationRequest, VaultPanelState,
    load_vault_panel_state,
};

use super::*;

const ASTRO_OPTIMIZER_COMPRESSION_VAULT_MISSING: &str = "ASTRO_OPTIMIZER_COMPRESSION_VAULT_MISSING";
const ASTRO_OPTIMIZER_COMPRESSION_VAULT_OPEN: &str = "ASTRO_OPTIMIZER_COMPRESSION_VAULT_OPEN";
const ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED: &str =
    "ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED";
const ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID: &str =
    "ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID";
const ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID: &str =
    "ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID";

/// Reads current compression-admission truth for one shadow project.
///
/// The storage boundary is Registry-owned pointer/receipt point reads only. It
/// never scans a slot generation, receipt family, raw sidecar, Assay, or
/// unrelated column family. The panel/registry manifest and vault sequence must
/// remain invariant across the read or the whole surface refuses.
pub(crate) fn optimizer_compression_admission_json_at(
    cache_dir: &Path,
    project: &str,
    ledger_chain_status: &str,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_VAULT_MISSING,
            format!(
                "project {project:?} shadow vault is missing at {}",
                vault_dir.display()
            ),
            "Re-run index_repository with calyx=\"shadow\" before reading compression admission state.",
        )
        .with_detail("project", project)
        .with_detail("vault_dir", vault_dir.display().to_string())
        .into());
    }

    let manifest_store = ManifestStore::open(&vault_dir);
    let manifest_before = manifest_store
        .load_current()
        .map_err(|error| calyx_status_fault(project, "load vault manifest", error))?;
    let Some(registry_ref) = manifest_before.registry_ref.as_ref() else {
        return Ok(json!({
            "schema": OPTIMIZER_COMPRESSION_ADMISSION_SCHEMA,
            "project": project,
            "status": "absent",
            "state_counts": {
                "latest_evaluation": {
                    "admitted": 0,
                    "candidate_evaluated": 0,
                    "pending_publication": 0,
                    "refused": 0,
                    "absent": 0,
                },
                "current_publication": { "present": 0, "absent": 0 },
            },
            "slot_count": 0,
            "slots": [],
            "diagnostics": [{
                "severity": "info",
                "code": "ASTRO_OPTIMIZER_COMPRESSION_REGISTRY_ABSENT",
                "message": "the exact vault manifest has no persisted Registry reference, so no Registry-owned compression admission can be current",
                "remediation": "Persist the exact panel and registered lens state before measuring a compressed generation; do not infer admission from raw slot bytes.",
            }],
            "source_state": {
                "vault_dir": vault_dir,
                "vault_id": vault_id,
                "selected_column_families": ["compression", "ledger"],
                "manifest_seq": manifest_before.manifest_seq,
                "durable_seq": manifest_before.durable_seq,
                "panel_ref": {
                    "logical_path": manifest_before.panel_ref.logical_path,
                    "blake3": manifest_before.panel_ref.blake3_hex,
                },
                "registry_ref": Value::Null,
            },
            "freshness": "fresh",
            "trust": "verified_absence",
        }));
    };

    let panel_state = load_vault_panel_state(&vault_dir).map_err(|error| {
        calyx_status_fault(project, "load persisted panel/Registry state", error)
    })?;
    if panel_state.registry_snapshot.is_none() {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} manifest names Registry asset {} but the loaded state has no Registry snapshot",
                registry_ref.logical_path
            ),
            "Restore the exact immutable Registry asset referenced by the vault manifest, then retry optimizer_status.",
        )
        .with_detail("project", project)
        .with_detail("registry_ref_blake3", registry_ref.blake3_hex.clone())
        .into());
    }
    if ledger_chain_status != "intact" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID,
            format!(
                "project {project:?} cannot expose compression admission because its admission Ledger chain status is {ledger_chain_status:?}"
            ),
            "Repair or rebuild the exact shadow vault until its complete Ledger chain verifies intact, then retry optimizer_status.",
        )
        .with_detail("project", project)
        .with_detail("ledger_chain_status", ledger_chain_status)
        .into());
    }

    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Compression, ColumnFamily::Ledger],
    )
    .map_err(|error| -> DynError {
        ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_VAULT_OPEN,
            format!(
                "project {project:?} compression-admission read-only vault open failed: {error}"
            ),
            "Inspect the exact shadow vault's Compression and Ledger durable state, repair the reported fault, and retry optimizer_status.",
        )
        .with_detail("project", project)
        .with_detail("vault_dir", vault_dir.display().to_string())
        .with_detail("selected_column_families", json!(["compression", "ledger"]))
        .into()
    })?;
    let vault_seq_before = vault.latest_seq();

    let mut slots = panel_state.panel.slots.iter().collect::<Vec<_>>();
    slots.sort_by_key(|slot| slot.slot_id);
    if slots
        .windows(2)
        .any(|pair| pair[0].slot_id == pair[1].slot_id)
    {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} persisted panel version {} repeats a SlotId",
                panel_state.panel.version
            ),
            "Repair and repersist the panel; optimizer_status cannot associate admission pointers with duplicate SlotIds.",
        )
        .with_detail("project", project)
        .with_detail("panel_version", u64::from(panel_state.panel.version))
        .into());
    }

    let mut admitted = 0_u64;
    let mut candidate_evaluated = 0_u64;
    let mut pending_publication = 0_u64;
    let mut refused = 0_u64;
    let mut absent = 0_u64;
    let mut current_present = 0_u64;
    let mut current_absent = 0_u64;
    let mut slot_values = Vec::with_capacity(slots.len());
    for slot in slots {
        let status = panel_state
            .registry
            .compression_admission_status(&vault, slot)
            .map_err(|error| {
                calyx_status_fault(
                    project,
                    &format!("read compression admission for slot {}", slot.slot_id.get()),
                    error,
                )
            })?;
        validate_status(project, slot.slot_id, &status)?;
        let current_state = if status.current_admission.is_some() {
            current_present += 1;
            "present"
        } else {
            current_absent += 1;
            "absent"
        };
        let (state, diagnostics) = match status.latest_evaluation.as_ref() {
            Some(readback) => match readback.receipt.verdict {
                CompressionAdmissionVerdict::Admitted => {
                    let published = status
                        .current_admission
                        .as_ref()
                        .is_some_and(|current| current.receipt_sha256 == readback.receipt_sha256);
                    if published {
                        admitted += 1;
                        ("admitted", Vec::new())
                    } else if readback.receipt.candidate_selection.is_some() {
                        pending_publication += 1;
                        (
                            "pending_publication",
                            vec![json!({
                                "severity": "error",
                                "code": "ASTRO_OPTIMIZER_COMPRESSION_ADMISSION_PENDING",
                                "message": format!(
                                    "slot {} has a physically verified admitted evaluation whose second-phase current pointer was not published",
                                    slot.slot_id.get()
                                ),
                                "receipt_sha256": readback.receipt_sha256,
                                "prior_current_receipt_sha256": status.current_admission.as_ref().map(|current| &current.receipt_sha256),
                                "remediation": "Call optimizer_status mode=select_compression_candidates with the exact original candidate receipt identities embedded in this selection receipt; publication occurs only after the complete set is independently recomputed.",
                            })],
                        )
                    } else {
                        candidate_evaluated += 1;
                        (
                            "candidate_evaluated",
                            vec![json!({
                                "severity": "info",
                                "code": "ASTRO_OPTIMIZER_COMPRESSION_CANDIDATE_EVALUATED",
                                "message": format!(
                                    "slot {} has a gate-admitted candidate receipt that correctly remains unpublished until multi-candidate selection",
                                    slot.slot_id.get()
                                ),
                                "receipt_sha256": readback.receipt_sha256,
                                "remediation": "Commission and select at least two exact-cohort candidate receipts; do not publish this candidate alone.",
                            })],
                        )
                    }
                }
                CompressionAdmissionVerdict::Refused => {
                    refused += 1;
                    (
                        "refused",
                        vec![json!({
                            "severity": "error",
                            "code": CALYX_COMPRESSION_ADMISSION_REFUSED,
                            "message": format!(
                                "latest physical evaluation for slot {} failed one or more admission gates",
                                slot.slot_id.get()
                            ),
                            "failed_gates": readback.receipt.gate_observations
                                .iter()
                                .filter(|gate| !gate.passed)
                                .collect::<Vec<_>>(),
                            "remediation": "Inspect the failed physical gates and retain the prior admitted generation; do not publish or tune from the refused receipt.",
                        })],
                    )
                }
            },
            None => {
                absent += 1;
                (
                    "absent",
                    vec![json!({
                        "severity": "info",
                        "code": "ASTRO_OPTIMIZER_COMPRESSION_ADMISSION_ABSENT",
                        "message": format!(
                            "slot {} has neither a latest physical evaluation nor a current admission pointer",
                            slot.slot_id.get()
                        ),
                        "remediation": "Measure the exact active compressed generation with real held-out queries before allowing the optimizer to act on it.",
                    })],
                )
            }
        };
        slot_values.push(json!({
            "slot_id": slot.slot_id.get(),
            "slot_key": slot.slot_key.key(),
            "lens_id": slot.lens_id.to_string(),
            "state": {
                "latest_evaluation": state,
                "current_publication": current_state,
            },
            "latest_evaluation": status.latest_evaluation.as_ref().map(readback_json),
            "current_admission": current_admission_json(&status),
            "diagnostics": diagnostics,
        }));
    }

    let vault_seq_after = vault.latest_seq();
    let manifest_after = manifest_store
        .load_current()
        .map_err(|error| calyx_status_fault(project, "re-read vault manifest", error))?;
    if vault_seq_after != vault_seq_before || manifest_after != manifest_before {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED,
            format!(
                "project {project:?} admission state changed while optimizer_status read it: vault seq {vault_seq_before}->{vault_seq_after}, manifest seq {}->{}",
                manifest_before.manifest_seq, manifest_after.manifest_seq
            ),
            "Retry optimizer_status after the concurrent compression admission or panel publication finishes; mixed-generation status is never returned.",
        )
        .with_detail("project", project)
        .with_detail("vault_seq_before", vault_seq_before)
        .with_detail("vault_seq_after", vault_seq_after)
        .with_detail("manifest_seq_before", manifest_before.manifest_seq)
        .with_detail("manifest_seq_after", manifest_after.manifest_seq)
        .into());
    }

    Ok(json!({
        "schema": OPTIMIZER_COMPRESSION_ADMISSION_SCHEMA,
        "project": project,
        "status": "read",
        "state_counts": {
            "latest_evaluation": {
                "admitted": admitted,
                "candidate_evaluated": candidate_evaluated,
                "pending_publication": pending_publication,
                "refused": refused,
                "absent": absent,
            },
            "current_publication": {
                "present": current_present,
                "absent": current_absent,
            },
        },
        "slot_count": slot_values.len(),
        "slots": slot_values,
        "diagnostics": [{
            "severity": "info",
            "code": "ASTRO_OPTIMIZER_COMPRESSION_LEDGER_BINDING_NOT_EXPOSED",
            "message": "the complete project Ledger chain verified intact, but the Registry status readback does not expose the exact admission publication LedgerRef",
            "remediation": "Use the receipt/pointer hashes as current admission truth. Do not claim receipt-to-Ledger-row point binding until Registry persists and returns that exact reference.",
        }],
        "source_state": {
            "vault_dir": vault_dir,
            "vault_id": vault_id,
            "selected_column_families": ["compression", "ledger"],
            "vault_seq": vault_seq_after,
            "manifest_seq": manifest_after.manifest_seq,
            "durable_seq": manifest_after.durable_seq,
            "panel_version": panel_state.panel.version,
            "panel_ref": {
                "logical_path": manifest_after.panel_ref.logical_path,
                "blake3": manifest_after.panel_ref.blake3_hex,
            },
            "registry_ref": {
                "logical_path": registry_ref.logical_path,
                "blake3": registry_ref.blake3_hex,
            },
            "ledger": {
                "selected": true,
                "chain_status": ledger_chain_status,
                "receipt_publication_binding": "not_exposed_by_registry_point_read",
                "trust": "not_claimed",
            },
        },
        "freshness": "fresh",
        "trust": "verified_registry_point_read",
    }))
}

/// Runs Registry's all-slot preflight, real candidate builds/evaluations, and
/// independently read-back deterministic selection as one production command.
pub(crate) fn commission_optimizer_compression_candidates_json_at(
    cache_dir: &Path,
    project: &str,
    candidate_slot_ids: &[SlotId],
    request: CompressionCandidateEvaluationRequest,
) -> Result<Value, DynError> {
    const MAX_CANDIDATE_SLOTS: usize = u16::MAX as usize + 1;
    const OPERATION_PREFLIGHT_STAGE: &str =
        "pure operation-shape preflight before vault/manifest/Ledger open";
    if !(2..=MAX_CANDIDATE_SLOTS).contains(&candidate_slot_ids.len()) {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "compression commission requires 2..={MAX_CANDIDATE_SLOTS} candidate_slot_ids, got {}",
                candidate_slot_ids.len()
            ),
            "Pass a bounded roster of at least two unique registered dense raw candidate slots.",
        )
        .with_detail("minimum_items", 2_u64)
        .with_detail("maximum_items", MAX_CANDIDATE_SLOTS as u64)
        .with_detail("observed_items", candidate_slot_ids.len() as u64)
        .with_detail("stage", OPERATION_PREFLIGHT_STAGE)
        .with_detail("vault_or_manifest_opened", false)
        .with_detail("ledger_chain_scanned", false)
        .into());
    }
    let mut unique_candidate_slots = BTreeSet::new();
    if candidate_slot_ids
        .iter()
        .any(|slot_id| !unique_candidate_slots.insert(slot_id.get()))
    {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "compression commission candidate_slot_ids must be unique",
            "Pass each exact registered candidate slot id once.",
        )
        .with_detail("stage", OPERATION_PREFLIGHT_STAGE)
        .with_detail("vault_or_manifest_opened", false)
        .with_detail("ledger_chain_scanned", false)
        .into());
    }
    let candidate_slot_values = candidate_slot_ids
        .iter()
        .map(|slot_id| slot_id.get())
        .collect::<Vec<_>>();
    calyx_registry::preflight_compression_candidate_operation(&candidate_slot_values, &request)
        .map_err(|error| -> DynError {
            ToolFault::new(
                error.code.clone(),
                format!(
                    "project {project:?} compression-admission {OPERATION_PREFLIGHT_STAGE} failed: {}",
                    error.message
                ),
                error.remediation,
            )
            .with_detail("project", project)
            .with_detail("stage", OPERATION_PREFLIGHT_STAGE)
            .with_detail("source_code", error.code)
            .with_detail("vault_or_manifest_opened", false)
            .with_detail("ledger_chain_scanned", false)
            .into()
        })?;

    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_VAULT_MISSING,
            format!(
                "project {project:?} shadow vault is missing at {}",
                vault_dir.display()
            ),
            "Re-run index_repository with calyx=\"shadow\" before commissioning candidates.",
        )
        .with_detail("project", project)
        .with_detail("vault_dir", vault_dir.display().to_string())
        .into());
    }
    let chain = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    if chain.status != "intact" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID,
            format!("project {project:?} Ledger status is {:?}", chain.status),
            "Repair or rebuild the exact shadow vault until its Ledger chain verifies intact.",
        )
        .with_detail("project", project)
        .into());
    }
    let (manifest_store, manifest_before, panel_state) =
        load_manifest_bound_panel_state(&vault_dir, project, "commission")?;
    let panel_slots = unique_panel_slot_index(project, "commission", &panel_state.panel.slots)?;
    let mut slots = Vec::with_capacity(candidate_slot_ids.len());
    for slot_id in candidate_slot_ids {
        let Some(slot) = panel_slots.get(slot_id).copied() else {
            return Err(ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                format!("candidate slot {} is not registered", slot_id.get()),
                "Pass each exact registered candidate slot id once.",
            )
            .with_detail("slot_id", u64::from(slot_id.get()))
            .into());
        };
        slots.push(slot);
    }
    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Compression, ColumnFamily::Ledger],
    )?;
    let before_seq = vault.latest_seq();
    let candidate_slots = slots
        .iter()
        .map(|slot| (**slot).clone())
        .collect::<Vec<_>>();
    let result = panel_state
        .registry
        .commission_and_select_compression_candidates(&vault, &candidate_slots, request)
        .map_err(|error| calyx_status_fault(project, "commission compression candidates", error))?;
    let selected_slot = slots
        .iter()
        .copied()
        .find(|slot| slot.slot_id.get() == result.selected.receipt.slot_id)
        .ok_or_else(|| -> DynError {
            ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                "selected receipt names a slot outside the commissioned candidate set",
                "Preserve the vault and inspect the complete selection receipt.",
            )
            .into()
        })?;
    let independent = panel_state
        .registry
        .compression_admission_status(&vault, selected_slot)
        .map_err(|error| calyx_status_fault(project, "read selected commission state", error))?;
    validate_status(project, selected_slot.slot_id, &independent)?;
    let current = independent
        .current_admission
        .as_ref()
        .ok_or_else(|| -> DynError {
            ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                "independent commission readback has no selected current admission",
                "Preserve the vault and inspect selection receipt, pointer, and Ledger bytes.",
            )
            .into()
        })?;
    if current.receipt_sha256 != result.selected.receipt_sha256 {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "independent commission readback differs from the selected receipt",
            "Preserve the vault and inspect selection receipt, pointer, and Ledger bytes.",
        )
        .into());
    }
    let after_seq = vault.latest_seq();
    let selected_configuration = readback_json(current);
    let publication = json!({
        "selection_receipt_commit_seq": result.selected.receipt_commit_seq,
        "selection_receipt_ledger": result.selected.receipt_ledger,
        "current_pointer_commit_seq": result.selected.pointer_commit_seq,
        "current_pointer_ledger": result.selected.pointer_ledger,
    });
    drop(vault);
    let manifest_post_write = require_unchanged_mutation_refs(
        &manifest_store,
        project,
        "post-commission write readback",
        &manifest_before,
    )?;
    let chain_after = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    if chain_after.status != "intact" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID,
            format!("post-commission Ledger status is {:?}", chain_after.status),
            "Preserve the vault; the commission result is not trusted until the complete Ledger chain verifies intact.",
        )
        .into());
    }
    let manifest_after_ledger = require_unchanged_mutation_refs(
        &manifest_store,
        project,
        "post-commission Ledger verification readback",
        &manifest_before,
    )?;
    let publication_action = compression_publication_action(project, &result.selected)?;
    if publication_action != "selection_receipt_and_current_pointer_published" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "initial commission omitted selection-receipt or current-pointer Ledger publication references",
            "Preserve the vault and inspect both Admission Ledger commits before retrying selection.",
        )
        .with_detail("project", project)
        .with_detail("publication_action", publication_action)
        .with_detail("receipt_sha256", result.selected.receipt_sha256.clone())
        .into());
    }
    Ok(json!({
        "schema": OPTIMIZER_COMPRESSION_ADMISSION_SCHEMA,
        "project": project,
        "status": "commissioned_and_selected",
        "publication_action": publication_action,
        "before_vault_seq": before_seq,
        "after_vault_seq": after_seq,
        "candidate_evaluations": result.candidates,
        "selected_configuration": selected_configuration,
        "publication": publication,
        "cost_scope": {
            "mode": "commission_compression_candidates",
            "bounded_path": "Registry compression core candidate preflight/build/evaluate/select",
            "work_limits": "candidate_request.work_limits",
            "bounded_dimensions": "canonical candidate count C, corpus rows R, held-out queries Q, dimensions D, and the receipt's enumerated codec/Registry accounting categories",
            "end_to_end_mcp_bounded": false,
        },
        "known_cost_gap": optimizer_compression_known_cost_gap(),
        "source_state": {
            "vault_dir": vault_dir,
            "ledger_chain_before": chain.status,
            "ledger_chain_after": chain_after.status,
            "preflight": "allocation-free slot/lens descriptors; raw/Base identity bindings; absent fresh compressed manifest, admission pointers, and raw sidecar; canonical corpus equality; work/limits; query disjointness; CPU backend. Codec-context creation begins during build after preflight",
            "partial_fault_contract": "mid-run physical faults retain the explicit persisted evaluation prefix; atomic commission is not claimed",
            "manifest_context": {
                "before_manifest_seq": manifest_before.manifest_seq,
                "post_write_manifest_seq": manifest_post_write.manifest_seq,
                "after_ledger_manifest_seq": manifest_after_ledger.manifest_seq,
                "panel_ref_blake3": manifest_after_ledger.panel_ref.blake3_hex,
                "registry_ref_blake3": manifest_after_ledger.registry_ref.as_ref().map(|reference| &reference.blake3_hex),
                "trust": "verified_immutable_refs_unchanged",
            },
        },
        "trust": "verified_registry_commission_selection_and_independent_current_readback",
    }))
}

/// Replays selection from explicit immutable candidate receipt identities.
/// This is the recovery path for a durable selection receipt whose current
/// pointer publication was interrupted; Registry re-reads and recomputes the
/// complete source set before an idempotent or new publication.
pub(crate) fn select_optimizer_compression_candidates_json_at(
    cache_dir: &Path,
    project: &str,
    candidate_receipts: &[(SlotId, [u8; 32])],
) -> Result<Value, DynError> {
    const MAX_CANDIDATE_RECEIPTS: usize = u16::MAX as usize + 1;
    const REPLAY_PREFLIGHT_STAGE: &str =
        "selection-replay roster preflight before vault/manifest/Ledger open";
    if !(2..=MAX_CANDIDATE_RECEIPTS).contains(&candidate_receipts.len()) {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "selection replay requires 2..={MAX_CANDIDATE_RECEIPTS} candidate receipts, got {}",
                candidate_receipts.len()
            ),
            "Pass the exact bounded slot_id and original receipt_sha256 roster from the pending selection receipt.",
        )
        .with_detail("stage", REPLAY_PREFLIGHT_STAGE)
        .with_detail("vault_or_manifest_opened", false)
        .with_detail("ledger_chain_scanned", false)
        .into());
    }
    let mut unique_slot_ids = BTreeSet::new();
    if candidate_receipts
        .iter()
        .any(|(slot_id, _)| !unique_slot_ids.insert(slot_id.get()))
    {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "selection replay candidate receipts repeat a slot id",
            "Pass every exact source candidate slot once.",
        )
        .with_detail("stage", REPLAY_PREFLIGHT_STAGE)
        .with_detail("vault_or_manifest_opened", false)
        .with_detail("ledger_chain_scanned", false)
        .into());
    }
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    let chain = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    if chain.status != "intact" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "selection replay requires an intact Ledger",
            "Repair or rebuild the exact shadow vault before replaying the immutable candidate roster.",
        )
        .into());
    }
    let (manifest_store, manifest_before, panel_state) =
        load_manifest_bound_panel_state(&vault_dir, project, "selection replay")?;
    let panel_slots =
        unique_panel_slot_index(project, "selection replay", &panel_state.panel.slots)?;
    let mut references = Vec::with_capacity(candidate_receipts.len());
    for (slot_id, receipt_sha256) in candidate_receipts {
        let Some(slot) = panel_slots.get(slot_id).copied() else {
            return Err(ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                format!("candidate slot {} is not registered", slot_id.get()),
                "Pass every exact source candidate once.",
            )
            .into());
        };
        references.push(calyx_registry::CompressionCandidateReference {
            slot: slot.clone(),
            receipt_sha256: *receipt_sha256,
        });
    }
    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Compression, ColumnFamily::Ledger],
    )?;
    let before_seq = vault.latest_seq();
    let selected = panel_state
        .registry
        .select_compression_candidate(&vault, &references)
        .map_err(|error| calyx_status_fault(project, "replay candidate selection", error))?;
    let selected_slot = references
        .iter()
        .find(|reference| reference.slot.slot_id.get() == selected.receipt.slot_id)
        .ok_or_else(|| -> DynError {
            ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                "selection replay winner is outside the supplied candidate set",
                "Preserve the vault and inspect the persisted selection receipt.",
            )
            .into()
        })?;
    let independent = panel_state
        .registry
        .compression_admission_status(&vault, &selected_slot.slot)
        .map_err(|error| calyx_status_fault(project, "read replayed selection", error))?;
    validate_status(project, selected_slot.slot.slot_id, &independent)?;
    let current = independent.current_admission.ok_or_else(|| -> DynError {
        ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "selection replay returned without a current winner",
            "Preserve the vault and inspect the selection receipt and pointer commits.",
        )
        .into()
    })?;
    if current.receipt_sha256 != selected.receipt_sha256 {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            "selection replay and independent current readback differ",
            "Preserve the vault and inspect the selection receipt and pointer commits.",
        )
        .into());
    }
    let after_seq = vault.latest_seq();
    let selected_json = readback_json(&current);
    let publication = json!({
        "selection_receipt_commit_seq": selected.receipt_commit_seq,
        "selection_receipt_ledger": selected.receipt_ledger,
        "current_pointer_commit_seq": selected.pointer_commit_seq,
        "current_pointer_ledger": selected.pointer_ledger,
    });
    drop(vault);
    let manifest_post_write = require_unchanged_mutation_refs(
        &manifest_store,
        project,
        "post-selection write readback",
        &manifest_before,
    )?;
    let chain_after = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    if chain_after.status != "intact" {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_LEDGER_INVALID,
            format!("post-selection Ledger status is {:?}", chain_after.status),
            "Preserve the vault; selection is not trusted until the Ledger chain verifies intact.",
        )
        .into());
    }
    let manifest_after_ledger = require_unchanged_mutation_refs(
        &manifest_store,
        project,
        "post-selection Ledger verification readback",
        &manifest_before,
    )?;
    let publication_action = compression_publication_action(project, &selected)?;
    Ok(json!({
        "schema": OPTIMIZER_COMPRESSION_ADMISSION_SCHEMA,
        "project": project,
        "status": "selection_replayed_and_current",
        "publication_action": publication_action,
        "before_vault_seq": before_seq,
        "after_vault_seq": after_seq,
        "selected_configuration": selected_json,
        "publication": publication,
        "cost_scope": {
            "mode": "select_compression_candidates",
            "bounded_path": "Registry exact-receipt streaming, canonical roster recomputation, and deterministic selection",
            "work_limits": "canonical work/limits persisted in the exact source receipts",
            "bounded_dimensions": "exact candidate receipt roster C and its persisted canonical C/R/Q/D accounting",
            "end_to_end_mcp_bounded": false,
        },
        "known_cost_gap": optimizer_compression_known_cost_gap(),
        "ledger_chain_before": chain.status,
        "ledger_chain_after": chain_after.status,
        "manifest_context": {
            "before_manifest_seq": manifest_before.manifest_seq,
            "post_write_manifest_seq": manifest_post_write.manifest_seq,
            "after_ledger_manifest_seq": manifest_after_ledger.manifest_seq,
            "panel_ref_blake3": manifest_after_ledger.panel_ref.blake3_hex,
            "registry_ref_blake3": manifest_after_ledger.registry_ref.as_ref().map(|reference| &reference.blake3_hex),
            "trust": "verified_immutable_refs_unchanged",
        },
        "trust": "verified_candidate_source_recompute_current_readback_and_post_ledger_chain",
    }))
}

fn optimizer_compression_known_cost_gap() -> Value {
    json!({
        "mcp_ledger_verification": {
            "issue": 1137,
            "defect_classes": ["PC-40", "PC-43"],
            "operation": "MCP commission/selection-replay pre/post full Ledger-chain verification plus repeated store opens",
            "asymptotic_cost": "Theta(M) for each full-chain verification over Ledger entry count M",
            "production_ledger_entries_m": "unknown",
            "production_store_open_count": "unknown",
            "bounded_by_candidate_request_work_limits": false,
        },
        "mcp_panel_roster_resolution": {
            "issue": 1137,
            "defect_classes": ["PC-05", "PC-43"],
            "operation": "one duplicate-detecting BTreeMap index over panel slots plus candidate lookups",
            "asymptotic_cost": "Theta(P log P + C log P) for panel slot count P and candidate count C",
            "production_panel_slots_p": "unknown",
            "bounded_by_candidate_request_work_limits": false,
        },
        "mxfp4_commission_evidence": {
            "issue": 1136,
            "defect_classes": ["PC-03", "PC-43"],
            "current_behavior": "multi-candidate commission preflight-refuses MXFP4 before candidate scan/write",
            "required_bounded_primitive": "exact-key bounded initial Assay evidence lookup",
            "single_candidate_diagnostic_behavior": "unchanged",
        },
    })
}

fn unique_panel_slot_index<'a>(
    project: &str,
    operation: &str,
    slots: &'a [calyx_core::Slot],
) -> Result<BTreeMap<SlotId, &'a calyx_core::Slot>, DynError> {
    let mut by_id = BTreeMap::new();
    for slot in slots {
        if by_id.insert(slot.slot_id, slot).is_some() {
            return Err(ToolFault::new(
                ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
                format!(
                    "project {project:?} panel repeats slot id {} during {operation}",
                    slot.slot_id.get()
                ),
                "Preserve the immutable Panel and repair the duplicate slot identity before retrying.",
            )
            .with_detail("project", project)
            .with_detail("operation", operation)
            .with_detail("slot_id", u64::from(slot.slot_id.get()))
            .into());
        }
    }
    Ok(by_id)
}

fn load_manifest_bound_panel_state(
    vault_dir: &Path,
    project: &str,
    operation: &str,
) -> Result<(ManifestStore, VaultManifest, VaultPanelState), DynError> {
    let manifest_store = ManifestStore::open(vault_dir);
    let manifest_before = manifest_store.load_current().map_err(|error| {
        calyx_status_fault(project, &format!("load {operation} vault manifest"), error)
    })?;
    if manifest_before.registry_ref.is_none() {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} cannot run compression {operation} because its exact vault manifest has no Registry reference"
            ),
            "Persist the exact Panel and Registry interpretation before mutating compression admission state.",
        )
        .with_detail("project", project)
        .with_detail("operation", operation)
        .with_detail("manifest_seq", manifest_before.manifest_seq)
        .into());
    }
    let panel_state = load_vault_panel_state(vault_dir).map_err(|error| {
        calyx_status_fault(
            project,
            &format!("load persisted {operation} Panel/Registry state"),
            error,
        )
    })?;
    let Some(registry_snapshot) = panel_state.registry_snapshot.as_ref() else {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} compression {operation} loaded no Registry snapshot despite the exact manifest reference"
            ),
            "Restore the immutable Registry asset named by CURRENT before mutating compression admission state.",
        )
        .with_detail("project", project)
        .with_detail("operation", operation)
        .with_detail("manifest_seq", manifest_before.manifest_seq)
        .into());
    };
    if registry_snapshot.panel_ref != manifest_before.panel_ref {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED,
            format!(
                "project {project:?} compression {operation} loaded a Registry snapshot bound to a different Panel reference than the captured CURRENT manifest"
            ),
            "Preserve the vault and restore the exact Panel/Registry asset pair named by CURRENT before mutating compression admission state.",
        )
        .with_detail("project", project)
        .with_detail("operation", operation)
        .with_detail("manifest_seq", manifest_before.manifest_seq)
        .with_detail(
            "manifest_panel_ref_blake3",
            manifest_before.panel_ref.blake3_hex.clone(),
        )
        .with_detail(
            "registry_snapshot_panel_ref_blake3",
            registry_snapshot.panel_ref.blake3_hex.clone(),
        )
        .into());
    }
    let manifest_after_load = manifest_store.load_current().map_err(|error| {
        calyx_status_fault(
            project,
            &format!("re-read {operation} vault manifest after Registry load"),
            error,
        )
    })?;
    if manifest_after_load != manifest_before {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED,
            format!(
                "project {project:?} vault manifest changed while loading the Panel/Registry state for compression {operation}: manifest seq {}->{}",
                manifest_before.manifest_seq, manifest_after_load.manifest_seq
            ),
            "Retry only after the concurrent Panel/Registry or vault publication finishes; stale interpretation is never used for a mutation.",
        )
        .with_detail("project", project)
        .with_detail("operation", operation)
        .with_detail("manifest_seq_before", manifest_before.manifest_seq)
        .with_detail("manifest_seq_after", manifest_after_load.manifest_seq)
        .into());
    }
    Ok((manifest_store, manifest_before, panel_state))
}

fn require_unchanged_mutation_refs(
    manifest_store: &ManifestStore,
    project: &str,
    stage: &str,
    manifest_before: &VaultManifest,
) -> Result<VaultManifest, DynError> {
    let manifest_after = manifest_store
        .load_current()
        .map_err(|error| calyx_status_fault(project, stage, error))?;
    if manifest_after.panel_ref != manifest_before.panel_ref
        || manifest_after.registry_ref != manifest_before.registry_ref
    {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_CONTEXT_CHANGED,
            format!(
                "project {project:?} immutable Panel/Registry references changed during compression mutation {stage}: manifest seq {}->{}",
                manifest_before.manifest_seq, manifest_after.manifest_seq
            ),
            "Preserve the completed vault writes, reload the exact current Panel/Registry interpretation, and inspect the reported context drift before any retry.",
        )
        .with_detail("project", project)
        .with_detail("stage", stage)
        .with_detail("manifest_seq_before", manifest_before.manifest_seq)
        .with_detail("manifest_seq_after", manifest_after.manifest_seq)
        .with_detail(
            "panel_ref_before",
            manifest_before.panel_ref.blake3_hex.clone(),
        )
        .with_detail("panel_ref_after", manifest_after.panel_ref.blake3_hex.clone())
        .with_detail(
            "registry_ref_before",
            json!(
                manifest_before
                    .registry_ref
                    .as_ref()
                    .map(|reference| &reference.blake3_hex)
            ),
        )
        .with_detail(
            "registry_ref_after",
            json!(
                manifest_after
                    .registry_ref
                    .as_ref()
                    .map(|reference| &reference.blake3_hex)
            ),
        )
        .into());
    }
    Ok(manifest_after)
}

fn compression_publication_action(
    project: &str,
    readback: &CompressionAdmissionReadback,
) -> Result<&'static str, DynError> {
    let receipt_published = match (
        readback.receipt_commit_seq.is_some(),
        readback.receipt_ledger.is_some(),
    ) {
        (true, true) => true,
        (false, false) => false,
        _ => {
            return Err(incoherent_publication_fault(
                project,
                "selection receipt",
                readback,
            ));
        }
    };
    let pointer_published = match (
        readback.pointer_commit_seq.is_some(),
        readback.pointer_ledger.is_some(),
    ) {
        (true, true) => true,
        (false, false) => false,
        _ => {
            return Err(incoherent_publication_fault(
                project,
                "current pointer",
                readback,
            ));
        }
    };
    match (receipt_published, pointer_published) {
        (true, true) => Ok("selection_receipt_and_current_pointer_published"),
        (false, true) => Ok("existing_selection_receipt_current_pointer_published"),
        (false, false) => Ok("idempotent_current_readback"),
        (true, false) => Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} selection returned a newly published receipt without a current-pointer publication"
            ),
            "Preserve the vault and inspect the selection receipt and current pointer; a successful current readback cannot omit only the pointer publication.",
        )
        .with_detail("project", project)
        .with_detail("receipt_sha256", readback.receipt_sha256.clone())
        .into()),
    }
}

fn incoherent_publication_fault(
    project: &str,
    component: &str,
    readback: &CompressionAdmissionReadback,
) -> DynError {
    ToolFault::new(
        ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
        format!(
            "project {project:?} compression {component} commit sequence and Ledger reference have incoherent presence"
        ),
        "Preserve the vault and inspect the atomic Admission commit; its commit sequence and Ledger reference must both be present or both be absent for an idempotent readback.",
    )
    .with_detail("project", project)
    .with_detail("component", component)
    .with_detail("receipt_sha256", readback.receipt_sha256.clone())
    .into()
}

fn validate_status(
    project: &str,
    slot_id: SlotId,
    status: &CompressionAdmissionStatus,
) -> Result<(), DynError> {
    let invalid = match (
        status.latest_evaluation.as_ref(),
        status.current_admission.as_ref(),
    ) {
        (None, None) => None,
        (None, Some(_)) => Some("current admission exists without a latest-evaluation pointer"),
        (Some(_latest), Some(current))
            if current.receipt.verdict != CompressionAdmissionVerdict::Admitted =>
        {
            Some("current-admission pointer names a refused receipt")
        }
        (Some(_latest), Some(current)) if current.receipt.candidate_selection.is_none() => {
            Some("current-admission pointer names an unselected candidate receipt")
        }
        (Some(latest), current)
            if latest.current
                != current
                    .is_some_and(|current| current.receipt_sha256 == latest.receipt_sha256) =>
        {
            Some("latest-evaluation current flag disagrees with the current-admission pointer")
        }
        (Some(latest), _)
            if latest.receipt.verdict == CompressionAdmissionVerdict::Refused && latest.current =>
        {
            Some("latest refused evaluation is marked as the current admission")
        }
        (Some(latest), _) if !latest.active_generation_current => {
            Some("latest evaluation does not match the exact active generation")
        }
        (_, Some(current)) if !current.active_generation_current => {
            Some("current admission does not match the exact active generation")
        }
        (_, Some(current)) if !current.current => {
            Some("current-admission readback is not marked current")
        }
        _ => None,
    };
    if let Some(message) = invalid {
        return Err(ToolFault::new(
            ASTRO_OPTIMIZER_COMPRESSION_STATUS_INVALID,
            format!(
                "project {project:?} slot {} compression admission status is contradictory: {message}",
                slot_id.get()
            ),
            "Inspect the latest-evaluation pointer, current-admission pointer, and immutable receipts for this exact slot; repair the Registry-owned publication before retrying.",
        )
        .with_detail("project", project)
        .with_detail("slot_id", u64::from(slot_id.get()))
        .into());
    }
    Ok(())
}

fn readback_json(readback: &CompressionAdmissionReadback) -> Value {
    let receipt = &readback.receipt;
    json!({
        "receipt_sha256": readback.receipt_sha256,
        "verdict": receipt.verdict,
        "current_admission": readback.current,
        "active_generation_current": readback.active_generation_current,
        "generation_validation": readback.trust,
        "identity": {
            "schema": receipt.schema,
            "generation_seq": receipt.generation_seq,
            "manifest_seq": receipt.manifest_seq,
            "codec": receipt.codec,
            "level": receipt.level,
            "raw_dim": receipt.raw_dim,
            "stored_dim": receipt.stored_dim,
            "corpus_rows": receipt.corpus_rows,
            "logical_values": receipt.logical_values,
        },
        "hashes": {
            "codec_context_sha256": receipt.codec_context_sha256,
            "generation_sha256": receipt.generation_sha256,
            "raw_generation_sha256": receipt.raw_generation_sha256,
            "membership_sha256": receipt.membership_sha256,
            "source_values_sha256": receipt.source_values_sha256,
            "query_values_sha256": receipt.query_values_sha256,
            "exact_ground_truth_sha256": receipt.exact_ground_truth_sha256,
        },
        "measurement": {
            "query_ids_disjoint": receipt.query_ids_disjoint,
            "metric": receipt.metric,
            "k": receipt.k,
            "requested_backend": receipt.requested_backend,
            "observed_backend": receipt.observed_backend,
            "device_identity": receipt.device_identity,
            "kernel_identity": receipt.kernel_identity,
            "build": receipt.build,
            "placement": receipt.placement,
            "warmup_runs": receipt.warmup_runs,
            "measured_runs": receipt.measured_runs,
            "held_out_query_count": receipt.held_out_queries.len(),
            "query_count": receipt.queries.len(),
            "reconstruction_count": receipt.reconstruction.len(),
            "total_physical_bytes": receipt.total_physical_bytes,
            "effective_bits_per_value": receipt.effective_bits_per_value,
            "primary_value_bytes": receipt.primary_value_bytes,
            "mean_reconstruction_cosine_error": receipt.mean_reconstruction_cosine_error,
            "max_reconstruction_cosine_error": receipt.max_reconstruction_cosine_error,
            "latency_p50_ns": receipt.latency_p50_ns,
            "latency_p95_ns": receipt.latency_p95_ns,
            "latency_p99_ns": receipt.latency_p99_ns,
            "vectors_per_second": receipt.vectors_per_second,
            "bytes_per_second": receipt.bytes_per_second,
            "allocations": receipt.allocations,
            "resources": receipt.resources,
            "work_limits": receipt.work_limits,
            "work": receipt.work,
            "gates": receipt.gates,
            "gate_observations": receipt.gate_observations,
            "physical_components": receipt.physical_components,
            "candidate_selection": receipt.candidate_selection,
        },
        "trust": readback.trust,
    })
}

fn current_admission_json(status: &CompressionAdmissionStatus) -> Option<Value> {
    let current = status.current_admission.as_ref()?;
    if status
        .latest_evaluation
        .as_ref()
        .is_some_and(|latest| latest.receipt_sha256 == current.receipt_sha256)
    {
        return Some(json!({
            "receipt_sha256": current.receipt_sha256,
            "same_as_latest_evaluation": true,
            "verdict": current.receipt.verdict,
            "current_admission": current.current,
            "active_generation_current": current.active_generation_current,
            "trust": current.trust,
        }));
    }
    Some(readback_json(current))
}

fn calyx_status_fault(project: &str, stage: &str, error: calyx_core::CalyxError) -> DynError {
    ToolFault::new(
        error.code,
        format!(
            "project {project:?} compression-admission {stage} failed: {}",
            error.message
        ),
        error.remediation,
    )
    .with_detail("project", project)
    .with_detail("stage", stage)
    .with_detail("source_code", error.code)
    .into()
}
