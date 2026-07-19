//! Manual Full State Verification for compression Ledger binding (#594).
//!
//! Source of truth: a real durable Aster vault reopened from disk. Every
//! scenario inventories the Compression, Slot, Base, and Ledger column-family
//! rows before and after the action, then independently opens the physical
//! Ledger view. Refused writes must leave the complete logical byte inventory
//! and sequence unchanged.
//!
//! Run the built artifact with `CALYX_FSV_ROOT` set to a fresh workspace-local
//! directory. The driver never deletes or reuses that evidence directory.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calyx_aster::cf::{
    ColumnFamily, compression_lifecycle_key, compression_lifecycle_prefix_range,
    compression_manifest_key,
};
use calyx_aster::compression_lifecycle::{
    COMPRESSION_GENERATION_MARKER, GenerationLifecycleRecord, GenerationTransition,
    compression_generation_slot_from_subject, compression_generation_subject,
};
use calyx_aster::dedup::{DedupPolicy, EpochSecs, IngestInput};
use calyx_aster::erase::{EraseRegistry, EraseScope};
use calyx_aster::ledger_view::AsterLedgerCfStore;
use calyx_aster::stream::{BackpressureGuard, StreamIngester};
use calyx_aster::vault::{AsterVault, QuotaConfig, VaultContext, VaultOptions};
use calyx_core::{
    Asymmetry, Modality, QuantPolicy, Slot, SlotId, SlotResource, SlotShape, SlotState, SlotVector,
    SystemClock, VaultId,
};
use calyx_ledger::{
    ActorId, EntryKind, LedgerCfStore, LedgerEntryInput, SubjectId, VerifyResult, verify_chain,
};
use calyx_registry::{
    AlgorithmicLens, CompressionQuery, LensRuntime, LensSpec, Registry, StoredSlotCodec,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const DIM: u32 = 8;
const ROWS: usize = 4;
const PANEL_VERSION: u32 = 594;
const SLOT_A: u16 = 70;
const SLOT_B: u16 = 71;
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SALT: &[u8] = b"issue-594-compression-ledger-fsv";

type AnyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RowEvidence {
    key_hex: String,
    value_len: usize,
    value_sha256: String,
    decoded: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct LedgerEvidence {
    seq: u64,
    value_len: usize,
    value_sha256: String,
    kind: String,
    subject_hex: String,
    compression_slot: Option<u16>,
    transition: Option<String>,
    payload: String,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct VaultState {
    seq: u64,
    base: Vec<RowEvidence>,
    compression: Vec<RowEvidence>,
    slot_a_primary: Vec<RowEvidence>,
    slot_a_raw: Vec<RowEvidence>,
    slot_b_primary: Vec<RowEvidence>,
    slot_b_raw: Vec<RowEvidence>,
    ledger: Vec<LedgerEvidence>,
    physical_ledger: Vec<LedgerEvidence>,
    digest_sha256: String,
}

#[derive(Clone, Copy, Debug)]
enum RefusalCase {
    TwoSlotsOneLedger,
    DuplicateLedger,
    WrongSlotLedger,
    MalformedReservedSubject,
}

impl RefusalCase {
    const fn name(self) -> &'static str {
        match self {
            Self::TwoSlotsOneLedger => "two_slots_one_ledger",
            Self::DuplicateLedger => "duplicate_slot_ledger",
            Self::WrongSlotLedger => "wrong_slot_ledger",
            Self::MalformedReservedSubject => "malformed_reserved_subject",
        }
    }
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({ "event": "fsv_failure", "error": error.to_string() })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let root = fresh_root()?;
    let vault_dir = root.join("vault");
    let artifact = std::env::current_exe()?;
    println!(
        "{}",
        json!({
            "event": "fsv_context",
            "issue": 594,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "artifact": artifact,
            "vault_dir": vault_dir,
            "source_of_truth": "freshly reopened durable Aster CF rows plus AsterLedgerCfStore physical WAL/SST view",
        })
    );

    let mut registry = Registry::new();
    let slot_a = register_slot(&mut registry, "issue594-slot-a", SLOT_A)?;
    let slot_b = register_slot(&mut registry, "issue594-slot-b", SLOT_B)?;

    let vault = Arc::new(open_vault(&vault_dir)?);
    let empty = read_state(&vault, &vault_dir)?;
    print_state("happy_before", &empty);
    require(
        empty.seq == 0
            && empty.base.is_empty()
            && empty.compression.is_empty()
            && empty.ledger.is_empty(),
        "fresh durable vault must begin with empty source-of-truth state",
    )?;

    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(16, 0));
    for index in 0..ROWS {
        ingester.send(event(index), EpochSecs(59_400 + index as i64))?;
    }
    let ingest_stats = ingester.drain_and_close()?;
    require(
        ingest_stats.ingested == ROWS,
        format!(
            "expected {ROWS} real ingests, observed {}",
            ingest_stats.ingested
        ),
    )?;
    let queries = queries(&vault);
    let report_a = registry.compress_streamed_column(&vault, &slot_a, &queries, 1)?;
    let report_b = registry.compress_streamed_column(&vault, &slot_b, &queries, 1)?;
    require(
        report_a.stored_codec == StoredSlotCodec::ScalarInt8
            && report_b.stored_codec == StoredSlotCodec::ScalarInt8,
        "lawful setup must persist the explicitly requested ScalarInt8 codec",
    )?;
    vault.flush()?;
    let happy_live = read_state(&vault, &vault_dir)?;
    require_happy_compressed_state(&happy_live)?;
    print_state("happy_after_live", &happy_live);
    drop(vault);

    let reopened = open_vault(&vault_dir)?;
    let happy_reopened = read_state(&reopened, &vault_dir)?;
    require(
        happy_reopened == happy_live,
        "fresh-handle happy-path readback differs from the committed CF bytes",
    )?;
    require_happy_compressed_state(&happy_reopened)?;
    print_state("happy_after_reopen", &happy_reopened);
    drop(reopened);

    for case in [
        RefusalCase::TwoSlotsOneLedger,
        RefusalCase::DuplicateLedger,
        RefusalCase::WrongSlotLedger,
        RefusalCase::MalformedReservedSubject,
    ] {
        exercise_refusal(&vault_dir, case)?;
    }

    exercise_multislot_erase(&vault_dir)?;
    println!(
        "{}",
        json!({
            "event": "fsv_success",
            "issue": 594,
            "fixture_root": root,
            "happy_path": "two lawful independently ledgered compressed slots",
            "refusals": [
                "two slots with one Ledger entry",
                "one slot with duplicate Ledger entries",
                "one slot with a different slot's Ledger subject",
                "malformed reserved compression subject"
            ],
            "multislot_erase": "global erase tombstone plus one DeleteGeneration Ledger entry per slot"
        })
    );
    Ok(())
}

fn exercise_refusal(vault_dir: &Path, case: RefusalCase) -> AnyResult<()> {
    let vault = open_vault(vault_dir)?;
    let before = read_state(&vault, vault_dir)?;
    let slots = match case {
        RefusalCase::TwoSlotsOneLedger => vec![SlotId::new(SLOT_A), SlotId::new(SLOT_B)],
        _ => vec![SlotId::new(SLOT_A)],
    };
    let (rows, records) = reseal_rows(&vault, &slots)?;
    let expected_seq = vault.latest_seq();
    let actor = ActorId::Service("issue594-fsv".to_string());
    let error = match case {
        RefusalCase::TwoSlotsOneLedger => vault
            .write_cf_batch_with_ledger_entry_if_seq(
                expected_seq,
                rows,
                EntryKind::Migrate,
                compression_generation_subject(SlotId::new(SLOT_A)),
                records[0].ledger_payload()?,
                actor,
            )
            .expect_err("two slots with one Ledger entry must fail closed"),
        RefusalCase::DuplicateLedger => {
            let payload = records[0].ledger_payload()?;
            let subject = compression_generation_subject(SlotId::new(SLOT_A));
            vault
                .write_cf_batch_with_ledger_entries_if_seq(
                    expected_seq,
                    rows,
                    [
                        LedgerEntryInput::new(
                            EntryKind::Migrate,
                            subject.clone(),
                            payload.clone(),
                            actor.clone(),
                        ),
                        LedgerEntryInput::new(EntryKind::Migrate, subject, payload, actor),
                    ],
                )
                .expect_err("duplicate slot-matched Ledger entries must fail closed")
        }
        RefusalCase::WrongSlotLedger => vault
            .write_cf_batch_with_ledger_entry_if_seq(
                expected_seq,
                rows,
                EntryKind::Migrate,
                compression_generation_subject(SlotId::new(SLOT_B)),
                records[0].ledger_payload()?,
                actor,
            )
            .expect_err("wrong-slot Ledger subject must fail closed"),
        RefusalCase::MalformedReservedSubject => {
            let mut malformed = COMPRESSION_GENERATION_MARKER.as_bytes().to_vec();
            malformed.push(b':');
            malformed.push(SLOT_A as u8);
            vault
                .write_cf_batch_with_ledger_entry_if_seq(
                    expected_seq,
                    rows,
                    EntryKind::Migrate,
                    SubjectId::Query(malformed),
                    records[0].ledger_payload()?,
                    actor,
                )
                .expect_err("malformed reserved compression subject must fail closed")
        }
    };
    require(
        error.code == "CALYX_COMPRESSION_LIFECYCLE_INVALID",
        format!(
            "{} returned unexpected error code {}: {}",
            case.name(),
            error.code,
            error.message
        ),
    )?;
    let after_live = read_state(&vault, vault_dir)?;
    require(
        after_live == before,
        format!(
            "{} changed live source-of-truth state despite refusal",
            case.name()
        ),
    )?;
    drop(vault);
    let reopened = open_vault(vault_dir)?;
    let after_reopen = read_state(&reopened, vault_dir)?;
    require(
        after_reopen == before,
        format!(
            "{} changed persisted source-of-truth bytes despite refusal",
            case.name()
        ),
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_refused",
            "case": case.name(),
            "error": {
                "code": error.code,
                "message": error.message,
                "remediation": error.remediation,
            },
            "before": before,
            "after_live": after_live,
            "after_reopen": after_reopen,
            "state_unchanged": true,
        })
    );
    Ok(())
}

fn exercise_multislot_erase(vault_dir: &Path) -> AnyResult<()> {
    let vault = open_vault(vault_dir)?;
    let before = read_state(&vault, vault_dir)?;
    require_happy_compressed_state(&before)?;
    let vault_id: VaultId = VAULT_ID.parse()?;
    let mut context = VaultContext::new(
        vault_id,
        b"issue594-fsv-master-key",
        QuotaConfig::default(),
        "issue594-native-windows",
    )?;
    let result = vault.erase(EraseScope::Vault, &mut context, &EraseRegistry::new())?;
    require(
        result.records_deleted == ROWS,
        format!(
            "vault erase deleted {} base rows, expected {ROWS}",
            result.records_deleted
        ),
    )?;
    require(
        context.is_key_shredded_for_erasure(),
        "full-vault erase must shred its live VaultContext key",
    )?;
    let after_live = read_state(&vault, vault_dir)?;
    require_erased_state(&after_live)?;
    drop(vault);

    let reopened = open_vault(vault_dir)?;
    let after_reopen = read_state(&reopened, vault_dir)?;
    require(
        after_reopen == after_live,
        "fresh-handle erase readback differs from the committed CF bytes",
    )?;
    require_erased_state(&after_reopen)?;
    let physical = AsterLedgerCfStore::open(vault_dir)?;
    let physical_rows = physical.scan()?;
    let verified = verify_chain(&physical, 0..physical_rows.len() as u64)?;
    require(
        matches!(
            verified,
            VerifyResult::Intact { count } if count == physical_rows.len() as u64
        ),
        format!("post-erase physical Ledger chain is not intact: {verified:?}"),
    )?;
    println!(
        "{}",
        json!({
            "event": "multislot_erase_committed",
            "before": before,
            "after_live": after_live,
            "after_reopen": after_reopen,
            "records_deleted": result.records_deleted,
            "vault_key_shredded": true,
            "physical_ledger_verify": format!("{verified:?}"),
        })
    );
    Ok(())
}

fn reseal_rows(
    vault: &AsterVault<SystemClock>,
    slots: &[SlotId],
) -> AnyResult<(
    Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    Vec<GenerationLifecycleRecord>,
)> {
    let snapshot = vault.latest_seq();
    let mut rows = Vec::with_capacity(slots.len() * 2);
    let mut records = Vec::with_capacity(slots.len());
    for slot in slots {
        let manifest = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Compression,
                &compression_manifest_key(*slot),
            )?
            .ok_or_else(|| format!("slot {} manifest missing", slot.get()))?;
        let lifecycle = vault.scan_cf_range_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_lifecycle_prefix_range(*slot),
        )?;
        let prior = lifecycle
            .last()
            .ok_or_else(|| format!("slot {} lifecycle missing", slot.get()))?;
        let prior = GenerationLifecycleRecord::parse(&prior.1)?;
        let record = GenerationLifecycleRecord::new(
            GenerationTransition::Reseal,
            slot.get(),
            snapshot,
            prior.generation_rows,
            prior.generation_root_sha256,
            prior.raw_generation_root_sha256,
            prior.affected_cx_ids,
        )?;
        rows.push((
            ColumnFamily::Compression,
            compression_manifest_key(*slot),
            manifest,
        ));
        rows.push((
            ColumnFamily::Compression,
            compression_lifecycle_key(*slot, snapshot),
            record.encode()?,
        ));
        records.push(record);
    }
    Ok((rows, records))
}

fn require_happy_compressed_state(state: &VaultState) -> AnyResult<()> {
    require(
        state.base.len() == ROWS
            && state.slot_a_primary.len() == ROWS
            && state.slot_a_raw.len() == ROWS
            && state.slot_b_primary.len() == ROWS
            && state.slot_b_raw.len() == ROWS,
        "happy path must persist four base, primary, and raw-sidecar rows per slot",
    )?;
    require(
        manifest_count(state) == 2,
        "happy path must persist exactly two generation manifests",
    )?;
    for slot in [SLOT_A, SLOT_B] {
        let entries = state
            .ledger
            .iter()
            .filter(|entry| entry.compression_slot == Some(slot))
            .collect::<Vec<_>>();
        require(
            entries.len() == 1 && entries[0].transition.as_deref() != Some("delete_generation"),
            format!(
                "slot {slot} must have exactly one non-delete compression Ledger statement, got {entries:?}"
            ),
        )?;
    }
    require(
        state.ledger == state.physical_ledger,
        "logical Ledger CF and independently opened physical Ledger view differ",
    )?;
    Ok(())
}

fn require_erased_state(state: &VaultState) -> AnyResult<()> {
    require(
        state.base.is_empty()
            && state.slot_a_primary.is_empty()
            && state.slot_a_raw.is_empty()
            && state.slot_b_primary.is_empty()
            && state.slot_b_raw.is_empty(),
        "full-vault erase must leave no Base or compressed primary/raw rows",
    )?;
    require(
        manifest_count(state) == 0,
        "full-vault erase must leave no live two-byte compression manifest",
    )?;
    for slot in [SLOT_A, SLOT_B] {
        let entries = state
            .ledger
            .iter()
            .filter(|entry| entry.compression_slot == Some(slot))
            .collect::<Vec<_>>();
        require(
            entries.len() == 2
                && entries
                    .iter()
                    .any(|entry| entry.transition.as_deref() == Some("delete_generation")),
            format!(
                "slot {slot} must retain create plus DeleteGeneration Ledger statements, got {entries:?}"
            ),
        )?;
    }
    require(
        state.ledger == state.physical_ledger,
        "post-erase logical Ledger CF and physical Ledger view differ",
    )?;
    Ok(())
}

fn manifest_count(state: &VaultState) -> usize {
    state
        .compression
        .iter()
        .filter(|row| row.key_hex.len() == 4)
        .count()
}

fn read_state(vault: &AsterVault<SystemClock>, vault_dir: &Path) -> AnyResult<VaultState> {
    let seq = vault.latest_seq();
    let base = row_evidence(vault.scan_cf_at(seq, ColumnFamily::Base)?, false)?;
    let compression = row_evidence(vault.scan_cf_at(seq, ColumnFamily::Compression)?, true)?;
    let slot_a_primary = row_evidence(
        vault.scan_cf_at(seq, ColumnFamily::slot(SlotId::new(SLOT_A)))?,
        false,
    )?;
    let slot_a_raw = row_evidence(
        vault.scan_cf_at(seq, ColumnFamily::slot_raw(SlotId::new(SLOT_A)))?,
        false,
    )?;
    let slot_b_primary = row_evidence(
        vault.scan_cf_at(seq, ColumnFamily::slot(SlotId::new(SLOT_B)))?,
        false,
    )?;
    let slot_b_raw = row_evidence(
        vault.scan_cf_at(seq, ColumnFamily::slot_raw(SlotId::new(SLOT_B)))?,
        false,
    )?;
    let ledger = ledger_evidence(
        vault
            .scan_cf_at(seq, ColumnFamily::Ledger)?
            .into_iter()
            .map(|(key, value)| {
                let seq = u64::from_be_bytes(
                    key.as_slice()
                        .try_into()
                        .expect("Aster Ledger key is eight bytes"),
                );
                (seq, value)
            })
            .collect(),
    )?;
    let physical_ledger = if ledger.is_empty() {
        Vec::new()
    } else {
        let physical = AsterLedgerCfStore::open(vault_dir)?;
        ledger_evidence(
            physical
                .scan()?
                .into_iter()
                .map(|row| (row.seq, row.bytes))
                .collect(),
        )?
    };
    let digest_bytes = serde_json::to_vec(&(
        seq,
        &base,
        &compression,
        &slot_a_primary,
        &slot_a_raw,
        &slot_b_primary,
        &slot_b_raw,
        &ledger,
        &physical_ledger,
    ))?;
    Ok(VaultState {
        seq,
        base,
        compression,
        slot_a_primary,
        slot_a_raw,
        slot_b_primary,
        slot_b_raw,
        ledger,
        physical_ledger,
        digest_sha256: sha256(&digest_bytes),
    })
}

fn row_evidence(
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    decode_compression: bool,
) -> AnyResult<Vec<RowEvidence>> {
    rows.into_iter()
        .map(|(key, value)| {
            let decoded = if decode_compression {
                if key.len() == 2 {
                    Some(format!(
                        "manifest(slot={},magic={})",
                        u16::from_be_bytes([key[0], key[1]]),
                        String::from_utf8_lossy(value.get(..4).unwrap_or(&value))
                    ))
                } else {
                    Some(serde_json::to_string(&GenerationLifecycleRecord::parse(
                        &value,
                    )?)?)
                }
            } else {
                None
            };
            Ok(RowEvidence {
                key_hex: hex(&key),
                value_len: value.len(),
                value_sha256: sha256(&value),
                decoded,
            })
        })
        .collect()
}

fn ledger_evidence(rows: Vec<(u64, Vec<u8>)>) -> AnyResult<Vec<LedgerEvidence>> {
    rows.into_iter()
        .map(|(seq, value)| {
            let entry = calyx_ledger::decode(&value)?;
            require(
                entry.seq == seq,
                format!(
                    "Ledger key seq {seq} differs from encoded seq {}",
                    entry.seq
                ),
            )?;
            let compression_slot =
                compression_generation_slot_from_subject(&entry.subject)?.map(SlotId::get);
            let transition = serde_json::from_slice::<serde_json::Value>(&entry.payload)
                .ok()
                .and_then(|value| {
                    value
                        .get("transition")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                });
            Ok(LedgerEvidence {
                seq,
                value_len: value.len(),
                value_sha256: sha256(&value),
                kind: format!("{:?}", entry.kind),
                subject_hex: subject_hex(&entry.subject),
                compression_slot,
                transition,
                payload: String::from_utf8_lossy(&entry.payload).to_string(),
                prev_hash: hex(&entry.prev_hash),
                entry_hash: hex(&entry.entry_hash),
            })
        })
        .collect()
}

fn print_state(event: &str, state: &VaultState) {
    println!("{}", json!({ "event": event, "state": state }));
}

fn register_slot(registry: &mut Registry, name: &str, slot_id: u16) -> AnyResult<Slot> {
    let lens = AlgorithmicLens::one_hot(name, Modality::Code, DIM);
    let contract = lens.contract().clone();
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic {
            kind: format!("one_hot:{DIM}"),
        },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: None,
        axis: Some("issue594-ledger-binding".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: QuantPolicy::ScalarInt8,
        truncate_dim: None,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let id = SlotId::new(slot_id);
    Ok(Slot {
        slot_id: id,
        slot_key: id.with_key(format!("{name}-slot")),
        lens_id,
        shape: SlotShape::Dense(DIM),
        modality: Modality::Code,
        asymmetry: Asymmetry::None,
        quant: QuantPolicy::ScalarInt8,
        resource: SlotResource::default(),
        axis: Some("issue594-ledger-binding".to_string()),
        retrieval_only: false,
        excluded_from_dedup: false,
        bits_about: BTreeMap::new(),
        state: SlotState::Active,
        added_at_panel_version: PANEL_VERSION,
    })
}

fn event(index: usize) -> IngestInput {
    IngestInput::new(
        format!("issue594-real-code-record-{index}").into_bytes(),
        PANEL_VERSION,
        Modality::Code,
    )
    .with_slot(SlotId::new(SLOT_A), dense_vector(index))
    .with_slot(SlotId::new(SLOT_B), dense_vector(index))
}

fn dense_vector(index: usize) -> SlotVector {
    let mut data = vec![0.0; DIM as usize];
    data[index] = 1.0;
    SlotVector::Dense { dim: DIM, data }
}

fn queries(vault: &AsterVault<SystemClock>) -> Vec<CompressionQuery> {
    let input = event(0);
    let mut values = vec![0.0; DIM as usize];
    for (index, value) in values.iter_mut().take(ROWS).enumerate() {
        *value = 1.0 / (index + 1) as f32;
    }
    Vec::from([CompressionQuery {
        cx_id: vault.cx_id_for_input(&input.raw_bytes, input.panel_version),
        values,
    }])
}

fn open_vault(dir: &Path) -> AnyResult<AsterVault<SystemClock>> {
    fs::create_dir_all(dir)?;
    let options = VaultOptions {
        dedup_policy: Some(DedupPolicy::Off),
        ..VaultOptions::default()
    };
    Ok(AsterVault::open(
        dir,
        VAULT_ID.parse::<VaultId>()?,
        VAULT_SALT.to_vec(),
        options,
    )?)
}

fn fresh_root() -> AnyResult<PathBuf> {
    let workspace = std::env::current_dir()?;
    let root = std::env::var_os("CALYX_FSV_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            workspace.join(".tmp").join(format!(
                "issue594-compression-ledger-{}",
                std::process::id()
            ))
        });
    require(
        !root.exists(),
        format!(
            "FSV root already exists and will not be reused: {}",
            root.display()
        ),
    )?;
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn subject_hex(subject: &SubjectId) -> String {
    match subject {
        SubjectId::Cx(id) => format!("cx:{}", hex(id.as_bytes())),
        SubjectId::Lens(id) => format!("lens:{}", hex(id.as_bytes())),
        SubjectId::Kernel(bytes) => format!("kernel:{}", hex(bytes)),
        SubjectId::Guard(bytes) => format!("guard:{}", hex(bytes)),
        SubjectId::Query(bytes) => format!("query:{}", hex(bytes)),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
