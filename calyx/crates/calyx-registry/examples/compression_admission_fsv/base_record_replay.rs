use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

use calyx_aster::cf::{anchor_key, anchor_prefix_range, ledger_key};
use calyx_aster::vault::encode::{BaseRecord, WriteRow, decode_write_batch};
use calyx_aster::wal::replay_dir_read_only_after;
use calyx_core::{Anchor, AnchorKind, AnchorValue, FixedClock, LedgerRef, SlotVector};
use calyx_ledger::{ActorId, LedgerEntry, SubjectId, decode as decode_ledger_entry};
use serde::{Deserialize, Serialize};

const BASELINE_SCHEMA: &str = "astrolabe.base-record-replay-baseline.v1";
const READBACK_SCHEMA: &str = "astrolabe.base-record-replay-readback.v1";
const FIXTURE_DATE: &str = "2026-08-17";
const FIXTURE_N: usize = 2;
const FIXED_CLOCK_MS: u64 = 1_787_000_000_000;
const FIXED_VAULT_NAME: &str = "issue-1138-base-record-replay";
const FIXED_PANEL_TEMPLATE: &str = "issue-1138-manual-fsv";
const TEXT_ROLE: &str = "text_replay";
const BATCH_ROLE: &str = "batch_target";
const TEXT_INPUT: &str = "issue-1138 existing text replay with empty metadata";
const BATCH_INPUT: &str = "issue-1138 existing batch replay with retained provenance metadata";
const ANCHOR_AXIS: &str = "test";
const ANCHOR_VALUE: &str = "base-record-replay";
const ANCHOR_SOURCE: &str = "issue-1138-manual-fsv";
const BASELINE_FILE: &str = "base-record-replay-baseline.json";
const READBACK_FILE: &str = "base-record-replay-readback.json";
const TEXT_FILE: &str = "base-record-text.txt";
const BATCH_NO_ANCHOR_FILE: &str = "base-record-batch-no-anchor.jsonl";
const BATCH_ANCHOR_FILE: &str = "base-record-batch.jsonl";
const BATCH_MISMATCH_FILE: &str = "base-record-batch-mismatch.jsonl";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ValueIdentity {
    bytes: usize,
    sha256: String,
    hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct NonAnchorIdentity {
    cx_id: String,
    vault_id: String,
    panel_version: u32,
    created_at: u64,
    input_hash: String,
    input_pointer: Option<String>,
    input_redacted: bool,
    modality: String,
    slot_hashes: BTreeMap<u16, String>,
    scalar_bits: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    ungrounded_normalized: bool,
    degraded: bool,
    novel_region: bool,
    redacted_input: bool,
    provenance: LedgerIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerIdentity {
    seq: u64,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BaseEvidence {
    role: String,
    text: String,
    cx_id: String,
    wire_variant: String,
    value: ValueIdentity,
    canonical_reencode_equal: bool,
    slot_hashes: BTreeMap<u16, String>,
    non_anchor_identity: NonAnchorIdentity,
    non_anchor_identity_sha256: String,
    metadata: BTreeMap<String, String>,
    ungrounded: bool,
    anchors: usize,
    provenance: LedgerIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ResolvedVectorEvidence {
    cx_id: String,
    slot_id: u16,
    dim: u32,
    original_f32_bits: Vec<String>,
    resolved_f32_bits: Vec<String>,
    original_slot_blake3: String,
    differing_coefficients: usize,
    representation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompressedRowEvidence {
    role: String,
    cx_id: String,
    primary_key_hex: String,
    primary: ValueIdentity,
    membership_key_hex: String,
    membership_proof: ValueIdentity,
    resolved: ResolvedVectorEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompressionEvidence {
    slot_id: u16,
    stored_codec: String,
    manifest_key_hex: String,
    manifest: ValueIdentity,
    generation_identity: Value,
    rows: Vec<CompressedRowEvidence>,
    recovery_raw_sidecar_rows: usize,
    recovery_raw_sidecar_sha256: String,
    serving_selected_column_families: Vec<String>,
    raw_sidecar_selected_for_serving: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerRowEvidence {
    seq: u64,
    value: ValueIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEvidence {
    rows: Vec<LedgerRowEvidence>,
    rows_sha256: String,
    chain: String,
    head_height: u64,
    head_tip_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WalRecordEvidence {
    seq: u64,
    time_index_millis: u64,
    segment_relative_path: String,
    start_offset: u64,
    end_offset: u64,
    payload: ValueIdentity,
    rows: Vec<WalRowEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WalRowEvidence {
    column_family: String,
    key_hex: String,
    value_sha256: String,
    value_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WalEvidence {
    tip_seq: u64,
    records: Vec<WalRecordEvidence>,
    segment_files: Vec<FileReadback>,
    segment_files_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct InputFileEvidence {
    path: String,
    value: ValueIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CliRole {
    role: String,
    environment: BTreeMap<String, String>,
    arguments: Vec<String>,
    expected_exit: i32,
    expected_effect: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BaselineReport {
    schema: String,
    fixture_date: String,
    fixture_n: usize,
    cost_claim: String,
    fixture_root: String,
    calyx_home: String,
    vault_dir: String,
    catalog_path: String,
    catalog_sha256: String,
    vault_name: String,
    vault_id: String,
    vault_salt_utf8: String,
    panel_version: u32,
    slot_id: u16,
    text: String,
    text_cx_id: String,
    batch_text: String,
    batch_cx_id: String,
    inputs: BTreeMap<String, InputFileEvidence>,
    batch_metadata: BTreeMap<String, String>,
    expected_anchor_key_hex: String,
    expected_anchor_without_observed_at: Value,
    cli_roles: Vec<CliRole>,
    legacy_rewrite_ledger: LedgerIdentity,
    base: Vec<BaseEvidence>,
    compression: CompressionEvidence,
    ledger: LedgerEvidence,
    wal: WalEvidence,
    snapshot: Seq,
    vault_files: Vec<FileReadback>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerSuffixEvidence {
    ordinal: usize,
    seq: u64,
    mode: String,
    subject_cx_id: String,
    value: ValueIdentity,
    entry_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReadbackReport {
    schema: String,
    fixture_date: String,
    fixture_n: usize,
    fixture_root: String,
    baseline_path: String,
    baseline_sha256: String,
    snapshot: Seq,
    text_base: BaseEvidence,
    batch_base: BaseEvidence,
    anchors_rows: Vec<WalRowEvidence>,
    anchor: Value,
    compression: CompressionEvidence,
    ledger: LedgerEvidence,
    ledger_suffix: Vec<LedgerSuffixEvidence>,
    batch_sessions: BTreeMap<String, Value>,
    wal: WalEvidence,
    wal_suffix: Vec<WalRecordEvidence>,
    selected_column_families: Vec<String>,
    raw_sidecar_selected_for_serving: bool,
    exact_base_anchor_writes_in_suffix: usize,
    text_base_byte_identical: bool,
    batch_non_anchor_identity_unchanged: bool,
    batch_slot_hashes_unchanged: bool,
    compression_bytes_unchanged: bool,
    ledger_prefix_byte_identical: bool,
    exact_five_commit_suffix: bool,
    mismatch_added_no_commit: bool,
    disk_unchanged_during_readback: bool,
    vault_files_before: Vec<FileReadback>,
    vault_files_after: Vec<FileReadback>,
}

pub(super) fn prepare(root: &Path) -> AnyResult<()> {
    require(
        !root.exists(),
        format!(
            "base_record_replay_prepare root already exists: {}",
            root.display()
        ),
    )?;
    fs::create_dir_all(root)?;
    let home = root.join("calyx-home");
    let vault_id: VaultId = VAULT_ID.parse()?;
    let vault_dir = home.join("vaults").join(vault_id.to_string());
    let salt = fixture_salt();

    let mut registry = Registry::new();
    let registered = register(
        &mut registry,
        "issue-1138-base-record-tq35",
        TQ35_SLOT,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
    )?;
    let slot = registered.slot;
    let panel = panel_for_slots([slot.clone()]);
    let vault = Arc::new(AsterVault::new_durable_with_clock(
        &vault_dir,
        vault_id,
        salt.clone(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            panel: Some(panel.clone()),
            ..VaultOptions::default()
        },
        FixedClock::new(FIXED_CLOCK_MS),
    )?);
    persist_vault_panel_state(&vault_dir, &panel, &registry)?;
    let panel_readback = load_vault_panel_state(&vault_dir)?;
    require(
        panel_readback.panel == panel && panel_readback.registry_snapshot.is_some(),
        "base-record replay Panel/Registry readback differs",
    )?;

    let metadata = batch_metadata();
    let mut text_input = fixture_input(TEXT_INPUT, fixture_vector(TEXT_ROLE), BTreeMap::new());
    text_input.redacted = false;
    let mut batch_input = fixture_input(BATCH_INPUT, fixture_vector(BATCH_ROLE), metadata.clone());
    batch_input.redacted = false;
    let text_cx_id = vault.cx_id_for_input(TEXT_INPUT.as_bytes(), PANEL_VERSION);
    let batch_cx_id = vault.cx_id_for_input(BATCH_INPUT.as_bytes(), PANEL_VERSION);
    require(
        text_cx_id != batch_cx_id,
        "fixture texts produced the same CxId",
    )?;

    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(FIXTURE_N, 0));
    ingester.send(text_input, EpochSecs(1_787_000_000))?;
    ingester.send(batch_input, EpochSecs(1_787_000_001))?;
    let ingest = ingester.drain_and_close()?;
    require(
        ingest.ingested == FIXTURE_N,
        "base-record replay preparation did not ingest exactly two rows",
    )?;
    vault.flush_with_report()?;
    let legacy_rewrite_ledger = rewrite_empty_metadata_row_as_legacy(&vault, text_cx_id)?;

    let queries = vec![
        CompressionQuery {
            cx_id: vault.cx_id_for_input(b"issue-1138-held-out-text", PANEL_VERSION),
            values: fixture_vector(TEXT_ROLE),
        },
        CompressionQuery {
            cx_id: vault.cx_id_for_input(b"issue-1138-held-out-batch", PANEL_VERSION),
            values: fixture_vector(BATCH_ROLE),
        },
    ];
    let work = exact_work_plan(
        &[candidate_work_spec(&slot, FIXTURE_N as u32, DIM)?],
        queries.len(),
    )?;
    let candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &slot,
        candidate_request_with_k(queries, 1, work.limits.clone(), passing_gates()),
    )?;
    require_v3_work_plan(&candidate.evaluation.receipt, &work)?;
    require_unpublished_candidate(&candidate.evaluation)?;
    require(
        candidate.generation.stored_codec == StoredSlotCodec::TurboQuantBits3p5
            && candidate.generation.rows.len() == FIXTURE_N
            && candidate.generation.snapshot.is_some()
            && candidate.generation.ledger.is_some()
            && candidate.evaluation.receipt.verdict == CompressionAdmissionVerdict::Admitted
            && !candidate.evaluation.current,
        "single TQ3.5 fixture generation was substituted, incomplete, refused, or promoted",
    )?;
    vault.flush_with_report()?;
    drop(vault);

    let catalog_path = home.join("vaults").join("index.json");
    let catalog = json!({
        "vaults": [{
            "name": FIXED_VAULT_NAME,
            "vault_id": VAULT_ID,
            "path": format!("vaults/{VAULT_ID}"),
            "panel_template": FIXED_PANEL_TEMPLATE,
        }]
    });
    write_json_durable(&catalog_path, &catalog)?;

    let input_paths = write_replay_inputs(root, &metadata)?;
    let read_vault = open_replay_read_vault(&vault_dir)?;
    let snapshot = read_vault.latest_seq();
    let loaded = load_vault_panel_state(&vault_dir)?;
    require_exact_base_roster(&read_vault, snapshot, &[text_cx_id, batch_cx_id])?;
    let raw_sidecar = raw_sidecar_evidence(
        &vault_dir,
        &[(TEXT_ROLE, text_cx_id), (BATCH_ROLE, batch_cx_id)],
    )?;
    let base = vec![
        base_evidence(&read_vault, snapshot, TEXT_ROLE, TEXT_INPUT, text_cx_id)?,
        base_evidence(&read_vault, snapshot, BATCH_ROLE, BATCH_INPUT, batch_cx_id)?,
    ];
    require(
        base[0].wire_variant == "legacy_no_metadata_tail"
            && base[0].metadata.is_empty()
            && base[1].wire_variant == "metadata_tail"
            && base[1].metadata == metadata
            && base.iter().all(|row| row.ungrounded)
            && base.iter().all(|row| row.anchors == 0),
        "prepared Base rows do not have the exact empty/provenance metadata split",
    )?;
    require(
        read_vault
            .scan_cf_at(snapshot, ColumnFamily::Anchors)?
            .is_empty(),
        "prepared two-row fixture unexpectedly contains an Anchors row",
    )?;
    let compression = compression_evidence(
        &read_vault,
        &loaded,
        snapshot,
        &[(TEXT_ROLE, text_cx_id), (BATCH_ROLE, batch_cx_id)],
        raw_sidecar,
    )?;
    require(
        compression
            .rows
            .iter()
            .all(|row| row.resolved.differing_coefficients > 0),
        "TurboQuant fixture did not demonstrably alter both dense vectors",
    )?;
    let ledger = ledger_evidence(&read_vault)?;
    let wal = wal_evidence(&vault_dir, 0)?;
    require(
        wal.tip_seq == snapshot,
        "prepared WAL tip differs from the reopened vault snapshot",
    )?;
    drop(read_vault);

    let baseline_path = root.join(BASELINE_FILE);
    let expected_anchor = expected_anchor_without_time();
    let report = BaselineReport {
        schema: BASELINE_SCHEMA.to_string(),
        fixture_date: FIXTURE_DATE.to_string(),
        fixture_n: FIXTURE_N,
        cost_claim: "fixed N=2 manual fixture; no production performance claim".to_string(),
        fixture_root: root.display().to_string(),
        calyx_home: home.display().to_string(),
        vault_dir: vault_dir.display().to_string(),
        catalog_path: catalog_path.display().to_string(),
        catalog_sha256: sha256_file(&catalog_path)?,
        vault_name: FIXED_VAULT_NAME.to_string(),
        vault_id: VAULT_ID.to_string(),
        vault_salt_utf8: String::from_utf8(salt)?,
        panel_version: PANEL_VERSION,
        slot_id: TQ35_SLOT,
        text: TEXT_INPUT.to_string(),
        text_cx_id: text_cx_id.to_string(),
        batch_text: BATCH_INPUT.to_string(),
        batch_cx_id: batch_cx_id.to_string(),
        inputs: input_paths,
        batch_metadata: metadata,
        expected_anchor_key_hex: hex(&anchor_key(batch_cx_id, &expected_anchor.kind)),
        expected_anchor_without_observed_at: anchor_without_time_json(&expected_anchor),
        cli_roles: cli_roles(root),
        legacy_rewrite_ledger: ledger_identity(&legacy_rewrite_ledger),
        base,
        compression,
        ledger,
        wal,
        snapshot,
        vault_files: disk_inventory(&vault_dir)?,
    };
    let baseline_sha256 = write_json_durable(&baseline_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "base_record_replay_prepare_success",
            "schema": BASELINE_SCHEMA,
            "fixture_n": FIXTURE_N,
            "fixture_date": FIXTURE_DATE,
            "fixture_root": root,
            "calyx_home": home,
            "vault_dir": vault_dir,
            "vault_name": FIXED_VAULT_NAME,
            "vault_id": VAULT_ID,
            "vault_salt_utf8": report.vault_salt_utf8,
            "panel_version": PANEL_VERSION,
            "slot_id": TQ35_SLOT,
            "text": TEXT_INPUT,
            "text_cx_id": text_cx_id,
            "batch_text": BATCH_INPUT,
            "batch_cx_id": batch_cx_id,
            "input_paths": report.inputs,
            "cli_roles": report.cli_roles,
            "baseline_path": baseline_path,
            "baseline_sha256": baseline_sha256,
            "next_required_mode": "base_record_replay_readback",
        })
    );
    Ok(())
}

pub(super) fn readback(root: &Path) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!(
            "base_record_replay_readback root is absent: {}",
            root.display()
        ),
    )?;
    let baseline_path = root.join(BASELINE_FILE);
    let readback_path = root.join(READBACK_FILE);
    require(
        !readback_path.exists(),
        format!("refusing to overwrite {}", readback_path.display()),
    )?;
    let baseline_bytes = fs::read(&baseline_path)?;
    let baseline_sha256 = sha256_hex(&baseline_bytes);
    let baseline: BaselineReport = serde_json::from_slice(&baseline_bytes)?;
    validate_baseline_contract(root, &baseline)?;
    validate_input_files(&baseline)?;

    let vault_dir = PathBuf::from(&baseline.vault_dir);
    let files_before = disk_inventory(&vault_dir)?;
    let text_cx_id: CxId = baseline.text_cx_id.parse()?;
    let batch_cx_id: CxId = baseline.batch_cx_id.parse()?;
    let final_raw_sidecar = raw_sidecar_evidence(
        &vault_dir,
        &[(TEXT_ROLE, text_cx_id), (BATCH_ROLE, batch_cx_id)],
    )?;
    require(
        final_raw_sidecar
            == (
                baseline.compression.recovery_raw_sidecar_rows,
                baseline.compression.recovery_raw_sidecar_sha256.clone(),
            ),
        "final recovery-only raw sidecar differs from the independent baseline audit",
    )?;
    let vault = open_replay_read_vault(&vault_dir)?;
    let snapshot = vault.latest_seq();
    let loaded = load_vault_panel_state(&vault_dir)?;
    require(
        loaded.panel.version == PANEL_VERSION && loaded.registry_snapshot.is_some(),
        "readback Panel/Registry state is absent or changed",
    )?;
    require(
        vault.cx_id_for_input(TEXT_INPUT.as_bytes(), PANEL_VERSION) == text_cx_id
            && vault.cx_id_for_input(BATCH_INPUT.as_bytes(), PANEL_VERSION) == batch_cx_id
            && text_cx_id != batch_cx_id,
        "final-process Cx derivation from fixed bytes/CLI salt/panel differs from baseline",
    )?;
    require_exact_base_roster(&vault, snapshot, &[text_cx_id, batch_cx_id])?;
    let baseline_text = baseline_base(&baseline, TEXT_ROLE)?;
    let baseline_batch = baseline_base(&baseline, BATCH_ROLE)?;
    require(
        baseline_text.ungrounded
            && baseline_batch.ungrounded
            && baseline_text.anchors == 0
            && baseline_batch.anchors == 0,
        "baseline Base rows do not record the exact pre-anchor ungrounded state",
    )?;
    let legacy_rewrite_entry = decode_ledger_row(&vault, baseline.legacy_rewrite_ledger.seq)?;
    let expected_legacy_rewrite_payload = json!({
        "mode": "issue-1138-base-record-legacy-wire-rewrite",
        "cx_id": text_cx_id,
        "wire_variant": "legacy_no_metadata_tail",
        "base_sha256": baseline_text.value.sha256.as_str(),
    });
    require(
        hex(&legacy_rewrite_entry.entry_hash) == baseline.legacy_rewrite_ledger.hash
            && legacy_rewrite_entry.kind == EntryKind::Migrate
            && legacy_rewrite_entry.subject == SubjectId::Cx(text_cx_id)
            && legacy_rewrite_entry.actor == ActorId::Service("issue-1138-manual-fsv".to_string())
            && serde_json::from_slice::<Value>(&legacy_rewrite_entry.payload)?
                == expected_legacy_rewrite_payload,
        "final baseline prefix does not retain the exact ledger-bound legacy Base rewrite",
    )?;
    let text_base = base_evidence(&vault, snapshot, TEXT_ROLE, TEXT_INPUT, text_cx_id)?;
    let batch_base = base_evidence(&vault, snapshot, BATCH_ROLE, BATCH_INPUT, batch_cx_id)?;

    require(
        text_base.value == baseline_text.value
            && text_base.slot_hashes == baseline_text.slot_hashes
            && text_base.non_anchor_identity == baseline_text.non_anchor_identity
            && text_base.anchors == 0
            && text_base.ungrounded
            && text_base.metadata.is_empty()
            && text_base.wire_variant == "legacy_no_metadata_tail",
        "text replay did not preserve its exact legacy empty-metadata Base bytes",
    )?;
    require(
        batch_base.value != baseline_batch.value
            && batch_base.slot_hashes == baseline_batch.slot_hashes
            && batch_base.non_anchor_identity == baseline_batch.non_anchor_identity
            && batch_base.provenance == baseline_batch.provenance
            && batch_base.metadata == baseline.batch_metadata
            && !batch_base.ungrounded
            && batch_base.anchors == 1,
        "batch replay changed sealed slot/non-anchor identity or omitted its one Base anchor",
    )?;

    let anchor_rows = vault.scan_cf_at(snapshot, ColumnFamily::Anchors)?;
    require(
        anchor_rows.len() == 1,
        "final Anchors CF does not contain exactly one row",
    )?;
    let (anchor_key_bytes, anchor_bytes) = &anchor_rows[0];
    require(
        hex(anchor_key_bytes) == baseline.expected_anchor_key_hex,
        "final Anchors key differs from the fixed batch label:test key",
    )?;
    let anchor = encode::decode_anchor(anchor_bytes)?;
    require(
        anchor_without_time_json(&anchor) == baseline.expected_anchor_without_observed_at
            && anchor.observed_at > 0,
        "final anchor kind/value/source/confidence differs or has no observed timestamp",
    )?;
    let batch_record =
        BaseRecord::decode_for_key(batch_cx_id, &decode_hex(&batch_base.value.hex)?)?;
    require(
        batch_record.constellation().anchors == vec![anchor.clone()],
        "Base anchor and Anchors CF value differ",
    )?;
    let text_anchor_range = anchor_prefix_range(text_cx_id);
    require(
        vault
            .scan_cf_range_at(snapshot, ColumnFamily::Anchors, &text_anchor_range)?
            .is_empty(),
        "text replay row unexpectedly gained an anchor",
    )?;

    let compression = compression_evidence(
        &vault,
        &loaded,
        snapshot,
        &[(TEXT_ROLE, text_cx_id), (BATCH_ROLE, batch_cx_id)],
        final_raw_sidecar,
    )?;
    require(
        compression == baseline.compression,
        "manifest/proof/primary/resolved compressed state differs from baseline",
    )?;

    let ledger = ledger_evidence(&vault)?;
    require(
        ledger.rows.len() == baseline.ledger.rows.len() + 5
            && ledger.rows[..baseline.ledger.rows.len()] == baseline.ledger.rows,
        "final Ledger does not preserve its exact baseline prefix plus five CLI entries",
    )?;
    let ledger_suffix = validate_ledger_suffix(
        &vault,
        &ledger,
        baseline.ledger.rows.len(),
        text_cx_id,
        batch_cx_id,
    )?;
    let batch_sessions = validate_batch_sessions(&vault_dir, &baseline)?;

    let wal = wal_evidence(&vault_dir, 0)?;
    require(
        wal.tip_seq == snapshot
            && wal.records.len() == baseline.wal.records.len() + 5
            && wal.records[..baseline.wal.records.len()] == baseline.wal.records,
        "final WAL does not preserve its exact logical baseline prefix plus five commits",
    )?;
    let wal_suffix = wal.records[baseline.wal.records.len()..].to_vec();
    validate_wal_suffix(
        &wal_suffix,
        baseline.wal.tip_seq,
        &ledger_suffix,
        &batch_base,
        anchor_key_bytes,
        anchor_bytes,
    )?;
    let base_anchor_writes = wal_suffix
        .iter()
        .flat_map(|record| &record.rows)
        .filter(|row| {
            row.column_family == ColumnFamily::Base.name()
                || row.column_family == ColumnFamily::Anchors.name()
        })
        .count();
    require(
        base_anchor_writes == 2,
        "repeat or mismatch added an unexpected Base/Anchors WAL write",
    )?;
    drop(vault);
    let files_after = disk_inventory(&vault_dir)?;
    require(
        files_before == files_after,
        "independent read-only Base-record readback changed the vault files",
    )?;

    let report = ReadbackReport {
        schema: READBACK_SCHEMA.to_string(),
        fixture_date: FIXTURE_DATE.to_string(),
        fixture_n: FIXTURE_N,
        fixture_root: root.display().to_string(),
        baseline_path: baseline_path.display().to_string(),
        baseline_sha256: baseline_sha256.clone(),
        snapshot,
        text_base,
        batch_base,
        anchors_rows: anchor_rows
            .iter()
            .map(|(key, value)| WalRowEvidence {
                column_family: ColumnFamily::Anchors.name().to_string(),
                key_hex: hex(key),
                value_sha256: sha256_hex(value),
                value_bytes: value.len(),
            })
            .collect(),
        anchor: json!({
            "kind_value_source_confidence": anchor_without_time_json(&anchor),
            "observed_at": anchor.observed_at,
            "value": value_identity(anchor_bytes),
        }),
        compression,
        ledger,
        ledger_suffix,
        batch_sessions,
        wal,
        wal_suffix,
        selected_column_families: serving_selected_cf_names(),
        raw_sidecar_selected_for_serving: false,
        exact_base_anchor_writes_in_suffix: base_anchor_writes,
        text_base_byte_identical: true,
        batch_non_anchor_identity_unchanged: true,
        batch_slot_hashes_unchanged: true,
        compression_bytes_unchanged: true,
        ledger_prefix_byte_identical: true,
        exact_five_commit_suffix: true,
        mismatch_added_no_commit: true,
        disk_unchanged_during_readback: true,
        vault_files_before: files_before,
        vault_files_after: files_after,
    };
    let readback_sha256 = write_json_durable(&readback_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "base_record_replay_readback_success",
            "schema": READBACK_SCHEMA,
            "fixture_n": FIXTURE_N,
            "fixture_date": FIXTURE_DATE,
            "fixture_root": root,
            "vault_name": baseline.vault_name,
            "vault_id": baseline.vault_id,
            "slot_id": baseline.slot_id,
            "text": baseline.text,
            "text_cx_id": baseline.text_cx_id,
            "batch_text": baseline.batch_text,
            "batch_cx_id": baseline.batch_cx_id,
            "baseline_path": baseline_path,
            "baseline_sha256": baseline_sha256,
            "readback_path": readback_path,
            "readback_sha256": readback_sha256,
            "final_snapshot_and_wal_tip": snapshot,
            "ledger_rows": report.ledger.rows.len(),
            "wal_suffix_commits": report.wal_suffix.len(),
            "selected_column_families": report.selected_column_families,
            "raw_sidecar_selected_for_serving": false,
            "text_base_byte_identical": true,
            "batch_slot_hashes_and_non_anchor_identity_unchanged": true,
            "exactly_one_label_test_anchor": true,
            "repeat_and_mismatch_added_no_base_or_anchor_write": true,
            "compressed_serving_vectors_verified_without_raw_sidecar": true,
        })
    );
    Ok(())
}

fn fixture_salt() -> Vec<u8> {
    format!("calyx-cli-vault:{VAULT_ID}:{FIXED_VAULT_NAME}").into_bytes()
}

fn fixture_vector(role: &str) -> Vec<f32> {
    (0..DIM)
        .map(|index| match role {
            TEXT_ROLE => {
                let centered = ((index * 17 + 3) % 29) as f32 - 14.0;
                centered / 7.0 + index as f32 * 0.003_125
            }
            BATCH_ROLE => {
                let centered = ((index * 17 + 3) % 29) as f32 - 14.0;
                -(centered / 7.0 + index as f32 * 0.003_125)
            }
            _ => unreachable!("fixed fixture role"),
        })
        .collect()
}

fn fixture_input(text: &str, values: Vec<f32>, metadata: BTreeMap<String, String>) -> IngestInput {
    let mut input = IngestInput::new(text.as_bytes(), PANEL_VERSION, Modality::Text).with_slot(
        SlotId::new(TQ35_SLOT),
        SlotVector::Dense {
            dim: DIM,
            data: values,
        },
    );
    input.metadata = metadata;
    input
}

fn batch_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "source_dataset".to_string(),
            "astrolabe-issue-1138-base-record-fsv".to_string(),
        ),
        (
            "source_sha256".to_string(),
            sha256_hex(BATCH_INPUT.as_bytes()),
        ),
        ("license".to_string(), "CC0-1.0".to_string()),
        (
            "retrieval_ts".to_string(),
            "2026-08-17T00:00:00Z".to_string(),
        ),
        (
            "source_url".to_string(),
            "https://example.invalid/astrolabe/issue-1138".to_string(),
        ),
    ])
}

fn rewrite_empty_metadata_row_as_legacy(
    vault: &AsterVault<FixedClock>,
    cx_id: CxId,
) -> AnyResult<LedgerRef> {
    let snapshot = vault.latest_seq();
    let key = base_key(cx_id);
    let mut bytes = required_row(vault, snapshot, ColumnFamily::Base, &key, "text Base row")?;
    let current = BaseRecord::decode_for_key(cx_id, &bytes)?;
    require(
        current.constellation().metadata.is_empty()
            && bytes.len() >= 4
            && bytes[bytes.len() - 4..] == [0_u8; 4],
        "fresh empty-metadata Base row does not carry the current zero-count tail",
    )?;
    bytes.truncate(bytes.len() - 4);
    let legacy = BaseRecord::decode_for_key(cx_id, &bytes)?;
    require(
        legacy.encode()? == bytes
            && legacy.slot_hashes() == current.slot_hashes()
            && legacy.constellation() == current.constellation(),
        "tail-less empty-metadata Base row is not the exact legacy variant",
    )?;
    let payload = serde_json::to_vec(&json!({
        "mode": "issue-1138-base-record-legacy-wire-rewrite",
        "cx_id": cx_id,
        "wire_variant": "legacy_no_metadata_tail",
        "base_sha256": sha256_hex(&bytes),
    }))?;
    let (committed, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        snapshot,
        [(ColumnFamily::Base, key, bytes.clone())],
        EntryKind::Migrate,
        SubjectId::Cx(cx_id),
        payload,
        ActorId::Service("issue-1138-manual-fsv".to_string()),
    )?;
    require(
        committed == snapshot + 1
            && required_row(
                vault,
                committed,
                ColumnFamily::Base,
                &base_key(cx_id),
                "legacy text Base row",
            )? == bytes,
        "legacy Base row commit/readback differs",
    )?;
    let ledger_entry = decode_ledger_row(vault, ledger_ref.seq)?;
    require(
        ledger_entry.entry_hash == ledger_ref.hash
            && ledger_entry.kind == EntryKind::Migrate
            && ledger_entry.subject == SubjectId::Cx(cx_id),
        "legacy Base rewrite Ledger binding differs on immediate readback",
    )?;
    vault.flush_with_report()?;
    Ok(ledger_ref)
}

fn write_replay_inputs(
    root: &Path,
    metadata: &BTreeMap<String, String>,
) -> AnyResult<BTreeMap<String, InputFileEvidence>> {
    let text_path = root.join(TEXT_FILE);
    write_bytes_durable(&text_path, TEXT_INPUT.as_bytes())?;

    let no_anchor_path = root.join(BATCH_NO_ANCHOR_FILE);
    let no_anchor = json_line(&json!({
        "text": BATCH_INPUT,
        "metadata": metadata,
        "anchors": [],
    }))?;
    write_bytes_durable(&no_anchor_path, &no_anchor)?;

    let anchor_path = root.join(BATCH_ANCHOR_FILE);
    let anchored = json_line(&json!({
        "text": BATCH_INPUT,
        "metadata": metadata,
        "anchors": [{
            "kind": "label:test",
            "value": ANCHOR_VALUE,
            "source": ANCHOR_SOURCE,
            "confidence": 1.0,
        }],
    }))?;
    write_bytes_durable(&anchor_path, &anchored)?;

    let mismatch_path = root.join(BATCH_MISMATCH_FILE);
    let mut mismatch_metadata = metadata.clone();
    mismatch_metadata.insert("license".to_string(), "MIT".to_string());
    let mismatch = json_line(&json!({
        "text": BATCH_INPUT,
        "metadata": mismatch_metadata,
        "anchors": [{
            "kind": "label:test",
            "value": ANCHOR_VALUE,
            "source": ANCHOR_SOURCE,
            "confidence": 1.0,
        }],
    }))?;
    write_bytes_durable(&mismatch_path, &mismatch)?;

    Ok(BTreeMap::from([
        ("text".to_string(), input_file_evidence(&text_path)?),
        (
            "batch_no_anchor".to_string(),
            input_file_evidence(&no_anchor_path)?,
        ),
        (
            "batch_anchor".to_string(),
            input_file_evidence(&anchor_path)?,
        ),
        (
            "batch_mismatch".to_string(),
            input_file_evidence(&mismatch_path)?,
        ),
    ]))
}

fn cli_roles(root: &Path) -> Vec<CliRole> {
    let environment = BTreeMap::from([(
        "CALYX_HOME".to_string(),
        root.join("calyx-home").display().to_string(),
    )]);
    vec![
        CliRole {
            role: "text_existing_replay".to_string(),
            environment: environment.clone(),
            arguments: vec![
                "ingest".to_string(),
                FIXED_VAULT_NAME.to_string(),
                "--text".to_string(),
                TEXT_INPUT.to_string(),
                "--output".to_string(),
                "rows".to_string(),
            ],
            expected_exit: 0,
            expected_effect: "one logical Ledger-only idempotent occurrence plus its mandatory TimeIndex row; exact text Base unchanged"
                .to_string(),
        },
        batch_cli_role(
            "batch_existing_no_anchor",
            root.join(BATCH_NO_ANCHOR_FILE),
            "issue1138-no-anchor",
            0,
            "one logical Ledger-only occurrence plus its mandatory TimeIndex row; no Base or Anchors write",
            environment.clone(),
        ),
        batch_cli_role(
            "batch_add_label_test_anchor",
            root.join(BATCH_ANCHOR_FILE),
            "issue1138-anchor-first",
            0,
            "one atomic Base+Anchors+marker-Ledger+TimeIndex commit followed by one occurrence Ledger+TimeIndex commit",
            environment.clone(),
        ),
        batch_cli_role(
            "batch_repeat_label_test_anchor",
            root.join(BATCH_ANCHOR_FILE),
            "issue1138-anchor-repeat",
            0,
            "one logical Ledger-only occurrence plus its mandatory TimeIndex row; repeated anchor adds no Base or Anchors write",
            environment.clone(),
        ),
        batch_cli_role(
            "batch_metadata_mismatch",
            root.join(BATCH_MISMATCH_FILE),
            "issue1138-metadata-mismatch",
            2,
            "usage refusal before any vault commit",
            environment,
        ),
    ]
}

fn batch_cli_role(
    role: &str,
    path: PathBuf,
    session_id: &str,
    expected_exit: i32,
    expected_effect: &str,
    environment: BTreeMap<String, String>,
) -> CliRole {
    CliRole {
        role: role.to_string(),
        environment,
        arguments: vec![
            "ingest".to_string(),
            FIXED_VAULT_NAME.to_string(),
            "--batch".to_string(),
            path.display().to_string(),
            "--output".to_string(),
            "summary".to_string(),
            "--session-id".to_string(),
            session_id.to_string(),
        ],
        expected_exit,
        expected_effect: expected_effect.to_string(),
    }
}

fn open_replay_read_vault(dir: &Path) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    let vault_id: VaultId = VAULT_ID.parse()?;
    Ok(Arc::new(AsterVault::open(
        dir,
        vault_id,
        fixture_salt(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(serving_selected_cfs()),
            ..VaultOptions::default()
        },
    )?))
}

fn serving_selected_cfs() -> Vec<ColumnFamily> {
    vec![
        ColumnFamily::Base,
        ColumnFamily::Compression,
        ColumnFamily::slot(SlotId::new(TQ35_SLOT)),
        ColumnFamily::Anchors,
        ColumnFamily::Ledger,
    ]
}

fn serving_selected_cf_names() -> Vec<String> {
    serving_selected_cfs()
        .into_iter()
        .map(|cf| cf.name().to_string())
        .collect()
}

fn raw_sidecar_evidence(vault_dir: &Path, roles: &[(&str, CxId)]) -> AnyResult<(usize, String)> {
    require(
        roles.len() == FIXTURE_N,
        "raw-sidecar audit requires exactly the two fixed fixture roles",
    )?;
    let raw = AsterVault::open(
        vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        fixture_salt(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![ColumnFamily::slot_raw(SlotId::new(TQ35_SLOT))]),
            ..VaultOptions::default()
        },
    )?;
    let rows = raw.scan_cf_at(
        raw.latest_seq(),
        ColumnFamily::slot_raw(SlotId::new(TQ35_SLOT)),
    )?;
    require(
        rows.len() == FIXTURE_N,
        "compression preparation did not retain exactly two recovery raw sidecars",
    )?;
    let observed_ids = rows
        .iter()
        .map(|(key, _)| cx_id_from_key(key))
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let expected_ids = roles
        .iter()
        .map(|(_, cx_id)| *cx_id)
        .collect::<BTreeSet<_>>();
    require(
        observed_ids == expected_ids,
        "recovery raw sidecar keys differ from the fixed text/batch CxIds",
    )?;
    for (role, cx_id) in roles {
        let value = rows
            .iter()
            .find(|(key, _)| key == &slot_key(*cx_id))
            .map(|(_, value)| value)
            .ok_or_else(|| format!("recovery raw sidecar is absent for {role}"))?;
        let expected = encode::encode_slot_vector(&SlotVector::Dense {
            dim: DIM,
            data: fixture_vector(role),
        })?;
        require(
            value.as_slice() == expected.as_slice(),
            format!("recovery raw sidecar for {role} is not the byte-exact source vector"),
        )?;
    }
    Ok((rows.len(), rows_sha256(&rows)))
}

fn base_evidence<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    role: &str,
    text: &str,
    cx_id: CxId,
) -> AnyResult<BaseEvidence> {
    let bytes = required_row(vault, snapshot, ColumnFamily::Base, &base_key(cx_id), role)?;
    let record = BaseRecord::decode_for_key(cx_id, &bytes)?;
    require(
        record.vault_id() == VAULT_ID.parse::<VaultId>()? && record.encode()? == bytes,
        format!("{role} Base row has wrong vault identity or noncanonical bytes"),
    )?;
    let wire_variant = match role {
        TEXT_ROLE => {
            require(
                record.constellation().metadata.is_empty(),
                "text Base row labeled legacy has nonempty metadata",
            )?;
            let mut metadata_tail = bytes.clone();
            metadata_tail.extend_from_slice(&0_u32.to_be_bytes());
            let current = BaseRecord::decode_for_key(cx_id, &metadata_tail)?;
            require(
                current.encode()? == metadata_tail
                    && current.constellation() == record.constellation()
                    && current.slot_hashes() == record.slot_hashes(),
                "text Base bytes are not the exact tail-less legacy form of the current empty-metadata row",
            )?;
            "legacy_no_metadata_tail"
        }
        BATCH_ROLE => {
            require(
                !record.constellation().metadata.is_empty(),
                "batch Base row labeled current has empty metadata",
            )?;
            "metadata_tail"
        }
        other => return Err(format!("unknown Base evidence role {other}").into()),
    };
    let slot_hashes = slot_hash_evidence(record.slot_hashes());
    require(
        slot_hashes.len() == 1 && slot_hashes.contains_key(&TQ35_SLOT),
        format!("{role} Base row does not seal exactly slot81"),
    )?;
    let non_anchor_identity = non_anchor_identity(&record);
    let non_anchor_identity_sha256 = sha256_hex(&serde_json::to_vec(&non_anchor_identity)?);
    Ok(BaseEvidence {
        role: role.to_string(),
        text: text.to_string(),
        cx_id: cx_id.to_string(),
        wire_variant: wire_variant.to_string(),
        value: value_identity(&bytes),
        canonical_reencode_equal: true,
        slot_hashes,
        non_anchor_identity,
        non_anchor_identity_sha256,
        metadata: record.constellation().metadata.clone(),
        ungrounded: record.constellation().flags.ungrounded,
        anchors: record.constellation().anchors.len(),
        provenance: ledger_identity(&record.constellation().provenance),
    })
}

fn require_exact_base_roster<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    expected: &[CxId],
) -> AnyResult<()> {
    let rows = vault.scan_cf_at(snapshot, ColumnFamily::Base)?;
    let observed = rows
        .iter()
        .map(|(key, _)| cx_id_from_key(key))
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    require(
        rows.len() == FIXTURE_N && observed == expected,
        "Base CF does not contain exactly the two fixed fixture CxIds",
    )
}

fn slot_hash_evidence(hashes: &BTreeMap<SlotId, [u8; 32]>) -> BTreeMap<u16, String> {
    hashes
        .iter()
        .map(|(slot, hash)| (slot.get(), hex(hash)))
        .collect()
}

fn non_anchor_identity(record: &BaseRecord) -> NonAnchorIdentity {
    let cx = record.constellation();
    NonAnchorIdentity {
        cx_id: cx.cx_id.to_string(),
        vault_id: cx.vault_id.to_string(),
        panel_version: cx.panel_version,
        created_at: cx.created_at,
        input_hash: hex(&cx.input_ref.hash),
        input_pointer: cx.input_ref.pointer.clone(),
        input_redacted: cx.input_ref.redacted,
        modality: cx.modality.stable_str().to_string(),
        slot_hashes: slot_hash_evidence(record.slot_hashes()),
        scalar_bits: cx
            .scalars
            .iter()
            .map(|(key, value)| (key.clone(), format!("{:016x}", value.to_bits())))
            .collect(),
        metadata: cx.metadata.clone(),
        ungrounded_normalized: false,
        degraded: cx.flags.degraded,
        novel_region: cx.flags.novel_region,
        redacted_input: cx.flags.redacted_input,
        provenance: ledger_identity(&cx.provenance),
    }
}

fn compression_evidence<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    state: &VaultPanelState,
    snapshot: Seq,
    roles: &[(&str, CxId)],
    raw_sidecar: (usize, String),
) -> AnyResult<CompressionEvidence> {
    require(
        roles.len() == FIXTURE_N,
        "compression evidence requires exactly two role rows",
    )?;
    let slot = panel_slot(state, TQ35_SLOT)?;
    require(
        slot.state == SlotState::Active
            && slot.shape == SlotShape::Dense(DIM)
            && slot.quant
                == QuantPolicy::TurboQuant {
                    bits_per_channel_x2: 7,
                },
        "reopened slot81 is not the exact active dense TQ3.5 slot",
    )?;
    let index = state.registry.compressed_slot_index(vault, slot)?;
    let serving_rows = index.read_all_at(snapshot)?;
    let expected_ids = roles
        .iter()
        .map(|(_, cx_id)| *cx_id)
        .collect::<BTreeSet<_>>();
    let serving_ids = serving_rows
        .iter()
        .map(|(cx_id, _)| *cx_id)
        .collect::<BTreeSet<_>>();
    require(
        serving_rows.len() == FIXTURE_N && serving_ids == expected_ids,
        "compressed serving read did not return exactly two rows",
    )?;
    let generation_identity = serde_json::to_value(index.generation_identity_at(snapshot)?)?;
    let manifest_key = compression_manifest_key(slot.slot_id);
    let manifest = required_row(
        vault,
        snapshot,
        ColumnFamily::Compression,
        &manifest_key,
        "slot81 compression manifest",
    )?;
    let primary_rows = vault.scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?;
    let proof_range = compression_membership_proof_prefix_range(slot.slot_id);
    let proof_rows = vault.scan_cf_range_at(snapshot, ColumnFamily::Compression, &proof_range)?;
    require(
        primary_rows.len() == FIXTURE_N && proof_rows.len() == FIXTURE_N,
        "compressed slot81 does not have exactly two primary/proof rows",
    )?;
    let primary_ids = primary_rows
        .iter()
        .map(|(key, _)| cx_id_from_key(key))
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let mut proof_ids = Vec::with_capacity(proof_rows.len());
    for (key, _) in &proof_rows {
        proof_ids.push(
            calyx_aster::cf::parse_compression_membership_proof_key(key)
                .ok_or("malformed compression proof key")?,
        );
    }
    require(
        primary_ids == expected_ids
            && proof_ids.len() == FIXTURE_N
            && proof_ids.iter().all(|(proof_slot, cx_id)| {
                *proof_slot == slot.slot_id && expected_ids.contains(cx_id)
            }),
        "compressed primary/proof Cx roster differs from the two fixture rows",
    )?;

    let mut rows = Vec::with_capacity(roles.len());
    for (role, cx_id) in roles {
        let primary_key = slot_key(*cx_id);
        let primary = required_row(
            vault,
            snapshot,
            ColumnFamily::slot(slot.slot_id),
            &primary_key,
            "compressed primary",
        )?;
        require(
            primary.first().copied() == Some(COMPRESSED_SLOT_TAG),
            "slot81 primary row is not a compressed registry envelope",
        )?;
        let proof_key = compression_membership_proof_key(slot.slot_id, *cx_id);
        let proof = required_row(
            vault,
            snapshot,
            ColumnFamily::Compression,
            &proof_key,
            "compression membership proof",
        )?;
        let vector = state
            .resolve_slot_vector_at(vault, snapshot, *cx_id, slot.slot_id)?
            .ok_or("compressed resolver returned no vector")?;
        let resolved = resolved_vector_evidence(vault, snapshot, *role, *cx_id, vector)?;
        rows.push(CompressedRowEvidence {
            role: (*role).to_string(),
            cx_id: cx_id.to_string(),
            primary_key_hex: hex(&primary_key),
            primary: value_identity(&primary),
            membership_key_hex: hex(&proof_key),
            membership_proof: value_identity(&proof),
            resolved,
        });
    }
    Ok(CompressionEvidence {
        slot_id: TQ35_SLOT,
        stored_codec: "turboquant_bits3p5".to_string(),
        manifest_key_hex: hex(&manifest_key),
        manifest: value_identity(&manifest),
        generation_identity,
        rows,
        recovery_raw_sidecar_rows: raw_sidecar.0,
        recovery_raw_sidecar_sha256: raw_sidecar.1,
        serving_selected_column_families: serving_selected_cf_names(),
        raw_sidecar_selected_for_serving: false,
    })
}

fn resolved_vector_evidence<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    role: &str,
    cx_id: CxId,
    vector: SlotVector,
) -> AnyResult<ResolvedVectorEvidence> {
    let SlotVector::Dense { dim, data } = vector else {
        return Err(format!("compressed {role} vector is not dense").into());
    };
    require(
        dim == DIM && data.len() == DIM as usize,
        format!("compressed {role} vector has wrong dimension"),
    )?;
    let original = fixture_vector(role);
    let original_slot = SlotVector::Dense {
        dim: DIM,
        data: original.clone(),
    };
    let encoded_original = encode::encode_slot_vector(&original_slot)?;
    let expected_slot_hash = *blake3::hash(&encoded_original).as_bytes();
    let original_slot_blake3 = hex(&expected_slot_hash);
    let base = BaseRecord::decode_for_key(
        cx_id,
        &required_row(
            vault,
            snapshot,
            ColumnFamily::Base,
            &base_key(cx_id),
            "resolved-vector Base",
        )?,
    )?;
    require(
        base.slot_hashes().get(&SlotId::new(TQ35_SLOT)) == Some(&expected_slot_hash),
        format!("{role} Base slot hash does not bind the fixed raw vector"),
    )?;
    let original_bits = original
        .iter()
        .map(|value| format!("{:08x}", value.to_bits()))
        .collect::<Vec<_>>();
    let resolved_bits = data
        .iter()
        .map(|value| format!("{:08x}", value.to_bits()))
        .collect::<Vec<_>>();
    let differing_coefficients = original_bits
        .iter()
        .zip(&resolved_bits)
        .filter(|(left, right)| left != right)
        .count();
    Ok(ResolvedVectorEvidence {
        cx_id: cx_id.to_string(),
        slot_id: TQ35_SLOT,
        dim,
        original_f32_bits: original_bits,
        resolved_f32_bits: resolved_bits,
        original_slot_blake3,
        differing_coefficients,
        representation: "manifest_authenticated_turboquant_primary".to_string(),
    })
}

fn cx_id_from_key(key: &[u8]) -> AnyResult<CxId> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| format!("Cx key has {} bytes instead of 16", key.len()))?;
    Ok(CxId::from_bytes(bytes))
}

fn ledger_evidence<C: calyx_core::Clock>(vault: &AsterVault<C>) -> AnyResult<LedgerEvidence> {
    let store = vault.retained_read_only_ledger_store()?;
    let rows = store.scan()?;
    let chain = verify_chain(&store, 0..rows.len() as u64)?;
    require(
        matches!(chain, VerifyResult::Intact { count } if count == rows.len() as u64),
        format!("physical Ledger chain is not intact: {chain:?}"),
    )?;
    let head = store
        .head_anchor()?
        .ok_or("physical Ledger has no external head anchor")?;
    require(
        head.height == rows.len() as u64
            && rows
                .last()
                .map(|row| decode_ledger_entry(&row.bytes))
                .transpose()?
                .is_some_and(|entry| entry.entry_hash == head.tip_hash),
        "physical Ledger head does not bind the exact final row",
    )?;
    let evidence = LedgerEvidence {
        rows: rows
            .iter()
            .map(|row| LedgerRowEvidence {
                seq: row.seq,
                value: value_identity(&row.bytes),
            })
            .collect(),
        rows_sha256: ledger_rows_sha256(&rows),
        chain: format!("{chain:?}"),
        head_height: head.height,
        head_tip_hash: hex(&head.tip_hash),
    };
    Ok(evidence)
}

fn wal_evidence(vault_dir: &Path, replay_floor: u64) -> AnyResult<WalEvidence> {
    let wal_dir = vault_dir.join("wal");
    let replay = replay_dir_read_only_after(&wal_dir, replay_floor)?;
    require(
        replay.torn_tail.is_none(),
        "read-only WAL replay reported a torn tail",
    )?;
    let mut records = Vec::with_capacity(replay.records.len());
    for record in replay.records {
        let rows = decode_write_batch(&record.payload)?;
        let time_index_millis = validate_write_batch_time_index(record.seq, &rows)?;
        let segment_relative_path = record
            .segment_path
            .strip_prefix(vault_dir)?
            .to_string_lossy()
            .replace('\\', "/");
        records.push(WalRecordEvidence {
            seq: record.seq,
            time_index_millis,
            segment_relative_path,
            start_offset: record.start_offset,
            end_offset: record.end_offset,
            payload: value_identity(&record.payload),
            rows: rows.iter().map(wal_row_evidence).collect(),
        });
    }
    require(
        records
            .windows(2)
            .all(|pair| pair[0].seq.checked_add(1) == Some(pair[1].seq)),
        "WAL logical records are not contiguous",
    )?;
    validate_physical_time_index(vault_dir, &records)?;
    let segment_files = disk_inventory(vault_dir)?
        .into_iter()
        .filter(|file| {
            file.relative_path.starts_with("wal/") && file.relative_path.ends_with(".wal")
        })
        .collect::<Vec<_>>();
    require(
        !segment_files.is_empty(),
        "WAL has no canonical segment file",
    )?;
    let segment_files_sha256 = sha256_hex(&serde_json::to_vec(&segment_files)?);
    Ok(WalEvidence {
        tip_seq: records.last().map_or(replay_floor, |record| record.seq),
        records,
        segment_files,
        segment_files_sha256,
    })
}

fn wal_row_evidence(row: &WriteRow) -> WalRowEvidence {
    WalRowEvidence {
        column_family: row.cf.name().to_string(),
        key_hex: hex(&row.key),
        value_sha256: sha256_hex(&row.value),
        value_bytes: row.value.len(),
    }
}

fn validate_write_batch_time_index(seq: Seq, rows: &[WriteRow]) -> AnyResult<u64> {
    let (time_index, logical_rows) = rows
        .split_last()
        .ok_or("nonempty WAL commit has no time-index row")?;
    require(
        time_index.cf == ColumnFamily::TimeIndex
            && logical_rows
                .iter()
                .all(|row| row.cf != ColumnFamily::TimeIndex)
            && time_index.key.len() == 16
            && time_index.value.as_slice() == &[0_u8],
        format!("WAL commit {seq} does not end in exactly one canonical time-index row"),
    )?;
    let millis = u64::from_be_bytes(time_index.key[..8].try_into()?);
    let indexed_seq = u64::from_be_bytes(time_index.key[8..].try_into()?);
    require(
        millis > 0 && indexed_seq == seq,
        format!("WAL commit {seq} time-index key has wrong millis/sequence"),
    )?;
    Ok(millis)
}

fn validate_physical_time_index(vault_dir: &Path, records: &[WalRecordEvidence]) -> AnyResult<()> {
    let vault = AsterVault::open(
        vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        fixture_salt(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![ColumnFamily::TimeIndex]),
            ..VaultOptions::default()
        },
    )?;
    let mut physical = vault.scan_cf_at(vault.latest_seq(), ColumnFamily::TimeIndex)?;
    physical.sort_by(|left, right| left.0.cmp(&right.0));
    let mut expected = records
        .iter()
        .map(|record| {
            (
                time_index_key(record.time_index_millis, record.seq),
                vec![0_u8],
            )
        })
        .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    require(
        physical == expected,
        "physical TimeIndex CF is not the exact one-row-per-WAL-commit roster",
    )
}

fn time_index_key(millis: u64, seq: Seq) -> Vec<u8> {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&millis.to_be_bytes());
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn time_index_wal_row(record: &WalRecordEvidence) -> WalRowEvidence {
    WalRowEvidence {
        column_family: ColumnFamily::TimeIndex.name().to_string(),
        key_hex: hex(&time_index_key(record.time_index_millis, record.seq)),
        value_sha256: sha256_hex(&[0_u8]),
        value_bytes: 1,
    }
}

fn validate_ledger_suffix<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    ledger: &LedgerEvidence,
    prefix_len: usize,
    text_cx_id: CxId,
    batch_cx_id: CxId,
) -> AnyResult<Vec<LedgerSuffixEvidence>> {
    let suffix = &ledger.rows[prefix_len..];
    require(
        suffix.len() == 5,
        "CLI Ledger suffix does not contain exactly five entries",
    )?;
    let expected_subjects = [
        text_cx_id,
        batch_cx_id,
        batch_cx_id,
        batch_cx_id,
        batch_cx_id,
    ];
    let expected_payloads = [
        json!({ "mode": "cli-idempotent-ingest" }),
        batch_occurrence_payload(batch_cx_id),
        json!({ "mode": "cli-anchor", "anchor_kind": "label:test" }),
        batch_occurrence_payload(batch_cx_id),
        batch_occurrence_payload(batch_cx_id),
    ];
    let expected_modes = [
        "cli-idempotent-ingest",
        "cli-idempotent-ingest-batch",
        "cli-anchor",
        "cli-idempotent-ingest-batch",
        "cli-idempotent-ingest-batch",
    ];
    let mut evidence = Vec::with_capacity(5);
    for ordinal in 0..5 {
        let row = &suffix[ordinal];
        let entry = decode_ledger_row(vault, row.seq)?;
        require(
            entry.seq == row.seq
                && entry.verify()
                && entry.kind == EntryKind::Ingest
                && entry.subject == SubjectId::Cx(expected_subjects[ordinal])
                && entry.actor == ActorId::Service("calyx-cli".to_string())
                && serde_json::from_slice::<Value>(&entry.payload)? == expected_payloads[ordinal],
            format!("CLI Ledger suffix entry {ordinal} differs from its exact role"),
        )?;
        evidence.push(LedgerSuffixEvidence {
            ordinal,
            seq: row.seq,
            mode: expected_modes[ordinal].to_string(),
            subject_cx_id: expected_subjects[ordinal].to_string(),
            value: row.value.clone(),
            entry_hash: hex(&entry.entry_hash),
        });
    }
    Ok(evidence)
}

fn batch_occurrence_payload(cx_id: CxId) -> Value {
    let value = cx_id.to_string();
    json!({
        "mode": "cli-idempotent-ingest-batch",
        "count": 1,
        "cx_id": [value.clone()],
        "first_cx_id": value.clone(),
        "last_cx_id": value,
    })
}

fn decode_ledger_row<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    seq: u64,
) -> AnyResult<LedgerEntry> {
    let bytes = required_row(
        vault,
        vault.latest_seq(),
        ColumnFamily::Ledger,
        &ledger_key(seq),
        "Ledger suffix row",
    )?;
    let entry = decode_ledger_entry(&bytes)?;
    require(
        entry.seq == seq && entry.verify(),
        "Ledger suffix row is not canonical",
    )?;
    Ok(entry)
}

#[allow(clippy::too_many_arguments)]
fn validate_wal_suffix(
    suffix: &[WalRecordEvidence],
    baseline_tip: u64,
    ledger_suffix: &[LedgerSuffixEvidence],
    batch_base: &BaseEvidence,
    anchor_key_bytes: &[u8],
    anchor_bytes: &[u8],
) -> AnyResult<()> {
    require(
        suffix.len() == 5 && ledger_suffix.len() == 5,
        "WAL/Ledger role suffixes must both contain five entries",
    )?;
    for (ordinal, record) in suffix.iter().enumerate() {
        require(
            record.seq == baseline_tip + ordinal as u64 + 1,
            format!("WAL suffix record {ordinal} is not the next contiguous commit"),
        )?;
        let expected_ledger = &ledger_suffix[ordinal];
        let expected_ledger_row = WalRowEvidence {
            column_family: ColumnFamily::Ledger.name().to_string(),
            key_hex: hex(&ledger_key(expected_ledger.seq)),
            value_sha256: expected_ledger.value.sha256.clone(),
            value_bytes: expected_ledger.value.bytes,
        };
        let expected_time_index_row = time_index_wal_row(record);
        if ordinal != 2 {
            require(
                record.rows == vec![expected_ledger_row, expected_time_index_row],
                format!(
                    "WAL suffix record {ordinal} is not exact Ledger+TimeIndex state in commit order"
                ),
            )?;
            continue;
        }
        let expected = vec![
            WalRowEvidence {
                column_family: ColumnFamily::Base.name().to_string(),
                key_hex: hex(&base_key(batch_base.cx_id.parse()?)),
                value_sha256: batch_base.value.sha256.clone(),
                value_bytes: batch_base.value.bytes,
            },
            WalRowEvidence {
                column_family: ColumnFamily::Anchors.name().to_string(),
                key_hex: hex(anchor_key_bytes),
                value_sha256: sha256_hex(anchor_bytes),
                value_bytes: anchor_bytes.len(),
            },
            expected_ledger_row,
            expected_time_index_row,
        ];
        require(
            record.rows == expected,
            "anchor-add WAL commit is not exact Base+Anchors+marker-Ledger+TimeIndex state in commit order",
        )?;
    }
    Ok(())
}

fn validate_baseline_contract(root: &Path, baseline: &BaselineReport) -> AnyResult<()> {
    let expected_home = root.join("calyx-home");
    let expected_vault = expected_home.join("vaults").join(VAULT_ID);
    require(
        baseline.schema == BASELINE_SCHEMA
            && baseline.fixture_date == FIXTURE_DATE
            && baseline.fixture_n == FIXTURE_N
            && baseline.fixture_root == root.display().to_string()
            && baseline.calyx_home == expected_home.display().to_string()
            && baseline.vault_dir == expected_vault.display().to_string()
            && baseline.catalog_path
                == expected_home
                    .join("vaults")
                    .join("index.json")
                    .display()
                    .to_string()
            && baseline.vault_name == FIXED_VAULT_NAME
            && baseline.vault_id == VAULT_ID
            && baseline.vault_salt_utf8 == String::from_utf8(fixture_salt())?
            && baseline.panel_version == PANEL_VERSION
            && baseline.slot_id == TQ35_SLOT
            && baseline.text == TEXT_INPUT
            && baseline.batch_text == BATCH_INPUT
            && baseline.base.len() == FIXTURE_N
            && baseline.cli_roles == cli_roles(root)
            && baseline.snapshot == baseline.wal.tip_seq
            && baseline.compression.serving_selected_column_families == serving_selected_cf_names()
            && !baseline.compression.raw_sidecar_selected_for_serving,
        "baseline report does not match the fixed N=2 replay contract",
    )?;
    require(
        sha256_file(Path::new(&baseline.catalog_path))? == baseline.catalog_sha256,
        "CLI vault catalog changed after prepare",
    )?;
    let catalog: Value = serde_json::from_slice(&fs::read(&baseline.catalog_path)?)?;
    require(
        catalog
            == json!({
                "vaults": [{
                    "name": FIXED_VAULT_NAME,
                    "vault_id": VAULT_ID,
                    "path": format!("vaults/{VAULT_ID}"),
                    "panel_template": FIXED_PANEL_TEMPLATE,
                }]
            }),
        "CLI vault catalog rows differ from the exact fixed index entry",
    )?;
    Ok(())
}

fn validate_batch_sessions(
    vault_dir: &Path,
    baseline: &BaselineReport,
) -> AnyResult<BTreeMap<String, Value>> {
    let contracts = [
        (
            "issue1138-no-anchor",
            "complete",
            BATCH_NO_ANCHOR_FILE,
            None,
        ),
        (
            "issue1138-anchor-first",
            "complete",
            BATCH_ANCHOR_FILE,
            None,
        ),
        (
            "issue1138-anchor-repeat",
            "complete",
            BATCH_ANCHOR_FILE,
            None,
        ),
        (
            "issue1138-metadata-mismatch",
            "failed",
            BATCH_MISMATCH_FILE,
            Some("CALYX_CLI_USAGE_ERROR"),
        ),
    ];
    let mut sessions = BTreeMap::new();
    for (session_id, status, input_name, error_code) in contracts {
        let path = vault_dir
            .join("idx")
            .join("ingest")
            .join("runs")
            .join(session_id)
            .join("status.json");
        let bytes = fs::read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let input_path = baseline
            .inputs
            .values()
            .find(|input| {
                Path::new(&input.path)
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy() == input_name)
            })
            .ok_or_else(|| format!("baseline input for session {session_id} is absent"))?;
        let canonical_input = fs::canonicalize(&input_path.path)?;
        require(
            value.get("schema_version").and_then(Value::as_u64) == Some(1)
                && value.get("session_id").and_then(Value::as_str) == Some(session_id)
                && value.get("status").and_then(Value::as_str) == Some(status)
                && value.get("vault_name").and_then(Value::as_str) == Some(FIXED_VAULT_NAME)
                && value.get("vault_id").and_then(Value::as_str) == Some(VAULT_ID)
                && value.get("vault_path").and_then(Value::as_str)
                    == Some(vault_dir.to_string_lossy().as_ref())
                && value.get("batch_path").and_then(Value::as_str)
                    == Some(canonical_input.to_string_lossy().as_ref())
                && value.get("planned_row_count").and_then(Value::as_u64) == Some(1),
            format!("batch session {session_id} identity/status differs"),
        )?;
        match error_code {
            Some(code) => require(
                value
                    .get("error")
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_str)
                    == Some(code)
                    && value
                        .get("error")
                        .and_then(|error| error.get("message"))
                        .and_then(Value::as_str)
                        .is_some_and(|message| {
                            message.contains("changed stored non-anchor identity")
                                && message.contains("metadata")
                        })
                    && value.get("rows_committed").and_then(Value::as_u64) == Some(0),
                "metadata-mismatch session did not persist the exact pre-commit usage refusal",
            )?,
            None => require(
                value.get("error").is_some_and(Value::is_null)
                    && value.get("rows_committed").and_then(Value::as_u64) == Some(1)
                    && value.get("already_idempotent_rows").and_then(Value::as_u64) == Some(1),
                format!("successful batch session {session_id} did not persist exact row counts"),
            )?,
        }
        sessions.insert(session_id.to_string(), value);
    }
    Ok(sessions)
}

fn validate_input_files(baseline: &BaselineReport) -> AnyResult<()> {
    require(
        baseline.inputs.len() == 4,
        "baseline does not name the four fixed replay input files",
    )?;
    for (role, expected) in &baseline.inputs {
        let path = Path::new(&expected.path);
        require(
            path.is_file(),
            format!("fixed replay input {role} is absent: {}", path.display()),
        )?;
        let bytes = fs::read(path)?;
        require(
            value_identity(&bytes) == expected.value,
            format!("fixed replay input {role} bytes changed"),
        )?;
    }
    Ok(())
}

fn baseline_base<'a>(baseline: &'a BaselineReport, role: &str) -> AnyResult<&'a BaseEvidence> {
    let rows = baseline
        .base
        .iter()
        .filter(|row| row.role == role)
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        format!("baseline has {} Base rows for role {role}", rows.len()),
    )?;
    Ok(rows[0])
}

fn expected_anchor_without_time() -> Anchor {
    Anchor {
        kind: AnchorKind::Label(ANCHOR_AXIS.to_string()),
        value: AnchorValue::Enum(ANCHOR_VALUE.to_string()),
        source: ANCHOR_SOURCE.to_string(),
        observed_at: 0,
        confidence: 1.0,
    }
}

fn anchor_without_time_json(anchor: &Anchor) -> Value {
    let kind = match &anchor.kind {
        AnchorKind::Label(axis) => format!("label:{axis}"),
        other => format!("{other:?}"),
    };
    let value = match &anchor.value {
        AnchorValue::Enum(value) => json!({ "enum": value }),
        AnchorValue::Bool(value) => json!({ "bool": value }),
        AnchorValue::Number(value) => json!({ "number_bits": format!("{:016x}", value.to_bits()) }),
        AnchorValue::OneHot(value) => json!({ "one_hot": value }),
        AnchorValue::Text(value) => json!({ "text": value }),
        AnchorValue::Vector(value) => json!({
            "vector_bits": value
                .iter()
                .map(|value| format!("{:08x}", value.to_bits()))
                .collect::<Vec<_>>()
        }),
    };
    json!({
        "kind": kind,
        "value": value,
        "source": anchor.source,
        "confidence_bits": format!("{:08x}", anchor.confidence.to_bits()),
        "observed_at_normalized": 0,
    })
}

fn ledger_identity(value: &LedgerRef) -> LedgerIdentity {
    LedgerIdentity {
        seq: value.seq,
        hash: hex(&value.hash),
    }
}

fn value_identity(bytes: &[u8]) -> ValueIdentity {
    ValueIdentity {
        bytes: bytes.len(),
        sha256: sha256_hex(bytes),
        hex: hex(bytes),
    }
}

fn input_file_evidence(path: &Path) -> AnyResult<InputFileEvidence> {
    Ok(InputFileEvidence {
        path: path.display().to_string(),
        value: value_identity(&fs::read(path)?),
    })
}

fn json_line(value: &Value) -> AnyResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_json_durable<T: Serialize>(path: &Path, value: &T) -> AnyResult<String> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_durable(path, &bytes)?;
    Ok(sha256_hex(&bytes))
}

fn write_bytes_durable(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    require(
        !path.exists(),
        format!("refusing to overwrite {}", path.display()),
    )?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn decode_hex(value: &str) -> AnyResult<Vec<u8>> {
    require(value.len().is_multiple_of(2), "hex value has odd length")?;
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}
