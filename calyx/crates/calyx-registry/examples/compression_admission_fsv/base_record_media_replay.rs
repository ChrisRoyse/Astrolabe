use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;

use calyx_aster::cf::ledger_key;
use calyx_aster::media_artifact::{DerivedMediaArtifactRecord, derived_media_artifact_key};
use calyx_aster::vault::encode::BaseRecord;
use calyx_core::{
    AbsentReason, DERIVED_TEXT_MODE, FixedClock, Input, LEDGER_FIELD_DERIVED_ARTIFACT_ID,
    LEDGER_FIELD_DERIVED_KIND, LEDGER_FIELD_MODE, LEDGER_FIELD_MODEL_ID, LEDGER_FIELD_RUNTIME_ID,
    LEDGER_FIELD_SOURCE_CX_ID, LEDGER_FIELD_SOURCE_INPUT_HASH, LEDGER_FIELD_SOURCE_MODALITY,
    LEDGER_FIELD_SOURCE_SHA256, LEDGER_FIELD_TARGET_CX_ID, LEDGER_FIELD_TARGET_TEXT_SHA256,
    LedgerRef, Lens, MEDIA_DERIVED_TEXT_ENV, METADATA_DERIVED_CONFIDENCE, METADATA_DERIVED_KIND,
    METADATA_DERIVED_LANGUAGE, METADATA_DERIVED_MODEL, METADATA_DERIVED_POINTER,
    METADATA_DERIVED_RUNTIME, METADATA_DERIVED_TEXT_BYTES, METADATA_DERIVED_TEXT_SHA256,
};
use calyx_ledger::{ActorId, SubjectId, decode as decode_ledger_entry};
use calyx_registry::CALYX_COMPRESSION_ADMISSION_REFUSED;
use serde::{Deserialize, Serialize};

const PREPARE_SCHEMA: &str = "astrolabe.base-record-media-replay-prepare.v1";
const BASELINE_SCHEMA: &str = "astrolabe.base-record-media-replay-baseline.v1";
const READBACK_SCHEMA: &str = "astrolabe.base-record-media-replay-readback.v1";
const FIXTURE_DATE: &str = "2026-08-17";
const FIXTURE_N_ROLES: usize = 2;
const MEDIA_DIM: u32 = 16;
const FIXED_CLOCK_MS: u64 = 1_787_100_000_000;
const FIXED_VAULT_NAME: &str = "issue-1138-base-record-media-replay";
const FIXED_PANEL_TEMPLATE: &str = "issue-1138-media-manual-fsv";
const TEXT_SLOT: u16 = 86;
const IMAGE_SLOT: u16 = 87;
const TEXT_ROLE: &str = "derived_text";
const IMAGE_ROLE: &str = "source_image";
const TEXT_LENS_NAME: &str = "issue-1138-media-text-byte-features";
const IMAGE_LENS_NAME: &str = "issue-1138-media-image-byte-features";
const SOURCE_RELATIVE_PATH: &str = "cbm/docs/graph-ui-screenshot.png";
const SOURCE_BYTES: u64 = 1_246_084;
const SOURCE_SHA256: &str = "5a88cd28711417ec12dbf07f2b7e68d2e0ab5ee1b05b76fed6697ded389e9712";
const DERIVED_TEXT: &str = "Astrolabe graph UI screenshot fixture; source sha256 5a88cd28711417ec12dbf07f2b7e68d2e0ab5ee1b05b76fed6697ded389e9712.";
const DERIVED_RUNTIME: &str = "compression-admission-fsv-media-adapter-v1";
const DERIVED_MODEL: &str = "deterministic-sha256-bound-caption-v1";
const DERIVED_LANGUAGE: &str = "en";
const DERIVED_CONFIDENCE: f64 = 1.0;
const DERIVED_KIND: &str = "caption";
const SOURCE_MODALITY: &str = "image";
const PREPARE_FILE: &str = "base-record-media-replay-prepare.json";
const BASELINE_FILE: &str = "base-record-media-replay-baseline.json";
const READBACK_FILE: &str = "base-record-media-replay-readback.json";
const COST_CLAIM: &str =
    "fixed N=2 media/derived-text role fixture; correctness only; no production cost claim";
const ADAPTER_BINDING: &str = "same promoted compression_admission_fsv artifact";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ValueIdentity {
    bytes: usize,
    sha256: String,
    hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerIdentity {
    seq: u64,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CliRole {
    role: String,
    environment: BTreeMap<String, String>,
    runtime_environment_binding: BTreeMap<String, String>,
    arguments: Vec<String>,
    expected_exit: i32,
    expected_reports: Vec<bool>,
    expected_effect: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PrepareReport {
    schema: String,
    fixture_date: String,
    fixture_n_roles: usize,
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
    text_slot: u16,
    image_slot: u16,
    source_path: String,
    source: FileIdentity,
    derived_text: String,
    derived_text_sha256: String,
    source_cx_id: String,
    target_cx_id: String,
    cli_roles: Vec<CliRole>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BaseEvidence {
    role: String,
    cx_id: String,
    modality: String,
    value: ValueIdentity,
    slot_hashes: BTreeMap<u16, String>,
    input_pointer: Option<String>,
    input_hash: String,
    metadata: BTreeMap<String, String>,
    provenance: LedgerIdentity,
}

struct BaseEvidenceRequest<'a> {
    role: &'a str,
    cx_id: CxId,
    slot_id: u16,
    modality: Modality,
    input_bytes: &'a [u8],
    source_vector: &'a [f32],
}

/// One product refusal of a real commissioning attempt against one slot of the
/// shared two-slot media panel. `error` is the complete `Display` form of the
/// `CalyxError` the shipping Registry returned (`"{code}: {message}"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompressionRefusalEvidence {
    slot_id: u16,
    error: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KeyValueEvidence {
    key_hex: String,
    value: ValueIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ArtifactIdentity {
    artifact_id: String,
    source_cx_id: String,
    target_cx_id: String,
    derived_kind: String,
    source_modality: String,
    source_input_hash: String,
    source_sha256: String,
    source_pointer: String,
    target_pointer: String,
    target_text_sha256: String,
    runtime: String,
    model: String,
    language: Option<String>,
    confidence_bits: Option<String>,
    ledger: LedgerIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GraphEvidence {
    rows: Vec<KeyValueEvidence>,
    rows_sha256: String,
    source_artifacts: Vec<ArtifactIdentity>,
    target_artifacts: Vec<ArtifactIdentity>,
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
struct RetainedBlobEvidence {
    source_pointer: String,
    source_path: String,
    source: FileIdentity,
    target_pointer: String,
    target_path: String,
    target: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BaselineReport {
    schema: String,
    fixture_date: String,
    fixture_n_roles: usize,
    cost_claim: String,
    fixture_root: String,
    prepare_path: String,
    prepare_sha256: String,
    vault_dir: String,
    source_cx_id: String,
    target_cx_id: String,
    snapshot: Seq,
    base: Vec<BaseEvidence>,
    compression_refusals: Vec<CompressionRefusalEvidence>,
    refusals_left_base_and_vault_files_unchanged: bool,
    graph: GraphEvidence,
    ledger: LedgerEvidence,
    retained_blobs: RetainedBlobEvidence,
    adapter_outputs: Vec<FileReadback>,
    selected_column_families: Vec<String>,
    raw_sidecar_selected_for_serving: bool,
    vault_files: Vec<FileReadback>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReadbackReport {
    schema: String,
    fixture_date: String,
    fixture_n_roles: usize,
    cost_claim: String,
    fixture_root: String,
    baseline_path: String,
    baseline_sha256: String,
    snapshot: Seq,
    base: Vec<BaseEvidence>,
    compression_refusals: Vec<CompressionRefusalEvidence>,
    graph: GraphEvidence,
    graph_new_rows: Vec<KeyValueEvidence>,
    new_artifact: ArtifactIdentity,
    ledger: LedgerEvidence,
    ledger_new_row: LedgerRowEvidence,
    retained_blobs: RetainedBlobEvidence,
    adapter_outputs: Vec<FileReadback>,
    selected_column_families: Vec<String>,
    raw_sidecar_selected_for_serving: bool,
    base_bytes_and_slot_hashes_unchanged: bool,
    commission_refusals_byte_identical: bool,
    no_compression_state_persisted: bool,
    exact_two_deterministic_adapter_outputs: bool,
    exact_one_artifact_graph_ledger_transition: bool,
    disk_unchanged_during_readback: bool,
    vault_files_before: Vec<FileReadback>,
    vault_files_after: Vec<FileReadback>,
}

#[derive(Serialize)]
struct AdapterOutput<'a> {
    text: &'a str,
    runtime: &'a str,
    model: &'a str,
    language: &'a str,
    confidence: f64,
}

pub(super) fn try_run_adapter(args: &[String]) -> AnyResult<bool> {
    if args.first().map(String::as_str) != Some("--input") {
        return Ok(false);
    }
    run_adapter(args)?;
    Ok(true)
}

fn run_adapter(args: &[String]) -> AnyResult<()> {
    require(
        args.len() == 8 && args.len().is_multiple_of(2),
        "media adapter requires exactly --input/--output/--modality/--kind pairs",
    )?;
    let mut parsed = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            matches!(
                pair[0].as_str(),
                "--input" | "--output" | "--modality" | "--kind"
            ),
            format!("media adapter received unknown flag {}", pair[0]),
        )?;
        require(
            parsed.insert(pair[0].clone(), pair[1].clone()).is_none(),
            format!("media adapter received duplicate flag {}", pair[0]),
        )?;
    }
    let input = PathBuf::from(required_adapter_arg(&parsed, "--input")?);
    let output = PathBuf::from(required_adapter_arg(&parsed, "--output")?);
    let home = std::env::var_os("CALYX_HOME")
        .map(PathBuf::from)
        .ok_or("media adapter requires the shipping CLI CALYX_HOME binding")?;
    let vault_dir = home.join("vaults").join(VAULT_ID);
    let expected_input = vault_dir
        .join("inputs")
        .join("media")
        .join("image")
        .join(format!("{SOURCE_SHA256}.png"));
    let expected_output_parent = vault_dir.join("tmp").join("derived_text");
    require(
        home.is_absolute()
            && input == expected_input
            && output.parent() == Some(expected_output_parent.as_path())
            && output.extension().and_then(|value| value.to_str()) == Some("json")
            && output
                .file_stem()
                .and_then(|value| value.to_str())
                .is_some_and(|value| !value.is_empty()),
        "media adapter input/output paths do not match the exact inherited CLI vault binding",
    )?;
    require(
        required_adapter_arg(&parsed, "--modality")? == SOURCE_MODALITY,
        "media adapter modality must be exactly image",
    )?;
    require(
        required_adapter_arg(&parsed, "--kind")? == DERIVED_KIND,
        "media adapter derived kind must be exactly caption",
    )?;
    let bytes = fs::read(&input)?;
    require(
        bytes.len() as u64 == SOURCE_BYTES
            && sha256_hex(&bytes) == SOURCE_SHA256
            && bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
        format!(
            "media adapter input {} is not the exact retained issue-1138 PNG",
            input.display()
        ),
    )?;
    let encoded = adapter_output_bytes()?;
    write_bytes_durable(&output, &encoded)?;
    println!(
        "{}",
        json!({
            "event": "base_record_media_replay_adapter_success",
            "input": input,
            "input_bytes": bytes.len(),
            "input_sha256": SOURCE_SHA256,
            "output": output,
            "output_sha256": sha256_hex(&encoded),
            "modality": SOURCE_MODALITY,
            "kind": DERIVED_KIND,
        })
    );
    Ok(())
}

pub(super) fn prepare(root: &Path) -> AnyResult<()> {
    require(
        !root.exists(),
        format!(
            "base_record_media_replay_prepare root already exists: {}",
            root.display()
        ),
    )?;
    fs::create_dir_all(root)?;
    let workspace = std::env::current_dir()?;
    let source_path = workspace.join(SOURCE_RELATIVE_PATH);
    let source = file_identity(&source_path)?;
    require(
        source.bytes == SOURCE_BYTES && source.sha256 == SOURCE_SHA256,
        "purpose-built media fixture source bytes differ from the bound PNG",
    )?;

    let home = root.join("calyx-home");
    let vault_id: VaultId = VAULT_ID.parse()?;
    let vault_dir = home.join("vaults").join(vault_id.to_string());
    let salt = fixture_salt();
    let (registry, panel) = fixture_registry_and_panel()?;
    let vault = AsterVault::new_durable_with_clock(
        &vault_dir,
        vault_id,
        salt.clone(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            panel: Some(panel.clone()),
            ..VaultOptions::default()
        },
        FixedClock::new(FIXED_CLOCK_MS),
    )?;
    persist_vault_panel_state(&vault_dir, &panel, &registry)?;
    let state = load_vault_panel_state(&vault_dir)?;
    require_fixture_panel(&state)?;
    let source_cx_id = vault.cx_id_for_input(&fs::read(&source_path)?, PANEL_VERSION);
    let target_cx_id = vault.cx_id_for_input(DERIVED_TEXT.as_bytes(), PANEL_VERSION);
    require(
        source_cx_id != target_cx_id,
        "media source and derived text produced the same CxId",
    )?;
    require(
        vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)?
            .is_empty(),
        "fresh media replay vault unexpectedly contains Base rows",
    )?;
    drop(vault);

    let catalog_path = home.join("vaults").join("index.json");
    let catalog = catalog_value();
    write_json_durable(&catalog_path, &catalog)?;

    let report = PrepareReport {
        schema: PREPARE_SCHEMA.to_string(),
        fixture_date: FIXTURE_DATE.to_string(),
        fixture_n_roles: FIXTURE_N_ROLES,
        cost_claim: COST_CLAIM.to_string(),
        fixture_root: root.display().to_string(),
        calyx_home: home.display().to_string(),
        vault_dir: vault_dir.display().to_string(),
        catalog_path: catalog_path.display().to_string(),
        catalog_sha256: sha256_file(&catalog_path)?,
        vault_name: FIXED_VAULT_NAME.to_string(),
        vault_id: VAULT_ID.to_string(),
        vault_salt_utf8: String::from_utf8(salt)?,
        panel_version: PANEL_VERSION,
        text_slot: TEXT_SLOT,
        image_slot: IMAGE_SLOT,
        source_path: source_path.display().to_string(),
        source,
        derived_text: DERIVED_TEXT.to_string(),
        derived_text_sha256: sha256_hex(DERIVED_TEXT.as_bytes()),
        source_cx_id: source_cx_id.to_string(),
        target_cx_id: target_cx_id.to_string(),
        cli_roles: cli_roles(root, &source_path),
    };
    let prepare_path = root.join(PREPARE_FILE);
    let prepare_sha256 = write_json_durable(&prepare_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "base_record_media_replay_prepare_success",
            "schema": PREPARE_SCHEMA,
            "fixture_n_roles": FIXTURE_N_ROLES,
            "cost_claim": COST_CLAIM,
            "fixture_root": root,
            "calyx_home": home,
            "vault_dir": vault_dir,
            "vault_name": FIXED_VAULT_NAME,
            "source_path": source_path,
            "source_bytes": SOURCE_BYTES,
            "source_sha256": SOURCE_SHA256,
            "source_cx_id": source_cx_id,
            "target_cx_id": target_cx_id,
            "text_slot": TEXT_SLOT,
            "image_slot": IMAGE_SLOT,
            "cli_seed_role": report.cli_roles[0],
            "prepare_path": prepare_path,
            "prepare_sha256": prepare_sha256,
            "next_required_mode": "base_record_media_replay_compress",
        })
    );
    Ok(())
}

pub(super) fn compress(root: &Path) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!(
            "base_record_media_replay_compress root is absent: {}",
            root.display()
        ),
    )?;
    let prepare_path = root.join(PREPARE_FILE);
    let baseline_path = root.join(BASELINE_FILE);
    require(
        !baseline_path.exists(),
        format!("refusing to overwrite {}", baseline_path.display()),
    )?;
    let prepare_bytes = fs::read(&prepare_path)?;
    let prepare_sha256 = sha256_hex(&prepare_bytes);
    let prepare: PrepareReport = serde_json::from_slice(&prepare_bytes)?;
    validate_prepare_contract(root, &prepare)?;
    let source_cx_id: CxId = prepare.source_cx_id.parse()?;
    let target_cx_id: CxId = prepare.target_cx_id.parse()?;
    let source_bytes = fs::read(&prepare.source_path)?;
    let source_vector = expected_vector(IMAGE_ROLE, &source_bytes)?;
    let target_vector = expected_vector(TEXT_ROLE, DERIVED_TEXT.as_bytes())?;
    let vault_dir = PathBuf::from(&prepare.vault_dir);
    let state = load_vault_panel_state(&vault_dir)?;
    require_fixture_panel(&state)?;
    let vault: Arc<AsterVault<SystemClock>> = Arc::new(AsterVault::open(
        &vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        fixture_salt(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            panel: Some(state.panel.clone()),
            ..VaultOptions::default()
        },
    )?);
    require_expected_cx_derivation(&vault, source_cx_id, target_cx_id, &source_bytes)?;
    let seed_snapshot = vault.latest_seq();
    require_exact_base_roster(&vault, seed_snapshot, &[source_cx_id, target_cx_id])?;
    let base_before = base_evidence_set(
        &vault,
        seed_snapshot,
        source_cx_id,
        target_cx_id,
        &source_bytes,
        &source_vector,
        &target_vector,
    )?;
    let seed_graph = graph_evidence(&vault, seed_snapshot, source_cx_id, target_cx_id)?;
    require(
        seed_graph.rows.len() == 3
            && seed_graph.source_artifacts.len() == 1
            && seed_graph.source_artifacts == seed_graph.target_artifacts,
        "shipping media seed did not persist exactly one three-row Graph artifact",
    )?;
    let seed_artifact = seed_graph
        .source_artifacts
        .first()
        .ok_or("shipping media seed artifact is absent")?;
    validate_artifact_contract(
        &vault,
        seed_snapshot,
        seed_artifact,
        source_cx_id,
        target_cx_id,
        &source_bytes,
    )?;

    // Refusal proof. This fixture's ONE panel carries two active slots (86
    // Text, 87 Image), and the shipping ingest measures every panel slot for
    // every Cx, so each slot column necessarily holds one cross-modality
    // `SlotVector::Absent { NotApplicable }` row beside its one dense row. The
    // product's commissioning preflight requires every row of the candidate
    // column to decode Dense before it rewrites the column atomically
    // (`calyx-registry/src/compression/measurement.rs:1736-1741`,
    // `compression/mod.rs:1105-1119`), so commissioning here can only ever be
    // refused. That is fail-closed product design, not a defect: this mode
    // proves the exact refusal per slot plus the byte-immutability of the seed
    // it refused to touch. Compressing only the dense subset of a multimodal
    // column is a deliberate product-capability gap and is out of scope here.
    let files_before_refusals = disk_inventory(&vault_dir)?;
    let compression_refusals = vec![
        require_commission_refusal(
            &vault,
            &state.registry,
            panel_slot(&state, TEXT_SLOT)?,
            TEXT_ROLE,
            &target_vector,
            source_cx_id,
        )?,
        require_commission_refusal(
            &vault,
            &state.registry,
            panel_slot(&state, IMAGE_SLOT)?,
            IMAGE_ROLE,
            &source_vector,
            target_cx_id,
        )?,
    ];
    require(
        vault.latest_seq() == seed_snapshot,
        "refused media commissioning advanced the vault sequence",
    )?;
    require(
        base_evidence_set(
            &vault,
            seed_snapshot,
            source_cx_id,
            target_cx_id,
            &source_bytes,
            &source_vector,
            &target_vector,
        )? == base_before,
        "refused media commissioning changed the shipping seed Base bytes or sealed slot hashes",
    )?;
    require_cross_modality_raw_columns(
        &vault,
        seed_snapshot,
        source_cx_id,
        target_cx_id,
        &source_vector,
        &target_vector,
    )?;
    require(
        disk_inventory(&vault_dir)? == files_before_refusals,
        "refused media commissioning changed vault files",
    )?;
    drop(vault);

    let serving = open_serving_vault(&vault_dir)?;
    let snapshot = serving.latest_seq();
    let reopened_state = load_vault_panel_state(&vault_dir)?;
    require_fixture_panel(&reopened_state)?;
    require_exact_base_roster(&serving, snapshot, &[source_cx_id, target_cx_id])?;
    let base = base_evidence_set(
        &serving,
        snapshot,
        source_cx_id,
        target_cx_id,
        &source_bytes,
        &source_vector,
        &target_vector,
    )?;
    require(
        base == base_before,
        "compression preparation changed the shipping seed Base bytes or sealed slot hashes",
    )?;
    require_cross_modality_raw_columns(
        &serving,
        snapshot,
        source_cx_id,
        target_cx_id,
        &source_vector,
        &target_vector,
    )?;
    let graph = graph_evidence(&serving, snapshot, source_cx_id, target_cx_id)?;
    require(
        graph == seed_graph,
        "compression preparation changed the shipping media seed Graph artifact",
    )?;
    let ledger = ledger_evidence(&serving)?;
    let retained_blobs = retained_blob_evidence(&vault_dir)?;
    let adapter_outputs = adapter_output_evidence(&vault_dir)?;
    require(
        adapter_outputs.len() == 1,
        "shipping media seed did not retain exactly one deterministic adapter output",
    )?;
    drop(serving);

    let report = BaselineReport {
        schema: BASELINE_SCHEMA.to_string(),
        fixture_date: FIXTURE_DATE.to_string(),
        fixture_n_roles: FIXTURE_N_ROLES,
        cost_claim: COST_CLAIM.to_string(),
        fixture_root: root.display().to_string(),
        prepare_path: prepare_path.display().to_string(),
        prepare_sha256,
        vault_dir: vault_dir.display().to_string(),
        source_cx_id: source_cx_id.to_string(),
        target_cx_id: target_cx_id.to_string(),
        snapshot,
        base,
        compression_refusals,
        refusals_left_base_and_vault_files_unchanged: true,
        graph,
        ledger,
        retained_blobs,
        adapter_outputs,
        selected_column_families: serving_selected_cf_names(),
        raw_sidecar_selected_for_serving: false,
        vault_files: disk_inventory(&vault_dir)?,
    };
    let baseline_sha256 = write_json_durable(&baseline_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "base_record_media_replay_compress_success",
            "schema": BASELINE_SCHEMA,
            "fixture_n_roles": FIXTURE_N_ROLES,
            "cost_claim": COST_CLAIM,
            "fixture_root": root,
            "vault_dir": vault_dir,
            "source_cx_id": source_cx_id,
            "target_cx_id": target_cx_id,
            "snapshot": snapshot,
            "refused_slots": [TEXT_SLOT, IMAGE_SLOT],
            "compression_refusals": report
                .compression_refusals
                .iter()
                .map(|slot| json!({
                    "slot_id": slot.slot_id,
                    "error": slot.error,
                }))
                .collect::<Vec<_>>(),
            "refusals_left_base_and_vault_files_unchanged": true,
            "selected_column_families": report.selected_column_families,
            "raw_sidecar_selected_for_serving": false,
            "cli_replay_role": prepare.cli_roles[1],
            "baseline_path": baseline_path,
            "baseline_sha256": baseline_sha256,
            "next_required_mode": "base_record_media_replay_readback",
        })
    );
    Ok(())
}

pub(super) fn readback(root: &Path) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!(
            "base_record_media_replay_readback root is absent: {}",
            root.display()
        ),
    )?;
    let prepare_path = root.join(PREPARE_FILE);
    let baseline_path = root.join(BASELINE_FILE);
    let readback_path = root.join(READBACK_FILE);
    require(
        !readback_path.exists(),
        format!("refusing to overwrite {}", readback_path.display()),
    )?;
    let prepare_bytes = fs::read(&prepare_path)?;
    let prepare: PrepareReport = serde_json::from_slice(&prepare_bytes)?;
    validate_prepare_contract(root, &prepare)?;
    let baseline_bytes = fs::read(&baseline_path)?;
    let baseline_sha256 = sha256_hex(&baseline_bytes);
    let baseline: BaselineReport = serde_json::from_slice(&baseline_bytes)?;
    validate_baseline_contract(root, &prepare_path, &prepare_bytes, &prepare, &baseline)?;

    let vault_dir = PathBuf::from(&baseline.vault_dir);
    let source_cx_id: CxId = baseline.source_cx_id.parse()?;
    let target_cx_id: CxId = baseline.target_cx_id.parse()?;
    let source_bytes = fs::read(&prepare.source_path)?;
    let source_vector = expected_vector(IMAGE_ROLE, &source_bytes)?;
    let target_vector = expected_vector(TEXT_ROLE, DERIVED_TEXT.as_bytes())?;
    let files_before = disk_inventory(&vault_dir)?;
    let vault = open_serving_vault(&vault_dir)?;
    let snapshot = vault.latest_seq();
    let state = load_vault_panel_state(&vault_dir)?;
    require_fixture_panel(&state)?;
    require_expected_cx_derivation(&vault, source_cx_id, target_cx_id, &source_bytes)?;
    require_exact_base_roster(&vault, snapshot, &[source_cx_id, target_cx_id])?;
    let base = base_evidence_set(
        &vault,
        snapshot,
        source_cx_id,
        target_cx_id,
        &source_bytes,
        &source_vector,
        &target_vector,
    )?;
    require(
        base == baseline.base,
        "identical shipping media replay changed Base bytes or sealed slot-hash maps",
    )?;
    // Determinism of the fail-closed refusal: the same two commissioning
    // attempts are made against the replayed vault and must produce the exact
    // baseline refusal strings, because the cross-modality Absent row that
    // causes them is itself immutable.
    let compression_refusals = vec![
        require_commission_refusal(
            &vault,
            &state.registry,
            panel_slot(&state, TEXT_SLOT)?,
            TEXT_ROLE,
            &target_vector,
            source_cx_id,
        )?,
        require_commission_refusal(
            &vault,
            &state.registry,
            panel_slot(&state, IMAGE_SLOT)?,
            IMAGE_ROLE,
            &source_vector,
            target_cx_id,
        )?,
    ];
    require(
        compression_refusals == baseline.compression_refusals,
        "identical shipping media replay changed the product's fail-closed commissioning refusals",
    )?;
    require(
        vault.latest_seq() == snapshot,
        "refused media commissioning advanced the replayed vault sequence",
    )?;
    require_cross_modality_raw_columns(
        &vault,
        snapshot,
        source_cx_id,
        target_cx_id,
        &source_vector,
        &target_vector,
    )?;
    let graph = graph_evidence(&vault, snapshot, source_cx_id, target_cx_id)?;
    let (graph_new_rows, new_artifact) = validate_graph_suffix(&baseline.graph, &graph)?;
    validate_artifact_contract(
        &vault,
        snapshot,
        &new_artifact,
        source_cx_id,
        target_cx_id,
        &source_bytes,
    )?;
    let ledger = ledger_evidence(&vault)?;
    require(
        ledger.rows.len() == baseline.ledger.rows.len() + 1
            && ledger.rows[..baseline.ledger.rows.len()] == baseline.ledger.rows,
        "media replay Ledger is not the exact baseline prefix plus one entry",
    )?;
    let ledger_new_row = ledger
        .rows
        .last()
        .cloned()
        .ok_or("media replay Ledger suffix is absent")?;
    require(
        ledger_new_row.seq == new_artifact.ledger.seq
            && ledger_new_row.value.sha256
                == required_row(
                    &vault,
                    snapshot,
                    ColumnFamily::Ledger,
                    &ledger_key(new_artifact.ledger.seq),
                    "media replay Ledger entry",
                )
                .map(|bytes| sha256_hex(&bytes))?,
        "new media artifact does not bind the exact one-row Ledger suffix",
    )?;
    require(
        snapshot
            == baseline
                .snapshot
                .checked_add(1)
                .ok_or("snapshot overflow")?,
        "identical media replay did not add exactly one logical vault commit",
    )?;
    let retained_blobs = retained_blob_evidence(&vault_dir)?;
    require(
        retained_blobs == baseline.retained_blobs,
        "identical media replay changed retained source or derived-text bytes",
    )?;
    let adapter_outputs = adapter_output_evidence(&vault_dir)?;
    require(
        adapter_outputs.len() == 2
            && baseline.adapter_outputs.len() == 1
            && adapter_outputs.contains(&baseline.adapter_outputs[0]),
        "media seed/replay did not retain exactly two byte-identical deterministic adapter outputs",
    )?;
    drop(vault);
    let files_after = disk_inventory(&vault_dir)?;
    require(
        files_before == files_after,
        "independent media replay readback changed vault files",
    )?;

    let report = ReadbackReport {
        schema: READBACK_SCHEMA.to_string(),
        fixture_date: FIXTURE_DATE.to_string(),
        fixture_n_roles: FIXTURE_N_ROLES,
        cost_claim: COST_CLAIM.to_string(),
        fixture_root: root.display().to_string(),
        baseline_path: baseline_path.display().to_string(),
        baseline_sha256: baseline_sha256.clone(),
        snapshot,
        base,
        compression_refusals,
        graph,
        graph_new_rows,
        new_artifact,
        ledger,
        ledger_new_row,
        retained_blobs,
        adapter_outputs,
        selected_column_families: serving_selected_cf_names(),
        raw_sidecar_selected_for_serving: false,
        base_bytes_and_slot_hashes_unchanged: true,
        commission_refusals_byte_identical: true,
        no_compression_state_persisted: true,
        exact_two_deterministic_adapter_outputs: true,
        exact_one_artifact_graph_ledger_transition: true,
        disk_unchanged_during_readback: true,
        vault_files_before: files_before,
        vault_files_after: files_after,
    };
    let readback_sha256 = write_json_durable(&readback_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "base_record_media_replay_readback_success",
            "schema": READBACK_SCHEMA,
            "fixture_n_roles": FIXTURE_N_ROLES,
            "cost_claim": COST_CLAIM,
            "fixture_root": root,
            "source_cx_id": source_cx_id,
            "target_cx_id": target_cx_id,
            "baseline_path": baseline_path,
            "baseline_sha256": baseline_sha256,
            "readback_path": readback_path,
            "readback_sha256": readback_sha256,
            "final_snapshot": snapshot,
            "selected_column_families": report.selected_column_families,
            "raw_sidecar_selected_for_serving": false,
            "base_bytes_and_slot_hashes_unchanged": true,
            "commission_refusals_byte_identical": true,
            "no_compression_state_persisted": true,
            "compression_refusals": report
                .compression_refusals
                .iter()
                .map(|slot| json!({
                    "slot_id": slot.slot_id,
                    "error": slot.error,
                }))
                .collect::<Vec<_>>(),
            "deterministic_adapter_outputs": report.adapter_outputs.len(),
            "new_graph_rows": report.graph_new_rows.len(),
            "new_ledger_rows": 1,
            "new_artifact_id": report.new_artifact.artifact_id,
            "exact_one_artifact_graph_ledger_transition": true,
        })
    );
    Ok(())
}

fn required_adapter_arg<'a>(args: &'a BTreeMap<String, String>, flag: &str) -> AnyResult<&'a str> {
    args.get(flag)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("media adapter requires nonempty {flag}").into())
}

fn fixture_salt() -> Vec<u8> {
    format!("calyx-cli-vault:{VAULT_ID}:{FIXED_VAULT_NAME}").into_bytes()
}

fn catalog_value() -> Value {
    json!({
        "vaults": [{
            "name": FIXED_VAULT_NAME,
            "vault_id": VAULT_ID,
            "path": format!("vaults/{VAULT_ID}"),
            "panel_template": FIXED_PANEL_TEMPLATE,
        }]
    })
}

fn fixture_registry_and_panel() -> AnyResult<(Registry, Panel)> {
    let mut registry = Registry::new();
    let text =
        register_byte_feature_slot(&mut registry, TEXT_LENS_NAME, TEXT_SLOT, Modality::Text)?;
    let image =
        register_byte_feature_slot(&mut registry, IMAGE_LENS_NAME, IMAGE_SLOT, Modality::Image)?;
    Ok((registry, panel_for_slots([text, image])))
}

fn register_byte_feature_slot(
    registry: &mut Registry,
    name: &str,
    slot_id: u16,
    modality: Modality,
) -> AnyResult<Slot> {
    let lens = AlgorithmicLens::byte_features(name, modality);
    let contract = lens.contract().clone();
    require(
        contract.shape() == SlotShape::Dense(MEDIA_DIM) && contract.modality() == modality,
        format!("{name} is not the exact dense 16-D {modality:?} byte-feature contract"),
    )?;
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic {
            kind: "byte-features".to_string(),
        },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: None,
        axis: Some("issue-1138-media-replay".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
        truncate_dim: None,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let slot_id = SlotId::new(slot_id);
    Ok(Slot {
        slot_id,
        slot_key: slot_id.with_key(format!("{name}-slot")),
        lens_id,
        shape: SlotShape::Dense(MEDIA_DIM),
        modality,
        asymmetry: Asymmetry::None,
        quant: QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
        resource: SlotResource::default(),
        axis: Some("issue-1138-media-replay".to_string()),
        retrieval_only: false,
        excluded_from_dedup: false,
        bits_about: BTreeMap::new(),
        state: SlotState::Active,
        added_at_panel_version: PANEL_VERSION,
    })
}

fn require_fixture_panel(state: &VaultPanelState) -> AnyResult<()> {
    let (expected_registry, expected_panel) = fixture_registry_and_panel()?;
    let expected_lenses = expected_registry.lens_snapshots();
    let snapshot = state
        .registry_snapshot
        .as_ref()
        .ok_or("media fixture persisted Registry snapshot is absent")?;
    require(
        state.panel == expected_panel
            && snapshot.lenses.len() == 2
            && snapshot.lenses == expected_lenses
            && state.registry.lens_snapshots() == expected_lenses,
        "media fixture exact Panel/Registry/lens-runtime snapshot is absent or changed",
    )?;
    let text = panel_slot(state, TEXT_SLOT)?;
    let image = panel_slot(state, IMAGE_SLOT)?;
    require(
        text.modality == Modality::Text
            && image.modality == Modality::Image
            && text.shape == SlotShape::Dense(MEDIA_DIM)
            && image.shape == SlotShape::Dense(MEDIA_DIM)
            && text.state == SlotState::Active
            && image.state == SlotState::Active
            && text.quant
                == QuantPolicy::TurboQuant {
                    bits_per_channel_x2: 7,
                }
            && image.quant
                == QuantPolicy::TurboQuant {
                    bits_per_channel_x2: 7,
                },
        "media fixture does not retain exact active Text/Image dense TQ3.5 slots",
    )
}

fn cli_roles(root: &Path, source_path: &Path) -> Vec<CliRole> {
    let environment = BTreeMap::from([(
        "CALYX_HOME".to_string(),
        root.join("calyx-home").display().to_string(),
    )]);
    let runtime_environment_binding = BTreeMap::from([(
        MEDIA_DERIVED_TEXT_ENV.to_string(),
        ADAPTER_BINDING.to_string(),
    )]);
    let arguments = vec![
        "ingest".to_string(),
        FIXED_VAULT_NAME.to_string(),
        "--file".to_string(),
        source_path.display().to_string(),
        "--modality".to_string(),
        SOURCE_MODALITY.to_string(),
        "--output".to_string(),
        "rows".to_string(),
    ];
    vec![
        CliRole {
            role: "media_seed".to_string(),
            environment: environment.clone(),
            runtime_environment_binding: runtime_environment_binding.clone(),
            arguments: arguments.clone(),
            expected_exit: 0,
            expected_reports: vec![true, true],
            expected_effect: "two new Base rows plus one derived-media Graph artifact and one Ledger entry"
                .to_string(),
        },
        CliRole {
            role: "media_existing_replay".to_string(),
            environment,
            runtime_environment_binding,
            arguments,
            expected_exit: 0,
            expected_reports: vec![false, false],
            expected_effect: "Base rows and both raw cross-modality slot columns unchanged; one new derived-media Graph artifact and one Ledger entry"
                .to_string(),
        },
    ]
}

fn validate_prepare_contract(root: &Path, report: &PrepareReport) -> AnyResult<()> {
    let workspace = std::env::current_dir()?;
    let expected_home = root.join("calyx-home");
    let expected_vault_dir = expected_home.join("vaults").join(VAULT_ID);
    let expected_catalog_path = expected_home.join("vaults").join("index.json");
    let expected_source_path = workspace.join(SOURCE_RELATIVE_PATH);
    require(
        report.schema == PREPARE_SCHEMA
            && report.fixture_date == FIXTURE_DATE
            && report.fixture_n_roles == FIXTURE_N_ROLES
            && report.cost_claim == COST_CLAIM
            && report.fixture_root == root.display().to_string()
            && report.calyx_home == expected_home.display().to_string()
            && report.vault_dir == expected_vault_dir.display().to_string()
            && report.catalog_path == expected_catalog_path.display().to_string()
            && report.vault_name == FIXED_VAULT_NAME
            && report.vault_id == VAULT_ID
            && report.vault_salt_utf8 == String::from_utf8(fixture_salt())?
            && report.panel_version == PANEL_VERSION
            && report.text_slot == TEXT_SLOT
            && report.image_slot == IMAGE_SLOT
            && report.source.bytes == SOURCE_BYTES
            && report.source.sha256 == SOURCE_SHA256
            && report.source_path == expected_source_path.display().to_string()
            && report.derived_text == DERIVED_TEXT
            && report.derived_text_sha256 == sha256_hex(DERIVED_TEXT.as_bytes())
            && report.cli_roles == cli_roles(root, &expected_source_path),
        "media fixture prepare contract differs from the exact deterministic schema",
    )?;
    require(
        file_identity(&expected_source_path)? == report.source,
        "bound media source bytes changed after prepare",
    )?;
    let catalog_bytes = fs::read(&expected_catalog_path)?;
    require(
        sha256_hex(&catalog_bytes) == report.catalog_sha256
            && serde_json::from_slice::<Value>(&catalog_bytes)? == catalog_value(),
        "media fixture CLI catalog is not the exact one-vault object from prepare",
    )
}

fn validate_baseline_contract(
    root: &Path,
    prepare_path: &Path,
    prepare_bytes: &[u8],
    prepare: &PrepareReport,
    report: &BaselineReport,
) -> AnyResult<()> {
    require(
        report.schema == BASELINE_SCHEMA
            && report.fixture_date == FIXTURE_DATE
            && report.fixture_n_roles == FIXTURE_N_ROLES
            && report.cost_claim == COST_CLAIM
            && report.fixture_root == root.display().to_string()
            && report.prepare_path == prepare_path.display().to_string()
            && report.prepare_sha256 == sha256_hex(prepare_bytes)
            && report.vault_dir == prepare.vault_dir
            && report.source_cx_id == prepare.source_cx_id
            && report.target_cx_id == prepare.target_cx_id
            && report.base.len() == FIXTURE_N_ROLES
            && report.compression_refusals.len() == FIXTURE_N_ROLES
            && report.refusals_left_base_and_vault_files_unchanged
            && report.adapter_outputs.len() == 1
            && report.selected_column_families == serving_selected_cf_names()
            && !report.raw_sidecar_selected_for_serving,
        "media fixture baseline contract differs from the exact deterministic schema",
    )?;
    // Slot 86 (Text) is dense only for the derived-text Cx, so its one
    // cross-modality Absent row belongs to the source-image Cx; slot 87 (Image)
    // is the exact mirror.
    let expected_refusals = [
        (TEXT_SLOT, prepare.source_cx_id.as_str()),
        (IMAGE_SLOT, prepare.target_cx_id.as_str()),
    ];
    let observed_slots = report
        .compression_refusals
        .iter()
        .map(|refusal| refusal.slot_id)
        .collect::<Vec<_>>();
    require(
        observed_slots == [TEXT_SLOT, IMAGE_SLOT],
        "media fixture baseline refusals are not exactly the ordered text/image slot pair",
    )?;
    for (refusal, (slot_id, non_dense_cx_id)) in
        report.compression_refusals.iter().zip(expected_refusals)
    {
        require(
            !refusal.error.is_empty()
                && refusal
                    .error
                    .starts_with(&format!("{CALYX_COMPRESSION_ADMISSION_REFUSED}: "))
                && refusal
                    .error
                    .contains(&expected_not_dense_refusal(slot_id, non_dense_cx_id)),
            format!(
                "media fixture baseline slot {slot_id} refusal is not the product's fail-closed not-dense contract"
            ),
        )?;
    }
    Ok(())
}

fn require_expected_cx_derivation<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    source_cx_id: CxId,
    target_cx_id: CxId,
    source_bytes: &[u8],
) -> AnyResult<()> {
    require(
        vault.cx_id_for_input(source_bytes, PANEL_VERSION) == source_cx_id
            && vault.cx_id_for_input(DERIVED_TEXT.as_bytes(), PANEL_VERSION) == target_cx_id
            && source_cx_id != target_cx_id,
        "media fixture Cx derivation changed for fixed source/text bytes and CLI salt",
    )
}

fn expected_vector(role: &str, bytes: &[u8]) -> AnyResult<Vec<f32>> {
    let (name, modality) = match role {
        TEXT_ROLE => (TEXT_LENS_NAME, Modality::Text),
        IMAGE_ROLE => (IMAGE_LENS_NAME, Modality::Image),
        other => return Err(format!("unknown media fixture role {other}").into()),
    };
    let lens = AlgorithmicLens::byte_features(name, modality);
    let vector = lens.measure(&Input::new(modality, bytes.to_vec()))?;
    let SlotVector::Dense { dim, data } = vector else {
        return Err(format!("{role} byte-feature lens did not return a dense vector").into());
    };
    require(
        dim == MEDIA_DIM && data.len() == MEDIA_DIM as usize,
        format!("{role} byte-feature vector is not exact D=16"),
    )?;
    Ok(data)
}

/// Attempts one real commissioning of `slot` and requires the shipping product
/// to refuse it with its exact not-dense contract for `non_dense_cx_id`, the
/// one cross-modality `Absent { NotApplicable }` row this fixture's shared
/// two-slot panel persists in that slot column.
fn require_commission_refusal(
    vault: &Arc<AsterVault<SystemClock>>,
    registry: &Registry,
    slot: &Slot,
    role: &str,
    values: &[f32],
    non_dense_cx_id: CxId,
) -> AnyResult<CompressionRefusalEvidence> {
    let slot_id = slot.slot_id.get();
    let query = CompressionQuery {
        cx_id: vault.cx_id_for_input(
            format!("issue-1138-media-held-out-{role}").as_bytes(),
            PANEL_VERSION,
        ),
        values: values.to_vec(),
    };
    // The declared corpus bound must admit the real FIXTURE_N_ROLES-row slot
    // column: the product checks its declared row ceiling before it decodes a
    // row (`measurement.rs:1722-1741`), so a one-row declaration would refuse
    // with a work-limit diagnostic and hide the modality contract being proven.
    let work = exact_work_plan(
        &[candidate_work_spec(
            slot,
            u32::try_from(FIXTURE_N_ROLES)?,
            MEDIA_DIM,
        )?],
        1,
    )?;
    let refused = registry.build_and_evaluate_compression_candidate(
        vault,
        slot,
        candidate_request_with_k(vec![query], 1, work.limits.clone(), passing_gates()),
    );
    let error = match refused {
        Ok(_) => {
            return Err(format!(
                "{role} slot {slot_id} commissioning was admitted, but its column retains a cross-modality Absent row that the full-column-dense contract must refuse"
            )
            .into());
        }
        Err(error) => error.to_string(),
    };
    require(
        error.starts_with(&format!("{CALYX_COMPRESSION_ADMISSION_REFUSED}: "))
            && error.contains(&expected_not_dense_refusal(
                slot_id,
                &non_dense_cx_id.to_string(),
            )),
        format!(
            "{role} slot {slot_id} refusal is not the product's fail-closed not-dense contract: {error}"
        ),
    )?;
    Ok(CompressionRefusalEvidence { slot_id, error })
}

/// The product's exact fail-closed refusal for a candidate slot column that
/// holds a non-dense row, quoted from
/// `calyx-registry/src/compression/measurement.rs:1736-1741`.
fn expected_not_dense_refusal(slot_id: u16, non_dense_cx_id: &str) -> String {
    format!("candidate slot {slot_id} row {non_dense_cx_id} is not dense")
}

/// Independently reads back the exact persisted slot columns that make
/// commissioning impossible here: each column holds one dense source row for
/// its own modality plus one cross-modality `Absent { NotApplicable }` row, and
/// no compressed envelope or Compression row exists at `snapshot`.
fn require_cross_modality_raw_columns<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    source_cx_id: CxId,
    target_cx_id: CxId,
    source_vector: &[f32],
    target_vector: &[f32],
) -> AnyResult<()> {
    require(
        vault
            .scan_cf_at(snapshot, ColumnFamily::Compression)?
            .is_empty(),
        "media fixture Compression CF is not empty",
    )?;
    let absent = not_applicable_slot_encoding()?;
    for (slot_id, dense_cx_id, dense_vector, absent_cx_id) in [
        (TEXT_SLOT, target_cx_id, target_vector, source_cx_id),
        (IMAGE_SLOT, source_cx_id, source_vector, target_cx_id),
    ] {
        let rows = vault.scan_cf_at(snapshot, ColumnFamily::slot(SlotId::new(slot_id)))?;
        let expected = [
            (slot_key(dense_cx_id), dense_slot_encoding(dense_vector)?),
            (slot_key(absent_cx_id), absent.clone()),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        require(
            rows.len() == FIXTURE_N_ROLES
                && rows.iter().cloned().collect::<BTreeMap<_, _>>() == expected
                && rows
                    .iter()
                    .all(|(_, value)| value.first().copied() != Some(COMPRESSED_SLOT_TAG)),
            format!(
                "slot {slot_id} column is not exactly its dense source row plus one cross-modality Absent row"
            ),
        )?;
    }
    Ok(())
}

fn open_serving_vault(dir: &Path) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    Ok(Arc::new(AsterVault::open(
        dir,
        VAULT_ID.parse::<VaultId>()?,
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

/// Exactly the column families this fixture family persists. `Compression` is
/// created empty by every write-capable vault open (it is a static CF) and is
/// selected so the refusal readback can prove it stayed empty; no `slot_8x.raw`
/// sidecar CF exists here, because commissioning is always refused.
fn serving_selected_cfs() -> Vec<ColumnFamily> {
    vec![
        ColumnFamily::Base,
        ColumnFamily::Compression,
        ColumnFamily::slot(SlotId::new(TEXT_SLOT)),
        ColumnFamily::slot(SlotId::new(IMAGE_SLOT)),
        ColumnFamily::Graph,
        ColumnFamily::Ledger,
    ]
}

fn serving_selected_cf_names() -> Vec<String> {
    serving_selected_cfs()
        .into_iter()
        .map(|cf| cf.name().to_string())
        .collect()
}

fn base_evidence_set<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    source_cx_id: CxId,
    target_cx_id: CxId,
    source_bytes: &[u8],
    source_vector: &[f32],
    target_vector: &[f32],
) -> AnyResult<Vec<BaseEvidence>> {
    Ok(vec![
        base_evidence(
            vault,
            snapshot,
            BaseEvidenceRequest {
                role: TEXT_ROLE,
                cx_id: target_cx_id,
                slot_id: TEXT_SLOT,
                modality: Modality::Text,
                input_bytes: DERIVED_TEXT.as_bytes(),
                source_vector: target_vector,
            },
        )?,
        base_evidence(
            vault,
            snapshot,
            BaseEvidenceRequest {
                role: IMAGE_ROLE,
                cx_id: source_cx_id,
                slot_id: IMAGE_SLOT,
                modality: Modality::Image,
                input_bytes: source_bytes,
                source_vector,
            },
        )?,
    ])
}

fn base_evidence<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    request: BaseEvidenceRequest<'_>,
) -> AnyResult<BaseEvidence> {
    let BaseEvidenceRequest {
        role,
        cx_id,
        slot_id,
        modality,
        input_bytes,
        source_vector,
    } = request;
    let bytes = required_row(vault, snapshot, ColumnFamily::Base, &base_key(cx_id), role)?;
    let record = BaseRecord::decode_for_key(cx_id, &bytes)?;
    let cx = record.constellation();
    let expected_slot_hashes = expected_base_slot_hashes(slot_id, source_vector)?;
    require(
        record.vault_id() == VAULT_ID.parse::<VaultId>()?
            && record.encode()? == bytes
            && cx.cx_id == cx_id
            && cx.panel_version == PANEL_VERSION
            && cx.modality == modality
            && cx.input_ref.hash == *blake3::hash(input_bytes).as_bytes()
            && !cx.input_ref.redacted
            && *record.slot_hashes() == expected_slot_hashes,
        format!("{role} Base row does not retain its exact identity and sealed slot-hash roster"),
    )?;
    match role {
        IMAGE_ROLE => {
            let pointer = format!("calyx-vault://inputs/media/image/{SOURCE_SHA256}.png");
            require(
                cx.input_ref.pointer.as_deref() == Some(pointer.as_str())
                    && cx.metadata.get("media.pointer") == Some(&pointer)
                    && cx.metadata.get("media.source_sha256").map(String::as_str)
                        == Some(SOURCE_SHA256)
                    && cx.metadata.get("media.bytes").map(String::as_str) == Some("1246084")
                    && cx.metadata.get("media.extension").map(String::as_str) == Some("png")
                    && cx.metadata.get("media.codec").map(String::as_str) == Some("png")
                    && cx.metadata.get("media.container").map(String::as_str) == Some("png_pipe")
                    && cx.metadata.get("media.width").map(String::as_str) == Some("1538")
                    && cx.metadata.get("media.height").map(String::as_str) == Some("932")
                    && cx.metadata.get("media.frame_count").map(String::as_str) == Some("1"),
                "source-image Base row does not bind the exact retained PNG metadata",
            )?;
        }
        TEXT_ROLE => {
            let text_sha256 = sha256_hex(DERIVED_TEXT.as_bytes());
            let text_bytes = DERIVED_TEXT.len().to_string();
            let pointer =
                format!("calyx-vault://inputs/derived_text/{DERIVED_KIND}/{text_sha256}.txt");
            require(
                cx.input_ref.pointer.as_deref() == Some(pointer.as_str())
                    && cx.metadata.get(METADATA_DERIVED_POINTER) == Some(&pointer)
                    && cx
                        .metadata
                        .get(METADATA_DERIVED_TEXT_SHA256)
                        .map(String::as_str)
                        == Some(text_sha256.as_str())
                    && cx
                        .metadata
                        .get(METADATA_DERIVED_TEXT_BYTES)
                        .map(String::as_str)
                        == Some(text_bytes.as_str())
                    && cx.metadata.get(METADATA_DERIVED_KIND).map(String::as_str)
                        == Some(DERIVED_KIND)
                    && cx
                        .metadata
                        .get(METADATA_DERIVED_RUNTIME)
                        .map(String::as_str)
                        == Some(DERIVED_RUNTIME)
                    && cx.metadata.get(METADATA_DERIVED_MODEL).map(String::as_str)
                        == Some(DERIVED_MODEL)
                    && cx
                        .metadata
                        .get(METADATA_DERIVED_LANGUAGE)
                        .map(String::as_str)
                        == Some(DERIVED_LANGUAGE)
                    && cx
                        .metadata
                        .get(METADATA_DERIVED_CONFIDENCE)
                        .map(String::as_str)
                        == Some("1.000000"),
                "derived-text Base row does not bind the deterministic caption metadata",
            )?;
        }
        _ => return Err(format!("unknown Base evidence role {role}").into()),
    }
    Ok(BaseEvidence {
        role: role.to_string(),
        cx_id: cx_id.to_string(),
        modality: cx.modality.stable_str().to_string(),
        value: value_identity(&bytes),
        slot_hashes: slot_hash_evidence(record.slot_hashes()),
        input_pointer: cx.input_ref.pointer.clone(),
        input_hash: hex(&cx.input_ref.hash),
        metadata: cx.metadata.clone(),
        provenance: ledger_identity(&cx.provenance),
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
        rows.len() == FIXTURE_N_ROLES && observed == expected,
        "Base CF does not contain exactly the fixed media/text Cx roster",
    )
}

fn graph_evidence<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    source_cx_id: CxId,
    target_cx_id: CxId,
) -> AnyResult<GraphEvidence> {
    let rows = vault.scan_cf_at(snapshot, ColumnFamily::Graph)?;
    let mut source_artifacts = vault
        .derived_media_artifacts_for_source(snapshot, source_cx_id)?
        .iter()
        .map(artifact_identity)
        .collect::<Vec<_>>();
    let mut target_artifacts = vault
        .derived_media_artifacts_for_target(snapshot, target_cx_id)?
        .iter()
        .map(artifact_identity)
        .collect::<Vec<_>>();
    source_artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    target_artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    Ok(GraphEvidence {
        rows: rows
            .iter()
            .map(|(key, value)| KeyValueEvidence {
                key_hex: hex(key),
                value: value_identity(value),
            })
            .collect(),
        rows_sha256: rows_sha256(&rows),
        source_artifacts,
        target_artifacts,
    })
}

fn artifact_identity(record: &DerivedMediaArtifactRecord) -> ArtifactIdentity {
    ArtifactIdentity {
        artifact_id: record.artifact_id.clone(),
        source_cx_id: record.source_cx_id.to_string(),
        target_cx_id: record.target_cx_id.to_string(),
        derived_kind: record.derived_kind.clone(),
        source_modality: record.source_modality.clone(),
        source_input_hash: record.source_input_hash.clone(),
        source_sha256: record.source_sha256.clone(),
        source_pointer: record.source_pointer.clone(),
        target_pointer: record.target_pointer.clone(),
        target_text_sha256: record.target_text_sha256.clone(),
        runtime: record.runtime.clone(),
        model: record.model.clone(),
        language: record.language.clone(),
        confidence_bits: record
            .confidence
            .map(|value| format!("{:016x}", value.to_bits())),
        ledger: ledger_identity(&record.ledger_ref),
    }
}

fn validate_artifact_contract<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    artifact: &ArtifactIdentity,
    source_cx_id: CxId,
    target_cx_id: CxId,
    source_bytes: &[u8],
) -> AnyResult<()> {
    let expected_source_pointer = format!("calyx-vault://inputs/media/image/{SOURCE_SHA256}.png");
    let target_text_sha256 = sha256_hex(DERIVED_TEXT.as_bytes());
    let expected_target_pointer =
        format!("calyx-vault://inputs/derived_text/{DERIVED_KIND}/{target_text_sha256}.txt");
    let confidence_bits = format!("{:016x}", DERIVED_CONFIDENCE.to_bits());
    let source_cx_id_text = source_cx_id.to_string();
    let target_cx_id_text = target_cx_id.to_string();
    let runtime_id = sha256_hex(DERIVED_RUNTIME.as_bytes());
    let model_id = sha256_hex(DERIVED_MODEL.as_bytes());
    require(
        artifact.source_cx_id == source_cx_id_text
            && artifact.target_cx_id == target_cx_id_text
            && artifact.derived_kind == DERIVED_KIND
            && artifact.source_modality == SOURCE_MODALITY
            && artifact.source_input_hash == hex(blake3::hash(source_bytes).as_bytes())
            && artifact.source_sha256 == SOURCE_SHA256
            && artifact.source_pointer == expected_source_pointer
            && artifact.target_pointer == expected_target_pointer
            && artifact.target_text_sha256 == target_text_sha256
            && artifact.runtime == DERIVED_RUNTIME
            && artifact.model == DERIVED_MODEL
            && artifact.language.as_deref() == Some(DERIVED_LANGUAGE)
            && artifact.confidence_bits.as_deref() == Some(confidence_bits.as_str()),
        "derived media artifact content differs from the exact source/caption contract",
    )?;
    let bytes = required_row(
        vault,
        snapshot,
        ColumnFamily::Ledger,
        &ledger_key(artifact.ledger.seq),
        "derived media artifact Ledger entry",
    )?;
    let entry = decode_ledger_entry(&bytes)?;
    let payload: Value = serde_json::from_slice(&entry.payload)?;
    require(
        entry.seq == artifact.ledger.seq
            && hex(&entry.entry_hash) == artifact.ledger.hash
            && entry.kind == EntryKind::Ingest
            && entry.subject == SubjectId::Cx(target_cx_id)
            && entry.actor == ActorId::Service("calyx-cli".to_string())
            && payload.get(LEDGER_FIELD_MODE).and_then(Value::as_str) == Some(DERIVED_TEXT_MODE)
            && payload
                .get(LEDGER_FIELD_DERIVED_ARTIFACT_ID)
                .and_then(Value::as_str)
                == Some(artifact.artifact_id.as_str())
            && payload
                .get(LEDGER_FIELD_SOURCE_CX_ID)
                .and_then(Value::as_str)
                == Some(source_cx_id_text.as_str())
            && payload
                .get(LEDGER_FIELD_TARGET_CX_ID)
                .and_then(Value::as_str)
                == Some(target_cx_id_text.as_str())
            && payload
                .get(LEDGER_FIELD_DERIVED_KIND)
                .and_then(Value::as_str)
                == Some(DERIVED_KIND)
            && payload
                .get(LEDGER_FIELD_SOURCE_MODALITY)
                .and_then(Value::as_str)
                == Some(SOURCE_MODALITY)
            && payload
                .get(LEDGER_FIELD_SOURCE_INPUT_HASH)
                .and_then(Value::as_str)
                == Some(artifact.source_input_hash.as_str())
            && payload
                .get(LEDGER_FIELD_SOURCE_SHA256)
                .and_then(Value::as_str)
                == Some(SOURCE_SHA256)
            && payload
                .get(LEDGER_FIELD_TARGET_TEXT_SHA256)
                .and_then(Value::as_str)
                == Some(target_text_sha256.as_str())
            && payload.get(LEDGER_FIELD_RUNTIME_ID).and_then(Value::as_str)
                == Some(runtime_id.as_str())
            && payload.get(LEDGER_FIELD_MODEL_ID).and_then(Value::as_str)
                == Some(model_id.as_str()),
        "derived media artifact Ledger entry does not bind its exact payload and record",
    )
}

fn validate_graph_suffix(
    baseline: &GraphEvidence,
    final_graph: &GraphEvidence,
) -> AnyResult<(Vec<KeyValueEvidence>, ArtifactIdentity)> {
    require(
        baseline.source_artifacts.len() == 1
            && baseline.source_artifacts == baseline.target_artifacts
            && final_graph.source_artifacts.len() == 2
            && final_graph.source_artifacts == final_graph.target_artifacts,
        "media replay artifact indexes do not contain exact one-to-two source/target rosters",
    )?;
    let baseline_rows = baseline
        .rows
        .iter()
        .map(|row| (row.key_hex.as_str(), &row.value))
        .collect::<BTreeMap<_, _>>();
    let final_rows = final_graph
        .rows
        .iter()
        .map(|row| (row.key_hex.as_str(), &row.value))
        .collect::<BTreeMap<_, _>>();
    require(
        baseline_rows
            .iter()
            .all(|(key, value)| final_rows.get(key).copied() == Some(*value)),
        "media replay changed or removed a baseline Graph row",
    )?;
    let graph_new_rows = final_graph
        .rows
        .iter()
        .filter(|row| !baseline_rows.contains_key(row.key_hex.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let baseline_ids = baseline
        .source_artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let new_artifacts = final_graph
        .source_artifacts
        .iter()
        .filter(|artifact| !baseline_ids.contains(artifact.artifact_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    require(
        graph_new_rows.len() == 3 && new_artifacts.len() == 1,
        "media replay did not add exactly one three-row Graph artifact",
    )?;
    let new_artifact = new_artifacts[0].clone();
    let primary_key = hex(&derived_media_artifact_key(&new_artifact.artifact_id)?);
    require(
        graph_new_rows.iter().any(|row| row.key_hex == primary_key)
            && graph_new_rows
                .iter()
                .filter(|row| row.key_hex != primary_key)
                .all(|row| row.value.hex == hex(new_artifact.artifact_id.as_bytes())),
        "new media Graph primary/source/target rows do not bind one artifact id",
    )?;
    let baseline_artifact = &baseline.source_artifacts[0];
    require(
        same_derivation(baseline_artifact, &new_artifact)
            && baseline_artifact.artifact_id != new_artifact.artifact_id
            && baseline_artifact.ledger != new_artifact.ledger,
        "media replay artifact changed derivation content instead of adding a new occurrence",
    )?;
    Ok((graph_new_rows, new_artifact))
}

fn same_derivation(left: &ArtifactIdentity, right: &ArtifactIdentity) -> bool {
    left.source_cx_id == right.source_cx_id
        && left.target_cx_id == right.target_cx_id
        && left.derived_kind == right.derived_kind
        && left.source_modality == right.source_modality
        && left.source_input_hash == right.source_input_hash
        && left.source_sha256 == right.source_sha256
        && left.source_pointer == right.source_pointer
        && left.target_pointer == right.target_pointer
        && left.target_text_sha256 == right.target_text_sha256
        && left.runtime == right.runtime
        && left.model == right.model
        && left.language == right.language
        && left.confidence_bits == right.confidence_bits
}

fn ledger_evidence<C: calyx_core::Clock>(vault: &AsterVault<C>) -> AnyResult<LedgerEvidence> {
    let store = vault.retained_read_only_ledger_store()?;
    let rows = store.scan()?;
    let chain = verify_chain(&store, 0..rows.len() as u64)?;
    require(
        matches!(chain, VerifyResult::Intact { count } if count == rows.len() as u64),
        format!("physical media replay Ledger chain is not intact: {chain:?}"),
    )?;
    let head = store
        .head_anchor()?
        .ok_or("physical media replay Ledger has no external head anchor")?;
    require(
        head.height == rows.len() as u64
            && rows
                .last()
                .map(|row| decode_ledger_entry(&row.bytes))
                .transpose()?
                .is_some_and(|entry| entry.entry_hash == head.tip_hash),
        "physical media replay Ledger head does not bind the final row",
    )?;
    Ok(LedgerEvidence {
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
    })
}

fn retained_blob_evidence(vault_dir: &Path) -> AnyResult<RetainedBlobEvidence> {
    let source_pointer = format!("calyx-vault://inputs/media/image/{SOURCE_SHA256}.png");
    let target_sha256 = sha256_hex(DERIVED_TEXT.as_bytes());
    let target_pointer =
        format!("calyx-vault://inputs/derived_text/{DERIVED_KIND}/{target_sha256}.txt");
    let source_path = vault_dir
        .join("inputs")
        .join("media")
        .join("image")
        .join(format!("{SOURCE_SHA256}.png"));
    let target_path = vault_dir
        .join("inputs")
        .join("derived_text")
        .join(DERIVED_KIND)
        .join(format!("{target_sha256}.txt"));
    let source = file_identity(&source_path)?;
    let target = file_identity(&target_path)?;
    require(
        source.bytes == SOURCE_BYTES
            && source.sha256 == SOURCE_SHA256
            && target.bytes == DERIVED_TEXT.len() as u64
            && target.sha256 == target_sha256,
        "retained source/derived text blobs differ from the exact media fixture bytes",
    )?;
    Ok(RetainedBlobEvidence {
        source_pointer,
        source_path: source_path.display().to_string(),
        source,
        target_pointer,
        target_path: target_path.display().to_string(),
        target,
    })
}

fn adapter_output_bytes() -> AnyResult<Vec<u8>> {
    let value = AdapterOutput {
        text: DERIVED_TEXT,
        runtime: DERIVED_RUNTIME,
        model: DERIVED_MODEL,
        language: DERIVED_LANGUAGE,
        confidence: DERIVED_CONFIDENCE,
    };
    let mut encoded = serde_json::to_vec(&value)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn adapter_output_evidence(vault_dir: &Path) -> AnyResult<Vec<FileReadback>> {
    let expected = adapter_output_bytes()?;
    let expected_sha256 = sha256_hex(&expected);
    let outputs = disk_inventory(vault_dir)?
        .into_iter()
        .filter(|file| {
            file.relative_path.starts_with("tmp/derived_text/")
                && file.relative_path.ends_with(".json")
        })
        .collect::<Vec<_>>();
    require(
        outputs
            .iter()
            .all(|file| file.bytes == expected.len() as u64 && file.sha256 == expected_sha256),
        "retained media adapter output bytes differ from the deterministic JSON contract",
    )?;
    Ok(outputs)
}

fn slot_hash_evidence(hashes: &BTreeMap<SlotId, [u8; 32]>) -> BTreeMap<u16, String> {
    hashes
        .iter()
        .map(|(slot, hash)| (slot.get(), hex(hash)))
        .collect()
}

/// The exact sealed slot-hash roster the shipping ingest persists for one Cx of
/// this fixture: the applicable slot binds its dense source vector, and the
/// other slot of the shared panel binds the cross-modality
/// `Absent { NotApplicable }` placeholder the ingest measured for it.
fn expected_base_slot_hashes(
    applicable_slot: u16,
    source_vector: &[f32],
) -> AnyResult<BTreeMap<SlotId, [u8; 32]>> {
    let inapplicable_slot = match applicable_slot {
        TEXT_SLOT => IMAGE_SLOT,
        IMAGE_SLOT => TEXT_SLOT,
        other => return Err(format!("unknown media fixture slot {other}").into()),
    };
    Ok(BTreeMap::from([
        (
            SlotId::new(applicable_slot),
            source_slot_hash(source_vector)?,
        ),
        (SlotId::new(inapplicable_slot), not_applicable_slot_hash()?),
    ]))
}

fn dense_slot_encoding(values: &[f32]) -> AnyResult<Vec<u8>> {
    Ok(encode::encode_slot_vector(&SlotVector::Dense {
        dim: MEDIA_DIM,
        data: values.to_vec(),
    })?)
}

fn not_applicable_slot_encoding() -> AnyResult<Vec<u8>> {
    Ok(encode::encode_slot_vector(&SlotVector::Absent {
        reason: AbsentReason::NotApplicable,
    })?)
}

fn source_slot_hash(values: &[f32]) -> AnyResult<[u8; 32]> {
    Ok(*blake3::hash(&dense_slot_encoding(values)?).as_bytes())
}

fn not_applicable_slot_hash() -> AnyResult<[u8; 32]> {
    Ok(*blake3::hash(&not_applicable_slot_encoding()?).as_bytes())
}

fn cx_id_from_key(key: &[u8]) -> AnyResult<CxId> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| format!("Cx key has {} bytes instead of 16", key.len()))?;
    Ok(CxId::from_bytes(bytes))
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

fn file_identity(path: &Path) -> AnyResult<FileIdentity> {
    Ok(FileIdentity {
        bytes: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
    })
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
