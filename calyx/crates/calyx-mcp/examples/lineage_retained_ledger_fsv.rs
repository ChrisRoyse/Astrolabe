//! Native manual FSV for the retained-Ledger `calyx.provenance` read path.
//!
//! `exercise` dispatches real JSON-RPC requests through the public MCP server
//! and persists only an external evidence report. `readback` runs in a fresh
//! process, reconstructs current Base/slot state, and joins it to a physical
//! Ledger SST+WAL view. Both modes require an existing vault and reject any
//! report path inside that vault.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use calyx_aster::cf::{ColumnFamily, base_key};
use calyx_aster::ledger_view::AsterLedgerCfStore;
use calyx_aster::vault::encode::BaseRecord;
use calyx_aster::vault::{AsterVault, SlotVectorResolver, VaultOptions};
use calyx_core::{AnchorKind, AuthN, CxId, VaultId};
use calyx_ledger::{EntryKind, LedgerCfStore, LedgerEntry, SubjectId, decode};
use calyx_mcp::{McpServer, decode_jsonrpc_request};
use calyx_registry::load_vault_panel_state;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REPORT_SCHEMA: &str = "astrolabe.calyx-mcp.lineage-retained-ledger-fsv.v1";
const ABSENT_CX_ID: &str = "ffffffffffffffffffffffffffffffff";
const MALFORMED_CX_ID: &str = "not-a-cx-id";

type AnyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct InventoryEntry {
    path: String,
    kind: String,
    bytes: u64,
    sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TreeInventory {
    files: usize,
    directories: usize,
    bytes: u64,
    entries: Vec<InventoryEntry>,
    tree_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Exchange {
    request: Value,
    request_sha256: String,
    response: Value,
    response_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LineagePayload {
    cx_id: String,
    ingest_seq: u64,
    ledger_chain_hash: String,
    lens_measures: Vec<LensMeasure>,
    anchors: Vec<AnchorEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LensMeasure {
    slot: u16,
    lens_id: String,
    measured_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AnchorEvidence {
    kind: String,
    ledger_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExerciseReport {
    schema: String,
    home: String,
    catalog: String,
    catalog_bytes: u64,
    catalog_sha256: String,
    vault: String,
    vault_id: String,
    vault_name: String,
    cx_id: String,
    absent_cx_id: String,
    malformed_cx_id: String,
    before: TreeInventory,
    after: TreeInventory,
    first_valid: Exchange,
    second_valid: Exchange,
    absent: Exchange,
    malformed: Exchange,
    lineage: LineagePayload,
    lineage_text_sha256: String,
}

#[derive(Debug, Serialize)]
struct PhysicalReadback {
    snapshot_seq: u64,
    selected_cfs: Vec<String>,
    ledger_rows: usize,
    ledger_head_height: u64,
    ledger_head_tip_hash: String,
    base_provenance_seq: u64,
    base_provenance_hash: String,
    ingest_seq: u64,
    ingest_hash: String,
    measured_slots: usize,
    anchors: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Exercise,
    Readback,
}

struct Inputs {
    mode: Mode,
    home: PathBuf,
    catalog: PathBuf,
    catalog_bytes: Vec<u8>,
    vault: PathBuf,
    vault_id: VaultId,
    vault_name: String,
    cx_id: CxId,
    report: PathBuf,
}

#[derive(Deserialize)]
struct VaultCatalog {
    vaults: Vec<VaultCatalogEntry>,
}

#[derive(Deserialize)]
struct VaultCatalogEntry {
    name: String,
    vault_id: VaultId,
    path: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("LINEAGE_RETAINED_LEDGER_FSV_FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> AnyResult<()> {
    let inputs = parse_inputs()?;
    match inputs.mode {
        Mode::Exercise => exercise(&inputs),
        Mode::Readback => readback(&inputs),
    }
}

fn parse_inputs() -> AnyResult<Inputs> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    require(
        args.len() == 6,
        "usage: lineage_retained_ledger_fsv <exercise|readback> <calyx-home> <vault-id> <vault-name> <cx-id> <report-json>",
    )?;
    let mode = match args[0].as_str() {
        "exercise" => Mode::Exercise,
        "readback" => Mode::Readback,
        other => return Err(fsv_error(format!("unsupported mode {other:?}"))),
    };
    let home = fs::canonicalize(&args[1])?;
    require(
        home.is_dir(),
        format!("CALYX home is not a directory: {}", home.display()),
    )?;
    let ambient_home = env::var_os("CALYX_HOME")
        .ok_or_else(|| fsv_error("CALYX_HOME is required for the real MCP vault resolver"))?;
    let ambient_home = fs::canonicalize(ambient_home)?;
    require(
        ambient_home == home,
        format!(
            "CALYX_HOME {} differs from the bound home {}",
            ambient_home.display(),
            home.display()
        ),
    )?;

    let vault_id = VaultId::from_str(&args[2])?;
    let vault_name = args[3].clone();
    require(
        !vault_name.trim().is_empty(),
        "vault name must be a nonempty logical catalog name",
    )?;
    let cx_id = CxId::from_str(&args[4])?;
    let vault = fs::canonicalize(home.join("vaults").join(vault_id.to_string()))?;
    require(
        vault.is_dir(),
        format!("vault is not a directory: {}", vault.display()),
    )?;
    let (catalog, catalog_bytes) = bind_catalog_entry(&home, &vault, vault_id, &vault_name)?;

    let report_input = PathBuf::from(&args[5]);
    let report_name = report_input
        .file_name()
        .ok_or_else(|| fsv_error("report path has no file name"))?;
    let report_parent = report_input
        .parent()
        .ok_or_else(|| fsv_error("report path has no parent"))?;
    let report = fs::canonicalize(report_parent)?.join(report_name);
    require(
        !report.starts_with(&vault),
        "the exercise report must remain outside the immutable vault",
    )?;

    Ok(Inputs {
        mode,
        home,
        catalog,
        catalog_bytes,
        vault,
        vault_id,
        vault_name,
        cx_id,
        report,
    })
}

fn bind_catalog_entry(
    home: &Path,
    vault: &Path,
    vault_id: VaultId,
    vault_name: &str,
) -> AnyResult<(PathBuf, Vec<u8>)> {
    let index_path = home.join("vaults").join("index.json");
    let index_bytes = fs::read(&index_path)?;
    let catalog: VaultCatalog = serde_json::from_slice(&index_bytes)?;
    let matching = catalog
        .vaults
        .iter()
        .filter(|entry| entry.name == vault_name)
        .collect::<Vec<_>>();
    require(
        matching.len() == 1,
        format!(
            "catalog must contain exactly one vault named {vault_name:?}, found {}",
            matching.len()
        ),
    )?;
    let entry = matching[0];
    require(
        entry.vault_id == vault_id,
        format!("catalog vault {vault_name:?} has a different vault_id"),
    )?;
    let catalog_path = fs::canonicalize(home.join(&entry.path))?;
    require(
        catalog_path == vault,
        format!("catalog vault {vault_name:?} resolves to a different path"),
    )?;
    Ok((index_path, index_bytes))
}

fn exercise(inputs: &Inputs) -> AnyResult<()> {
    require(
        !inputs.report.exists(),
        format!(
            "exercise report already exists: {}",
            inputs.report.display()
        ),
    )?;
    require(
        inputs.cx_id.to_string() != ABSENT_CX_ID,
        "the selected real cx_id collides with the absent edge fixture",
    )?;

    let before = inventory(&inputs.vault)?;
    require(
        fs::read(&inputs.catalog)? == inputs.catalog_bytes,
        "vault catalog changed after initial identity binding",
    )?;
    let mut server = McpServer::new();
    calyx_mcp::tools::register_all(&mut server)?;
    let authn = AuthN::InProcess {
        host_app_id: "calyx-mcp-lineage-retained-ledger-fsv".to_string(),
    };
    let vault = inputs.vault_name.clone();
    let cx_id = inputs.cx_id.to_string();

    let first_valid = exchange(&server, &authn, 1, &vault, &cx_id)?;
    let second_valid = exchange(&server, &authn, 2, &vault, &cx_id)?;
    let absent = exchange(&server, &authn, 3, &vault, ABSENT_CX_ID)?;
    let malformed = exchange(&server, &authn, 4, &vault, MALFORMED_CX_ID)?;

    let (first_text, first_lineage) = extract_lineage(&first_valid, 1)?;
    let (second_text, second_lineage) = extract_lineage(&second_valid, 2)?;
    require(
        first_text == second_text && first_lineage == second_lineage,
        "two valid lineage calls in one MCP process returned different payloads",
    )?;
    require(
        first_lineage.cx_id == cx_id,
        "valid lineage response returned a different cx_id",
    )?;
    require(
        !first_lineage.lens_measures.is_empty(),
        "the real fixture produced no measured slots",
    )?;
    require_calyx_error(&absent, 3, "CALYX_VAULT_ACCESS_DENIED")?;
    require_invalid_params(&malformed, 4)?;

    let after = inventory(&inputs.vault)?;
    require(
        before == after,
        "calyx.provenance changed the immutable vault tree",
    )?;
    require(
        fs::read(&inputs.catalog)? == inputs.catalog_bytes,
        "vault catalog changed while calyx.provenance requests were dispatched",
    )?;

    let report = ExerciseReport {
        schema: REPORT_SCHEMA.to_string(),
        home: display(&inputs.home),
        catalog: display(&inputs.catalog),
        catalog_bytes: u64::try_from(inputs.catalog_bytes.len())?,
        catalog_sha256: sha256(&inputs.catalog_bytes),
        vault: display(&inputs.vault),
        vault_id: inputs.vault_id.to_string(),
        vault_name: vault,
        cx_id,
        absent_cx_id: ABSENT_CX_ID.to_string(),
        malformed_cx_id: MALFORMED_CX_ID.to_string(),
        before,
        after,
        first_valid,
        second_valid,
        absent,
        malformed,
        lineage: first_lineage,
        lineage_text_sha256: sha256(first_text.as_bytes()),
    };
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&inputs.report)?;
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    drop(output);

    let report_bytes = fs::read(&inputs.report)?;
    let persisted: ExerciseReport = serde_json::from_slice(&report_bytes)?;
    require(persisted == report, "exercise report readback differs")?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "lineage_retained_ledger_fsv_exercise_success",
            "report": display(&inputs.report),
            "report_bytes": report_bytes.len(),
            "report_sha256": sha256(&report_bytes),
            "vault_tree_sha256": report.after.tree_sha256,
            "cx_id": report.cx_id,
            "ingest_seq": report.lineage.ingest_seq,
            "ledger_chain_hash": report.lineage.ledger_chain_hash,
            "measured_slots": report.lineage.lens_measures.len(),
            "anchors": report.lineage.anchors.len(),
        }))?
    );
    Ok(())
}

fn readback(inputs: &Inputs) -> AnyResult<()> {
    require(
        inputs.report.is_file(),
        format!("exercise report is absent: {}", inputs.report.display()),
    )?;
    let report_bytes = fs::read(&inputs.report)?;
    let report: ExerciseReport = serde_json::from_slice(&report_bytes)?;
    require(
        report.schema == REPORT_SCHEMA,
        "exercise report schema differs",
    )?;
    require(
        report.home == display(&inputs.home),
        "exercise report home differs",
    )?;
    require(
        report.catalog == display(&inputs.catalog),
        "exercise report catalog path differs",
    )?;
    require(
        report.catalog_bytes == u64::try_from(inputs.catalog_bytes.len())?
            && report.catalog_sha256 == sha256(&inputs.catalog_bytes)
            && fs::read(&inputs.catalog)? == inputs.catalog_bytes,
        "exercise report catalog identity differs",
    )?;
    require(
        report.vault == display(&inputs.vault),
        "exercise report vault differs",
    )?;
    require(
        report.vault_id == inputs.vault_id.to_string(),
        "exercise report vault_id differs",
    )?;
    require(
        report.vault_name == inputs.vault_name,
        "exercise report vault_name differs",
    )?;
    require(
        report.cx_id == inputs.cx_id.to_string(),
        "exercise report cx_id differs",
    )?;
    require(
        report.absent_cx_id == ABSENT_CX_ID && report.malformed_cx_id == MALFORMED_CX_ID,
        "exercise report edge inputs differ",
    )?;
    require_request_identity(&report.first_valid, 1, &report.vault_name, &report.cx_id)?;
    require_request_identity(&report.second_valid, 2, &report.vault_name, &report.cx_id)?;
    require_request_identity(&report.absent, 3, &report.vault_name, ABSENT_CX_ID)?;
    require_request_identity(&report.malformed, 4, &report.vault_name, MALFORMED_CX_ID)?;
    require(
        report.before == report.after,
        "exercise report records vault mutation",
    )?;
    validate_exchange_hashes(&report.first_valid)?;
    validate_exchange_hashes(&report.second_valid)?;
    validate_exchange_hashes(&report.absent)?;
    validate_exchange_hashes(&report.malformed)?;

    let (first_text, first_lineage) = extract_lineage(&report.first_valid, 1)?;
    let (second_text, second_lineage) = extract_lineage(&report.second_valid, 2)?;
    require(
        first_text == second_text
            && first_lineage == second_lineage
            && first_lineage == report.lineage,
        "persisted valid lineage exchanges are not byte- and value-stable",
    )?;
    require(
        sha256(first_text.as_bytes()) == report.lineage_text_sha256,
        "persisted lineage text hash differs",
    )?;
    require_calyx_error(&report.absent, 3, "CALYX_VAULT_ACCESS_DENIED")?;
    require_invalid_params(&report.malformed, 4)?;

    let before = inventory(&inputs.vault)?;
    require(
        before == report.after,
        "vault bytes differ from the completed exercise generation",
    )?;
    let physical = physical_readback(inputs, &first_lineage)?;
    let after = inventory(&inputs.vault)?;
    require(
        before == after,
        "independent readback changed the vault tree",
    )?;
    require(
        fs::read(&inputs.catalog)? == inputs.catalog_bytes,
        "vault catalog changed during independent readback",
    )?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "lineage_retained_ledger_fsv_readback_success",
            "report": display(&inputs.report),
            "report_bytes": report_bytes.len(),
            "report_sha256": sha256(&report_bytes),
            "vault_tree_sha256": after.tree_sha256,
            "physical": physical,
            "source_of_truth": "fresh current Base/Compression/slot resolution joined to a separately opened physical Ledger SST+read-only-WAL view and exact before/after vault-file hashes",
        }))?
    );
    Ok(())
}

fn exchange(
    server: &McpServer,
    authn: &AuthN,
    id: i64,
    vault: &str,
    cx_id: &str,
) -> AnyResult<Exchange> {
    let request = request_value(id, vault, cx_id);
    let request_bytes = serde_json::to_vec(&request)?;
    let decoded = decode_jsonrpc_request(&request_bytes)?;
    let response = serde_json::to_value(server.dispatch_with_authn(decoded, Some(authn)))?;
    let response_bytes = serde_json::to_vec(&response)?;
    Ok(Exchange {
        request,
        request_sha256: sha256(&request_bytes),
        response,
        response_sha256: sha256(&response_bytes),
    })
}

fn request_value(id: i64, vault: &str, cx_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "calyx.provenance",
            "arguments": { "vault": vault, "cx_id": cx_id },
        },
    })
}

fn require_request_identity(
    exchange: &Exchange,
    id: i64,
    vault: &str,
    cx_id: &str,
) -> AnyResult<()> {
    require(
        exchange.request == request_value(id, vault, cx_id),
        format!("persisted request {id} identity differs"),
    )
}

fn extract_lineage(exchange: &Exchange, id: i64) -> AnyResult<(String, LineagePayload)> {
    require_response_identity(&exchange.response, id)?;
    require(
        exchange.response.get("error").is_none(),
        format!("request {id} unexpectedly returned an error"),
    )?;
    let content = exchange
        .response
        .pointer("/result/content")
        .and_then(Value::as_array)
        .ok_or_else(|| fsv_error(format!("request {id} has no MCP content array")))?;
    require(
        content.len() == 1,
        format!("request {id} content cardinality differs"),
    )?;
    require(
        content[0].get("type").and_then(Value::as_str) == Some("text"),
        format!("request {id} content is not text"),
    )?;
    let text = content[0]
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| fsv_error(format!("request {id} text payload is absent")))?
        .to_string();
    let lineage = serde_json::from_str(&text)?;
    Ok((text, lineage))
}

fn require_calyx_error(exchange: &Exchange, id: i64, expected_code: &str) -> AnyResult<()> {
    require_response_identity(&exchange.response, id)?;
    require(
        exchange.response.get("result").is_none(),
        format!("request {id} unexpectedly returned a result"),
    )?;
    require(
        exchange
            .response
            .pointer("/error/code")
            .and_then(Value::as_i64)
            == Some(-32000),
        format!("request {id} did not return JSON-RPC Calyx error -32000"),
    )?;
    require(
        exchange
            .response
            .pointer("/error/data/calyx_code")
            .and_then(Value::as_str)
            == Some(expected_code),
        format!("request {id} returned a different Calyx error code"),
    )
}

fn require_invalid_params(exchange: &Exchange, id: i64) -> AnyResult<()> {
    require_response_identity(&exchange.response, id)?;
    require(
        exchange.response.get("result").is_none(),
        format!("request {id} unexpectedly returned a result"),
    )?;
    require(
        exchange
            .response
            .pointer("/error/code")
            .and_then(Value::as_i64)
            == Some(-32602),
        format!("request {id} did not return JSON-RPC invalid params -32602"),
    )
}

fn require_response_identity(response: &Value, id: i64) -> AnyResult<()> {
    require(
        response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && response.get("id").and_then(Value::as_i64) == Some(id),
        format!("response identity differs for request {id}"),
    )
}

fn validate_exchange_hashes(exchange: &Exchange) -> AnyResult<()> {
    require(
        sha256(&serde_json::to_vec(&exchange.request)?) == exchange.request_sha256,
        "persisted request hash differs",
    )?;
    require(
        sha256(&serde_json::to_vec(&exchange.response)?) == exchange.response_sha256,
        "persisted response hash differs",
    )
}

fn physical_readback(inputs: &Inputs, actual: &LineagePayload) -> AnyResult<PhysicalReadback> {
    let salt = format!("calyx-cli-vault:{}:{}", inputs.vault_id, inputs.vault_name).into_bytes();
    let base_vault: AsterVault = AsterVault::open(
        &inputs.vault,
        inputs.vault_id,
        salt.clone(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(vec![ColumnFamily::Base]),
            ..VaultOptions::default()
        },
    )?;
    let snapshot_seq = base_vault.latest_seq();
    let state = load_vault_panel_state(&inputs.vault)?;
    let base_bytes = base_vault
        .read_cf_at(snapshot_seq, ColumnFamily::Base, &base_key(inputs.cx_id))?
        .ok_or_else(|| fsv_error("selected cx_id is absent from the physical Base CF"))?;
    let base = BaseRecord::decode_for_key(inputs.cx_id, &base_bytes)?;
    require(
        base.vault_id() == inputs.vault_id,
        "physical Base row vault_id differs",
    )?;
    let slot_ids = base.slot_hashes().keys().copied().collect::<BTreeSet<_>>();
    let mut selected_names = vec![ColumnFamily::Base.name()];
    let mut measured_slots = BTreeSet::new();
    if !slot_ids.is_empty() {
        let mut selected_cfs = Vec::with_capacity(1_usize.saturating_add(slot_ids.len()));
        selected_cfs.push(ColumnFamily::Compression);
        selected_cfs.extend(slot_ids.iter().copied().map(ColumnFamily::slot));
        selected_names.extend(selected_cfs.iter().map(ColumnFamily::name));
        let vault: AsterVault = AsterVault::open(
            &inputs.vault,
            inputs.vault_id,
            salt,
            VaultOptions {
                restore_mvcc_rows: false,
                restore_ledger_hook: false,
                read_only: true,
                selected_cfs: Some(selected_cfs),
                ..VaultOptions::default()
            },
        )?;
        require(
            vault.latest_seq() == snapshot_seq,
            "slot-resolution snapshot changed while the retained Base reader was held",
        )?;
        for slot_id in &slot_ids {
            let vector = state
                .resolve_slot_vector_at(&vault, snapshot_seq, inputs.cx_id, *slot_id)?
                .ok_or_else(|| {
                    fsv_error(format!(
                        "slot {} Base declaration has no physical row",
                        slot_id.get()
                    ))
                })?;
            if !vector.is_absent() {
                measured_slots.insert(*slot_id);
            }
        }
        drop(vault);
    }
    let stored = base.constellation();
    drop(base_vault);

    let physical = AsterLedgerCfStore::open(&inputs.vault)?;
    let rows = physical.scan()?;
    let head = physical
        .head_anchor()?
        .ok_or_else(|| fsv_error("physical Ledger head anchor is absent"))?;
    let height = u64::try_from(rows.len())?;
    require(
        head.height == height,
        "physical Ledger height differs from its head anchor",
    )?;

    let mut entries = Vec::with_capacity(rows.len());
    let mut expected_prev = [0_u8; 32];
    for (index, row) in rows.iter().enumerate() {
        let expected_seq = u64::try_from(index)?;
        require(
            row.seq == expected_seq,
            format!("physical Ledger row {index} is non-contiguous"),
        )?;
        let entry = decode(&row.bytes)?;
        require(
            entry.seq == row.seq,
            format!("physical Ledger row {} key/entry differs", row.seq),
        )?;
        require(
            entry.prev_hash == expected_prev && entry.verify(),
            format!("physical Ledger row {} hash chain is broken", row.seq),
        )?;
        expected_prev = entry.entry_hash;
        entries.push(entry);
    }
    require(
        expected_prev == head.tip_hash,
        "physical Ledger tip differs from its external head anchor",
    )?;

    let base_entry = entries
        .iter()
        .find(|entry| entry.seq == stored.provenance.seq)
        .ok_or_else(|| fsv_error("Base provenance sequence is absent from physical Ledger"))?;
    require(
        base_entry.entry_hash == stored.provenance.hash,
        "Base provenance hash differs from physical Ledger",
    )?;
    require(
        matches!(&base_entry.subject, SubjectId::Cx(id) if id == &inputs.cx_id),
        "Base provenance Ledger subject differs",
    )?;

    let ingest = entries
        .iter()
        .filter(|entry| {
            entry.kind == EntryKind::Ingest
                && matches!(&entry.subject, SubjectId::Cx(id) if id == &inputs.cx_id)
                && payload(entry)
                    .get("anchor_kind")
                    .and_then(Value::as_str)
                    .is_none()
        })
        .min_by_key(|entry| entry.seq)
        .ok_or_else(|| fsv_error("physical Ledger has no non-anchor ingest for the cx_id"))?;

    let lens_measures = state
        .panel
        .slots
        .iter()
        .filter(|slot| measured_slots.contains(&slot.slot_id))
        .map(|slot| LensMeasure {
            slot: slot.slot_id.get(),
            lens_id: slot.lens_id.to_string(),
            measured_at: stored.created_at,
        })
        .collect::<Vec<_>>();
    let anchors = expected_anchors(inputs.cx_id, ingest.seq, &stored.anchors, &entries)?;
    let expected = LineagePayload {
        cx_id: inputs.cx_id.to_string(),
        ingest_seq: ingest.seq,
        ledger_chain_hash: hex(&ingest.entry_hash),
        lens_measures,
        anchors,
    };
    require(
        &expected == actual,
        "MCP lineage payload differs from independent current-state/physical-Ledger join",
    )?;

    Ok(PhysicalReadback {
        snapshot_seq,
        selected_cfs: selected_names,
        ledger_rows: rows.len(),
        ledger_head_height: head.height,
        ledger_head_tip_hash: hex(&head.tip_hash),
        base_provenance_seq: stored.provenance.seq,
        base_provenance_hash: hex(&stored.provenance.hash),
        ingest_seq: ingest.seq,
        ingest_hash: hex(&ingest.entry_hash),
        measured_slots: expected.lens_measures.len(),
        anchors: expected.anchors.len(),
    })
}

fn expected_anchors(
    cx_id: CxId,
    ingest_seq: u64,
    anchors: &[calyx_core::Anchor],
    entries: &[LedgerEntry],
) -> AnyResult<Vec<AnchorEvidence>> {
    let mut used = BTreeSet::new();
    let mut expected = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        let kind = anchor_kind(&anchor.kind);
        let entry = entries
            .iter()
            .find(|entry| {
                if used.contains(&entry.seq)
                    || entry.seq <= ingest_seq
                    || entry.kind != EntryKind::Ingest
                    || !matches!(&entry.subject, SubjectId::Cx(id) if id == &cx_id)
                {
                    return false;
                }
                let payload = payload(entry);
                let mode = payload.get("mode").and_then(Value::as_str);
                let exact_mode = mode == Some("mcp-anchor") || mode == Some("cli-anchor");
                exact_mode
                    && payload.get("anchor_kind").and_then(Value::as_str) == Some(kind.as_str())
            })
            .ok_or_else(|| fsv_error(format!("anchor {kind} has no exact physical Ledger row")))?;
        used.insert(entry.seq);
        expected.push(AnchorEvidence {
            kind,
            ledger_seq: entry.seq,
        });
    }
    Ok(expected)
}

fn anchor_kind(kind: &AnchorKind) -> String {
    match kind {
        AnchorKind::TestPass => "test_pass".to_string(),
        AnchorKind::TieFormed => "tie_formed".to_string(),
        AnchorKind::Thumbs => "thumbs".to_string(),
        AnchorKind::Label(value) => format!("label:{value}"),
        AnchorKind::Reward => "reward".to_string(),
        AnchorKind::SpeakerMatch => "speaker_match".to_string(),
        AnchorKind::StyleHold => "style_hold".to_string(),
        AnchorKind::Recurrence => "recurrence".to_string(),
    }
}

fn payload(entry: &LedgerEntry) -> Value {
    serde_json::from_slice(&entry.payload).unwrap_or_else(|_| json!({}))
}

fn inventory(root: &Path) -> AnyResult<TreeInventory> {
    let root = fs::canonicalize(root)?;
    let mut entries = Vec::new();
    collect_inventory(&root, &root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let files = entries.iter().filter(|entry| entry.kind == "file").count();
    let directories = entries
        .iter()
        .filter(|entry| entry.kind == "directory")
        .count();
    let bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .ok_or_else(|| fsv_error("vault inventory byte count overflow"))
    })?;
    let tree_sha256 = sha256(&serde_json::to_vec(&entries)?);
    Ok(TreeInventory {
        files,
        directories,
        bytes,
        entries,
        tree_sha256,
    })
}

fn collect_inventory(
    root: &Path,
    directory: &Path,
    out: &mut Vec<InventoryEntry>,
) -> AnyResult<()> {
    let mut children = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    for child in children {
        let metadata = fs::symlink_metadata(&child)?;
        require(
            !metadata.file_type().is_symlink(),
            format!("vault inventory rejects symbolic link: {}", child.display()),
        )?;
        let path = relative(root, &child)?;
        if metadata.is_dir() {
            out.push(InventoryEntry {
                path,
                kind: "directory".to_string(),
                bytes: 0,
                sha256: None,
            });
            collect_inventory(root, &child, out)?;
        } else if metadata.is_file() {
            let contents = fs::read(&child)?;
            require(
                u64::try_from(contents.len())? == metadata.len(),
                format!(
                    "vault file length changed while reading: {}",
                    child.display()
                ),
            )?;
            out.push(InventoryEntry {
                path,
                kind: "file".to_string(),
                bytes: metadata.len(),
                sha256: Some(sha256(&contents)),
            });
        } else {
            return Err(fsv_error(format!(
                "vault inventory rejects non-file entry: {}",
                child.display()
            )));
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> AnyResult<String> {
    let relative = path.strip_prefix(root)?;
    let value = relative
        .to_str()
        .ok_or_else(|| fsv_error(format!("vault path is not Unicode: {}", path.display())))?;
    Ok(value.replace('\\', "/"))
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(fsv_error(message))
    }
}

fn fsv_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}
