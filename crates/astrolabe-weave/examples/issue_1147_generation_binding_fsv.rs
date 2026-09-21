//! Manual Full State Verification for #1147's latest-only Weave binding.
//!
//! `execute` creates a durable Aster vault, reopens it in the same latest-only
//! mode used by shadow import, proves one bound raw Slot read, mutates that
//! exact physical row, and proves the stale binding refuses without another
//! mutation. `readback` is a separate process that independently reopens the
//! narrow Slot, Compression, Kv, Ledger, and TimeIndex projection and verifies
//! the final source row, disjoint derived row, and provenance chain.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use astrolabe_weave::{ASTRO_WEAVE_SLOT_BINDING_CHANGED, WeaveSlotBinding, WeaveSlotSource};
use calyx_aster::cf::{ColumnFamily, compression_manifest_key, ledger_key, slot_key};
use calyx_aster::vault::encode::encode_slot_vector;
use calyx_aster::vault::{AsterVault, VaultOptions, decode_strict_raw_slot_value};
use calyx_core::{CxId, LedgerRef, SlotId, SlotVector, VaultId};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode as decode_ledger};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SALT: &[u8] = b"astrolabe-issue-1147-generation-binding-v1";
const SLOT: u16 = 23;
const CX_BYTES: [u8; 16] = [0x47; 16];
const INITIAL_ACTOR: &str = "astrolabe-issue-1147-fsv-initial";
const DERIVED_ACTOR: &str = "astrolabe-issue-1147-fsv-derived";
const MUTATION_ACTOR: &str = "astrolabe-issue-1147-fsv-mutation";
const DERIVED_KEY: &[u8] = b"astrolabe:issue-1147:derived-sequence-crossing";
const DERIVED_VALUE: &[u8] = b"lawful-disjoint-derived-state-v1";

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> AnyResult<Vec<u8>> {
    require(
        value.len().is_multiple_of(2),
        "ISSUE_1147_HEX_LENGTH_INVALID",
        value.len(),
    )?;
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let digits = std::str::from_utf8(pair)?;
        decoded.push(u8::from_str_radix(digits, 16)?);
    }
    require(
        hex_lower(&decoded) == value,
        "ISSUE_1147_HEX_NOT_CANONICAL_LOWER",
        value,
    )?;
    Ok(decoded)
}

fn require(condition: bool, code: &str, evidence: impl serde::Serialize) -> AnyResult<()> {
    if condition {
        return Ok(());
    }
    Err(format!("{code}: {}", serde_json::to_string(&evidence)?).into())
}

fn stable_relative(root: &Path, path: &Path) -> AnyResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_str()
        .ok_or("ISSUE_1147_TREE_PATH_NON_UNICODE")?
        .replace('\\', "/"))
}

fn collect_tree(
    root: &Path,
    current: &Path,
    entries: &mut BTreeMap<String, Value>,
) -> AnyResult<()> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        let relative = stable_relative(root, &path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("ISSUE_1147_TREE_REPARSE_REFUSED: {relative}").into());
        }
        if metadata.is_dir() {
            entries.insert(relative, json!({"kind":"directory"}));
            collect_tree(root, &path, entries)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            require(
                metadata.len() == u64::try_from(bytes.len())?,
                "ISSUE_1147_TREE_LENGTH_CHANGED",
                json!({"path":relative,"metadata":metadata.len(),"read":bytes.len()}),
            )?;
            entries.insert(
                relative,
                json!({
                    "kind":"file",
                    "bytes":bytes.len(),
                    "sha256":sha256(&bytes),
                }),
            );
        } else {
            return Err(format!("ISSUE_1147_TREE_TYPE_REFUSED: {relative}").into());
        }
    }
    Ok(())
}

fn tree_state(root: &Path) -> AnyResult<Value> {
    require(
        root.try_exists()?,
        "ISSUE_1147_TREE_MISSING",
        root.display().to_string(),
    )?;
    let metadata = fs::symlink_metadata(root)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "ISSUE_1147_TREE_ROOT_INVALID",
        root.display().to_string(),
    )?;
    let mut entries = BTreeMap::new();
    collect_tree(root, root, &mut entries)?;
    let canonical = serde_json::to_vec(&entries)?;
    Ok(json!({
        "entry_count":entries.len(),
        "canonical_bytes":canonical.len(),
        "sha256":sha256(&canonical),
        "entries":entries,
    }))
}

fn vector_state(vector: &SlotVector) -> Value {
    match vector {
        SlotVector::Dense { dim, data } => json!({
            "kind":"dense",
            "dim":dim,
            "bits":data.iter().map(|value| value.to_bits()).collect::<Vec<_>>(),
        }),
        SlotVector::Multi { token_dim, tokens } => json!({
            "kind":"multi",
            "token_dim":token_dim,
            "bits":tokens.iter().map(|token| token.iter().map(|value| value.to_bits()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        }),
        SlotVector::Sparse { dim, entries } => json!({
            "kind":"sparse",
            "dim":dim,
            "entries":entries.iter().map(|entry| json!({"idx":entry.idx,"bits":entry.val.to_bits()})).collect::<Vec<_>>(),
        }),
        SlotVector::Absent { reason } => json!({
            "kind":"absent",
            "reason":reason,
        }),
    }
}

fn ledger_payload(phase: &str, row_bytes: &[u8]) -> AnyResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "schema":"astrolabe.issue-1147.slot-mutation-ledger.v1",
        "phase":phase,
        "slot":SLOT,
        "cx_id":CxId::from_bytes(CX_BYTES).to_string(),
        "row_bytes":row_bytes.len(),
        "row_sha256":sha256(row_bytes),
    }))?)
}

struct LedgerExpectation<'a> {
    label: &'a str,
    reference: &'a LedgerRef,
    kind: EntryKind,
    subject: &'a SubjectId,
    actor: &'a ActorId,
    payload: &'a [u8],
}

fn physical_ledger_evidence(
    vault: &AsterVault,
    expectations: &[LedgerExpectation<'_>],
) -> AnyResult<Value> {
    require(
        !expectations.is_empty(),
        "ISSUE_1147_LEDGER_EXPECTATIONS_EMPTY",
        json!({}),
    )?;
    let wanted = expectations
        .iter()
        .map(|expected| expected.reference.seq)
        .collect::<BTreeSet<_>>();
    require(
        wanted.len() == expectations.len(),
        "ISSUE_1147_LEDGER_REFERENCE_DUPLICATE",
        &wanted,
    )?;
    let (rows, trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let resolved = trace.tiers.iter().map(|tier| tier.resolved).sum::<usize>();
    let complete_scan_wanted = trace
        .tiers
        .iter()
        .filter(|tier| tier.tier == "complete_scan")
        .map(|tier| tier.wanted)
        .sum::<usize>();
    require(
        rows.len() == expectations.len()
            && resolved == expectations.len()
            && complete_scan_wanted == 0,
        "ISSUE_1147_PHYSICAL_LEDGER_POINT_READ_INCOMPLETE",
        json!({
            "wanted":wanted,
            "rows":rows.len(),
            "resolved":resolved,
            "complete_scan_wanted":complete_scan_wanted,
            "trace":trace,
        }),
    )?;

    let mut evidence = Vec::with_capacity(expectations.len());
    for expected in expectations {
        let row = rows
            .get(&expected.reference.seq)
            .ok_or("ISSUE_1147_PHYSICAL_LEDGER_ROW_MISSING")?;
        let entry = decode_ledger(&row.bytes)?;
        require(
            row.seq == expected.reference.seq
                && entry.seq == expected.reference.seq
                && entry.entry_hash == expected.reference.hash
                && entry.verify()
                && entry.kind == expected.kind
                && entry.subject == *expected.subject
                && entry.actor == *expected.actor
                && entry.payload == expected.payload,
            "ISSUE_1147_PHYSICAL_LEDGER_ROW_MISMATCH",
            json!({
                "label":expected.label,
                "reference":expected.reference,
                "physical_row_seq":row.seq,
                "decoded":entry,
                "expected_kind":expected.kind,
                "expected_subject":expected.subject,
                "expected_actor":expected.actor,
                "expected_payload_bytes":expected.payload.len(),
                "expected_payload_sha256":sha256(expected.payload),
            }),
        )?;
        evidence.push(json!({
            "label":expected.label,
            "reference":expected.reference,
            "physical_row_bytes":row.bytes.len(),
            "physical_row_sha256":sha256(&row.bytes),
            "entry":entry,
            "payload_bytes":expected.payload.len(),
            "payload_sha256":sha256(expected.payload),
        }));
    }
    Ok(json!({
        "wanted_seqs":wanted,
        "point_read_trace":trace,
        "complete_scan_wanted":complete_scan_wanted,
        "rows":evidence,
    }))
}

fn physical_commit_evidence(
    vault: &AsterVault,
    commit_seq: u64,
    data_cf: ColumnFamily,
    data_key: &[u8],
    data_value: &[u8],
    ledger_ref: &LedgerRef,
) -> AnyResult<Value> {
    let mut expected_cfs = vec![data_cf, ColumnFamily::Ledger, ColumnFamily::TimeIndex];
    expected_cfs.sort();
    let inventory = vault.physical_commit_inventory(commit_seq, &expected_cfs)?;
    let ledger_bytes = vault
        .read_cf_at(
            vault.latest_seq(),
            ColumnFamily::Ledger,
            &ledger_key(ledger_ref.seq),
        )?
        .ok_or("ISSUE_1147_COMMIT_LEDGER_ROW_MISSING")?;
    let decoded_ledger = decode_ledger(&ledger_bytes)?;
    require(
        decoded_ledger.seq == ledger_ref.seq
            && decoded_ledger.entry_hash == ledger_ref.hash
            && decoded_ledger.verify(),
        "ISSUE_1147_COMMIT_LEDGER_DECODED_REFERENCE_MISMATCH",
        json!({
            "commit_seq":commit_seq,
            "reference":ledger_ref,
            "decoded":decoded_ledger,
            "physical_row_bytes":ledger_bytes.len(),
            "physical_row_sha256":sha256(&ledger_bytes),
        }),
    )?;
    let data_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == data_cf)
        .collect::<Vec<_>>();
    let ledger_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Ledger)
        .collect::<Vec<_>>();
    let time_index_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::TimeIndex)
        .collect::<Vec<_>>();
    let expected_ledger_key = ledger_key(ledger_ref.seq);
    let expected_time_index_value = [0_u8];
    let expected_time_index_suffix = commit_seq.to_be_bytes();
    require(
        inventory.seq == commit_seq
            && inventory.column_families == expected_cfs
            && inventory.rows.len() == 3
            && inventory.total_physical_bytes > 0
            && !inventory.components.is_empty()
            && data_rows.len() == 1
            && data_rows[0].key == data_key
            && data_rows[0].value_length == u64::try_from(data_value.len())?
            && data_rows[0].value_sha256_hex() == sha256(data_value)
            && !data_rows[0].tombstoned
            && ledger_rows.len() == 1
            && ledger_rows[0].key == expected_ledger_key
            && ledger_rows[0].value_length == u64::try_from(ledger_bytes.len())?
            && ledger_rows[0].value_sha256_hex() == sha256(&ledger_bytes)
            && !ledger_rows[0].tombstoned
            && time_index_rows.len() == 1
            && time_index_rows[0].key.len() == 16
            && time_index_rows[0].key[8..] == expected_time_index_suffix
            && time_index_rows[0].value_length == u64::try_from(expected_time_index_value.len())?
            && time_index_rows[0].value_sha256_hex() == sha256(&expected_time_index_value)
            && !time_index_rows[0].tombstoned,
        "ISSUE_1147_PHYSICAL_COMMIT_INVENTORY_MISMATCH",
        format!("{inventory:#?}"),
    )?;
    Ok(json!({
        "commit_seq":commit_seq,
        "manifest_seq":inventory.manifest_seq,
        "column_families":inventory.column_families.iter().map(|cf| cf.name()).collect::<Vec<_>>(),
        "rows":inventory.rows.iter().map(|row| json!({
            "ordinal":row.ordinal,
            "cf":row.cf.name(),
            "key_hex":row.key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "key_sha256":row.key_sha256_hex(),
            "value_length":row.value_length,
            "value_sha256":row.value_sha256_hex(),
            "tombstoned":row.tombstoned,
        })).collect::<Vec<_>>(),
        "components":inventory.components.iter().map(|component| json!({
            "role":format!("{:?}",component.role),
            "identity":component.canonical_identity(),
            "length":component.length,
            "sha256":component.sha256_hex(),
        })).collect::<Vec<_>>(),
        "total_physical_bytes":inventory.total_physical_bytes,
        "exact_column_family_roster_verified":true,
        "exact_three_row_roster_verified":true,
        "exact_data_row_verified":true,
        "exact_ledger_row_verified":true,
        "decoded_ledger_reference_verified":true,
        "exact_time_index_row_verified":true,
        "decoded_ledger":decoded_ledger,
        "time_index":{
            "key_hex":hex_lower(&time_index_rows[0].key),
            "commit_seq_suffix_hex":hex_lower(&expected_time_index_suffix),
            "value_length":time_index_rows[0].value_length,
            "value_sha256":time_index_rows[0].value_sha256_hex(),
            "sentinel_hex":hex_lower(&expected_time_index_value),
        },
    }))
}

fn physical_ledger_chain_segment(vault: &AsterVault, refs: &[LedgerRef]) -> AnyResult<Value> {
    require(!refs.is_empty(), "ISSUE_1147_LEDGER_CHAIN_EMPTY", json!({}))?;
    let wanted = refs
        .iter()
        .map(|reference| reference.seq)
        .collect::<BTreeSet<_>>();
    require(
        wanted.len() == refs.len(),
        "ISSUE_1147_LEDGER_CHAIN_REFERENCE_DUPLICATE",
        json!({"references":refs,"wanted":wanted}),
    )?;
    let (rows, trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let resolved = trace.tiers.iter().map(|tier| tier.resolved).sum::<usize>();
    let complete_scan_wanted = trace
        .tiers
        .iter()
        .filter(|tier| tier.tier == "complete_scan")
        .map(|tier| tier.wanted)
        .sum::<usize>();
    require(
        rows.len() == refs.len() && resolved == refs.len() && complete_scan_wanted == 0,
        "ISSUE_1147_LEDGER_CHAIN_POINT_READ_INCOMPLETE",
        json!({
            "references":refs,
            "wanted":wanted,
            "rows":rows.len(),
            "resolved":resolved,
            "complete_scan_wanted":complete_scan_wanted,
            "trace":trace,
        }),
    )?;
    let mut entries = Vec::with_capacity(refs.len());
    for (ordinal, reference) in refs.iter().enumerate() {
        let row = rows
            .get(&reference.seq)
            .ok_or("ISSUE_1147_LEDGER_CHAIN_ROW_MISSING")?;
        let entry = decode_ledger(&row.bytes)?;
        let linked = if ordinal == 0 {
            reference.seq == 0 && entry.prev_hash == [0_u8; 32]
        } else {
            refs[ordinal - 1].seq.checked_add(1) == Some(reference.seq)
                && entry.prev_hash == refs[ordinal - 1].hash
        };
        require(
            row.seq == reference.seq
                && entry.seq == reference.seq
                && entry.entry_hash == reference.hash
                && entry.verify()
                && linked,
            "ISSUE_1147_LEDGER_CHAIN_SEGMENT_BROKEN",
            json!({
                "ordinal":ordinal,
                "reference":reference,
                "physical_row_seq":row.seq,
                "physical_row_bytes":row.bytes.len(),
                "physical_row_sha256":sha256(&row.bytes),
                "entry":entry,
                "linked":linked,
            }),
        )?;
        entries.push(json!({
            "seq":entry.seq,
            "physical_row_bytes":row.bytes.len(),
            "physical_row_sha256":sha256(&row.bytes),
            "prev_hash":entry.prev_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "entry_hash":entry.entry_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "self_verified":true,
        }));
    }
    Ok(json!({
        "entries":entries,
        "point_read_trace":trace,
        "resolved":resolved,
        "complete_scan_wanted":complete_scan_wanted,
        "complete_point_read":true,
        "contiguous":true,
        "full_from_genesis":true,
    }))
}

struct CommitReceiptExpectation<'a> {
    label: &'a str,
    commit_seq: u64,
    data_cf: ColumnFamily,
    data_key: &'a [u8],
    data_value: &'a [u8],
    ledger_ref: &'a LedgerRef,
}

fn bind_execute_commit_receipt(
    vault: &AsterVault,
    receipt: &Value,
    expected: &CommitReceiptExpectation<'_>,
) -> AnyResult<Value> {
    let mut expected_cfs = [
        expected.data_cf,
        ColumnFamily::Ledger,
        ColumnFamily::TimeIndex,
    ];
    expected_cfs.sort();
    let expected_cf_names = expected_cfs.iter().map(|cf| cf.name()).collect::<Vec<_>>();
    let rows = receipt["rows"]
        .as_array()
        .ok_or("ISSUE_1147_COMMIT_RECEIPT_ROWS_MISSING")?;
    let components = receipt["components"]
        .as_array()
        .ok_or("ISSUE_1147_COMMIT_RECEIPT_COMPONENTS_MISSING")?;
    require(
        receipt["commit_seq"].as_u64() == Some(expected.commit_seq)
            && receipt["column_families"] == serde_json::to_value(&expected_cf_names)?
            && rows.len() == 3
            && !components.is_empty()
            && receipt["total_physical_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
            && expected.ledger_ref.seq.checked_add(1) == Some(expected.commit_seq),
        "ISSUE_1147_COMMIT_RECEIPT_OUTER_BINDING_MISMATCH",
        json!({
            "label":expected.label,
            "expected_commit_seq":expected.commit_seq,
            "expected_column_families":expected_cf_names,
            "expected_ledger_ref":expected.ledger_ref,
            "receipt":receipt,
        }),
    )?;

    let mut ordinals = BTreeSet::new();
    for row in rows {
        let ordinal = row["ordinal"]
            .as_u64()
            .ok_or("ISSUE_1147_COMMIT_RECEIPT_ORDINAL_MISSING")?;
        require(
            ordinals.insert(ordinal),
            "ISSUE_1147_COMMIT_RECEIPT_ORDINAL_DUPLICATE",
            json!({"label":expected.label,"ordinal":ordinal}),
        )?;
    }
    require(
        ordinals == BTreeSet::from([0_u64, 1, 2]),
        "ISSUE_1147_COMMIT_RECEIPT_ORDINAL_ROSTER_MISMATCH",
        json!({"label":expected.label,"ordinals":ordinals}),
    )?;

    let data_cf_name = expected.data_cf.name();
    let ledger_cf_name = ColumnFamily::Ledger.name();
    let time_index_cf_name = ColumnFamily::TimeIndex.name();
    let data_rows = rows
        .iter()
        .filter(|row| row["cf"].as_str() == Some(data_cf_name.as_str()))
        .collect::<Vec<_>>();
    let ledger_rows = rows
        .iter()
        .filter(|row| row["cf"].as_str() == Some(ledger_cf_name.as_str()))
        .collect::<Vec<_>>();
    let time_index_rows = rows
        .iter()
        .filter(|row| row["cf"].as_str() == Some(time_index_cf_name.as_str()))
        .collect::<Vec<_>>();
    require(
        data_rows.len() == 1 && ledger_rows.len() == 1 && time_index_rows.len() == 1,
        "ISSUE_1147_COMMIT_RECEIPT_ROW_ROSTER_MISMATCH",
        json!({
            "label":expected.label,
            "data_rows":data_rows.len(),
            "ledger_rows":ledger_rows.len(),
            "time_index_rows":time_index_rows.len(),
            "rows":rows,
        }),
    )?;

    let data_row = data_rows[0];
    let expected_data_key_hex = hex_lower(expected.data_key);
    let expected_data_sha256 = sha256(expected.data_value);
    require(
        data_row["key_hex"].as_str() == Some(expected_data_key_hex.as_str())
            && data_row["key_sha256"].as_str() == Some(sha256(expected.data_key).as_str())
            && data_row["value_length"].as_u64() == Some(u64::try_from(expected.data_value.len())?)
            && data_row["value_sha256"].as_str() == Some(expected_data_sha256.as_str())
            && data_row["tombstoned"] == Value::Bool(false),
        "ISSUE_1147_COMMIT_RECEIPT_DATA_ROW_MISMATCH",
        json!({"label":expected.label,"row":data_row}),
    )?;

    let expected_ledger_key = ledger_key(expected.ledger_ref.seq);
    let ledger_bytes = vault
        .read_cf_at(
            vault.latest_seq(),
            ColumnFamily::Ledger,
            &expected_ledger_key,
        )?
        .ok_or("ISSUE_1147_COMMIT_RECEIPT_LEDGER_ROW_MISSING")?;
    let decoded_ledger = decode_ledger(&ledger_bytes)?;
    let ledger_row = ledger_rows[0];
    let ledger_sha256 = sha256(&ledger_bytes);
    require(
        decoded_ledger.seq == expected.ledger_ref.seq
            && decoded_ledger.entry_hash == expected.ledger_ref.hash
            && decoded_ledger.verify()
            && ledger_row["key_hex"].as_str() == Some(hex_lower(&expected_ledger_key).as_str())
            && ledger_row["key_sha256"].as_str() == Some(sha256(&expected_ledger_key).as_str())
            && ledger_row["value_length"].as_u64() == Some(u64::try_from(ledger_bytes.len())?)
            && ledger_row["value_sha256"].as_str() == Some(ledger_sha256.as_str())
            && ledger_row["tombstoned"] == Value::Bool(false),
        "ISSUE_1147_COMMIT_RECEIPT_LEDGER_ROW_MISMATCH",
        json!({
            "label":expected.label,
            "reference":expected.ledger_ref,
            "decoded":decoded_ledger,
            "row":ledger_row,
            "reopened_bytes":ledger_bytes.len(),
            "reopened_sha256":ledger_sha256,
        }),
    )?;

    let time_index_row = time_index_rows[0];
    let time_index_key_hex = time_index_row["key_hex"]
        .as_str()
        .ok_or("ISSUE_1147_COMMIT_RECEIPT_TIME_INDEX_KEY_MISSING")?;
    let time_index_key = decode_hex(time_index_key_hex)?;
    let commit_seq_suffix = expected.commit_seq.to_be_bytes();
    let sentinel = [0_u8];
    let reopened_time_index = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::TimeIndex, &time_index_key)?
        .ok_or("ISSUE_1147_COMMIT_RECEIPT_TIME_INDEX_ROW_MISSING")?;
    require(
        time_index_key.len() == 16
            && &time_index_key[8..] == commit_seq_suffix.as_slice()
            && time_index_row["key_sha256"].as_str() == Some(sha256(&time_index_key).as_str())
            && time_index_row["value_length"].as_u64() == Some(1)
            && time_index_row["value_sha256"].as_str() == Some(sha256(&sentinel).as_str())
            && time_index_row["tombstoned"] == Value::Bool(false)
            && reopened_time_index == sentinel,
        "ISSUE_1147_COMMIT_RECEIPT_TIME_INDEX_ROW_MISMATCH",
        json!({
            "label":expected.label,
            "commit_seq":expected.commit_seq,
            "row":time_index_row,
            "reopened_value_hex":hex_lower(&reopened_time_index),
        }),
    )?;

    Ok(json!({
        "label":expected.label,
        "commit_seq":expected.commit_seq,
        "column_families":expected_cf_names,
        "exact_three_row_roster_verified":true,
        "data_row":{
            "cf":data_cf_name,
            "key_hex":expected_data_key_hex,
            "value_length":expected.data_value.len(),
            "value_sha256":expected_data_sha256,
        },
        "ledger_row":{
            "reference":expected.ledger_ref,
            "physical_row_bytes":ledger_bytes.len(),
            "physical_row_sha256":ledger_sha256,
            "decoded_self_verified":true,
        },
        "time_index_row":{
            "key_hex":time_index_key_hex,
            "commit_seq_suffix_hex":hex_lower(&commit_seq_suffix),
            "reopened_sentinel_hex":hex_lower(&reopened_time_index),
        },
    }))
}

fn source_state(
    vault: &AsterVault,
    vault_dir: &Path,
    slot: SlotId,
    cx_id: CxId,
) -> AnyResult<Value> {
    let snapshot = vault.latest_seq();
    let key = slot_key(cx_id);
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::slot(slot), &key)?
        .ok_or("ISSUE_1147_PHYSICAL_SLOT_ROW_MISSING")?;
    let compression_key = compression_manifest_key(slot);
    let compression_manifest =
        vault.read_cf_at(snapshot, ColumnFamily::Compression, &compression_key)?;
    let decoded = decode_strict_raw_slot_value(slot, cx_id, &bytes)?;
    Ok(json!({
        "snapshot_seq":snapshot,
        "slot_cf_generation":vault.cf_content_generation(ColumnFamily::slot(slot))?,
        "compression_cf_generation":vault.cf_content_generation(ColumnFamily::Compression)?,
        "compression_manifest":{
            "key_hex":compression_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "present":compression_manifest.is_some(),
            "bytes":compression_manifest.as_ref().map(Vec::len),
            "sha256":compression_manifest.as_ref().map(|value| sha256(value)),
        },
        "storage":vault.latest_only_readback_status(),
        "row":{
            "cf":ColumnFamily::slot(slot).name(),
            "key_hex":key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "bytes":bytes.len(),
            "sha256":sha256(&bytes),
            "decoded":vector_state(&decoded),
        },
        "tree":tree_state(vault_dir)?,
    }))
}

fn open_latest_only(vault_dir: &Path, read_only: bool) -> AnyResult<AsterVault> {
    let selected_cfs = read_only.then(|| {
        vec![
            ColumnFamily::slot(SlotId::new(SLOT)),
            ColumnFamily::Compression,
            ColumnFamily::Kv,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ]
    });
    Ok(AsterVault::open(
        vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        VAULT_SALT.to_vec(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: !read_only,
            read_only,
            selected_cfs,
            ..VaultOptions::default()
        },
    )?)
}

fn persist_new(path: &Path, value: &Value) -> AnyResult<Value> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let observed = fs::read(path)?;
    require(
        observed == bytes,
        "ISSUE_1147_RECEIPT_READBACK_MISMATCH",
        path.display().to_string(),
    )?;
    Ok(json!({
        "path":path,
        "bytes":observed.len(),
        "sha256":sha256(&observed),
    }))
}

fn exact_error<T>(result: calyx_core::Result<T>, phase: &str) -> AnyResult<Value> {
    match result {
        Ok(_) => Err(format!("ISSUE_1147_{phase}_UNEXPECTEDLY_SUCCEEDED").into()),
        Err(error) => {
            require(
                error.code == ASTRO_WEAVE_SLOT_BINDING_CHANGED
                    && !error.message.is_empty()
                    && !error.remediation.is_empty(),
                "ISSUE_1147_REFUSAL_DIAGNOSTIC_MISMATCH",
                &error,
            )?;
            Ok(json!({
                "code":error.code,
                "message":error.message,
                "remediation":error.remediation,
            }))
        }
    }
}

fn execute(payload: &Path) -> AnyResult<()> {
    require(
        payload.is_absolute() && !payload.try_exists()?,
        "ISSUE_1147_EXECUTE_ROOT_INVALID",
        payload.display().to_string(),
    )?;
    fs::create_dir_all(payload)?;
    let vault_dir = payload.join("vault");
    let slot = SlotId::new(SLOT);
    let cx_id = CxId::from_bytes(CX_BYTES);
    let key = slot_key(cx_id);
    let initial_vector = SlotVector::Dense {
        dim: 2,
        data: vec![1.25, -2.5],
    };
    let mutated_vector = SlotVector::Dense {
        dim: 2,
        data: vec![3.5, 7.75],
    };
    let initial_bytes = encode_slot_vector(&initial_vector)?;
    let mutated_bytes = encode_slot_vector(&mutated_vector)?;
    let initial_payload = ledger_payload("initial", &initial_bytes)?;
    let derived_payload = ledger_payload("derived", DERIVED_VALUE)?;
    let mutation_payload = ledger_payload("mutation", &mutated_bytes)?;
    let ledger_subject = SubjectId::Cx(cx_id);
    let initial_actor = ActorId::Service(INITIAL_ACTOR.to_string());
    let derived_actor = ActorId::Service(DERIVED_ACTOR.to_string());
    let mutation_actor = ActorId::Service(MUTATION_ACTOR.to_string());

    let initial_vault = AsterVault::new_durable(
        &vault_dir,
        VAULT_ID.parse::<VaultId>()?,
        VAULT_SALT.to_vec(),
        VaultOptions::default(),
    )?;
    let initial_expected_seq = initial_vault.latest_seq();
    let (initial_commit_seq, initial_ledger_ref) = initial_vault
        .write_cf_batch_with_ledger_entry_if_seq(
            initial_expected_seq,
            [(ColumnFamily::slot(slot), key.clone(), initial_bytes.clone())],
            EntryKind::Admin,
            ledger_subject.clone(),
            initial_payload.clone(),
            initial_actor.clone(),
        )?;
    initial_vault.flush()?;
    let initial_commit = physical_commit_evidence(
        &initial_vault,
        initial_commit_seq,
        ColumnFamily::slot(slot),
        &key,
        &initial_bytes,
        &initial_ledger_ref,
    )?;
    let initial_ledger = physical_ledger_evidence(
        &initial_vault,
        &[LedgerExpectation {
            label: "initial",
            reference: &initial_ledger_ref,
            kind: EntryKind::Admin,
            subject: &ledger_subject,
            actor: &initial_actor,
            payload: &initial_payload,
        }],
    )?;
    drop(initial_vault);

    let vault = open_latest_only(&vault_dir, false)?;
    let before = source_state(&vault, &vault_dir, slot, cx_id)?;
    require(
        before["snapshot_seq"].as_u64() == Some(initial_commit_seq)
            && before["storage"]["latest_only"] == Value::Bool(true)
            && before["storage"]["overlay_keys"].as_u64() == Some(0)
            && before["storage"]["overlay_versions"].as_u64() == Some(0)
            && before["storage"]["overlay_bytes"].as_u64() == Some(0)
            && before["row"]["decoded"] == vector_state(&initial_vector),
        "ISSUE_1147_INITIAL_PHYSICAL_STATE_MISMATCH",
        &before,
    )?;
    println!(
        "{}",
        json!({"case":"bound_read","phase":"before","state":before})
    );

    let source = WeaveSlotSource::open(initial_commit_seq, None, None)?;
    let binding = source.bind_latest_at(&vault, initial_commit_seq, slot)?;
    let resolved = source.resolve_many_bound_at(&vault, initial_commit_seq, &binding, &[cx_id])?;
    require(
        resolved == vec![(cx_id, Some(initial_vector.clone()))],
        "ISSUE_1147_BOUND_READ_VALUE_MISMATCH",
        json!({"resolved":resolved.iter().map(|(cx, vector)| json!({"cx":cx.to_string(),"vector":vector.as_ref().map(vector_state)})).collect::<Vec<_>>() }),
    )?;
    let bound_after = source_state(&vault, &vault_dir, slot, cx_id)?;
    require(
        bound_after == before,
        "ISSUE_1147_BOUND_READ_MUTATED_STATE",
        json!({"before":before,"after":bound_after}),
    )?;
    println!(
        "{}",
        json!({"case":"bound_read","phase":"after","state":bound_after})
    );

    let (derived_commit_seq, derived_ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        initial_commit_seq,
        [(
            ColumnFamily::Kv,
            DERIVED_KEY.to_vec(),
            DERIVED_VALUE.to_vec(),
        )],
        EntryKind::Admin,
        ledger_subject.clone(),
        derived_payload.clone(),
        derived_actor.clone(),
    )?;
    vault.flush()?;
    let derived_commit = physical_commit_evidence(
        &vault,
        derived_commit_seq,
        ColumnFamily::Kv,
        DERIVED_KEY,
        DERIVED_VALUE,
        &derived_ledger_ref,
    )?;
    let derived_state = source_state(&vault, &vault_dir, slot, cx_id)?;
    let derived_resolved =
        source.resolve_many_bound_at(&vault, derived_commit_seq, &binding, &[cx_id])?;
    require(
        derived_commit_seq > initial_commit_seq
            && derived_state["snapshot_seq"].as_u64() == Some(derived_commit_seq)
            && derived_state["slot_cf_generation"] == before["slot_cf_generation"]
            && derived_state["compression_cf_generation"] == before["compression_cf_generation"]
            && derived_state["compression_manifest"] == before["compression_manifest"]
            && derived_resolved == vec![(cx_id, Some(initial_vector.clone()))],
        "ISSUE_1147_DERIVED_SEQUENCE_CROSSING_MISMATCH",
        json!({"before":before,"after":derived_state,"resolved":derived_resolved.iter().map(|(cx, vector)| json!({"cx":cx.to_string(),"vector":vector.as_ref().map(vector_state)})).collect::<Vec<_>>() }),
    )?;
    println!(
        "{}",
        json!({"case":"disjoint_derived_commit","phase":"before","state":bound_after})
    );
    println!(
        "{}",
        json!({"case":"disjoint_derived_commit","phase":"after","state":derived_state,"commit":derived_commit})
    );

    let empty_before = source_state(&vault, &vault_dir, slot, cx_id)?;
    let empty = source.resolve_many_bound_at(&vault, derived_commit_seq, &binding, &[])?;
    let empty_after = source_state(&vault, &vault_dir, slot, cx_id)?;
    require(
        empty.is_empty() && empty_after == empty_before,
        "ISSUE_1147_EMPTY_ROSTER_MUTATED_STATE",
        json!({"result":empty.len(),"before":empty_before,"after":empty_after}),
    )?;
    println!(
        "{}",
        json!({"case":"empty_roster","phase":"before","state":empty_before})
    );
    println!(
        "{}",
        json!({"case":"empty_roster","phase":"after","state":empty_after})
    );

    let mutation_before = source_state(&vault, &vault_dir, slot, cx_id)?;
    let (mutation_seq, mutation_ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        derived_commit_seq,
        [(ColumnFamily::slot(slot), key.clone(), mutated_bytes.clone())],
        EntryKind::Admin,
        ledger_subject.clone(),
        mutation_payload.clone(),
        mutation_actor.clone(),
    )?;
    vault.flush()?;
    let mutation_ledger = physical_ledger_evidence(
        &vault,
        &[
            LedgerExpectation {
                label: "initial",
                reference: &initial_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &initial_actor,
                payload: &initial_payload,
            },
            LedgerExpectation {
                label: "derived",
                reference: &derived_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &derived_actor,
                payload: &derived_payload,
            },
            LedgerExpectation {
                label: "mutation",
                reference: &mutation_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &mutation_actor,
                payload: &mutation_payload,
            },
        ],
    )?;
    let mutation_commit = physical_commit_evidence(
        &vault,
        mutation_seq,
        ColumnFamily::slot(slot),
        &key,
        &mutated_bytes,
        &mutation_ledger_ref,
    )?;
    let ledger_chain = physical_ledger_chain_segment(
        &vault,
        &[
            initial_ledger_ref.clone(),
            derived_ledger_ref.clone(),
            mutation_ledger_ref.clone(),
        ],
    )?;
    let mutation_after = source_state(&vault, &vault_dir, slot, cx_id)?;
    require(
        mutation_seq > derived_commit_seq
            && mutation_after["snapshot_seq"].as_u64() == Some(mutation_seq)
            && mutation_after["slot_cf_generation"].as_u64()
                > mutation_before["slot_cf_generation"].as_u64()
            && mutation_after["compression_cf_generation"]
                == mutation_before["compression_cf_generation"]
            && mutation_after["row"]["decoded"] == vector_state(&mutated_vector)
            && mutation_after["storage"]["latest_only"] == Value::Bool(true)
            && mutation_after["storage"]["overlay_keys"].as_u64() == Some(0)
            && mutation_after["storage"]["overlay_versions"].as_u64() == Some(0)
            && mutation_after["storage"]["overlay_bytes"].as_u64() == Some(0),
        "ISSUE_1147_MUTATION_PHYSICAL_STATE_MISMATCH",
        json!({"before":mutation_before,"after":mutation_after}),
    )?;
    println!(
        "{}",
        json!({"case":"source_mutation","phase":"before","state":mutation_before})
    );
    println!(
        "{}",
        json!({"case":"source_mutation","phase":"after","state":mutation_after})
    );

    let refusal_before = source_state(&vault, &vault_dir, slot, cx_id)?;
    let stale_generation = exact_error(
        source.resolve_many_bound_at(&vault, mutation_seq, &binding, &[cx_id]),
        "STALE_GENERATION",
    )?;
    let refusal_middle = source_state(&vault, &vault_dir, slot, cx_id)?;
    let stale_epoch = exact_error(
        source.bind_latest_at(&vault, initial_commit_seq, slot),
        "STALE_EPOCH",
    )?;
    let refusal_after = source_state(&vault, &vault_dir, slot, cx_id)?;
    require(
        refusal_before == refusal_middle && refusal_middle == refusal_after,
        "ISSUE_1147_REFUSAL_MUTATED_STATE",
        json!({"before":refusal_before,"middle":refusal_middle,"after":refusal_after}),
    )?;
    println!(
        "{}",
        json!({"case":"stale_generation","phase":"before","state":refusal_before})
    );
    println!(
        "{}",
        json!({"case":"stale_generation","phase":"after","state":refusal_middle,"error":stale_generation})
    );
    println!(
        "{}",
        json!({"case":"stale_epoch","phase":"before","state":refusal_middle})
    );
    println!(
        "{}",
        json!({"case":"stale_epoch","phase":"after","state":refusal_after,"error":stale_epoch})
    );

    drop(vault);
    let closed_vault = open_latest_only(&vault_dir, true)?;
    let durable_after_close = source_state(&closed_vault, &vault_dir, slot, cx_id)?;
    require(
        durable_after_close["snapshot_seq"] == refusal_after["snapshot_seq"]
            && durable_after_close["row"] == refusal_after["row"]
            && durable_after_close["compression_manifest"] == refusal_after["compression_manifest"]
            && durable_after_close["compression_manifest"]["present"] == Value::Bool(false)
            && durable_after_close["storage"]["latest_only"] == Value::Bool(true)
            && durable_after_close["storage"]["overlay_keys"].as_u64() == Some(0)
            && durable_after_close["storage"]["overlay_versions"].as_u64() == Some(0)
            && durable_after_close["storage"]["overlay_bytes"].as_u64() == Some(0),
        "ISSUE_1147_CLOSE_REOPEN_STATE_MISMATCH",
        json!({"before_close":refusal_after,"after_reopen":durable_after_close}),
    )?;
    println!(
        "{}",
        json!({"case":"durable_reopen","phase":"after","state":durable_after_close})
    );
    drop(closed_vault);

    let receipt = json!({
        "schema":"astrolabe.issue-1147.generation-binding.execute.v1",
        "vault_dir":vault_dir,
        "slot":slot.get(),
        "cx_id":cx_id.to_string(),
        "initial_commit_seq":initial_commit_seq,
        "derived_commit_seq":derived_commit_seq,
        "mutation_seq":mutation_seq,
        "initial_ledger_ref":initial_ledger_ref,
        "derived_ledger_ref":derived_ledger_ref,
        "mutation_ledger_ref":mutation_ledger_ref,
        "initial_ledger_payload":serde_json::from_slice::<Value>(&initial_payload)?,
        "derived_ledger_payload":serde_json::from_slice::<Value>(&derived_payload)?,
        "mutation_ledger_payload":serde_json::from_slice::<Value>(&mutation_payload)?,
        "initial_commit":initial_commit,
        "derived_commit":derived_commit,
        "mutation_commit":mutation_commit,
        "initial_ledger":initial_ledger,
        "mutation_ledger":mutation_ledger,
        "ledger_chain":ledger_chain,
        "binding":binding,
        "bound_before":before,
        "bound_after":bound_after,
        "derived_state":derived_state,
        "empty_before":empty_before,
        "empty_after":empty_after,
        "mutation_before":mutation_before,
        "mutation_after":mutation_after,
        "stale_generation":stale_generation,
        "stale_epoch":stale_epoch,
        "refusal_before":refusal_before,
        "refusal_middle":refusal_middle,
        "refusal_after":refusal_after,
        "durable_after_close":durable_after_close,
    });
    let persisted = persist_new(&payload.join("execution.json"), &receipt)?;
    println!(
        "{}",
        json!({"event":"ISSUE_1147_EXECUTE_COMPLETE","receipt":persisted})
    );
    Ok(())
}

fn readback(payload: &Path) -> AnyResult<()> {
    require(
        payload.is_absolute() && payload.try_exists()?,
        "ISSUE_1147_READBACK_ROOT_INVALID",
        payload.display().to_string(),
    )?;
    let execution_path = payload.join("execution.json");
    let execution_bytes = fs::read(&execution_path)?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    require(
        execution["schema"] == "astrolabe.issue-1147.generation-binding.execute.v1",
        "ISSUE_1147_EXECUTION_SCHEMA_MISMATCH",
        &execution,
    )?;
    let vault_dir = payload.join("vault");
    require(
        execution["vault_dir"] == Value::String(vault_dir.to_string_lossy().into_owned()),
        "ISSUE_1147_EXECUTION_VAULT_PATH_MISMATCH",
        &execution["vault_dir"],
    )?;
    let slot = SlotId::new(SLOT);
    let cx_id = CxId::from_bytes(CX_BYTES);
    let vault = open_latest_only(&vault_dir, true)?;
    let physical = source_state(&vault, &vault_dir, slot, cx_id)?;
    let derived_bytes = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Kv, DERIVED_KEY)?
        .ok_or("ISSUE_1147_DERIVED_ROW_MISSING")?;
    require(
        derived_bytes.as_slice() == DERIVED_VALUE,
        "ISSUE_1147_DERIVED_ROW_MISMATCH",
        json!({
            "key_hex":DERIVED_KEY.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "expected_bytes":DERIVED_VALUE.len(),
            "expected_sha256":sha256(DERIVED_VALUE),
            "observed_bytes":derived_bytes.len(),
            "observed_sha256":sha256(&derived_bytes),
        }),
    )?;
    let derived_physical = json!({
        "snapshot_seq":vault.latest_seq(),
        "cf":ColumnFamily::Kv.name(),
        "key_hex":DERIVED_KEY.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "bytes":derived_bytes.len(),
        "sha256":sha256(&derived_bytes),
        "exact_value_verified":true,
    });
    let initial_ledger_ref: LedgerRef =
        serde_json::from_value(execution["initial_ledger_ref"].clone())?;
    let derived_ledger_ref: LedgerRef =
        serde_json::from_value(execution["derived_ledger_ref"].clone())?;
    let mutation_ledger_ref: LedgerRef =
        serde_json::from_value(execution["mutation_ledger_ref"].clone())?;
    let initial_commit_seq = execution["initial_commit_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_INITIAL_COMMIT_SEQ_MISSING")?;
    let derived_commit_seq = execution["derived_commit_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_DERIVED_COMMIT_SEQ_MISSING")?;
    let mutation_commit_seq = execution["mutation_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_MUTATION_COMMIT_SEQ_MISSING")?;
    require(
        initial_commit_seq == 1
            && initial_commit_seq.checked_add(1) == Some(derived_commit_seq)
            && derived_commit_seq.checked_add(1) == Some(mutation_commit_seq),
        "ISSUE_1147_EXECUTION_COMMIT_SEQUENCE_MISMATCH",
        json!({
            "initial":initial_commit_seq,
            "derived":derived_commit_seq,
            "mutation":mutation_commit_seq,
        }),
    )?;
    let initial_bytes = encode_slot_vector(&SlotVector::Dense {
        dim: 2,
        data: vec![1.25, -2.5],
    })?;
    let mutated_bytes = encode_slot_vector(&SlotVector::Dense {
        dim: 2,
        data: vec![3.5, 7.75],
    })?;
    let initial_payload = ledger_payload("initial", &initial_bytes)?;
    let derived_payload = ledger_payload("derived", DERIVED_VALUE)?;
    let mutation_payload = ledger_payload("mutation", &mutated_bytes)?;
    let ledger_subject = SubjectId::Cx(cx_id);
    let initial_actor = ActorId::Service(INITIAL_ACTOR.to_string());
    let derived_actor = ActorId::Service(DERIVED_ACTOR.to_string());
    let mutation_actor = ActorId::Service(MUTATION_ACTOR.to_string());
    require(
        execution["initial_ledger_payload"] == serde_json::from_slice::<Value>(&initial_payload)?
            && execution["derived_ledger_payload"]
                == serde_json::from_slice::<Value>(&derived_payload)?
            && execution["mutation_ledger_payload"]
                == serde_json::from_slice::<Value>(&mutation_payload)?,
        "ISSUE_1147_LEDGER_PAYLOAD_RECEIPT_MISMATCH",
        json!({
            "initial":execution["initial_ledger_payload"],
            "mutation":execution["mutation_ledger_payload"],
        }),
    )?;
    let physical_ledger = physical_ledger_evidence(
        &vault,
        &[
            LedgerExpectation {
                label: "initial",
                reference: &initial_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &initial_actor,
                payload: &initial_payload,
            },
            LedgerExpectation {
                label: "derived",
                reference: &derived_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &derived_actor,
                payload: &derived_payload,
            },
            LedgerExpectation {
                label: "mutation",
                reference: &mutation_ledger_ref,
                kind: EntryKind::Admin,
                subject: &ledger_subject,
                actor: &mutation_actor,
                payload: &mutation_payload,
            },
        ],
    )?;
    let execute_immediate_physical_commit_inventories = json!({
        "initial":execution["initial_commit"].clone(),
        "derived":execution["derived_commit"].clone(),
        "mutation":execution["mutation_commit"].clone(),
    });
    let execute_immediate_commit_receipt_bindings = json!({
        "initial":bind_execute_commit_receipt(
            &vault,
            &execute_immediate_physical_commit_inventories["initial"],
            &CommitReceiptExpectation {
                label:"initial",
                commit_seq:initial_commit_seq,
                data_cf:ColumnFamily::slot(slot),
                data_key:&slot_key(cx_id),
                data_value:&initial_bytes,
                ledger_ref:&initial_ledger_ref,
            },
        )?,
        "derived":bind_execute_commit_receipt(
            &vault,
            &execute_immediate_physical_commit_inventories["derived"],
            &CommitReceiptExpectation {
                label:"derived",
                commit_seq:derived_commit_seq,
                data_cf:ColumnFamily::Kv,
                data_key:DERIVED_KEY,
                data_value:DERIVED_VALUE,
                ledger_ref:&derived_ledger_ref,
            },
        )?,
        "mutation":bind_execute_commit_receipt(
            &vault,
            &execute_immediate_physical_commit_inventories["mutation"],
            &CommitReceiptExpectation {
                label:"mutation",
                commit_seq:mutation_commit_seq,
                data_cf:ColumnFamily::slot(slot),
                data_key:&slot_key(cx_id),
                data_value:&mutated_bytes,
                ledger_ref:&mutation_ledger_ref,
            },
        )?,
    });
    let physical_chain = physical_ledger_chain_segment(
        &vault,
        &[
            initial_ledger_ref.clone(),
            derived_ledger_ref.clone(),
            mutation_ledger_ref.clone(),
        ],
    )?;
    let ledger_head = vault
        .retained_read_only_ledger_head()?
        .ok_or("ISSUE_1147_LEDGER_HEAD_MISSING")?;
    let expected_ledger_height = mutation_ledger_ref
        .seq
        .checked_add(1)
        .ok_or("ISSUE_1147_LEDGER_HEIGHT_OVERFLOW")?;
    require(
        ledger_head.height == expected_ledger_height
            && ledger_head.tip_hash == mutation_ledger_ref.hash,
        "ISSUE_1147_LEDGER_HEAD_MISMATCH",
        json!({
            "head": ledger_head,
            "expected_height": expected_ledger_height,
            "expected_tip": mutation_ledger_ref,
        }),
    )?;
    let physical_ledger_rows = physical_ledger["rows"]
        .as_array()
        .ok_or("ISSUE_1147_REOPENED_LEDGER_ROWS_MISSING")?;
    let physical_chain_entries = physical_chain["entries"]
        .as_array()
        .ok_or("ISSUE_1147_REOPENED_CHAIN_ENTRIES_MISSING")?;
    require(
        physical_ledger_rows.len() == 3 && physical_chain_entries.len() == 3,
        "ISSUE_1147_REOPENED_LEDGER_ROSTER_MISMATCH",
        json!({"ledger":physical_ledger,"chain":physical_chain}),
    )?;
    for (ordinal, label) in ["initial", "derived", "mutation"].iter().enumerate() {
        let binding = &execute_immediate_commit_receipt_bindings[*label];
        require(
            physical_ledger_rows[ordinal]["label"] == *label
                && binding["ledger_row"]["physical_row_sha256"]
                    == physical_ledger_rows[ordinal]["physical_row_sha256"]
                && binding["ledger_row"]["physical_row_sha256"]
                    == physical_chain_entries[ordinal]["physical_row_sha256"],
            "ISSUE_1147_COMMIT_RECEIPT_LEDGER_CROSS_BINDING_MISMATCH",
            json!({
                "ordinal":ordinal,
                "label":label,
                "binding":binding,
                "physical_ledger_row":physical_ledger_rows[ordinal],
                "physical_chain_entry":physical_chain_entries[ordinal],
            }),
        )?;
    }
    require(
        execute_immediate_commit_receipt_bindings["derived"]["data_row"]["value_sha256"]
            == derived_physical["sha256"]
            && execute_immediate_commit_receipt_bindings["mutation"]["data_row"]["value_sha256"]
                == physical["row"]["sha256"],
        "ISSUE_1147_COMMIT_RECEIPT_DATA_CROSS_BINDING_MISMATCH",
        json!({
            "bindings":execute_immediate_commit_receipt_bindings,
            "derived":derived_physical,
            "source":physical["row"],
        }),
    )?;
    require(
        physical == execution["durable_after_close"]
            && physical["snapshot_seq"] == execution["mutation_after"]["snapshot_seq"]
            && physical["row"] == execution["mutation_after"]["row"]
            && physical["row"] == execution["refusal_after"]["row"]
            && physical["compression_manifest"]
                == execution["mutation_after"]["compression_manifest"]
            && physical["compression_manifest"]
                == execution["refusal_after"]["compression_manifest"]
            && physical["compression_manifest"]["present"] == Value::Bool(false)
            && physical["row"]["decoded"]
                == vector_state(&SlotVector::Dense {
                    dim: 2,
                    data: vec![3.5, 7.75],
                })
            && physical["snapshot_seq"].as_u64() == Some(mutation_commit_seq),
        "ISSUE_1147_INDEPENDENT_PHYSICAL_READBACK_MISMATCH",
        json!({"physical":physical,"execute_after":execution["mutation_after"]}),
    )?;
    let binding: WeaveSlotBinding = serde_json::from_value(execution["binding"].clone())?;
    require(
        binding.slot == slot
            && binding.slot_cf_generation
                == execution["mutation_before"]["slot_cf_generation"]
                    .as_u64()
                    .ok_or("ISSUE_1147_BINDING_GENERATION_MISSING")?
            && physical["slot_cf_generation"]
                .as_u64()
                .is_some_and(|generation| generation > binding.slot_cf_generation)
            && binding.compression_cf_generation
                == execution["mutation_before"]["compression_cf_generation"]
                    .as_u64()
                    .ok_or("ISSUE_1147_BINDING_COMPRESSION_GENERATION_MISSING")?
            && binding.compressed_generation_identity.is_none(),
        "ISSUE_1147_BINDING_RECEIPT_MISMATCH",
        &binding,
    )?;
    let report = json!({
        "schema":"astrolabe.issue-1147.generation-binding.readback.v1",
        "execution":{
            "path":execution_path,
            "bytes":execution_bytes.len(),
            "sha256":sha256(&execution_bytes),
        },
        "execute_immediate_physical_commit_inventories":execute_immediate_physical_commit_inventories,
        "execute_immediate_commit_receipt_bindings":execute_immediate_commit_receipt_bindings,
        "reopened_readback":{
            "source":physical,
            "derived":derived_physical,
            "physical_ledger":physical_ledger,
            "physical_ledger_chain":physical_chain,
            "ledger_head":ledger_head,
        },
        "binding":binding,
        "exact_mutated_row_verified":true,
        "execute_immediate_commit_receipts_cross_bound_to_reopened_rows_chain_head":true,
        "stale_binding_refusals_left_state_unchanged":true,
        "separate_process_readback":true,
    });
    let persisted = persist_new(&payload.join("readback.json"), &report)?;
    println!(
        "{}",
        json!({"event":"ISSUE_1147_READBACK_COMPLETE","receipt":persisted,"reopened_readback":report["reopened_readback"]})
    );
    Ok(())
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().and_then(|arg| arg.into_string().ok());
    let payload = args.next().map(PathBuf::from);
    let result = match (mode.as_deref(), payload.as_deref(), args.next()) {
        (Some("execute"), Some(payload), None) => execute(payload),
        (Some("readback"), Some(payload), None) => readback(payload),
        _ => Err("ISSUE_1147_ARGUMENT_INVALID: pass exactly `execute <absent-absolute-payload>` or `readback <existing-absolute-payload>`".into()),
    };
    if let Err(error) = result {
        eprintln!(
            "code=ISSUE_1147_FSV_FAILED message={} remediation=preserve the payload and inspect the first failed physical invariant",
            error
        );
        std::process::exit(1);
    }
}
