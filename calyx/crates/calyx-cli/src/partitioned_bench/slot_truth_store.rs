use std::path::Path;

use bincode::config;
use calyx_aster::cf::{CfRouter, ColumnFamily};
use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const KEY_PREFIX: &[u8] = b"calyx/partitioned-rrf/slot-truth/v1/";
const VALUE_MAGIC: &[u8] = b"CRRFST1\0";
const CF_MEMTABLE_CAP: usize = 64 * 1024 * 1024;

pub(crate) const DEFAULT_ASSOCIATION_KEY: &str = "partitioned_rrf_slot_truth";
pub(crate) const FORMAT: &str = "calyx-partitioned-rrf-slot-ground-truth-v1";
pub(crate) const MODE: &str = "per_slot_ranked_rrf_reference";
pub(crate) const ROW_ID_SPACE: &str = "partitioned_rrf_plan_corpus_row_idx";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SlotTruthRecord {
    pub(crate) format: String,
    pub(crate) mode: String,
    pub(crate) row_id_space: String,
    pub(crate) plan_sha256: String,
    pub(crate) query_count: usize,
    pub(crate) truth_depth: usize,
    pub(crate) corpus_rows: usize,
    pub(crate) reference_backend: String,
    pub(crate) scale_suitable: bool,
    pub(crate) slots: Vec<SlotTruthRecordSlot>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct SlotTruthRecordSlot {
    pub(crate) slot: u16,
    pub(crate) lens_id: String,
    pub(crate) weights_sha256: String,
    pub(crate) signal_kind: String,
    pub(crate) rows: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SlotTruthDbReadback {
    pub(crate) cf_root: String,
    pub(crate) association_key: String,
    pub(crate) row_key_sha256: String,
    pub(crate) value_bytes: usize,
    pub(crate) value_sha256: String,
    pub(crate) readback_matches: bool,
}

pub(crate) fn write(
    cf_root: &Path,
    association_key: &str,
    record: &SlotTruthRecord,
) -> Result<SlotTruthDbReadback> {
    let row_key = row_key(association_key)?;
    let value = encode(record)?;
    let mut router = CfRouter::open(cf_root, CF_MEMTABLE_CAP)?;
    router.put(ColumnFamily::Graph, &row_key, &value)?;
    router.flush_cf(ColumnFamily::Graph)?;
    drop(router);

    let reopened = CfRouter::open(cf_root, CF_MEMTABLE_CAP)?;
    let readback = reopened
        .get(ColumnFamily::Graph, &row_key)?
        .ok_or_else(|| {
            error(
                "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_MISSING",
                "slot truth row missing after Graph CF write",
            )
        })?;
    if readback != value {
        return Err(error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_MISMATCH",
            "slot truth Graph CF readback bytes changed after write",
        ));
    }
    Ok(readback_report(
        cf_root,
        association_key,
        &row_key,
        &readback,
        true,
    ))
}

pub(crate) fn read(
    cf_root: &Path,
    association_key: &str,
) -> Result<(SlotTruthRecord, SlotTruthDbReadback)> {
    let row_key = row_key(association_key)?;
    let router = CfRouter::open(cf_root, CF_MEMTABLE_CAP)?;
    let value = router.get(ColumnFamily::Graph, &row_key)?.ok_or_else(|| {
        error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_MISSING",
            "slot truth row missing in Graph CF",
        )
    })?;
    let record = decode(&value)?;
    Ok((
        record,
        readback_report(cf_root, association_key, &row_key, &value, true),
    ))
}

fn row_key(association_key: &str) -> Result<Vec<u8>> {
    if association_key.trim().is_empty() {
        return Err(error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_INVALID_KEY",
            "slot truth association key must be non-empty",
        ));
    }
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + association_key.len());
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(association_key.as_bytes());
    Ok(key)
}

fn encode<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    let mut bytes = VALUE_MAGIC.to_vec();
    let payload = bincode::serde::encode_to_vec(record, config::standard()).map_err(|err| {
        error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_ENCODE",
            format!("encode slot truth record failed: {err}"),
        )
    })?;
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let payload = bytes.strip_prefix(VALUE_MAGIC).ok_or_else(|| {
        error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_INVALID",
            "slot truth row has invalid magic",
        )
    })?;
    let (record, consumed): (T, usize) =
        bincode::serde::decode_from_slice(payload, config::standard()).map_err(|err| {
            error(
                "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_DECODE",
                format!("decode slot truth record failed: {err}"),
            )
        })?;
    if consumed != payload.len() {
        return Err(error(
            "CALYX_FSV_PARTITIONED_RRF_SLOT_TRUTH_DB_INVALID",
            "slot truth row has trailing bytes",
        ));
    }
    Ok(record)
}

fn readback_report(
    cf_root: &Path,
    association_key: &str,
    row_key: &[u8],
    value: &[u8],
    readback_matches: bool,
) -> SlotTruthDbReadback {
    SlotTruthDbReadback {
        cf_root: cf_root.display().to_string(),
        association_key: association_key.to_string(),
        row_key_sha256: hex_sha256(row_key),
        value_bytes: value.len(),
        value_sha256: hex_sha256(value),
        readback_matches,
    }
}

fn error(code: &'static str, message: impl Into<String>) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation: "write and read partitioned RRF slot truth through Calyx/Aster Graph CF",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

