use calyx_aster::cf::ColumnFamily;
use calyx_aster::manifest::ManifestStore;
use calyx_aster::sst::SstReader;
use calyx_aster::sst::level::SstLevel;
use calyx_aster::storage_names::{
    SstOrderKey, classify_sst, ensure_unambiguous_sst_order, sst_order_key,
};
use calyx_aster::vault::encode::{decode_constellation_base, decode_write_batch};
use calyx_aster::wal::{ReplayOutcome, replay_dir_after};
use calyx_core::VaultId;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{CliError, CliResult};

/// Lists canonical Aster SST files in deterministic readback order, failing
/// closed on seq-domain-ambiguous layouts (issue #1138): callers fold rows
/// newest-wins in this order, so an ambiguous order would read stale rows.
pub(crate) fn list_sst_files(dir: &Path) -> CliResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if classify_sst(&path)?.is_some() {
            files.push(path);
        }
    }
    ensure_unambiguous_sst_order(files.iter().map(PathBuf::as_path))?;
    files.sort_by(|left, right| sst_order(left).cmp(&sst_order(right)).then(left.cmp(right)));
    Ok(files)
}

pub(crate) fn sst_order(path: &Path) -> SstOrderKey {
    sst_order_key(path).ok().flatten().unwrap_or(SstOrderKey {
        epoch: 0,
        seq: 0,
        class_rank: 0,
        index: 0,
    })
}

pub(crate) fn latest_cf_rows(
    vault: &Path,
    cf: ColumnFamily,
) -> CliResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    for file in list_sst_files(&vault.join("cf").join(cf.name()))? {
        let reader = SstReader::open(&file)?;
        for row in reader.iter()? {
            rows.insert(row.key, row.value);
        }
    }
    let replay = replay_after_manifest(vault)?;
    for record in replay.records {
        for row in decode_write_batch(&record.payload)? {
            if row.cf == cf {
                rows.insert(row.key, row.value);
            }
        }
    }
    Ok(rows)
}

pub(crate) fn latest_cf_row(
    vault: &Path,
    cf: ColumnFamily,
    key: &[u8],
) -> CliResult<Option<Vec<u8>>> {
    let sst_files = list_sst_files(&vault.join("cf").join(cf.name()))?;
    let level = SstLevel::from_oldest_first(sst_files);
    let mut value = level.get(key)?;
    let replay = replay_after_manifest(vault)?;
    for record in replay.records {
        for row in decode_write_batch(&record.payload)? {
            if row.cf == cf && row.key == key {
                value = Some(row.value);
            }
        }
    }
    Ok(value)
}

pub(crate) fn latest_cf_rows_for_keys(
    vault: &Path,
    cf: ColumnFamily,
    keys: &[Vec<u8>],
) -> CliResult<BTreeMap<Vec<u8>, Option<Vec<u8>>>> {
    let sst_files = list_sst_files(&vault.join("cf").join(cf.name()))?;
    let level = SstLevel::from_oldest_first(sst_files);
    let mut rows = BTreeMap::new();
    for key in keys {
        rows.insert(key.clone(), level.get(key)?);
    }
    let replay = replay_after_manifest(vault)?;
    for record in replay.records {
        for row in decode_write_batch(&record.payload)? {
            if row.cf == cf && rows.contains_key(&row.key) {
                rows.insert(row.key, Some(row.value));
            }
        }
    }
    Ok(rows)
}

pub(crate) fn replay_after_manifest(vault: &Path) -> CliResult<ReplayOutcome> {
    let floor = wal_replay_floor(vault)?;
    Ok(replay_dir_after(vault.join("wal"), floor)?)
}

fn wal_replay_floor(vault: &Path) -> CliResult<u64> {
    if vault.join("CURRENT").exists() || vault.join("MANIFEST").exists() {
        return Ok(ManifestStore::open(vault)
            .load_current()
            .map(|manifest| manifest.durable_seq)?);
    }
    Ok(0)
}

pub(crate) fn vault_id_from_base(vault: &Path) -> CliResult<VaultId> {
    latest_cf_rows(vault, ColumnFamily::Base)?
        .into_values()
        .next()
        .map(|bytes| decode_constellation_base(&bytes).map(|cx| cx.vault_id))
        .transpose()?
        .ok_or_else(|| CliError::runtime("cannot infer vault id: base CF has no rows"))
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => unreachable!("nibble out of range"),
    }
}

