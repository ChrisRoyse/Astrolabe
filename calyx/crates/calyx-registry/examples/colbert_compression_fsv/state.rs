use std::error::Error;
use std::fs;
use std::path::Path;

use calyx_aster::cf::{COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, compression_manifest_key};
use calyx_aster::ledger_view::AsterLedgerCfStore;
use calyx_aster::vault::AsterVault;
use calyx_core::{LensId, Slot, SystemClock};
use calyx_ledger::{LedgerCfStore, VerifyResult, verify_chain};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub type AnyResult<T> = Result<T, Box<dyn Error>>;

const MANIFEST_PREFIX_BYTES: usize = 280;
const ROW_HEADER_BYTES: usize = 153;
const DIGEST_BYTES: usize = 32;
const MANIFEST_DOMAIN: &[u8] = b"calyx-colbert-residual-manifest-v1";
const ROW_DOMAIN: &[u8] = b"calyx-colbert-residual-row-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FamilyState {
    pub rows: usize,
    pub key_bytes: usize,
    pub value_bytes: usize,
    pub digest_sha256: String,
    pub keys_hex: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultState {
    pub seq: u64,
    pub base: FamilyState,
    pub compression: FamilyState,
    pub primary: FamilyState,
    pub raw: FamilyState,
    pub ledger: FamilyState,
    pub physical_ledger_rows: usize,
    pub ledger_chain: String,
    pub transitions: Vec<String>,
    pub digest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileInventory {
    pub files: usize,
    pub bytes: u64,
    pub digest_sha256: String,
    pub entries: Vec<FileEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileEvidence {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IndependentFormatReadback {
    pub manifest_bytes: usize,
    pub manifest_sha256: String,
    pub token_dim: u32,
    pub max_token_dim: u32,
    pub max_tokens: u32,
    pub centroid_count: u32,
    pub generation_rows: u32,
    pub total_tokens: u64,
    pub generation_seq: u64,
    pub slot_id: u16,
    pub lens_id_hex: String,
    pub context_sha256: String,
    pub generation_root_sha256: String,
    pub raw_generation_root_sha256: String,
    pub codebook_bytes: usize,
    pub rows: Vec<IndependentRowReadback>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IndependentRowReadback {
    pub cx_id_hex: String,
    pub value_bytes: usize,
    pub value_sha256: String,
    pub token_count: u32,
    pub centroid_code_bytes: usize,
    pub residual_bytes: usize,
    pub checksum_bytes: usize,
}

pub fn read_state(
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot: &Slot,
) -> AnyResult<VaultState> {
    let seq = vault.latest_seq();
    let base = family(vault.scan_cf_at(seq, ColumnFamily::Base)?);
    let compression = family(vault.scan_cf_at(seq, ColumnFamily::Compression)?);
    let primary = family(vault.scan_cf_at(seq, ColumnFamily::slot(slot.slot_id))?);
    let raw = family(vault.scan_cf_at(seq, ColumnFamily::slot_raw(slot.slot_id))?);
    let ledger_rows = vault.scan_cf_at(seq, ColumnFamily::Ledger)?;
    let transitions = ledger_rows
        .iter()
        .map(|(_, bytes)| {
            let entry = calyx_ledger::decode(bytes)?;
            let payload = serde_json::from_slice::<serde_json::Value>(&entry.payload)?;
            Ok(format!(
                "{}:{}:{}",
                entry.seq,
                payload
                    .get("slot_id")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                payload
                    .get("transition")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("non-compression")
            ))
        })
        .collect::<AnyResult<Vec<_>>>()?;
    let ledger = family(ledger_rows);
    let physical = AsterLedgerCfStore::open(vault_dir)?;
    let physical_rows = physical.scan()?;
    let chain = match verify_chain(&physical, 0..physical_rows.len() as u64)? {
        VerifyResult::Intact { count } => format!("intact:{count}"),
        other => format!("{other:?}"),
    };
    let digest_sha256 = digest_serialized(&(
        seq,
        &base,
        &compression,
        &primary,
        &raw,
        &ledger,
        physical_rows.len(),
        &chain,
        &transitions,
    ))?;
    Ok(VaultState {
        seq,
        base,
        compression,
        primary,
        raw,
        ledger,
        physical_ledger_rows: physical_rows.len(),
        ledger_chain: chain,
        transitions,
        digest_sha256,
    })
}

pub fn independent_format_readback(
    vault: &AsterVault<SystemClock>,
    slot: &Slot,
    expected_lens: LensId,
) -> AnyResult<IndependentFormatReadback> {
    let seq = vault.latest_seq();
    let manifest_bytes = vault
        .read_cf_at(
            seq,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
        )?
        .ok_or("independent reader found no generation manifest")?;
    require_digest(&manifest_bytes, MANIFEST_DOMAIN, "manifest")?;
    require(
        &manifest_bytes[0..4] == b"CMVF",
        "manifest magic is not CMVF",
    )?;
    require(
        be_u16(&manifest_bytes, 4)? == 1,
        "manifest version is not 1",
    )?;
    require(
        manifest_bytes[6..11] == [1, 1, 1, 2, 4],
        "manifest codec/metric/dtype/residual/code-width tags differ",
    )?;
    let token_dim = be_u32(&manifest_bytes, 12)?;
    let max_tokens = be_u32(&manifest_bytes, 16)?;
    let centroid_count = be_u32(&manifest_bytes, 20)?;
    let generation_rows = be_u32(&manifest_bytes, 32)?;
    let total_tokens = be_u64(&manifest_bytes, 36)?;
    let generation_seq = be_u64(&manifest_bytes, 44)?;
    let slot_id = be_u16(&manifest_bytes, 52)?;
    let lens_id = bytes_at::<16>(&manifest_bytes, 56)?;
    let context = bytes_at::<32>(&manifest_bytes, 72)?;
    let generation_root = bytes_at::<32>(&manifest_bytes, 104)?;
    let raw_generation_root = bytes_at::<32>(&manifest_bytes, 136)?;
    let codebook_bytes = usize::try_from(be_u64(&manifest_bytes, 252)?)?;
    let centroid_values = usize::try_from(be_u64(&manifest_bytes, 260)?)?;
    let max_token_dim = be_u32(&manifest_bytes, 276)?;
    let expected_values = (token_dim as usize)
        .checked_mul(centroid_count as usize)
        .ok_or("independent centroid geometry overflow")?;
    let expected_codebook = expected_values
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(28))
        .ok_or("independent codebook length overflow")?;
    require(
        centroid_values == expected_values
            && codebook_bytes == expected_codebook
            && manifest_bytes.len() == MANIFEST_PREFIX_BYTES + codebook_bytes + DIGEST_BYTES,
        "independent manifest codebook/length geometry mismatch",
    )?;
    require(
        slot_id == slot.slot_id.get()
            && lens_id == *expected_lens.as_bytes()
            && token_dim <= max_token_dim,
        "independent manifest slot/lens/dimension context mismatch",
    )?;
    let primary = vault.scan_cf_at(seq, ColumnFamily::slot(slot.slot_id))?;
    require(
        primary.len() == generation_rows as usize,
        "independent primary row count differs from manifest",
    )?;
    let mut rows = Vec::with_capacity(primary.len());
    let mut observed_tokens = 0_u64;
    for (key, bytes) in primary {
        require(key.len() == 16, "independent row key is not a CxId")?;
        require_digest(&bytes, ROW_DOMAIN, "row")?;
        require(
            bytes[0] == COMPRESSED_SLOT_VALUE_TAG && bytes[1..5] == *b"CMVR",
            "independent row tag/magic mismatch",
        )?;
        require(be_u16(&bytes, 5)? == 1, "independent row version mismatch")?;
        require(
            bytes[7..12] == [1, 1, 1, 2, 4],
            "independent row codec tags mismatch",
        )?;
        let row_dim = be_u32(&bytes, 13)?;
        let token_count = be_u32(&bytes, 17)?;
        let codes_offset = be_u32(&bytes, 29)? as usize;
        let residual_offset = be_u32(&bytes, 33)? as usize;
        let payload_end = be_u32(&bytes, 37)? as usize;
        let row_lens = bytes_at::<16>(&bytes, 57)?;
        let row_cx = bytes_at::<16>(&bytes, 73)?;
        let row_context = bytes_at::<32>(&bytes, 89)?;
        let row_root = bytes_at::<32>(&bytes, 121)?;
        let expected_residual = ROW_HEADER_BYTES + token_count as usize * 4;
        let expected_end = expected_residual + token_count as usize * (token_dim as usize / 4);
        require(
            row_dim == token_dim
                && codes_offset == ROW_HEADER_BYTES
                && residual_offset == expected_residual
                && payload_end == expected_end
                && bytes.len() == expected_end + DIGEST_BYTES
                && row_lens == lens_id
                && row_cx.as_slice() == key.as_slice()
                && row_context == context
                && row_root == generation_root,
            "independent row offsets/counts/context are non-canonical",
        )?;
        for index in 0..token_count as usize {
            require(
                be_u32(&bytes, codes_offset + index * 4)? < centroid_count,
                "independent row centroid code is out of range",
            )?;
        }
        observed_tokens = observed_tokens
            .checked_add(u64::from(token_count))
            .ok_or("independent token count overflow")?;
        rows.push(IndependentRowReadback {
            cx_id_hex: hex(&key),
            value_bytes: bytes.len(),
            value_sha256: sha256(&bytes),
            token_count,
            centroid_code_bytes: residual_offset - codes_offset,
            residual_bytes: payload_end - residual_offset,
            checksum_bytes: DIGEST_BYTES,
        });
    }
    require(
        observed_tokens == total_tokens,
        "independent row token sum differs from manifest",
    )?;
    Ok(IndependentFormatReadback {
        manifest_bytes: manifest_bytes.len(),
        manifest_sha256: sha256(&manifest_bytes),
        token_dim,
        max_token_dim,
        max_tokens,
        centroid_count,
        generation_rows,
        total_tokens,
        generation_seq,
        slot_id,
        lens_id_hex: hex(&lens_id),
        context_sha256: hex(&context),
        generation_root_sha256: hex(&generation_root),
        raw_generation_root_sha256: hex(&raw_generation_root),
        codebook_bytes,
        rows,
    })
}

pub fn file_inventory(root: &Path) -> AnyResult<FileInventory> {
    let mut entries = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let bytes = entries.iter().map(|entry| entry.bytes).sum();
    let digest_sha256 = digest_serialized(&entries)?;
    Ok(FileInventory {
        files: entries.len(),
        bytes,
        digest_sha256,
        entries,
    })
}

fn family(rows: Vec<(Vec<u8>, Vec<u8>)>) -> FamilyState {
    let mut hasher = Sha256::new();
    let mut key_bytes = 0;
    let mut value_bytes = 0;
    let mut keys_hex = Vec::with_capacity(rows.len());
    for (key, value) in &rows {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
        key_bytes += key.len();
        value_bytes += value.len();
        keys_hex.push(hex(key));
    }
    FamilyState {
        rows: rows.len(),
        key_bytes,
        value_bytes,
        digest_sha256: hex(&hasher.finalize()),
        keys_hex,
    }
}

fn collect_files(root: &Path, current: &Path, out: &mut Vec<FileEvidence>) -> AnyResult<()> {
    if !current.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("physical inventory refuses symlink {}", path.display()).into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, out)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            out.push(FileEvidence {
                path: path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                bytes: metadata.len(),
                sha256: sha256(&bytes),
            });
        }
    }
    Ok(())
}

fn require_digest(bytes: &[u8], domain: &[u8], label: &str) -> AnyResult<()> {
    require(
        bytes.len() >= DIGEST_BYTES,
        format!("{label} has no digest"),
    )?;
    let body = bytes.len() - DIGEST_BYTES;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&bytes[..body]);
    require(
        hasher.finalize().as_slice() == &bytes[body..],
        format!("{label} checksum mismatch"),
    )
}

fn be_u16(bytes: &[u8], at: usize) -> AnyResult<u16> {
    Ok(u16::from_be_bytes(bytes_at(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> AnyResult<u32> {
    Ok(u32::from_be_bytes(bytes_at(bytes, at)?))
}

fn be_u64(bytes: &[u8], at: usize) -> AnyResult<u64> {
    Ok(u64::from_be_bytes(bytes_at(bytes, at)?))
}

fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> AnyResult<[u8; N]> {
    let end = at
        .checked_add(N)
        .ok_or("independent field offset overflow")?;
    Ok(bytes
        .get(at..end)
        .ok_or("independent field exceeds record")?
        .try_into()?)
}

fn digest_serialized(value: &impl Serialize) -> AnyResult<String> {
    Ok(sha256(&serde_json::to_vec(value)?))
}

pub fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
