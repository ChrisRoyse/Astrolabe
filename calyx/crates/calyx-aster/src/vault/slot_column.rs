use super::{AsterVault, encode};
use crate::cf::ColumnFamily;
use crate::mmap_col::MmapColumn;
use crate::sst::arrow::{decode_column_chunk, encode_column_chunk};
use calyx_core::{CalyxError, Clock, CxId, Result, Seq, SlotId, SlotVector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MANIFEST_MAGIC: &str = "CXSC1";
const MANIFEST_VERSION: u32 = 1;
const CHUNK_FILE: &str = "slot-column.cxa1";
const MANIFEST_FILE: &str = "slot-column-manifest.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotColumnMaterialization {
    pub slot: SlotId,
    pub snapshot: Seq,
    pub rows: usize,
    pub dim: u32,
    pub manifest_path: PathBuf,
    pub chunk_path: PathBuf,
    pub manifest_sha256: String,
    pub chunk_sha256: String,
    pub cx_ids: Vec<CxId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotColumnManifest {
    pub magic: String,
    pub version: u32,
    pub slot: SlotId,
    pub snapshot: Seq,
    pub rows: usize,
    pub dim: u32,
    pub cx_ids: Vec<CxId>,
    pub chunk_file: String,
    pub chunk_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SlotColumnReadback {
    pub manifest: SlotColumnManifest,
    pub manifest_path: PathBuf,
    pub chunk_path: PathBuf,
    pub rows: Vec<SlotColumnRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SlotColumnRow {
    pub cx_id: CxId,
    pub values: Vec<f32>,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn materialize_slot_column_at(
        &self,
        snapshot: Seq,
        slot: SlotId,
        output_dir: impl AsRef<Path>,
    ) -> Result<SlotColumnMaterialization> {
        let rows = self.dense_slot_rows_at(snapshot, slot)?;
        let output_dir = output_dir.as_ref();
        fs::create_dir_all(output_dir)
            .map_err(|error| storage_error("create slot-column output dir", error))?;

        let refs = rows
            .iter()
            .map(|row| row.values.as_slice())
            .collect::<Vec<_>>();
        let chunk_bytes = encode_column_chunk(&refs)?;
        let chunk_sha256 = sha256_hex(&chunk_bytes);
        let chunk_path = output_dir.join(CHUNK_FILE);
        write_atomic(&chunk_path, &chunk_bytes)?;

        let dim = rows
            .first()
            .ok_or_else(|| CalyxError::stale_derived("slot column has no dense rows"))?
            .values
            .len() as u32;
        let manifest = SlotColumnManifest {
            magic: MANIFEST_MAGIC.to_string(),
            version: MANIFEST_VERSION,
            slot,
            snapshot,
            rows: rows.len(),
            dim,
            cx_ids: rows.iter().map(|row| row.cx_id).collect(),
            chunk_file: CHUNK_FILE.to_string(),
            chunk_sha256: chunk_sha256.clone(),
        };
        let manifest_bytes = encode_manifest(&manifest)?;
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        let manifest_path = output_dir.join(MANIFEST_FILE);
        write_atomic(&manifest_path, &manifest_bytes)?;

        Ok(SlotColumnMaterialization {
            slot,
            snapshot,
            rows: manifest.rows,
            dim,
            manifest_path,
            chunk_path,
            manifest_sha256,
            chunk_sha256,
            cx_ids: manifest.cx_ids,
        })
    }

    fn dense_slot_rows_at(&self, snapshot: Seq, slot: SlotId) -> Result<Vec<SlotColumnRow>> {
        let snapshot = self.snapshot_handle(snapshot);
        let rows =
            self.rows
                .scan_cf_at(snapshot.snapshot(), ColumnFamily::slot(slot), &self.clock)?;
        if rows.is_empty() {
            return Err(CalyxError::stale_derived(format!(
                "slot {slot} has no rows to materialize"
            )));
        }

        let mut out = Vec::with_capacity(rows.len());
        let mut dim = None;
        for (key, value) in rows {
            let cx_id = cx_id_from_key(&key)?;
            let vector = encode::decode_slot_vector(&value)?;
            let SlotVector::Dense { dim: row_dim, data } = vector else {
                return Err(CalyxError::stale_derived(
                    "slot column materialization requires dense slot vectors",
                ));
            };
            if let Some(expected) = dim {
                if expected != row_dim {
                    return Err(CalyxError::aster_corrupt_shard(
                        "slot column dense dimensions differ",
                    ));
                }
            } else {
                dim = Some(row_dim);
            }
            out.push(SlotColumnRow {
                cx_id,
                values: data,
            });
        }
        Ok(out)
    }
}

pub fn read_materialized_slot_column(
    manifest_path: impl AsRef<Path>,
) -> Result<SlotColumnReadback> {
    let manifest_path = manifest_path.as_ref();
    let manifest_bytes =
        fs::read(manifest_path).map_err(|error| storage_error("read slot manifest", error))?;
    let manifest = decode_manifest(&manifest_bytes)?;
    let parent = manifest_path
        .parent()
        .ok_or_else(|| CalyxError::disk_pressure("slot manifest has no parent"))?;
    if manifest.chunk_file != CHUNK_FILE {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column manifest chunk path invalid",
        ));
    }
    let chunk_path = parent.join(CHUNK_FILE);
    let column = MmapColumn::open(&chunk_path)?;
    let chunk_bytes = column.as_bytes();
    let actual_sha256 = sha256_hex(chunk_bytes);
    if actual_sha256 != manifest.chunk_sha256 {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column chunk sha256 mismatch",
        ));
    }

    let chunk = decode_column_chunk(chunk_bytes)?;
    if chunk.n_rows() != manifest.rows || chunk.dim() != manifest.dim as usize {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column manifest shape mismatch",
        ));
    }
    if manifest.cx_ids.len() != manifest.rows {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column cx_id count mismatch",
        ));
    }

    let mut rows = Vec::with_capacity(manifest.rows);
    for (index, cx_id) in manifest.cx_ids.iter().copied().enumerate() {
        rows.push(SlotColumnRow {
            cx_id,
            values: chunk.row(index)?.to_vec(),
        });
    }
    Ok(SlotColumnReadback {
        manifest,
        manifest_path: manifest_path.to_path_buf(),
        chunk_path,
        rows,
    })
}

fn cx_id_from_key(key: &[u8]) -> Result<CxId> {
    if key.len() != 16 {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column row key is not a CxId",
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}

fn encode_manifest(manifest: &SlotColumnManifest) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(manifest).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!("encode slot column manifest: {error}"))
    })
}

fn decode_manifest(bytes: &[u8]) -> Result<SlotColumnManifest> {
    let manifest: SlotColumnManifest = serde_json::from_slice(bytes).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!("decode slot column manifest: {error}"))
    })?;
    if manifest.magic != MANIFEST_MAGIC || manifest.version != MANIFEST_VERSION {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column manifest version mismatch",
        ));
    }
    Ok(manifest)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file =
            File::create(&tmp).map_err(|error| storage_error("create slot temp", error))?;
        file.write_all(bytes)
            .map_err(|error| storage_error("write slot temp", error))?;
        file.sync_all()
            .map_err(|error| storage_error("fsync slot temp", error))?;
    }
    fs::rename(&tmp, path).map_err(|error| storage_error("rename slot artifact", error))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<()> {
    crate::fsync::sync_parent(path, "slot artifact")
}

fn storage_error(context: &str, error: io::Error) -> CalyxError {
    CalyxError::disk_pressure(format!("{context}: {error}"))
}
