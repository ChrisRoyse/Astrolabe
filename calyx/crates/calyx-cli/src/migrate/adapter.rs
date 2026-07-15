use std::collections::BTreeMap;

use calyx_core::{
    CalyxError, CxFlags, CxId, InputRef, LedgerRef, LensId, METADATA_CHUNK_ID,
    METADATA_DATABASE_NAME, METADATA_SOURCE_EVENT_TIME_RAW, METADATA_SOURCE_EVENT_TIME_SECS,
    METADATA_SOURCE_SEQUENCE, METADATA_TEMPORAL_INACTIVE_REASON, METADATA_TEMPORAL_LANE_STATE,
    Modality, SlotId, SlotVector, TEMPORAL_LANE_ACTIVE, TEMPORAL_LANE_INACTIVE,
    TEMPORAL_MISSING_CREATED_AT, VaultId, content_address,
};
use calyx_registry::{instantiate_panel, text_default};

use super::manifest::{hex_encode, now_ms};
use super::reader::ChunkRow;
use crate::error::CliResult;

pub const BASE_SLOT: SlotId = SlotId::new(0);
pub const METADATA_ROWID: &str = "sqlite_rowid";
pub const METADATA_CONTENT_HASH: &str = "content_hash_blake3";
pub const METADATA_GTE_LENS_ID: &str = "gte_lens_id";
pub const GTE_EMBEDDING_DIM: usize = 768;

const CX_ID_PANEL_VERSION: u32 = 1;
const CX_ID_SALT: [u8; 16] = [0; 16];

/// Rust port of the `vault-sqlite.ts` direct-import invariants:
/// 1. `CxId` is deterministic from content bytes and the migration ID domain.
/// 2. Candidate text is never stored; the constellation carries a redacted hash reference.
/// 3. `chunk_id` and `database_name` survive verbatim as string metadata.
/// 4. GTE vectors are exact 768-d finite f32 payloads isolated by explicit lens/slot identity.
#[derive(Clone, Debug)]
pub struct VaultSqliteAdapter {
    vault_id: VaultId,
    panel_version: u32,
    gte_lens_id: LensId,
    slot_id: SlotId,
}

impl VaultSqliteAdapter {
    pub fn new_with_lens_slot(
        vault_id: VaultId,
        panel_version: u32,
        gte_lens_id: LensId,
        slot_id: SlotId,
    ) -> Self {
        Self {
            vault_id,
            panel_version,
            gte_lens_id,
            slot_id,
        }
    }

    pub fn cx_id(&self, row: &ChunkRow) -> CxId {
        CxId::from_input(&row.content, CX_ID_PANEL_VERSION, &CX_ID_SALT)
    }

    pub fn constellation(&self, row: &ChunkRow) -> CliResult<calyx_core::Constellation> {
        validate_gte_embedding(row)?;
        let cx_id = self.cx_id(row);
        let mut slots = BTreeMap::new();
        slots.insert(
            self.slot_id,
            SlotVector::Dense {
                dim: row.embedding.len() as u32,
                data: row.embedding.clone(),
            },
        );
        let mut metadata = BTreeMap::new();
        metadata.insert(METADATA_CHUNK_ID.to_string(), row.chunk_id.clone());
        metadata.insert(
            METADATA_DATABASE_NAME.to_string(),
            row.database_name.clone(),
        );
        metadata.insert(METADATA_ROWID.to_string(), row.row_num.to_string());
        metadata.insert(
            METADATA_SOURCE_SEQUENCE.to_string(),
            "sqlite_rowid".to_string(),
        );
        metadata.insert(
            METADATA_CONTENT_HASH.to_string(),
            hex_encode(&row.content_hash()),
        );
        metadata.insert(
            METADATA_GTE_LENS_ID.to_string(),
            self.gte_lens_id.to_string(),
        );
        let created_at = match row.event_time_secs {
            Some(secs) => {
                metadata.insert(
                    METADATA_TEMPORAL_LANE_STATE.to_string(),
                    TEMPORAL_LANE_ACTIVE.to_string(),
                );
                metadata.insert(
                    METADATA_SOURCE_EVENT_TIME_SECS.to_string(),
                    secs.to_string(),
                );
                if let Some(raw) = &row.event_time_raw {
                    metadata.insert(METADATA_SOURCE_EVENT_TIME_RAW.to_string(), raw.clone());
                }
                secs
            }
            None => {
                metadata.insert(
                    METADATA_TEMPORAL_LANE_STATE.to_string(),
                    TEMPORAL_LANE_INACTIVE.to_string(),
                );
                metadata.insert(
                    METADATA_TEMPORAL_INACTIVE_REASON.to_string(),
                    TEMPORAL_MISSING_CREATED_AT.to_string(),
                );
                now_ms()
            }
        };
        Ok(calyx_core::Constellation {
            cx_id,
            vault_id: self.vault_id,
            panel_version: self.panel_version,
            created_at,
            input_ref: InputRef {
                hash: row.content_hash(),
                pointer: Some(row.pointer()),
                redacted: true,
            },
            modality: Modality::Text,
            slots,
            scalars: BTreeMap::new(),
            metadata,
            anchors: Vec::new(),
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            flags: CxFlags {
                ungrounded: true,
                redacted_input: true,
                ..CxFlags::default()
            },
        })
    }
}

#[allow(dead_code)]
pub fn gte_lens_id_for_hash(model_weights_hash: &[u8; 32]) -> LensId {
    LensId::from_bytes(content_address([model_weights_hash.as_slice()]))
}

fn validate_gte_embedding(row: &ChunkRow) -> CliResult {
    if row.embedding.len() != GTE_EMBEDDING_DIM {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "row {} GTE embedding dim {} expected {GTE_EMBEDDING_DIM}",
            row.row_num,
            row.embedding.len()
        ))
        .into());
    }
    if row.embedding.iter().any(|value| !value.is_finite()) {
        return Err(CalyxError::lens_numerical_invariant(format!(
            "row {} GTE embedding contains NaN or Inf",
            row.row_num
        ))
        .into());
    }
    Ok(())
}

pub fn default_panel_version() -> u32 {
    instantiate_panel(&text_default(), 0).panel.version
}

pub fn default_gte_lens_id() -> LensId {
    instantiate_panel(&text_default(), 0).panel.slots[0].lens_id
}

pub fn default_base_lens_id() -> String {
    default_gte_lens_id().to_string()
}
