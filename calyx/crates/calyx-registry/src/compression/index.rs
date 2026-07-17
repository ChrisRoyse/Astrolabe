use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, Result, Seq, Slot, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BinaryHeap};

use super::codec::{
    CodecContext, CompressionManifest, ParsedStoredSlot, codec_context_id, generation_root,
    parse_compression_manifest, parse_stored_slot, raw_generation_root,
};
use super::recall::prepare_dense;
use super::{
    CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID, StoredSlotCodec,
    StoredSlotEnvelope, compression_error, verify_mxfp4_assay_attestation_at,
};
use crate::spec::LensSpec;

/// One hit scored directly from a persisted compressed slot row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedSlotHit {
    pub cx_id: CxId,
    pub score: f32,
}

/// Compression-aware view over one frozen lens/slot column.
///
/// The lens and slot are mandatory because codec seeds and dimensions are part
/// of the frozen interpretation contract. This type never consults the raw
/// sidecar when decoding or scoring a compressed row.
pub struct CompressedSlotIndex<'a, C: Clock> {
    vault: &'a AsterVault<C>,
    slot: &'a Slot,
    lens: &'a LensSpec,
    codec: CodecContext,
    codec_context_id: [u8; 32],
}

impl<'a, C: Clock> CompressedSlotIndex<'a, C> {
    pub(crate) fn open(
        vault: &'a AsterVault<C>,
        slot: &'a Slot,
        lens: &'a LensSpec,
    ) -> Result<Self> {
        let codec = CodecContext::for_read(slot, lens)?;
        let codec_context_id = codec_context_id(slot, lens, &codec)?;
        Ok(Self {
            vault,
            slot,
            lens,
            codec,
            codec_context_id,
        })
    }

    /// Reads and reconstructs one persisted compressed row at `snapshot`.
    pub fn read_at(&self, cx_id: CxId, snapshot: Seq) -> Result<SlotVector> {
        let parsed = self
            .validated_rows_at(snapshot, false)?
            .into_iter()
            .find_map(|(candidate_id, parsed)| (candidate_id == cx_id).then_some(parsed))
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_EMPTY,
                    format!(
                        "compressed slot row is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
        let data = self.codec.decode_parsed(&parsed)?;
        let vector = SlotVector::Dense {
            dim: parsed.envelope.stored_dim,
            data,
        };
        vector.validate_schema()?;
        Ok(vector)
    }

    /// Returns validated envelope metadata from the actual persisted CF row.
    pub fn envelope_at(&self, cx_id: CxId, snapshot: Seq) -> Result<StoredSlotEnvelope> {
        self.validated_rows_at(snapshot, true)?
            .into_iter()
            .find_map(|(candidate_id, parsed)| {
                (candidate_id == cx_id).then_some(parsed.envelope)
            })
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_EMPTY,
                    format!(
                        "compressed slot envelope is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })
    }

    /// Scores every visible compressed row with one prepared query and retains
    /// only the requested top-k candidates.
    pub fn search_at(
        &self,
        query: &[f32],
        k: usize,
        snapshot: Seq,
    ) -> Result<Vec<CompressedSlotHit>> {
        if k == 0 {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed slot search requires k > 0",
            ));
        }
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed slot search requires a dense slot",
            ));
        };
        if query.len() != raw_dim as usize {
            return Err(calyx_core::CalyxError::lens_dim_mismatch(format!(
                "compressed query dimension {} does not match slot dimension {raw_dim}",
                query.len()
            )));
        }
        if let Some(index) = query.iter().position(|value| !value.is_finite()) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("compressed query contains non-finite coefficient at index {index}"),
            ));
        }
        if query.iter().all(|value| *value == 0.0) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed slot search requires a non-zero query because cosine similarity is undefined at zero norm",
            ));
        }
        let prepared_values = prepare_dense(query, self.lens.truncate_dim)?;
        let prepared_query = self.codec.prepare_query(&prepared_values)?;
        let rows = self.validated_rows_at(snapshot, false)?;
        let mut best = BinaryHeap::with_capacity(k.min(rows.len()));
        for (cx_id, parsed) in rows {
            let score = self.codec.score_parsed(&prepared_query, &parsed)?;
            if !score.is_finite() {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("compressed score is non-finite for cx_id={cx_id}"),
                ));
            }
            retain_top_k(&mut best, CompressedSlotHit { cx_id, score }, k);
        }
        let mut best = best
            .into_vec()
            .into_iter()
            .map(|hit| hit.0)
            .collect::<Vec<_>>();
        best.sort_by(compare_hits);
        Ok(best)
    }

    /// Validates the manifest, every row binding, row count, and whole-column root.
    pub fn verify_at(&self, snapshot: Seq) -> Result<()> {
        self.validated_rows_at(snapshot, true).map(|_| ())
    }

    fn parse_contextual(&self, bytes: &[u8], expected_cx_id: CxId) -> Result<ParsedStoredSlot> {
        let parsed = parse_stored_slot(bytes)?;
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed row belongs to a non-dense slot",
            ));
        };
        if parsed.envelope.raw_dim != raw_dim
            || parsed.envelope.stored_dim as usize != self.codec.dim()
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "persisted envelope dimensions do not match frozen slot/lens: expected raw={} stored={} got raw={} stored={}",
                    raw_dim,
                    self.codec.dim(),
                    parsed.envelope.raw_dim,
                    parsed.envelope.stored_dim
                ),
            ));
        }
        if parsed.codec_context_id != self.codec_context_id {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "persisted envelope codec context does not match the frozen slot/lens",
            ));
        }
        if parsed.cx_id != expected_cx_id {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "persisted envelope CxId {} does not match CF key {expected_cx_id}",
                    parsed.cx_id
                ),
            ));
        }
        self.codec.validate_parsed(&parsed)?;
        Ok(parsed)
    }

    fn validated_rows_at(
        &self,
        snapshot: Seq,
        validate_payloads: bool,
    ) -> Result<Vec<(CxId, ParsedStoredSlot)>> {
        let manifest_bytes = self
            .vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Compression,
                &compression_manifest_key(self.slot.slot_id),
            )?
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_EMPTY,
                    format!(
                        "compression manifest is missing: slot={} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
        let manifest = parse_compression_manifest(&manifest_bytes)?;
        self.validate_manifest(&manifest)?;
        let rows = self
            .vault
            .scan_cf_at(snapshot, ColumnFamily::slot(self.slot.slot_id))?;
        if rows.len() != manifest.generation_rows as usize {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed generation row count mismatch: manifest={} persisted={}",
                    manifest.generation_rows,
                    rows.len()
                ),
            ));
        }
        let mut parsed_rows = Vec::with_capacity(rows.len());
        for (key, bytes) in rows {
            let cx_id = decode_cx_id_key(&key)?;
            let parsed = self.parse_contextual(&bytes, cx_id)?;
            if validate_payloads {
                self.codec.validate_payload(&parsed)?;
            }
            if parsed.generation_root != manifest.generation_root
                || parsed.generation_rows != manifest.generation_rows
            {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("compressed row {cx_id} disagrees with its generation manifest"),
                ));
            }
            parsed_rows.push((cx_id, parsed));
        }
        if manifest.codec == StoredSlotCodec::MxFp4 {
            let attestation_id = parsed_rows
                .first()
                .map(|(_, parsed)| parsed.qv.seed_id)
                .ok_or_else(|| {
                    compression_error(
                        CALYX_VECTOR_COMPRESSION_EMPTY,
                        "MXFP4 generation contains no rows to attest",
                    )
                })?;
            if parsed_rows
                .iter()
                .any(|(_, parsed)| parsed.qv.seed_id != attestation_id)
            {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    "MXFP4 generation rows disagree on Assay attestation identity",
                ));
            }
            verify_mxfp4_assay_attestation_at(
                self.vault,
                self.slot,
                self.lens,
                manifest.stored_dim,
                snapshot,
                attestation_id,
            )?;
        }
        let computed = generation_root(
            &self.codec_context_id,
            manifest.generation_rows,
            parsed_rows
                .iter()
                .map(|(cx_id, parsed)| (*cx_id, &parsed.qv)),
        )?;
        if computed != manifest.generation_root {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed whole-column generation root mismatch",
            ));
        }
        if validate_payloads {
            self.validate_raw_generation(snapshot, &manifest, &parsed_rows)?;
        }
        Ok(parsed_rows)
    }

    fn validate_raw_generation(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
        parsed_rows: &[(CxId, ParsedStoredSlot)],
    ) -> Result<()> {
        let raw_rows = self
            .vault
            .scan_cf_at(snapshot, ColumnFamily::slot_raw(self.slot.slot_id))?;
        if raw_rows.len() != manifest.generation_rows as usize {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "raw-sidecar generation row count mismatch: manifest={} persisted={}",
                    manifest.generation_rows,
                    raw_rows.len()
                ),
            ));
        }
        let expected_keys = parsed_rows
            .iter()
            .map(|(cx_id, _)| (*cx_id, ()))
            .collect::<BTreeMap<_, _>>();
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "raw-sidecar generation belongs to a non-dense slot",
            ));
        };
        let mut validated = Vec::with_capacity(raw_rows.len());
        for (key, bytes) in &raw_rows {
            let cx_id = decode_cx_id_key(key)?;
            if !expected_keys.contains_key(&cx_id) {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("raw sidecar has no matching compressed row for cx_id={cx_id}"),
                ));
            }
            let vector = encode::decode_slot_vector(bytes)?;
            match vector {
                SlotVector::Dense { dim, data } if dim == raw_dim => {
                    SlotVector::Dense { dim, data }.validate_schema()?;
                }
                SlotVector::Dense { dim, .. } => {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!(
                            "raw sidecar dimension {dim} does not match frozen slot dimension {raw_dim} for cx_id={cx_id}"
                        ),
                    ));
                }
                _ => {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!("raw sidecar is not dense for cx_id={cx_id}"),
                    ));
                }
            }
            validated.push((cx_id, bytes.as_slice()));
        }
        let computed =
            raw_generation_root(&self.codec_context_id, manifest.generation_rows, validated)?;
        if computed != manifest.raw_generation_root {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "raw-sidecar whole-column generation root mismatch",
            ));
        }
        Ok(())
    }

    fn validate_manifest(&self, manifest: &CompressionManifest) -> Result<()> {
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed manifest belongs to a non-dense slot",
            ));
        };
        if manifest.codec != self.codec.stored_codec()
            || manifest.level != self.codec.level()
            || manifest.raw_dim != raw_dim
            || manifest.stored_dim as usize != self.codec.dim()
            || manifest.codec_context_id != self.codec_context_id
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compression manifest does not match the frozen slot/lens codec context",
            ));
        }
        Ok(())
    }
}

fn decode_cx_id_key(key: &[u8]) -> Result<CxId> {
    if key.len() != 16 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "compressed slot key length must be 16-byte CxId, got {}",
                key.len()
            ),
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}

struct HeapHit(CompressedSlotHit);

impl PartialEq for HeapHit {
    fn eq(&self, other: &Self) -> bool {
        compare_hits(&self.0, &other.0).is_eq()
    }
}

impl Eq for HeapHit {}

impl PartialOrd for HeapHit {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapHit {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        compare_hits(&self.0, &other.0)
    }
}

fn retain_top_k(best: &mut BinaryHeap<HeapHit>, hit: CompressedSlotHit, k: usize) {
    if best.len() < k {
        best.push(HeapHit(hit));
        return;
    }
    let Some(worst) = best.peek() else {
        return;
    };
    if compare_hits(&hit, &worst.0).is_lt() {
        best.pop();
        best.push(HeapHit(hit));
    }
}

fn compare_hits(left: &CompressedSlotHit, right: &CompressedSlotHit) -> std::cmp::Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()))
}
