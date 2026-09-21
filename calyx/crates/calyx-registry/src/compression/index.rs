use calyx_aster::cf::{
    ColumnFamily, compression_manifest_key, compression_membership_proof_key,
    compression_membership_proof_prefix_range, parse_compression_membership_proof_key, slot_key,
};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, Result, Seq, Slot, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BinaryHeap};

use super::codec::{
    CodecContext, CodecDescriptor, CompressionManifest, ParsedStoredSlot, codec_context_id,
    codec_context_id_for_descriptor, generation_root, parse_compression_manifest,
    parse_stored_slot, raw_generation_root,
};
use super::membership::{membership_root_from_leaf_hashes, verify_membership_proof};
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

/// Immutable identity of one persisted compressed generation after the
/// registered slot/lens context has been verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedGenerationIdentity {
    pub slot_id: u16,
    pub codec: StoredSlotCodec,
    pub level: String,
    pub raw_dim: u32,
    pub stored_dim: u32,
    pub row_count: u32,
    pub codec_context_sha256: String,
    pub generation_sha256: String,
    pub raw_generation_sha256: String,
    pub membership_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assay_attestation_sha256: Option<String>,
}

/// Per-row reconstruction evidence derived from the registered compressed
/// decoder and the independently persisted raw sidecar.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressionReconstructionObservation {
    pub cx_id: CxId,
    pub cosine_error: f64,
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

/// Reads only the immutable manifest and validates it against a pure codec
/// descriptor. Status, selection, and publication use this path so a metadata
/// request cannot instantiate codec geometry (#1064 PC-43).
pub(crate) fn generation_identity_without_codec_at<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    snapshot: Seq,
) -> Result<CompressedGenerationIdentity> {
    let descriptor = CodecDescriptor::for_read(slot, lens)?;
    let codec_context_id = codec_context_id_for_descriptor(slot, lens, descriptor)?;
    let snapshot_lease = vault.retain_snapshot_at(snapshot);
    let manifest_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
        )?
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_EMPTY,
                format!(
                    "compression manifest is missing: slot={} snapshot={snapshot}",
                    slot.slot_key.key()
                ),
            )
        })?;
    let manifest = parse_compression_manifest(&manifest_bytes)?;
    validate_manifest_descriptor(slot, descriptor, codec_context_id, &manifest)?;
    snapshot_lease.record_progress();
    Ok(identity_from_manifest(slot, &manifest))
}

fn validate_manifest_descriptor(
    slot: &Slot,
    descriptor: CodecDescriptor,
    codec_context_id: [u8; 32],
    manifest: &CompressionManifest,
) -> Result<()> {
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "compressed manifest belongs to a non-dense slot",
        ));
    };
    if manifest.codec != descriptor.stored_codec()
        || manifest.level != descriptor.level()
        || manifest.raw_dim != raw_dim
        || manifest.stored_dim as usize != descriptor.dim()
        || manifest.codec_context_id != codec_context_id
    {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "compression manifest does not match the frozen slot/lens codec context",
        ));
    }
    Ok(())
}

fn identity_from_manifest(
    slot: &Slot,
    manifest: &CompressionManifest,
) -> CompressedGenerationIdentity {
    CompressedGenerationIdentity {
        slot_id: slot.slot_id.get(),
        codec: manifest.codec,
        level: manifest.level.to_string(),
        raw_dim: manifest.raw_dim,
        stored_dim: manifest.stored_dim,
        row_count: manifest.generation_rows,
        codec_context_sha256: hex(&manifest.codec_context_id),
        generation_sha256: hex(&manifest.generation_root),
        raw_generation_sha256: hex(&manifest.raw_generation_root),
        membership_sha256: hex(&manifest.membership_root),
        assay_attestation_sha256: (manifest.codec == StoredSlotCodec::MxFp4)
            .then(|| hex(&manifest.assay_attestation_id)),
    }
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

    /// Reuses the exact codec context returned by this candidate's encoder. The
    /// pure descriptor and context hash are re-derived before ownership moves
    /// into the index; manifest and row validation retain their seed bindings.
    pub(super) fn open_with_context(
        vault: &'a AsterVault<C>,
        slot: &'a Slot,
        lens: &'a LensSpec,
        codec: CodecContext,
    ) -> Result<Self> {
        let descriptor = CodecDescriptor::for_read(slot, lens)?;
        codec.validate_descriptor(descriptor)?;
        let codec_context_id = codec_context_id_for_descriptor(slot, lens, descriptor)?;
        Ok(Self {
            vault,
            slot,
            lens,
            codec,
            codec_context_id,
        })
    }

    pub(super) fn codec_geometry_physical_bytes(&self) -> Result<u64> {
        self.codec.geometry_physical_bytes()
    }

    /// Reads and reconstructs one persisted compressed row at `snapshot`.
    ///
    /// This resolves only the generation manifest, requested primary row, and
    /// its membership proof. Whole-generation row/raw/Assay scans remain the
    /// responsibility of [`Self::verify_at`].
    pub fn read_at(&self, cx_id: CxId, snapshot: Seq) -> Result<SlotVector> {
        let parsed = self.validated_row_at(cx_id, snapshot)?;
        let data = self.codec.decode_parsed(&parsed)?;
        let vector = SlotVector::Dense {
            dim: parsed.envelope.stored_dim,
            data,
        };
        vector.validate_schema()?;
        Ok(vector)
    }

    /// Reads one optional compressed member. Absence is returned only when
    /// both the primary row and its proof are absent; a one-sided presence is a
    /// corrupt generation.
    pub fn read_optional_at(&self, cx_id: CxId, snapshot: Seq) -> Result<Option<SlotVector>> {
        self.read_many_optional_at(&[cx_id], snapshot)
            .map(|mut rows| rows.pop().and_then(|(_, vector)| vector))
    }

    /// Returns membership-authenticated envelope metadata from the requested
    /// persisted CF row without scanning the slot column.
    pub fn envelope_at(&self, cx_id: CxId, snapshot: Seq) -> Result<StoredSlotEnvelope> {
        Ok(self.validated_row_at(cx_id, snapshot)?.envelope)
    }

    /// Reads a caller-declared set of rows while resolving and validating the
    /// immutable generation manifest exactly once. The manifest is resolved
    /// before the primary/proof batch so an invalid generation refuses before
    /// row I/O; one retained snapshot binds both plans. Duplicate identities
    /// are refused so work cannot be silently repeated.
    pub fn read_many_at(&self, cx_ids: &[CxId], snapshot: Seq) -> Result<Vec<(CxId, SlotVector)>> {
        self.read_many_optional_at(cx_ids, snapshot)?
            .into_iter()
            .map(|(cx_id, vector)| {
                vector
                    .map(|vector| (cx_id, vector))
                    .ok_or_else(|| {
                        compression_error(
                            CALYX_VECTOR_COMPRESSION_EMPTY,
                            format!(
                                "compressed slot row is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                                self.slot.slot_key.key()
                            ),
                        )
                    })
            })
            .collect()
    }

    /// Reads a duplicate-free roster in caller order under one retained
    /// snapshot. A requested non-member is `None` only when both its primary
    /// and proof rows are absent at the pinned sequence.
    pub fn read_many_optional_at(
        &self,
        cx_ids: &[CxId],
        snapshot: Seq,
    ) -> Result<Vec<(CxId, Option<SlotVector>)>> {
        self.validate_batch_request(cx_ids)?;
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        let capacity = cx_ids.len().checked_mul(2).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed batch read plan length overflowed usize",
            )
        })?;
        let mut reads = Vec::with_capacity(capacity);
        for cx_id in cx_ids {
            reads.push((ColumnFamily::slot(self.slot.slot_id), slot_key(*cx_id)));
            reads.push((
                ColumnFamily::Compression,
                compression_membership_proof_key(self.slot.slot_id, *cx_id),
            ));
        }
        let mut values = self.vault.read_cf_batch_at(snapshot, reads)?.into_iter();
        self.decode_optional_batch_rows(cx_ids, snapshot, &manifest, &mut values)
    }

    /// Resolves a roster after the Registry adapter has already read the exact
    /// manifest as its representation discriminator. The supplied bytes are
    /// still parsed and fully validated; only the redundant manifest I/O is
    /// removed from this operation.
    pub(crate) fn read_many_optional_with_manifest_at(
        &self,
        cx_ids: &[CxId],
        snapshot: Seq,
        manifest_bytes: &[u8],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>> {
        self.validate_batch_request(cx_ids)?;
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = parse_compression_manifest(manifest_bytes)?;
        self.validate_manifest(&manifest)?;
        snapshot_lease.record_progress();
        let capacity = cx_ids.len().checked_mul(2).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed batch read plan length overflowed usize",
            )
        })?;
        let mut reads = Vec::with_capacity(capacity);
        for cx_id in cx_ids {
            reads.push((ColumnFamily::slot(self.slot.slot_id), slot_key(*cx_id)));
            reads.push((
                ColumnFamily::Compression,
                compression_membership_proof_key(self.slot.slot_id, *cx_id),
            ));
        }
        let mut values = self.vault.read_cf_batch_at(snapshot, reads)?.into_iter();
        self.decode_optional_batch_rows(cx_ids, snapshot, &manifest, &mut values)
    }

    fn validate_batch_request(&self, cx_ids: &[CxId]) -> Result<()> {
        if cx_ids.is_empty() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_EMPTY,
                "compressed batch read requires at least one CxId",
            ));
        }
        let mut unique = cx_ids.to_vec();
        unique.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if unique.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed batch read contains a duplicate CxId",
            ));
        }
        Ok(())
    }

    fn decode_optional_batch_rows<I>(
        &self,
        cx_ids: &[CxId],
        snapshot: Seq,
        manifest: &CompressionManifest,
        values: &mut I,
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>
    where
        I: Iterator<Item = Option<Vec<u8>>>,
    {
        let mut rows = Vec::with_capacity(cx_ids.len());
        for cx_id in cx_ids {
            let stored = values.next().ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!(
                        "compressed batch result omitted the primary ordinal for slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
            let proof = values.next().ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!(
                        "compressed batch result omitted the proof ordinal for slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
            let (stored, proof) = match (stored, proof) {
                (None, None) => {
                    rows.push((*cx_id, None));
                    continue;
                }
                (Some(_), None) => {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!(
                            "compressed membership proof is missing: slot={} cx_id={cx_id} snapshot={snapshot}; re-commission or re-ingest the generation",
                            self.slot.slot_key.key()
                        ),
                    ));
                }
                (None, Some(_)) => {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!(
                            "compressed membership proof exists without its primary row: slot={} cx_id={cx_id} snapshot={snapshot}; repair the generation",
                            self.slot.slot_key.key()
                        ),
                    ));
                }
                (Some(stored), Some(proof)) => (stored, proof),
            };
            let parsed =
                self.validate_row_values_with_manifest(*cx_id, &stored, &proof, manifest)?;
            let data = self.codec.decode_parsed(&parsed)?;
            let vector = SlotVector::Dense {
                dim: parsed.envelope.stored_dim,
                data,
            };
            vector.validate_schema()?;
            rows.push((*cx_id, Some(vector)));
        }
        if values.next().is_some() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed batch result returned extra ordinals for slot={} snapshot={snapshot}",
                    self.slot.slot_key.key()
                ),
            ));
        }
        Ok(rows)
    }

    /// Decodes one complete serving generation after authenticating every
    /// primary row, membership proof, whole-column root, and required Assay
    /// attestation. Recovery-only raw sidecars are not opened by this serving
    /// operation. This performs one generation scan, never one manifest scan
    /// per row.
    pub fn read_all_at(&self, snapshot: Seq) -> Result<Vec<(CxId, SlotVector)>> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        self.decode_all_with_manifest_at(snapshot, &manifest)
    }

    /// Decodes one complete serving generation after the Registry adapter has
    /// already read the exact manifest as its representation discriminator.
    /// The supplied bytes remain fully parsed and context-validated; this only
    /// hoists redundant manifest I/O out of the operation.
    pub(crate) fn read_all_with_manifest_at(
        &self,
        snapshot: Seq,
        manifest_bytes: &[u8],
    ) -> Result<Vec<(CxId, SlotVector)>> {
        let _snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = parse_compression_manifest(manifest_bytes)?;
        self.validate_manifest(&manifest)?;
        self.decode_all_with_manifest_at(snapshot, &manifest)
    }

    fn decode_all_with_manifest_at(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
    ) -> Result<Vec<(CxId, SlotVector)>> {
        self.validated_rows_with_manifest_at(snapshot, manifest, true, true, false)?
            .into_iter()
            .map(|(cx_id, parsed)| {
                let data = self.codec.decode_parsed(&parsed)?;
                let vector = SlotVector::Dense {
                    dim: parsed.envelope.stored_dim,
                    data,
                };
                vector.validate_schema()?;
                Ok((cx_id, vector))
            })
            .collect()
    }

    /// Returns the verified immutable generation identity without exposing the
    /// manifest encoding as an alternate interpretation surface.
    pub fn generation_identity_at(&self, snapshot: Seq) -> Result<CompressedGenerationIdentity> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        Ok(identity_from_manifest(self.slot, &manifest))
    }

    /// Computes reconstruction error without retaining a decoded corpus. The
    /// compressed generation and its membership proofs are validated once,
    /// raw rows are independently root-checked once, and each decoded pair is
    /// discarded immediately after its observation is derived.
    pub fn reconstruction_observations_at(
        &self,
        snapshot: Seq,
    ) -> Result<Vec<CompressionReconstructionObservation>> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        self.verify_manifest_assay_source_at(snapshot, &manifest)?;
        snapshot_lease.record_progress();
        let parsed_rows =
            self.validated_rows_with_manifest_at(snapshot, &manifest, false, true, false)?;
        snapshot_lease.record_progress();
        let raw_rows = self.validated_raw_rows(snapshot, &manifest, &parsed_rows)?;
        self.reconstruction_observations_against_parsed(&parsed_rows, &raw_rows)
    }

    /// Derives reconstruction error from caller-held raw rows only after the
    /// complete compressed generation and membership proof set has been
    /// authenticated. Registry's admission path uses this after independently
    /// validating the same raw bytes/root, avoiding a second full raw-CF scan.
    pub(super) fn reconstruction_observations_against_at(
        &self,
        snapshot: Seq,
        raw_rows: &[(CxId, Vec<f32>)],
    ) -> Result<Vec<CompressionReconstructionObservation>> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        self.verify_manifest_assay_source_at(snapshot, &manifest)?;
        snapshot_lease.record_progress();
        let parsed_rows =
            self.validated_rows_with_manifest_at(snapshot, &manifest, false, true, false)?;
        self.reconstruction_observations_against_parsed(&parsed_rows, raw_rows)
    }

    fn reconstruction_observations_against_parsed(
        &self,
        parsed_rows: &[(CxId, ParsedStoredSlot)],
        raw_rows: &[(CxId, Vec<f32>)],
    ) -> Result<Vec<CompressionReconstructionObservation>> {
        let mut raw_by_id = raw_rows
            .iter()
            .map(|(cx_id, values)| (*cx_id, values.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let mut observations = Vec::with_capacity(parsed_rows.len());
        for (cx_id, parsed) in parsed_rows {
            let reconstructed = self.codec.decode_parsed(parsed)?;
            let raw = raw_by_id.remove(cx_id).ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("raw sidecar is missing during reconstruction for cx_id={cx_id}"),
                )
            })?;
            observations.push(CompressionReconstructionObservation {
                cx_id: *cx_id,
                cosine_error: cosine_error(raw, &reconstructed)?,
            });
        }
        if !raw_by_id.is_empty() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "raw sidecar contains rows without reconstruction observations",
            ));
        }
        Ok(observations)
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
        let rows = self.validated_rows_at(snapshot, false, false, false)?;
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

    /// Audits the manifest, every primary row and proof, the recovery raw
    /// sidecar, required Assay evidence, row counts, and both generation roots.
    pub fn verify_at(&self, snapshot: Seq) -> Result<()> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        self.verify_manifest_assay_source_at(snapshot, &manifest)?;
        snapshot_lease.record_progress();
        self.validated_rows_with_manifest_at(snapshot, &manifest, true, true, true)
            .map(|_| ())
    }

    fn validated_row_at(&self, cx_id: CxId, snapshot: Seq) -> Result<ParsedStoredSlot> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        let values = self.vault.read_cf_batch_at(
            snapshot,
            [
                (ColumnFamily::slot(self.slot.slot_id), slot_key(cx_id)),
                (
                    ColumnFamily::Compression,
                    compression_membership_proof_key(self.slot.slot_id, cx_id),
                ),
            ],
        )?;
        snapshot_lease.record_progress();
        let mut values = values.into_iter();
        let stored = values.next().flatten().ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_EMPTY,
                format!(
                    "compressed slot row is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                    self.slot.slot_key.key()
                ),
            )
        })?;
        let proof = values.next().flatten().ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed membership proof is missing: slot={} cx_id={cx_id} snapshot={snapshot}; re-commission or re-ingest the generation",
                    self.slot.slot_key.key()
                ),
            )
        })?;
        self.validate_row_values_with_manifest(cx_id, &stored, &proof, &manifest)
    }

    fn validate_row_values_with_manifest(
        &self,
        cx_id: CxId,
        stored: &[u8],
        proof: &[u8],
        manifest: &CompressionManifest,
    ) -> Result<ParsedStoredSlot> {
        let parsed = self.parse_contextual(stored, cx_id)?;
        self.codec.validate_payload(&parsed)?;
        self.validate_row_manifest(&parsed, manifest, cx_id)?;
        verify_membership_proof(
            proof,
            manifest.membership_root,
            manifest.membership_version,
            manifest.generation_rows,
            cx_id,
            stored,
        )?;
        Ok(parsed)
    }

    fn manifest_at(&self, snapshot: Seq) -> Result<CompressionManifest> {
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
        Ok(manifest)
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
        validate_membership_proofs: bool,
        validate_raw_generation: bool,
    ) -> Result<Vec<(CxId, ParsedStoredSlot)>> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let manifest = self.manifest_at(snapshot)?;
        snapshot_lease.record_progress();
        self.validated_rows_with_manifest_at(
            snapshot,
            &manifest,
            validate_payloads,
            validate_membership_proofs,
            validate_raw_generation,
        )
    }

    fn validated_rows_with_manifest_at(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
        validate_payloads: bool,
        validate_membership_proofs: bool,
        validate_raw_generation: bool,
    ) -> Result<Vec<(CxId, ParsedStoredSlot)>> {
        let snapshot_lease = self.vault.retain_snapshot_at(snapshot);
        let mut proofs = if validate_membership_proofs {
            let range = compression_membership_proof_prefix_range(self.slot.slot_id);
            let proof_rows =
                self.vault
                    .scan_cf_range_at(snapshot, ColumnFamily::Compression, &range)?;
            snapshot_lease.record_progress();
            if proof_rows.len() != manifest.generation_rows as usize {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!(
                        "compressed membership proof count mismatch: manifest={} persisted={}",
                        manifest.generation_rows,
                        proof_rows.len()
                    ),
                ));
            }
            let mut proofs = BTreeMap::new();
            for (key, value) in proof_rows {
                let (slot_id, cx_id) = parse_compression_membership_proof_key(&key)
                    .ok_or_else(|| {
                        compression_error(
                            CALYX_VECTOR_COMPRESSION_INVALID,
                            format!(
                                "compression membership key in slot {} range is malformed: {} bytes",
                                self.slot.slot_id.get(),
                                key.len()
                            ),
                        )
                    })?;
                if slot_id != self.slot.slot_id {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!(
                            "compression membership key slot {} does not match requested slot {}",
                            slot_id.get(),
                            self.slot.slot_id.get()
                        ),
                    ));
                }
                if proofs.insert(cx_id, value).is_some() {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!("duplicate compressed membership proof for cx_id={cx_id}"),
                    ));
                }
            }
            Some(proofs)
        } else {
            None
        };
        let rows = self
            .vault
            .scan_cf_at(snapshot, ColumnFamily::slot(self.slot.slot_id))?;
        snapshot_lease.record_progress();
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
        let mut membership_leaves = Vec::with_capacity(if validate_membership_proofs {
            rows.len()
        } else {
            0
        });
        for (key, bytes) in rows {
            let cx_id = decode_cx_id_key(&key)?;
            let parsed = self.parse_contextual(&bytes, cx_id)?;
            if validate_payloads {
                self.codec.validate_payload(&parsed)?;
            }
            self.validate_row_manifest(&parsed, manifest, cx_id)?;
            if let Some(proofs) = &mut proofs {
                let proof = proofs.remove(&cx_id).ok_or_else(|| {
                    compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        format!("compressed row {cx_id} has no membership proof"),
                    )
                })?;
                let leaf = verify_membership_proof(
                    &proof,
                    manifest.membership_root,
                    manifest.membership_version,
                    manifest.generation_rows,
                    cx_id,
                    &bytes,
                )?;
                membership_leaves.push((cx_id, leaf));
            }
            parsed_rows.push((cx_id, parsed));
        }
        if proofs.as_ref().is_some_and(|proofs| !proofs.is_empty()) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed generation has membership proofs without primary rows",
            ));
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
        if validate_membership_proofs {
            let computed_membership =
                membership_root_from_leaf_hashes(membership_leaves, manifest.generation_rows)?;
            if computed_membership != manifest.membership_root {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    "compressed whole-column membership root mismatch",
                ));
            }
        }
        if validate_raw_generation {
            self.validate_raw_generation(snapshot, manifest, &parsed_rows)?;
        }
        Ok(parsed_rows)
    }

    fn validate_raw_generation(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
        parsed_rows: &[(CxId, ParsedStoredSlot)],
    ) -> Result<()> {
        self.validated_raw_rows(snapshot, manifest, parsed_rows)
            .map(|_| ())
    }

    fn validated_raw_rows(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
        parsed_rows: &[(CxId, ParsedStoredSlot)],
    ) -> Result<Vec<(CxId, Vec<f32>)>> {
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
        let mut root_rows = Vec::with_capacity(raw_rows.len());
        for (key, bytes) in raw_rows {
            let cx_id = decode_cx_id_key(&key)?;
            if !expected_keys.contains_key(&cx_id) {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("raw sidecar has no matching compressed row for cx_id={cx_id}"),
                ));
            }
            let vector = encode::decode_slot_vector(&bytes)?;
            match vector {
                SlotVector::Dense { dim, data } if dim == raw_dim => {
                    SlotVector::Dense {
                        dim,
                        data: data.clone(),
                    }
                    .validate_schema()?;
                    validated.push((cx_id, data));
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
            root_rows.push((cx_id, bytes));
        }
        let computed = raw_generation_root(
            &self.codec_context_id,
            manifest.generation_rows,
            root_rows
                .iter()
                .map(|(cx_id, bytes)| (*cx_id, bytes.as_slice())),
        )?;
        if computed != manifest.raw_generation_root {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "raw-sidecar whole-column generation root mismatch",
            ));
        }
        Ok(validated)
    }

    fn validate_manifest(&self, manifest: &CompressionManifest) -> Result<()> {
        let descriptor = CodecDescriptor::for_read(self.slot, self.lens)?;
        validate_manifest_descriptor(self.slot, descriptor, self.codec_context_id, manifest)
    }

    /// Revalidates the original Assay source and recovery raw sidecar for a
    /// whole-generation audit. Serving reads do not call this verifier: their
    /// exact immutable manifest identity is checked against every requested
    /// row's bound seed instead.
    fn verify_manifest_assay_source_at(
        &self,
        snapshot: Seq,
        manifest: &CompressionManifest,
    ) -> Result<()> {
        if manifest.codec != StoredSlotCodec::MxFp4 {
            return Ok(());
        }
        verify_mxfp4_assay_attestation_at(
            self.vault,
            self.slot,
            self.lens,
            manifest.stored_dim,
            snapshot,
            manifest.assay_attestation_id,
        )
    }

    fn validate_row_manifest(
        &self,
        parsed: &ParsedStoredSlot,
        manifest: &CompressionManifest,
        cx_id: CxId,
    ) -> Result<()> {
        if parsed.generation_root != manifest.generation_root
            || parsed.generation_rows != manifest.generation_rows
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("compressed row {cx_id} disagrees with its generation manifest"),
            ));
        }
        if manifest.codec == StoredSlotCodec::MxFp4
            && parsed.qv.seed_id != manifest.assay_attestation_id
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed MXFP4 row {cx_id} Assay identity differs from its generation manifest"
                ),
            ));
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cosine_error(left: &[f32], right: &[f32]) -> Result<f64> {
    if left.len() != right.len() || left.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "reconstruction vectors have incompatible lengths {} and {}",
                left.len(),
                right.len()
            ),
        ));
    }
    let mut dot = 0.0_f64;
    let mut left_norm = 0.0_f64;
    let mut right_norm = 0.0_f64;
    for (a, b) in left.iter().zip(right) {
        let a = f64::from(*a);
        let b = f64::from(*b);
        dot += a * b;
        left_norm += a * a;
        right_norm += b * b;
    }
    if left_norm <= 0.0 || right_norm <= 0.0 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "reconstruction cosine is undefined for a zero-norm vector",
        ));
    }
    let cosine = (dot / (left_norm.sqrt() * right_norm.sqrt())).clamp(-1.0, 1.0);
    let error = 1.0 - cosine;
    if !error.is_finite() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "reconstruction cosine error is non-finite",
        ));
    }
    Ok(error)
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
