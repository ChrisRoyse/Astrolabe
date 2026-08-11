//! Versioned, checksummed persistence for the packed HNSW serving artifact.
//!
//! The format is deliberately independent of Rust/Serde layout. A fixed
//! header binds the slot, dimension, quantizer identity, construction seed,
//! sequence, row count, and body length. The body stores packed vectors and
//! graph rows. A BLAKE3 footer covers every preceding byte. Loading validates
//! the checksum and complete structure before allocating or serving a query.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use calyx_core::{CxId, Result, SlotId};
use calyx_forge::{QuantLevel, QuantizedVec, RotationSeed, SeedId, turboquant_payload_len};

use super::{HNSW_MAX_DIM, HnswIndex, Row};
use crate::error::{
    CALYX_SEXTANT_HNSW_ARTIFACT_CORRUPT, CALYX_SEXTANT_HNSW_ARTIFACT_IO,
    CALYX_SEXTANT_HNSW_ARTIFACT_STALE, CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED, sextant_error,
};
use crate::index::quant_config::{
    PackedVector, QuantConfig, QuantKind, SEXTANT_QUANT_LAYOUT_VERSION,
};

pub const HNSW_ARTIFACT_MAGIC: [u8; 8] = *b"CLXHNSW1";
pub const HNSW_ARTIFACT_VERSION: u16 = 2;
const DIGEST_BYTES: usize = 32;
const NO_ENTRY: u64 = u64::MAX;
const ROW_FIXED_BYTES: usize = 16 + 8 + 1 + 1 + 4;
const MAX_ARTIFACT_ROWS: usize = u32::MAX as usize;
const MAX_NEIGHBORS_HARD_LIMIT: usize = 4_096;

/// Exact identity a caller expects before allowing an artifact to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnswArtifactExpectation {
    pub slot: SlotId,
    pub dim: u32,
    pub quant_kind: QuantKind,
    /// Exact TurboQuant geometry, or all zeroes for non-seeded codecs.
    pub quant_geometry_id: SeedId,
    pub base_seq: u64,
}

/// Independently readable facts from a fully validated artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnswArtifactMetadata {
    pub version: u16,
    pub quant_layout_version: u8,
    pub quant_kind: QuantKind,
    pub quant_geometry_id: SeedId,
    pub slot: SlotId,
    pub dim: u32,
    pub seed: u64,
    pub max_neighbors: u32,
    pub row_count: u64,
    pub live_rows: u64,
    pub base_seq: u64,
    pub built_at_seq: u64,
    pub packed_vector_bytes: u64,
    pub artifact_bytes: u64,
    pub digest: [u8; DIGEST_BYTES],
}

/// Durable write receipt, populated from a separate final-path readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnswArtifactReceipt {
    pub path: PathBuf,
    pub metadata: HnswArtifactMetadata,
}

impl HnswIndex {
    /// Canonical artifact bytes for this exact packed index and graph.
    pub fn to_artifact_bytes(&self) -> Result<Vec<u8>> {
        self.validate_artifact_state()?;
        let row_count =
            u64::try_from(self.rows.len()).map_err(|_| corrupt("row count overflow"))?;
        let max_neighbors = u32::try_from(self.max_neighbors)
            .map_err(|_| corrupt("max_neighbors does not fit the artifact header"))?;
        let packed_vector_bytes = u64::try_from(self.physical_vector_bytes())
            .map_err(|_| corrupt("packed vector byte count overflow"))?;

        let mut body = Vec::new();
        for row in &self.rows {
            body.extend_from_slice(row.cx_id.as_bytes());
            put_u64(&mut body, row.seq);
            body.push(row.level);
            body.push(u8::from(row.deleted));
            put_u32(
                &mut body,
                u32::try_from(row.neighbors.len())
                    .map_err(|_| corrupt("neighbor count overflow"))?,
            );
            match &row.stored {
                PackedVector::F32 { values } => {
                    for value in values {
                        put_u32(&mut body, value.to_bits());
                    }
                }
                PackedVector::Scalar8 { codes, norm, .. } => {
                    put_u32(&mut body, norm.to_bits());
                    body.extend_from_slice(codes);
                }
                PackedVector::Binary { bits, .. } => body.extend_from_slice(bits),
                PackedVector::TurboQuant { candidate } => {
                    let quantized = candidate.quantized();
                    put_u32(&mut body, quantized.scale.to_bits());
                    body.extend_from_slice(&quantized.bytes);
                }
            }
            for neighbor in &row.neighbors {
                put_u32(
                    &mut body,
                    u32::try_from(*neighbor)
                        .map_err(|_| corrupt("neighbor ordinal does not fit u32"))?,
                );
            }
        }
        let body_len = u64::try_from(body.len()).map_err(|_| corrupt("artifact body overflow"))?;

        let mut bytes = Vec::with_capacity(body.len().saturating_add(128));
        bytes.extend_from_slice(&HNSW_ARTIFACT_MAGIC);
        put_u16(&mut bytes, HNSW_ARTIFACT_VERSION);
        bytes.push(SEXTANT_QUANT_LAYOUT_VERSION);
        bytes.push(quant_tag(self.quant.kind()));
        put_u16(&mut bytes, self.slot.get());
        put_u32(&mut bytes, self.dim);
        put_u64(&mut bytes, self.seed);
        put_u32(&mut bytes, max_neighbors);
        put_u64(&mut bytes, self.base_seq);
        put_u64(&mut bytes, self.built_at_seq);
        put_u32(&mut bytes, self.quant.scale().to_bits());
        bytes.push(self.quant.zero_point() as u8);
        bytes.extend_from_slice(&[0_u8; 3]);
        if let Some(seed) = self.quant.turbo_seed() {
            bytes.push(seed.version);
            bytes.extend_from_slice(&[0_u8; 3]);
            bytes.extend_from_slice(&seed.id);
            bytes.extend_from_slice(&seed.entropy);
            bytes.extend_from_slice(&self.quant.geometry_id());
        } else {
            bytes.extend_from_slice(&[0_u8; 100]);
        }
        put_u64(&mut bytes, row_count);
        put_u64(
            &mut bytes,
            self.entry_point
                .map(|value| value as u64)
                .unwrap_or(NO_ENTRY),
        );
        put_u64(&mut bytes, packed_vector_bytes);
        put_u64(&mut bytes, body_len);
        bytes.extend_from_slice(&body);
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    /// Opens a canonical artifact only when its identity matches `expected`.
    pub fn from_artifact_bytes(
        bytes: &[u8],
        expected: HnswArtifactExpectation,
    ) -> Result<(Self, HnswArtifactMetadata)> {
        let (header, body, digest) = decode_envelope(bytes)?;
        if header.slot != expected.slot
            || header.dim != expected.dim
            || header.quant_kind != expected.quant_kind
            || header.geometry_id != expected.quant_geometry_id
        {
            return Err(sextant_error(
                CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED,
                format!(
                    "HNSW artifact identity slot={}/dim={}/codec={:?}/geometry={:02x?} does not match expected slot={}/dim={}/codec={:?}/geometry={:02x?}",
                    header.slot.get(),
                    header.dim,
                    header.quant_kind,
                    header.geometry_id,
                    expected.slot.get(),
                    expected.dim,
                    expected.quant_kind,
                    expected.quant_geometry_id
                ),
            ));
        }
        if header.base_seq != expected.base_seq {
            return Err(sextant_error(
                CALYX_SEXTANT_HNSW_ARTIFACT_STALE,
                format!(
                    "HNSW artifact base_seq {} does not match live expected sequence {}",
                    header.base_seq, expected.base_seq
                ),
            ));
        }
        let quant = match header.quant_kind {
            QuantKind::None => QuantConfig::none(),
            QuantKind::Scalar8 => QuantConfig::scalar8(f32::from_bits(header.scale_bits)),
            QuantKind::Binary => QuantConfig::binary(),
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                let seed = RotationSeed {
                    id: header.seed_id,
                    version: header.seed_version,
                    dim: header.dim as usize,
                    entropy: header.seed_entropy,
                };
                let level = header.quant_kind.turboquant_level().ok_or_else(|| {
                    corrupt("TurboQuant artifact tag has no exact fractional level")
                })?;
                let config = QuantConfig::turboquant_structured(seed, level).map_err(|error| {
                    corrupt(format!("TurboQuant codec reconstruction failed: {error}"))
                })?;
                if config.geometry_id() != header.geometry_id {
                    return Err(corrupt(
                        "TurboQuant artifact geometry does not match its frozen seed/level",
                    ));
                }
                config
            }
        };
        if quant.zero_point() != header.zero_point {
            return Err(corrupt("artifact zero_point is non-canonical"));
        }
        quant.validate()?;

        let row_count = usize::try_from(header.row_count)
            .map_err(|_| corrupt("artifact row count does not fit this process"))?;
        if row_count > MAX_ARTIFACT_ROWS {
            return Err(corrupt(format!(
                "artifact row count {row_count} exceeds hard limit {MAX_ARTIFACT_ROWS}"
            )));
        }
        let min_vector_bytes = vector_body_bytes(header.quant_kind, header.dim)?;
        let min_row_bytes = ROW_FIXED_BYTES
            .checked_add(min_vector_bytes)
            .ok_or_else(|| corrupt("minimum row size overflow"))?;
        if row_count > 0 && row_count > body.len() / min_row_bytes.max(1) {
            return Err(corrupt(
                "artifact row count exceeds the bounded body length",
            ));
        }
        let mut decoder = Decoder::new(body);
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_count)
            .map_err(|error| corrupt(format!("cannot allocate {row_count} HNSW rows: {error}")))?;
        for ordinal in 0..row_count {
            let cx_id = CxId::from_bytes(decoder.array::<16>()?);
            let seq = decoder.u64()?;
            let level = decoder.u8()?;
            let flags = decoder.u8()?;
            if flags & !1 != 0 {
                return Err(corrupt(format!(
                    "row {ordinal} has unknown flags {flags:#04x}"
                )));
            }
            let neighbor_count = decoder.u32()? as usize;
            if neighbor_count > header.max_neighbors as usize {
                return Err(corrupt(format!(
                    "row {ordinal} has {neighbor_count} neighbors above max {}",
                    header.max_neighbors
                )));
            }
            let stored = match header.quant_kind {
                QuantKind::None => {
                    let mut values = Vec::new();
                    values
                        .try_reserve_exact(header.dim as usize)
                        .map_err(|error| {
                            corrupt(format!("cannot allocate f32 artifact row: {error}"))
                        })?;
                    for _ in 0..header.dim {
                        values.push(f32::from_bits(decoder.u32()?));
                    }
                    PackedVector::F32 { values }
                }
                QuantKind::Scalar8 => PackedVector::Scalar8 {
                    norm: f32::from_bits(decoder.u32()?),
                    scale: quant.scale(),
                    codes: decoder.take(header.dim as usize)?.to_vec(),
                },
                QuantKind::Binary => PackedVector::Binary {
                    bits: decoder.take((header.dim as usize).div_ceil(8))?.to_vec(),
                    dim: header.dim,
                },
                QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                    let level = header.quant_kind.turboquant_level().ok_or_else(|| {
                        corrupt("TurboQuant artifact tag has no exact fractional level")
                    })?;
                    let payload_len = turboquant_payload_bytes(level, header.dim)?;
                    let quantized = QuantizedVec {
                        level,
                        dim: header.dim as usize,
                        scale: f32::from_bits(decoder.u32()?),
                        seed_id: header.geometry_id,
                        bytes: decoder.take(payload_len)?.to_vec(),
                    };
                    let codec = quant.turbo_codec().ok_or_else(|| {
                        corrupt("TurboQuant artifact codec was not reconstructed")
                    })?;
                    let candidate = codec.validate_owned_candidate(quantized).map_err(|error| {
                        corrupt(format!("invalid TurboQuant row {ordinal}: {error}"))
                    })?;
                    PackedVector::TurboQuant { candidate }
                }
            };
            let mut neighbors = Vec::new();
            neighbors
                .try_reserve_exact(neighbor_count)
                .map_err(|error| {
                    corrupt(format!("cannot allocate row {ordinal} neighbors: {error}"))
                })?;
            for _ in 0..neighbor_count {
                neighbors.push(decoder.u32()? as usize);
            }
            rows.push(Row {
                cx_id,
                stored,
                seq,
                level,
                neighbors,
                neighbor_scores: Vec::new(),
                deleted: flags & 1 != 0,
            });
        }
        if !decoder.is_empty() {
            return Err(corrupt(format!(
                "artifact body has {} unconsumed bytes",
                decoder.remaining()
            )));
        }
        let entry_point = if header.entry_point == NO_ENTRY {
            None
        } else {
            Some(
                usize::try_from(header.entry_point)
                    .map_err(|_| corrupt("entry point does not fit this process"))?,
            )
        };
        let mut index = HnswIndex {
            slot: header.slot,
            dim: header.dim,
            seed: header.seed,
            max_neighbors: header.max_neighbors as usize,
            rows,
            positions: Default::default(),
            fingerprints: Default::default(),
            entry_point,
            quant,
            built_at_seq: header.built_at_seq,
            base_seq: header.base_seq,
            construction_scratch: Vec::new(),
        };
        if !index.rows.is_empty() {
            index.quant.lock_after_first_insert();
        }
        index.rebuild_lookup_maps();
        index.validate_artifact_state()?;
        if index.physical_vector_bytes() as u64 != header.packed_vector_bytes {
            return Err(corrupt(format!(
                "packed vector byte count {} does not match header {}",
                index.physical_vector_bytes(),
                header.packed_vector_bytes
            )));
        }
        let live_rows = index.live_len() as u64;
        let metadata = HnswArtifactMetadata {
            version: HNSW_ARTIFACT_VERSION,
            quant_layout_version: SEXTANT_QUANT_LAYOUT_VERSION,
            quant_kind: header.quant_kind,
            quant_geometry_id: header.geometry_id,
            slot: header.slot,
            dim: header.dim,
            seed: header.seed,
            max_neighbors: header.max_neighbors,
            row_count: header.row_count,
            live_rows,
            base_seq: header.base_seq,
            built_at_seq: header.built_at_seq,
            packed_vector_bytes: header.packed_vector_bytes,
            artifact_bytes: bytes.len() as u64,
            digest,
        };
        Ok((index, metadata))
    }

    /// Writes a new immutable artifact, then reopens the final path and returns
    /// only the independent readback. Existing targets are refused; generation
    /// activation must happen through an explicit pointer swap by the owner.
    pub fn persist_artifact(&self, path: &Path) -> Result<HnswArtifactReceipt> {
        if path.exists() {
            return Err(io_error(format!(
                "refusing to overwrite existing HNSW artifact {}",
                path.display()
            )));
        }
        let bytes = self.to_artifact_bytes()?;
        let digest = *blake3::hash(&bytes[..bytes.len() - DIGEST_BYTES]).as_bytes();
        let parent = path.parent().ok_or_else(|| {
            io_error(format!(
                "HNSW artifact path {} has no parent",
                path.display()
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            io_error(format!(
                "create HNSW artifact directory {}: {error}",
                parent.display()
            ))
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io_error(format!(
                    "HNSW artifact path {} has no UTF-8 name",
                    path.display()
                ))
            })?;
        let temp = parent.join(format!(
            ".{name}.part-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            digest[0],
            digest[1],
            digest[2],
            digest[3]
        ));
        let write_result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|error| io_error(format!("create {}: {error}", temp.display())))?;
            file.write_all(&bytes)
                .map_err(|error| io_error(format!("write {}: {error}", temp.display())))?;
            file.sync_all()
                .map_err(|error| io_error(format!("sync {}: {error}", temp.display())))?;
            let expected = self.artifact_expectation();
            let temp_bytes = read_all(&temp)?;
            Self::from_artifact_bytes(&temp_bytes, expected)?;
            std::fs::rename(&temp, path).map_err(|error| {
                io_error(format!(
                    "atomically publish {} -> {}: {error}",
                    temp.display(),
                    path.display()
                ))
            })?;
            Ok(())
        })();
        if write_result.is_err() && temp.exists() {
            let _ = std::fs::remove_file(&temp);
        }
        write_result?;
        let final_bytes = read_all(path)?;
        let (_, metadata) = Self::from_artifact_bytes(&final_bytes, self.artifact_expectation())?;
        if final_bytes != bytes {
            return Err(corrupt(format!(
                "final HNSW artifact {} differs from the bytes that were written",
                path.display()
            )));
        }
        Ok(HnswArtifactReceipt {
            path: path.to_path_buf(),
            metadata,
        })
    }

    /// Loads and validates the complete persisted state before returning it.
    pub fn load_artifact(
        path: &Path,
        expected: HnswArtifactExpectation,
    ) -> Result<(Self, HnswArtifactMetadata)> {
        let bytes = read_all(path)?;
        Self::from_artifact_bytes(&bytes, expected)
    }

    pub fn artifact_expectation(&self) -> HnswArtifactExpectation {
        HnswArtifactExpectation {
            slot: self.slot,
            dim: self.dim,
            quant_kind: self.quant.kind(),
            quant_geometry_id: self.quant.geometry_id(),
            base_seq: self.base_seq,
        }
    }

    fn validate_artifact_state(&self) -> Result<()> {
        self.quant.validate()?;
        if self.dim == 0 || self.dim > HNSW_MAX_DIM {
            return Err(corrupt(format!(
                "HNSW artifact dimension {} is outside 1..={HNSW_MAX_DIM}",
                self.dim
            )));
        }
        if self.max_neighbors == 0 || self.max_neighbors > MAX_NEIGHBORS_HARD_LIMIT {
            return Err(corrupt(format!(
                "max_neighbors {} is outside 1..={MAX_NEIGHBORS_HARD_LIMIT}",
                self.max_neighbors
            )));
        }
        match (self.rows.is_empty(), self.entry_point) {
            (true, None) => {}
            (true, Some(_)) => return Err(corrupt("empty HNSW artifact has an entry point")),
            (false, None) => return Err(corrupt("non-empty HNSW artifact has no entry point")),
            (false, Some(entry)) if entry >= self.rows.len() => {
                return Err(corrupt(format!("entry point {entry} is out of range")));
            }
            _ => {}
        }
        let mut ids = HashSet::new();
        for (ordinal, row) in self.rows.iter().enumerate() {
            if !ids.insert(row.cx_id) {
                return Err(corrupt(format!("duplicate CxId at row {ordinal}")));
            }
            validate_stored(row, ordinal, self.dim, &self.quant)?;
            if row.neighbors.len() > self.max_neighbors {
                return Err(corrupt(format!(
                    "row {ordinal} has {} neighbors above max {}",
                    row.neighbors.len(),
                    self.max_neighbors
                )));
            }
            if !row.neighbor_scores.is_empty()
                && (row.neighbor_scores.len() != row.neighbors.len()
                    || row.neighbor_scores.iter().any(|score| !score.is_finite()))
            {
                return Err(corrupt(format!(
                    "row {ordinal} has invalid ephemeral construction-score state"
                )));
            }
            let mut neighbors = HashSet::new();
            for neighbor in &row.neighbors {
                if *neighbor >= self.rows.len() || *neighbor == ordinal {
                    return Err(corrupt(format!(
                        "row {ordinal} has invalid neighbor {neighbor}"
                    )));
                }
                if !neighbors.insert(*neighbor) {
                    return Err(corrupt(format!(
                        "row {ordinal} repeats neighbor {neighbor}"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Header {
    quant_kind: QuantKind,
    slot: SlotId,
    dim: u32,
    seed: u64,
    max_neighbors: u32,
    base_seq: u64,
    built_at_seq: u64,
    scale_bits: u32,
    zero_point: i8,
    seed_version: u8,
    seed_id: SeedId,
    seed_entropy: SeedId,
    geometry_id: SeedId,
    row_count: u64,
    entry_point: u64,
    packed_vector_bytes: u64,
}

fn decode_envelope(bytes: &[u8]) -> Result<(Header, &[u8], [u8; DIGEST_BYTES])> {
    if bytes.len() < DIGEST_BYTES + 8 {
        return Err(corrupt(
            "HNSW artifact is truncated before its checksum footer",
        ));
    }
    let payload_len = bytes.len() - DIGEST_BYTES;
    let (payload, footer) = bytes.split_at(payload_len);
    let mut digest = [0_u8; DIGEST_BYTES];
    digest.copy_from_slice(footer);
    let computed = *blake3::hash(payload).as_bytes();
    if digest != computed {
        return Err(corrupt("HNSW artifact BLAKE3 footer mismatch"));
    }
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != HNSW_ARTIFACT_MAGIC {
        return Err(sextant_error(
            CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED,
            "HNSW artifact magic is not CLXHNSW1",
        ));
    }
    let version = decoder.u16()?;
    if version != HNSW_ARTIFACT_VERSION {
        return Err(sextant_error(
            CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED,
            format!(
                "HNSW artifact version {version} is unsupported; expected {HNSW_ARTIFACT_VERSION}"
            ),
        ));
    }
    let layout = decoder.u8()?;
    if layout != SEXTANT_QUANT_LAYOUT_VERSION {
        return Err(sextant_error(
            CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED,
            format!(
                "HNSW quant layout {layout} is unsupported; expected {SEXTANT_QUANT_LAYOUT_VERSION}"
            ),
        ));
    }
    let quant_kind = quant_from_tag(decoder.u8()?)?;
    let slot = SlotId::new(decoder.u16()?);
    let dim = decoder.u32()?;
    let seed = decoder.u64()?;
    let max_neighbors = decoder.u32()?;
    if max_neighbors == 0 || max_neighbors as usize > MAX_NEIGHBORS_HARD_LIMIT {
        return Err(corrupt(format!(
            "artifact max_neighbors {max_neighbors} is outside the hard limit"
        )));
    }
    let base_seq = decoder.u64()?;
    let built_at_seq = decoder.u64()?;
    let scale_bits = decoder.u32()?;
    let zero_point = decoder.u8()? as i8;
    if decoder.array::<3>()? != [0_u8; 3] {
        return Err(corrupt("artifact reserved header bytes are nonzero"));
    }
    let seed_version = decoder.u8()?;
    if decoder.array::<3>()? != [0_u8; 3] {
        return Err(corrupt("artifact TurboQuant reserved bytes are nonzero"));
    }
    let seed_id = decoder.array::<32>()?;
    let seed_entropy = decoder.array::<32>()?;
    let geometry_id = decoder.array::<32>()?;
    let has_turbo_identity = seed_version != 0
        || seed_id != [0_u8; 32]
        || seed_entropy != [0_u8; 32]
        || geometry_id != [0_u8; 32];
    if quant_kind.turboquant_level().is_some() != has_turbo_identity {
        return Err(corrupt(
            "artifact codec tag and TurboQuant geometry identity disagree",
        ));
    }
    let row_count = decoder.u64()?;
    let entry_point = decoder.u64()?;
    let packed_vector_bytes = decoder.u64()?;
    let body_len = usize::try_from(decoder.u64()?)
        .map_err(|_| corrupt("artifact body length does not fit this process"))?;
    if decoder.remaining() != body_len {
        return Err(corrupt(format!(
            "artifact body length {body_len} does not match remaining {} bytes",
            decoder.remaining()
        )));
    }
    let body = decoder.take(body_len)?;
    Ok((
        Header {
            quant_kind,
            slot,
            dim,
            seed,
            max_neighbors,
            base_seq,
            built_at_seq,
            scale_bits,
            zero_point,
            seed_version,
            seed_id,
            seed_entropy,
            geometry_id,
            row_count,
            entry_point,
            packed_vector_bytes,
        },
        body,
        digest,
    ))
}

fn validate_stored(row: &Row, ordinal: usize, dim: u32, quant: &QuantConfig) -> Result<()> {
    match (&row.stored, quant.kind()) {
        (PackedVector::F32 { values }, QuantKind::None) => {
            if values.len() != dim as usize || values.iter().any(|value| !value.is_finite()) {
                return Err(corrupt(format!(
                    "row {ordinal} has invalid F32 payload dimension or value"
                )));
            }
        }
        (PackedVector::Scalar8 { codes, scale, norm }, QuantKind::Scalar8) => {
            if codes.len() != dim as usize || scale.to_bits() != quant.scale().to_bits() {
                return Err(corrupt(format!(
                    "row {ordinal} Scalar8 dimension/scale does not match its index codec"
                )));
            }
            if !norm.is_finite() || *norm < 0.0 {
                return Err(corrupt(format!("row {ordinal} has invalid Scalar8 norm")));
            }
            let expected = codes
                .iter()
                .map(|code| {
                    let value = f64::from(*code as i8) * f64::from(*scale);
                    value * value
                })
                .sum::<f64>()
                .sqrt() as f32;
            if expected.to_bits() != norm.to_bits() {
                return Err(corrupt(format!(
                    "row {ordinal} Scalar8 norm does not match its packed codes"
                )));
            }
        }
        (PackedVector::Binary { bits, dim: row_dim }, QuantKind::Binary) => {
            if *row_dim != dim || bits.len() != (dim as usize).div_ceil(8) {
                return Err(corrupt(format!(
                    "row {ordinal} has invalid Binary dimensions"
                )));
            }
            let remainder = dim as usize % 8;
            if remainder != 0
                && bits
                    .last()
                    .is_some_and(|last| *last & !((1_u8 << remainder) - 1) != 0)
            {
                return Err(corrupt(format!(
                    "row {ordinal} has non-canonical Binary padding bits"
                )));
            }
        }
        (
            PackedVector::TurboQuant { candidate },
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5,
        ) => {
            let quantized = candidate.quantized();
            let level = quant.kind().turboquant_level().ok_or_else(|| {
                corrupt(format!("row {ordinal} TurboQuant codec has no exact level"))
            })?;
            if quantized.dim != dim as usize
                || quantized.level != level
                || quantized.seed_id != quant.geometry_id()
            {
                return Err(corrupt(format!(
                    "row {ordinal} TurboQuant shape/level/geometry does not match its index codec"
                )));
            }
            let codec = quant.turbo_codec().ok_or_else(|| {
                corrupt(format!(
                    "row {ordinal} TurboQuant codec geometry is missing"
                ))
            })?;
            codec.storage(quantized).map_err(|error| {
                corrupt(format!(
                    "row {ordinal} TurboQuant payload is invalid: {error}"
                ))
            })?;
        }
        _ => {
            return Err(corrupt(format!(
                "row {ordinal} packed kind does not match index codec {:?}",
                quant.kind()
            )));
        }
    }
    Ok(())
}

fn vector_body_bytes(kind: QuantKind, dim: u32) -> Result<usize> {
    let dim = dim as usize;
    match kind {
        QuantKind::None => dim
            .checked_mul(4)
            .ok_or_else(|| corrupt("F32 artifact row size overflow")),
        QuantKind::Scalar8 => dim
            .checked_add(4)
            .ok_or_else(|| corrupt("Scalar8 artifact row size overflow")),
        QuantKind::Binary => Ok(dim.div_ceil(8)),
        QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
            let level = kind
                .turboquant_level()
                .ok_or_else(|| corrupt("TurboQuant artifact tag has no exact fractional level"))?;
            turboquant_payload_bytes(level, dim as u32)?
                .checked_add(4)
                .ok_or_else(|| corrupt("TurboQuant artifact row size overflow"))
        }
    }
}

fn quant_tag(kind: QuantKind) -> u8 {
    match kind {
        QuantKind::None => 0,
        QuantKind::Scalar8 => 1,
        QuantKind::Binary => 2,
        QuantKind::TurboQuant2p5 => 3,
        QuantKind::TurboQuant3p5 => 4,
    }
}

fn quant_from_tag(tag: u8) -> Result<QuantKind> {
    match tag {
        0 => Ok(QuantKind::None),
        1 => Ok(QuantKind::Scalar8),
        2 => Ok(QuantKind::Binary),
        3 => Ok(QuantKind::TurboQuant2p5),
        4 => Ok(QuantKind::TurboQuant3p5),
        _ => Err(sextant_error(
            CALYX_SEXTANT_HNSW_ARTIFACT_UNSUPPORTED,
            format!("HNSW artifact quantizer tag {tag} is unsupported"),
        )),
    }
}

fn turboquant_payload_bytes(level: QuantLevel, dim: u32) -> Result<usize> {
    turboquant_payload_len(level, dim as usize).map_err(|error| {
        corrupt(format!(
            "invalid TurboQuant artifact payload layout: {error}"
        ))
    })
}

fn read_all(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|error| io_error(format!("open HNSW artifact {}: {error}", path.display())))?;
    let length = file
        .metadata()
        .map_err(|error| io_error(format!("stat HNSW artifact {}: {error}", path.display())))?
        .len();
    let capacity = usize::try_from(length)
        .map_err(|_| io_error(format!("HNSW artifact {} is too large", path.display())))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        io_error(format!(
            "reserve {capacity} bytes for HNSW artifact {}: {error}",
            path.display()
        ))
    })?;
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(format!("read HNSW artifact {}: {error}", path.display())))?;
    if bytes.len() != capacity {
        return Err(io_error(format!(
            "HNSW artifact {} changed while reading: stat={capacity} read={}",
            path.display(),
            bytes.len()
        )));
    }
    Ok(bytes)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| corrupt("artifact cursor overflow"))?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            corrupt(format!(
                "artifact truncated at offset {} while reading {len} bytes",
                self.offset
            ))
        })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("artifact fixed-width field conversion failed"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn corrupt(message: impl Into<String>) -> calyx_core::CalyxError {
    sextant_error(CALYX_SEXTANT_HNSW_ARTIFACT_CORRUPT, message)
}

fn io_error(message: impl Into<String>) -> calyx_core::CalyxError {
    sextant_error(CALYX_SEXTANT_HNSW_ARTIFACT_IO, message)
}
