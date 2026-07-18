use crate::cf::ColumnFamily;
use calyx_core::{
    AbsentReason, CalyxError, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality, Result,
    SlotId, SlotVector, SparseEntry, VaultId,
};
use std::collections::BTreeMap;

pub use super::anchor_codec::{decode_anchor, encode_anchor};
use super::cf_codec::{decode_cf_v2, encode_cf_v2};
use super::cursor::Cursor;

pub const HEADER_LEN: usize = 102;
const IDENTITY_HASH_LEN: usize = 32;
const WRITE_BATCH_MAGIC_V2: &[u8; 8] = b"CXLWAL2\0";

/// A persisted Base row was updated through a path that could not preserve, or
/// disagreed with, the immutable per-slot BLAKE3 hashes stored in that row.
pub const CALYX_ASTER_BASE_SLOT_HASH_VIOLATION: &str = "CALYX_ASTER_BASE_SLOT_HASH_VIOLATION";

fn base_slot_hash_violation(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_BASE_SLOT_HASH_VIOLATION,
        message: message.into(),
        remediation: "decode the persisted Base row into a BaseRecord and mutate only \
                      flags/metadata/scalars/provenance so the immutable per-slot BLAKE3 hashes \
                      survive the rewrite byte-for-byte; never round-trip a lossy decoded \
                      Constellation through encode_constellation_base to update a persisted Base row",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstellationHeader {
    pub cx_id: CxId,
    pub vault_id: VaultId,
    pub panel_version: u32,
    pub created_at: u64,
    pub modality: Modality,
    pub flags: CxFlags,
    pub n_slots: u16,
    pub n_anchors: u16,
    pub ledger_seq: u64,
    pub input_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstellationBaseIdentity {
    pub cx_id: CxId,
    pub slot_hashes: BTreeMap<SlotId, [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRow {
    pub cf: ColumnFamily,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn encode_header(cx: &Constellation) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(cx.cx_id.as_bytes());
    out.extend_from_slice(&cx.vault_id.as_ulid().to_bytes());
    out.extend_from_slice(&cx.panel_version.to_be_bytes());
    out.extend_from_slice(&cx.created_at.to_be_bytes());
    out.push(modality_tag(cx.modality));
    out.push(flags_bits(cx.flags));
    out.extend_from_slice(&(cx.slots.len() as u16).to_be_bytes());
    out.extend_from_slice(&(cx.anchors.len() as u16).to_be_bytes());
    out.extend_from_slice(&cx.provenance.seq.to_be_bytes());
    out.extend_from_slice(&cx.input_ref.hash);
    out.extend_from_slice(&[0_u8; 12]);
    out
}

pub fn decode_header(bytes: &[u8]) -> Result<ConstellationHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "constellation header too short: {} < {HEADER_LEN}",
            bytes.len()
        )));
    }
    let mut cursor = Cursor::new(bytes);
    let cx_id = CxId::from_bytes(cursor.array()?);
    let vault_id = VaultId::from_ulid(ulid::Ulid::from_bytes(cursor.array()?));
    let panel_version = cursor.u32()?;
    let created_at = cursor.u64()?;
    let modality = decode_modality(cursor.u8()?)?;
    let flags = decode_flags(cursor.u8()?);
    let n_slots = cursor.u16()?;
    let n_anchors = cursor.u16()?;
    let ledger_seq = cursor.u64()?;
    let input_hash = cursor.array()?;
    Ok(ConstellationHeader {
        cx_id,
        vault_id,
        panel_version,
        created_at,
        modality,
        flags,
        n_slots,
        n_anchors,
        ledger_seq,
        input_hash,
    })
}

/// Encodes a Base row from a **hydrated** constellation whose `slots` hold the
/// real [`SlotVector`]s, hashing each vector to derive its persisted per-slot
/// hash.
///
/// This is the correct encoder for a freshly built or slot-hydrated
/// constellation (e.g. one produced by `AsterVault::get`, which reconstructs
/// the actual slot vectors from the per-slot CFs). It is **not** safe for
/// updating a persisted Base row that was decoded through
/// [`decode_constellation_base`]: that decoder substitutes
/// `SlotVector::Absent` placeholders, so re-encoding it here would silently
/// replace every immutable slot hash with the hash of a placeholder. Use
/// [`BaseRecord`] to update a persisted Base row in place.
pub fn encode_constellation_base(cx: &Constellation) -> Result<Vec<u8>> {
    let slot_hashes = slot_hashes_from_vectors(cx)?;
    encode_base_with_slot_hashes(cx, &slot_hashes)
}

/// Encodes a Base row from the constellation's logical fields plus an explicit
/// map of the immutable per-slot hashes, emitting those hashes byte-for-byte
/// and recomputing the identity hash from them.
///
/// The stored per-slot hash is defined as `BLAKE3(encode_slot_vector(vector))`,
/// and the identity hash's slot contribution is exactly the same value, so a
/// persisted Base row can be re-emitted identically — including its identity
/// hash — without ever hydrating the slot vectors.
fn encode_base_with_slot_hashes(
    cx: &Constellation,
    slot_hashes: &BTreeMap<SlotId, [u8; 32]>,
) -> Result<Vec<u8>> {
    validate_slot_hash_agreement(cx, slot_hashes)?;
    let mut out = encode_header(cx);
    out.extend_from_slice(&identity_hash_with_slot_hashes(cx, slot_hashes)?.as_bytes()[..]);
    encode_input_ref_tail(&cx.input_ref, &mut out)?;
    out.extend_from_slice(&(cx.slots.len() as u16).to_be_bytes());
    for slot in cx.slots.keys() {
        let hash = slot_hashes.get(slot).ok_or_else(|| {
            base_slot_hash_violation(format!("Base slot {} has no preserved slot hash", slot.get()))
        })?;
        out.extend_from_slice(&slot.get().to_be_bytes());
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(&(cx.scalars.len() as u32).to_be_bytes());
    for (key, value) in &cx.scalars {
        put_string(&mut out, key)?;
        out.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    out.extend_from_slice(&(cx.anchors.len() as u32).to_be_bytes());
    for anchor in &cx.anchors {
        put_bytes(&mut out, &encode_anchor(anchor)?)?;
    }
    out.extend_from_slice(&cx.provenance.hash);
    encode_string_metadata(&cx.metadata, &mut out)?;
    Ok(out)
}

fn slot_hashes_from_vectors(cx: &Constellation) -> Result<BTreeMap<SlotId, [u8; 32]>> {
    let mut slot_hashes = BTreeMap::new();
    for (slot, vector) in &cx.slots {
        slot_hashes.insert(*slot, *blake3::hash(&encode_slot_vector(vector)?).as_bytes());
    }
    Ok(slot_hashes)
}

/// Rejects a slot-hash map whose key set does not exactly match the
/// constellation's slot set. Both are `BTreeMap`s, so equal length plus total
/// containment proves identical key sets (and thus identical iteration order).
fn validate_slot_hash_agreement(
    cx: &Constellation,
    slot_hashes: &BTreeMap<SlotId, [u8; 32]>,
) -> Result<()> {
    if cx.slots.len() != slot_hashes.len() {
        return Err(base_slot_hash_violation(format!(
            "Base slot set has {} slots but the preserved slot-hash map has {}",
            cx.slots.len(),
            slot_hashes.len()
        )));
    }
    for slot in cx.slots.keys() {
        if !slot_hashes.contains_key(slot) {
            return Err(base_slot_hash_violation(format!(
                "Base slot {} has no preserved slot hash",
                slot.get()
            )));
        }
    }
    Ok(())
}

/// Lossless in-memory view of a persisted Base row that preserves the exact
/// stored per-slot BLAKE3 hashes.
///
/// [`decode_constellation_base`] intentionally discards the persisted per-slot
/// hashes and substitutes `SlotVector::Absent` placeholders, so re-encoding
/// that logical [`Constellation`] through [`encode_constellation_base`]
/// silently replaces every immutable slot hash with the hash of a placeholder.
/// A metadata/flag/orphan-repair rewrite that round-trips a persisted Base row
/// that way corrupts its provenance identity.
///
/// `BaseRecord` keeps the stored slot-hash map alongside the decoded logical
/// fields, seals the slot set (there is no slot mutator), and re-emits the
/// stored hashes byte-for-byte via [`BaseRecord::encode`]. Callers update a
/// persisted Base row in place only through the targeted
/// flags/metadata/scalars/provenance mutators. This is the only supported path
/// for updating an already-persisted Base row without hydrating its slots.
#[derive(Clone, Debug)]
pub struct BaseRecord {
    constellation: Constellation,
    slot_hashes: BTreeMap<SlotId, [u8; 32]>,
}

impl BaseRecord {
    /// Decodes a persisted Base row, preserving its exact stored slot hashes.
    ///
    /// The shared Base decoder already rejects a non-strictly-increasing or
    /// duplicated slot id, so the returned record's slot set is ordered and
    /// unique; [`Self::from_parts`] additionally proves the slot set and the
    /// preserved slot-hash map agree.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (constellation, identity) = decode_constellation_base_parts(bytes)?;
        Self::from_parts(constellation, identity.slot_hashes)
    }

    /// Decodes a persisted Base row and proves its embedded CxId equals the CF
    /// key it was read under, failing closed on a key/embedded mismatch before
    /// any mutation is possible.
    pub fn decode_for_key(key_cx_id: CxId, bytes: &[u8]) -> Result<Self> {
        let record = Self::decode(bytes)?;
        if record.constellation.cx_id != key_cx_id {
            return Err(base_slot_hash_violation(format!(
                "Base row read under key CxId {key_cx_id} embeds CxId {}",
                record.constellation.cx_id
            )));
        }
        Ok(record)
    }

    fn from_parts(
        constellation: Constellation,
        slot_hashes: BTreeMap<SlotId, [u8; 32]>,
    ) -> Result<Self> {
        validate_slot_hash_agreement(&constellation, &slot_hashes)?;
        Ok(Self {
            constellation,
            slot_hashes,
        })
    }

    /// The Base row's constellation CxId.
    pub fn cx_id(&self) -> CxId {
        self.constellation.cx_id
    }

    /// The vault this Base row belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.constellation.vault_id
    }

    /// Read-only access to the decoded logical fields (slots are `Absent`
    /// placeholders; the durable hashes live in [`Self::slot_hashes`]).
    pub fn constellation(&self) -> &Constellation {
        &self.constellation
    }

    /// The exact stored per-slot hashes preserved from the persisted row.
    pub fn slot_hashes(&self) -> &BTreeMap<SlotId, [u8; 32]> {
        &self.slot_hashes
    }

    /// Mutable access to the Base flags (e.g. to mark a row degraded).
    pub fn flags_mut(&mut self) -> &mut CxFlags {
        &mut self.constellation.flags
    }

    /// Mutable access to the string metadata map.
    pub fn metadata_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.constellation.metadata
    }

    /// Mutable access to the scalar map (e.g. the recurrence frequency scalar).
    pub fn scalars_mut(&mut self) -> &mut BTreeMap<String, f64> {
        &mut self.constellation.scalars
    }

    /// Rebinds the Base row's ledger provenance reference.
    pub fn set_provenance(&mut self, provenance: LedgerRef) {
        self.constellation.provenance = provenance;
    }

    /// Re-encodes the Base row, emitting the preserved per-slot hashes
    /// byte-for-byte and recomputing the identity hash from them.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_base_with_slot_hashes(&self.constellation, &self.slot_hashes)
    }
}

/// Decodes a Base row into a logical [`Constellation`] with `SlotVector::Absent`
/// placeholders for every slot.
///
/// This decode is **lossy**: the persisted per-slot hashes are discarded. Do
/// not re-encode the returned constellation through
/// [`encode_constellation_base`] to update a persisted Base row — that would
/// replace the immutable slot hashes with placeholder hashes. Use
/// [`BaseRecord`] for any in-place persisted Base update.
pub fn decode_constellation_base(bytes: &[u8]) -> Result<Constellation> {
    let (constellation, _) = decode_constellation_base_parts(bytes)?;
    Ok(constellation)
}

pub fn decode_constellation_base_identity(bytes: &[u8]) -> Result<ConstellationBaseIdentity> {
    let (_, identity) = decode_constellation_base_parts(bytes)?;
    Ok(identity)
}

fn decode_constellation_base_parts(
    bytes: &[u8],
) -> Result<(Constellation, ConstellationBaseIdentity)> {
    let header = decode_header(bytes)?;
    let mut cursor = Cursor::new(&bytes[HEADER_LEN..]);
    let _identity = cursor.bytes(IDENTITY_HASH_LEN)?;
    let input_ref = decode_input_ref_tail(&mut cursor, header.input_hash)?;
    let slot_count = cursor.u16()? as usize;
    if slot_count != header.n_slots as usize {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "constellation Base slot count mismatch: header={} body={slot_count}",
            header.n_slots
        )));
    }
    let mut slots = BTreeMap::new();
    let mut slot_hashes = BTreeMap::new();
    let mut previous_slot: Option<SlotId> = None;
    for _ in 0..slot_count {
        let slot = SlotId::new(cursor.u16()?);
        if let Some(previous) = previous_slot
            && previous >= slot
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "constellation Base slot ids are not strictly increasing: previous={} current={}",
                previous.get(),
                slot.get()
            )));
        }
        previous_slot = Some(slot);
        let hash = cursor.array()?;
        if slots
            .insert(
                slot,
                SlotVector::Absent {
                    reason: AbsentReason::NotApplicable,
                },
            )
            .is_some()
            || slot_hashes.insert(slot, hash).is_some()
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "constellation Base contains duplicate slot id {}",
                slot.get()
            )));
        }
    }
    let scalar_count = cursor.u32()? as usize;
    let mut scalars = BTreeMap::new();
    for _ in 0..scalar_count {
        let key = cursor.string()?;
        scalars.insert(key, f64::from_bits(cursor.u64()?));
    }
    let anchor_count = cursor.u32()? as usize;
    if anchor_count != header.n_anchors as usize {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "constellation Base anchor count mismatch: header={} body={anchor_count}",
            header.n_anchors
        )));
    }
    let mut anchors = Vec::with_capacity(anchor_count);
    for _ in 0..anchor_count {
        anchors.push(decode_anchor(cursor.bytes_prefixed()?)?);
    }
    let provenance = LedgerRef {
        seq: header.ledger_seq,
        hash: cursor.array()?,
    };
    let metadata = if cursor.remaining() == 0 {
        BTreeMap::new()
    } else {
        decode_string_metadata(&mut cursor)?
    };
    if cursor.remaining() != 0 {
        return Err(CalyxError::aster_corrupt_shard(
            "trailing bytes after constellation metadata",
        ));
    }
    let constellation = Constellation {
        cx_id: header.cx_id,
        vault_id: header.vault_id,
        panel_version: header.panel_version,
        created_at: header.created_at,
        input_ref,
        modality: header.modality,
        slots,
        scalars,
        metadata,
        anchors,
        provenance,
        flags: header.flags,
    };
    let identity = ConstellationBaseIdentity {
        cx_id: header.cx_id,
        slot_hashes,
    };
    Ok((constellation, identity))
}

pub fn same_constellation_identity(left: &[u8], right: &[u8]) -> Result<bool> {
    Ok(decode_identity(left)? == decode_identity(right)?)
}

pub fn encode_slot_vector(vector: &SlotVector) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match vector {
        SlotVector::Dense { dim, data } => {
            if *dim as usize != data.len() {
                return Err(CalyxError::aster_corrupt_shard(
                    "dense slot dim does not match data length",
                ));
            }
            out.push(0);
            out.extend_from_slice(&dim.to_be_bytes());
            for value in data {
                out.extend_from_slice(&value.to_bits().to_be_bytes());
            }
        }
        SlotVector::Absent { reason } => {
            out.push(1);
            encode_absent_reason(reason, &mut out)?;
        }
        SlotVector::Sparse { dim, entries } => {
            encode_sparse_canonical(*dim, entries, &mut out)?;
        }
        SlotVector::Multi { token_dim, tokens } => {
            out.push(3);
            out.extend_from_slice(&token_dim.to_be_bytes());
            out.extend_from_slice(&(tokens.len() as u32).to_be_bytes());
            for token in tokens {
                if token.len() != *token_dim as usize {
                    return Err(CalyxError::aster_corrupt_shard(
                        "multi slot token dim does not match token length",
                    ));
                }
                for value in token {
                    out.extend_from_slice(&value.to_bits().to_be_bytes());
                }
            }
        }
    }
    Ok(out)
}

pub fn decode_slot_vector(bytes: &[u8]) -> Result<SlotVector> {
    let mut cursor = Cursor::new(bytes);
    match cursor.u8()? {
        0 => {
            let dim = cursor.u32()?;
            let mut data = Vec::with_capacity(dim as usize);
            for _ in 0..dim {
                data.push(f32::from_bits(cursor.u32()?));
            }
            Ok(SlotVector::Dense { dim, data })
        }
        1 => Ok(SlotVector::Absent {
            reason: decode_absent_reason(&mut cursor)?,
        }),
        2 => Err(CalyxError {
            code: "CALYX_ASTER_SPARSE_LEGACY",
            message: "sparse slot vector uses legacy tag 2 (fixed u32+f32 pairs with no \
                      canonical ordering/bounds contract); refusing to guess its contents"
                .to_string(),
            remediation: "re-ingest the constellation so sparse slots are persisted in the \
                          canonical delta-varint (tag 4) or dense-selected (tag 5) form",
        }),
        3 => {
            let token_dim = cursor.u32()?;
            let n = cursor.u32()? as usize;
            let mut tokens = Vec::with_capacity(n);
            for _ in 0..n {
                let mut token = Vec::with_capacity(token_dim as usize);
                for _ in 0..token_dim {
                    token.push(f32::from_bits(cursor.u32()?));
                }
                tokens.push(token);
            }
            Ok(SlotVector::Multi { token_dim, tokens })
        }
        4 => decode_sparse_varint(&mut cursor),
        5 => decode_sparse_dense_selected(&mut cursor),
        tag => Err(CalyxError::aster_corrupt_shard(format!(
            "unknown slot vector tag {tag}"
        ))),
    }
}

/// Value dtype declared inside canonical sparse encodings. Only f32 exists
/// today; the byte is explicit so future dtypes are versioned, never guessed.
const SPARSE_VALUE_DTYPE_F32: u8 = 1;

/// Validates the canonical sparse row contract: strictly increasing indices
/// bounded by `dim`, finite values, and no explicit ±0.0 entries (a canonical
/// sparse vector never stores zeros — implicit coordinates are zero).
fn validate_sparse_canonical(dim: u32, entries: &[SparseEntry]) -> Result<()> {
    let mut previous: Option<u32> = None;
    for entry in entries {
        if entry.idx >= dim {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} is outside ambient dim {dim}",
                entry.idx
            )));
        }
        if let Some(previous) = previous
            && previous >= entry.idx
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry indices are not strictly increasing: {previous} then {}",
                entry.idx
            )));
        }
        if !entry.val.is_finite() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} value {} is not finite",
                entry.idx, entry.val
            )));
        }
        if entry.val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse entry index {} stores explicit ±0.0; canonical sparse rows omit zero \
                 coordinates",
                entry.idx
            )));
        }
        previous = Some(entry.idx);
    }
    Ok(())
}

/// Encodes a sparse slot vector canonically, selecting the physically smaller
/// of the delta-varint sparse form (tag 4) and the dense form (tag 5) from the
/// actual encoded byte counts. The selected representation is persisted
/// explicitly via its tag — readback always reconstructs the identical
/// `SlotVector::Sparse`.
fn encode_sparse_canonical(dim: u32, entries: &[SparseEntry], out: &mut Vec<u8>) -> Result<()> {
    validate_sparse_canonical(dim, entries)?;
    // Tag 4 candidate: dim + dtype + varint n + delta-varint indices + f32 values.
    let mut sparse = Vec::with_capacity(16 + entries.len() * 6);
    sparse.push(4);
    sparse.extend_from_slice(&dim.to_be_bytes());
    sparse.push(SPARSE_VALUE_DTYPE_F32);
    let count = u32::try_from(entries.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("sparse entry count exceeds u32"))?;
    put_varint(&mut sparse, count);
    let mut previous: Option<u32> = None;
    for entry in entries {
        let delta = match previous {
            None => entry.idx,
            // Strictly increasing (validated above), so the gap is >= 1.
            Some(previous) => entry.idx - previous,
        };
        put_varint(&mut sparse, delta);
        previous = Some(entry.idx);
    }
    for entry in entries {
        sparse.extend_from_slice(&entry.val.to_bits().to_be_bytes());
    }
    // Tag 5 candidate: dim + full f32 lattice (indices implicit).
    let dense_len = 1_usize + 4 + (dim as usize) * 4;
    if sparse.len() <= dense_len {
        out.extend_from_slice(&sparse);
        return Ok(());
    }
    out.push(5);
    out.extend_from_slice(&dim.to_be_bytes());
    let mut lattice = vec![0_u32; dim as usize];
    for entry in entries {
        lattice[entry.idx as usize] = entry.val.to_bits();
    }
    for bits in lattice {
        out.extend_from_slice(&bits.to_be_bytes());
    }
    Ok(())
}

fn decode_sparse_varint(cursor: &mut Cursor<'_>) -> Result<SlotVector> {
    let dim = cursor.u32()?;
    let dtype = cursor.u8()?;
    if dtype != SPARSE_VALUE_DTYPE_F32 {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "unknown sparse value dtype {dtype}"
        )));
    }
    let count = read_varint(cursor)? as usize;
    let mut indices = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let delta = read_varint(cursor)?;
        let idx = match previous {
            None => delta,
            Some(previous) => {
                if delta == 0 {
                    return Err(CalyxError::aster_corrupt_shard(
                        "sparse delta 0 would repeat an index; indices must be strictly \
                         increasing",
                    ));
                }
                previous.checked_add(delta).ok_or_else(|| {
                    CalyxError::aster_corrupt_shard("sparse index delta overflows u32")
                })?
            }
        };
        if idx >= dim {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse index {idx} is outside ambient dim {dim}"
            )));
        }
        indices.push(idx);
        previous = Some(idx);
    }
    let mut entries = Vec::with_capacity(count);
    for idx in indices {
        let val = f32::from_bits(cursor.u32()?);
        if !val.is_finite() || val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse index {idx} decodes non-canonical value {val}"
            )));
        }
        entries.push(SparseEntry { idx, val });
    }
    Ok(SlotVector::Sparse { dim, entries })
}

fn decode_sparse_dense_selected(cursor: &mut Cursor<'_>) -> Result<SlotVector> {
    let dim = cursor.u32()?;
    let mut entries = Vec::new();
    for idx in 0..dim {
        let bits = cursor.u32()?;
        if bits == 0 {
            continue;
        }
        let val = f32::from_bits(bits);
        if !val.is_finite() || val == 0.0 {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "sparse-selected-dense index {idx} decodes non-canonical value {val}"
            )));
        }
        entries.push(SparseEntry { idx, val });
    }
    Ok(SlotVector::Sparse { dim, entries })
}

/// Unsigned LEB128.
fn put_varint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_varint(cursor: &mut Cursor<'_>) -> Result<u32> {
    let mut value: u32 = 0;
    let mut shift = 0_u32;
    loop {
        let byte = cursor.u8()?;
        let chunk = u32::from(byte & 0x7f);
        if shift >= 32 || (shift == 28 && chunk > 0x0f) {
            return Err(CalyxError::aster_corrupt_shard("varint exceeds u32 range"));
        }
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            // Canonical LEB128: no trailing zero continuation groups.
            if byte == 0 && shift != 0 {
                return Err(CalyxError::aster_corrupt_shard(
                    "non-canonical varint with redundant trailing zero group",
                ));
            }
            return Ok(value);
        }
        shift += 7;
    }
}

pub fn encode_write_batch(rows: &[WriteRow]) -> Result<Vec<u8>> {
    let count = u32::try_from(rows.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("write batch row count exceeds u32"))?;
    let mut out = Vec::new();
    out.extend_from_slice(WRITE_BATCH_MAGIC_V2);
    out.extend_from_slice(&count.to_be_bytes());
    for row in rows {
        encode_cf_v2(row.cf, &mut out);
        put_bytes(&mut out, &row.key)?;
        put_bytes(&mut out, &row.value)?;
    }
    Ok(out)
}

pub fn decode_write_batch(bytes: &[u8]) -> Result<Vec<WriteRow>> {
    if bytes.len() < WRITE_BATCH_MAGIC_V2.len() {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "WAL write batch is {} bytes, smaller than the {}-byte CXLWAL2 header",
            bytes.len(),
            WRITE_BATCH_MAGIC_V2.len()
        )));
    }
    if !bytes.starts_with(WRITE_BATCH_MAGIC_V2) {
        return Err(CalyxError {
            code: "CALYX_ASTER_WAL_PAYLOAD_LEGACY",
            message: "WAL write batch has no CXLWAL2 header; the legacy one-byte column-family tag truncated u16 slot ids and overlapped raw/quantized slot families"
                .to_string(),
            remediation: "restore this pre-CXLWAL2 vault with a format-specific migration that knows every original slot id/family, or re-ingest it from its provenanced source; never reinterpret ambiguous committed state",
        });
    }
    let payload = &bytes[WRITE_BATCH_MAGIC_V2.len()..];
    let mut cursor = Cursor::new(payload);
    let count = cursor.u32()? as usize;
    let minimum_row_bytes = 11;
    if count > cursor.remaining() / minimum_row_bytes {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "write batch declares {count} rows but {} remaining bytes cannot hold that many canonical rows",
            cursor.remaining()
        )));
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count).map_err(|error| {
        CalyxError::aster_corrupt_shard(format!(
            "reserve {count} decoded write rows failed: {error}"
        ))
    })?;
    for _ in 0..count {
        rows.push(WriteRow {
            cf: decode_cf_v2(&mut cursor)?,
            key: cursor.bytes_prefixed()?.to_vec(),
            value: cursor.bytes_prefixed()?.to_vec(),
        });
    }
    if cursor.remaining() != 0 {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "write batch has {} trailing bytes after its declared rows",
            cursor.remaining()
        )));
    }
    Ok(rows)
}

fn decode_identity(bytes: &[u8]) -> Result<(ConstellationHeader, [u8; 32])> {
    let header = decode_header(bytes)?;
    let mut cursor = Cursor::new(&bytes[HEADER_LEN..]);
    let identity = cursor.array()?;
    Ok((header_without_anchor_count(header), identity))
}

fn header_without_anchor_count(mut header: ConstellationHeader) -> ConstellationHeader {
    header.n_anchors = 0;
    header
}

fn identity_hash_with_slot_hashes(
    cx: &Constellation,
    slot_hashes: &BTreeMap<SlotId, [u8; 32]>,
) -> Result<blake3::Hash> {
    let mut bytes = encode_header(cx);
    bytes[50..58].copy_from_slice(&0_u64.to_be_bytes());
    bytes[48..50].copy_from_slice(&0_u16.to_be_bytes());
    for slot in cx.slots.keys() {
        let hash = slot_hashes.get(slot).ok_or_else(|| {
            base_slot_hash_violation(format!("Base slot {} has no preserved slot hash", slot.get()))
        })?;
        bytes.extend_from_slice(&slot.get().to_be_bytes());
        bytes.extend_from_slice(hash);
    }
    for (key, value) in &cx.scalars {
        put_string(&mut bytes, key)?;
        bytes.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    if !cx.metadata.is_empty() {
        encode_string_metadata(&cx.metadata, &mut bytes)?;
    }
    bytes.extend_from_slice(&[0_u8; 32]);
    Ok(blake3::hash(&bytes))
}

fn encode_input_ref_tail(input: &InputRef, out: &mut Vec<u8>) -> Result<()> {
    out.push(u8::from(input.redacted));
    match &input.pointer {
        Some(pointer) => {
            out.push(1);
            put_string(out, pointer)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn decode_input_ref_tail(cursor: &mut Cursor<'_>, hash: [u8; 32]) -> Result<InputRef> {
    let redacted = cursor.u8()? != 0;
    let pointer = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.string()?),
        tag => {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "unknown input pointer tag {tag}"
            )));
        }
    };
    Ok(InputRef {
        hash,
        pointer,
        redacted,
    })
}

fn encode_absent_reason(reason: &AbsentReason, out: &mut Vec<u8>) -> Result<()> {
    match reason {
        AbsentReason::NotApplicable => out.push(0),
        AbsentReason::Redacted => out.push(1),
        AbsentReason::LensUnavailable => out.push(2),
        AbsentReason::Deferred => out.push(3),
        AbsentReason::LensInactive => out.push(4),
        AbsentReason::Error(value) => {
            out.push(5);
            put_string(out, value)?;
        }
    }
    Ok(())
}

fn decode_absent_reason(cursor: &mut Cursor<'_>) -> Result<AbsentReason> {
    Ok(match cursor.u8()? {
        0 => AbsentReason::NotApplicable,
        1 => AbsentReason::Redacted,
        2 => AbsentReason::LensUnavailable,
        3 => AbsentReason::Deferred,
        4 => AbsentReason::LensInactive,
        5 => AbsentReason::Error(cursor.string()?),
        tag => {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "unknown absent tag {tag}"
            )));
        }
    })
}

fn modality_tag(modality: Modality) -> u8 {
    match modality {
        Modality::Text => 0,
        Modality::Code => 1,
        Modality::Image => 2,
        Modality::Audio => 3,
        Modality::Video => 4,
        Modality::Structured => 5,
        Modality::Mixed => 6,
        Modality::Protein => 7,
        Modality::Dna => 8,
        Modality::Molecule => 9,
    }
}

fn decode_modality(tag: u8) -> Result<Modality> {
    Ok(match tag {
        0 => Modality::Text,
        1 => Modality::Code,
        2 => Modality::Image,
        3 => Modality::Audio,
        4 => Modality::Video,
        5 => Modality::Structured,
        6 => Modality::Mixed,
        7 => Modality::Protein,
        8 => Modality::Dna,
        9 => Modality::Molecule,
        _ => return Err(CalyxError::aster_corrupt_shard("unknown modality tag")),
    })
}

fn flags_bits(flags: CxFlags) -> u8 {
    u8::from(flags.ungrounded)
        | (u8::from(flags.degraded) << 1)
        | (u8::from(flags.novel_region) << 2)
        | (u8::from(flags.redacted_input) << 3)
}

fn decode_flags(bits: u8) -> CxFlags {
    CxFlags {
        ungrounded: bits & 1 != 0,
        degraded: bits & 2 != 0,
        novel_region: bits & 4 != 0,
        redacted_input: bits & 8 != 0,
    }
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    put_bytes(out, value.as_bytes())
}

fn encode_string_metadata(metadata: &BTreeMap<String, String>, out: &mut Vec<u8>) -> Result<()> {
    let count = u32::try_from(metadata.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("metadata map too large"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (key, value) in metadata {
        put_string(out, key)?;
        put_string(out, value)?;
    }
    Ok(())
}

fn decode_string_metadata(cursor: &mut Cursor<'_>) -> Result<BTreeMap<String, String>> {
    let count = cursor.u32()? as usize;
    let mut metadata = BTreeMap::new();
    for _ in 0..count {
        let key = cursor.string()?;
        let value = cursor.string()?;
        metadata.insert(key, value);
    }
    Ok(metadata)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CalyxError::aster_corrupt_shard("encoded field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
