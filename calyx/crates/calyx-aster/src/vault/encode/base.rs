//! The constellation Base row: its identity view, the hash-preserving
//! [`BaseRecord`] update path, encode/decode of the full row, the identity hash
//! derivation, and the input-ref/metadata tail codecs the row body carries.

use super::header::{HEADER_LEN, decode_header, encode_header};
use super::vector::encode_slot_vector;
use super::{put_bytes, put_string};
use crate::vault::anchor_codec::{decode_anchor, encode_anchor};
use crate::vault::cursor::Cursor;
use calyx_core::{
    AbsentReason, Anchor, CalyxError, Constellation, CxFlags, CxId, InputRef, LedgerRef, Result,
    SlotId, SlotVector, VaultId,
};
use std::collections::BTreeMap;

const IDENTITY_HASH_LEN: usize = 32;

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
pub struct ConstellationBaseIdentity {
    pub cx_id: CxId,
    pub slot_hashes: BTreeMap<SlotId, [u8; 32]>,
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
            base_slot_hash_violation(format!(
                "Base slot {} has no preserved slot hash",
                slot.get()
            ))
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
        slot_hashes.insert(
            *slot,
            *blake3::hash(&encode_slot_vector(vector)?).as_bytes(),
        );
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

    /// Mutable access to grounded outcomes for a Base-only anchor update. Slot
    /// hashes remain sealed in this record and are re-emitted unchanged.
    pub(crate) fn anchors_mut(&mut self) -> &mut Vec<Anchor> {
        &mut self.constellation.anchors
    }

    /// Canonical duplicate-ingest identity with anchor-only variance removed.
    /// This is derived through the lossless record so persisted slot hashes are
    /// compared without hydrating or re-encoding slot values.
    pub(crate) fn anchor_merge_identity(&self) -> Result<Vec<u8>> {
        let mut normalized = self.clone();
        normalized.constellation.anchors.clear();
        normalized.constellation.created_at = 0;
        normalized.constellation.flags.ungrounded = false;
        normalized.constellation.provenance = LedgerRef {
            seq: 0,
            hash: [0; 32],
        };
        normalized.encode()
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

fn identity_hash_with_slot_hashes(
    cx: &Constellation,
    slot_hashes: &BTreeMap<SlotId, [u8; 32]>,
) -> Result<blake3::Hash> {
    let mut bytes = encode_header(cx);
    bytes[50..58].copy_from_slice(&0_u64.to_be_bytes());
    bytes[48..50].copy_from_slice(&0_u16.to_be_bytes());
    for slot in cx.slots.keys() {
        let hash = slot_hashes.get(slot).ok_or_else(|| {
            base_slot_hash_violation(format!(
                "Base slot {} has no preserved slot hash",
                slot.get()
            ))
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
