//! The fixed-width constellation header: its typed view, byte layout, and the
//! modality/flags tag codecs it depends on, plus identity comparison over two
//! encoded Base rows.

use crate::vault::cursor::Cursor;
use calyx_core::{CalyxError, Constellation, CxFlags, CxId, Modality, Result, VaultId};

pub const HEADER_LEN: usize = 102;

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

pub fn same_constellation_identity(left: &[u8], right: &[u8]) -> Result<bool> {
    Ok(decode_identity(left)? == decode_identity(right)?)
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
