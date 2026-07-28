use crate::cf::{ColumnFamily, SlotFamilyKind};
use calyx_core::{CalyxError, Result, SlotId};

use super::cursor::Cursor;

const CF_FIXED: u8 = 0;
const CF_SLOT_QUANTIZED: u8 = 1;
const CF_SLOT_RAW: u8 = 2;

pub(super) fn encode_cf_v2(cf: ColumnFamily, out: &mut Vec<u8>) {
    match cf {
        ColumnFamily::Slot { slot, kind } => {
            out.push(match kind {
                SlotFamilyKind::Quantized => CF_SLOT_QUANTIZED,
                SlotFamilyKind::Raw => CF_SLOT_RAW,
            });
            out.extend_from_slice(&slot.get().to_be_bytes());
        }
        fixed => {
            out.push(CF_FIXED);
            out.extend_from_slice(&u16::from(fixed_cf_tag(fixed)).to_be_bytes());
        }
    }
}

pub(super) fn decode_cf_v2(cursor: &mut Cursor<'_>) -> Result<ColumnFamily> {
    let kind = cursor.u8()?;
    let value = cursor.u16()?;
    match kind {
        CF_FIXED => {
            let tag = u8::try_from(value).map_err(|_| {
                CalyxError::aster_corrupt_shard(format!(
                    "CXLWAL2 fixed column-family tag {value} exceeds u8"
                ))
            })?;
            if (16..=111).contains(&tag) {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "CXLWAL2 fixed column-family tag {tag} overlaps the legacy slot range; slots require an explicit family kind and u16 id"
                )));
            }
            decode_fixed_cf(tag)
        }
        CF_SLOT_QUANTIZED => Ok(ColumnFamily::slot(SlotId::new(value))),
        CF_SLOT_RAW => Ok(ColumnFamily::slot_raw(SlotId::new(value))),
        other => Err(CalyxError::aster_corrupt_shard(format!(
            "CXLWAL2 column-family kind {other} is invalid"
        ))),
    }
}

fn fixed_cf_tag(cf: ColumnFamily) -> u8 {
    match cf {
        ColumnFamily::Base => 0,
        ColumnFamily::Collections => 117,
        ColumnFamily::Relational => 118,
        ColumnFamily::Document => 119,
        ColumnFamily::Kv => 120,
        ColumnFamily::TimeSeries => 121,
        ColumnFamily::Blob => 122,
        ColumnFamily::Anchors => 1,
        ColumnFamily::Ledger => 2,
        ColumnFamily::XTerm => 3,
        ColumnFamily::Scalars => 4,
        ColumnFamily::Online => 5,
        ColumnFamily::Assay => 6,
        ColumnFamily::Recurrence => 7,
        ColumnFamily::Reactive => 126,
        ColumnFamily::TemporalXTerm => 8,
        ColumnFamily::AnnealRollback => 9,
        ColumnFamily::AnnealHealth => 10,
        ColumnFamily::AnnealChecksums => 11,
        ColumnFamily::Graph => 12,
        ColumnFamily::AnnealMistakes => 13,
        ColumnFamily::AnnealReplay => 14,
        ColumnFamily::AnnealHeads => 15,
        ColumnFamily::AnnealBandit => 112,
        ColumnFamily::AnnealSoak => 113,
        ColumnFamily::AnnealReport => 114,
        ColumnFamily::AnnealGrowth => 115,
        ColumnFamily::TimeIndex => 116,
        ColumnFamily::IndexBtree => 123,
        ColumnFamily::IndexInverted => 124,
        ColumnFamily::AnnealOperators => 125,
        ColumnFamily::Kernel => 127,
        ColumnFamily::Guard => 128,
        ColumnFamily::Compression => 129,
        ColumnFamily::Slot { .. } => unreachable!("slot CFs use the explicit CXLWAL2 family kind"),
    }
}

pub(crate) fn decode_fixed_cf(tag: u8) -> Result<ColumnFamily> {
    Ok(match tag {
        0 => ColumnFamily::Base,
        117 => ColumnFamily::Collections,
        118 => ColumnFamily::Relational,
        119 => ColumnFamily::Document,
        120 => ColumnFamily::Kv,
        121 => ColumnFamily::TimeSeries,
        122 => ColumnFamily::Blob,
        1 => ColumnFamily::Anchors,
        2 => ColumnFamily::Ledger,
        3 => ColumnFamily::XTerm,
        4 => ColumnFamily::Scalars,
        5 => ColumnFamily::Online,
        6 => ColumnFamily::Assay,
        7 => ColumnFamily::Recurrence,
        126 => ColumnFamily::Reactive,
        8 => ColumnFamily::TemporalXTerm,
        9 => ColumnFamily::AnnealRollback,
        10 => ColumnFamily::AnnealHealth,
        11 => ColumnFamily::AnnealChecksums,
        12 => ColumnFamily::Graph,
        13 => ColumnFamily::AnnealMistakes,
        14 => ColumnFamily::AnnealReplay,
        15 => ColumnFamily::AnnealHeads,
        112 => ColumnFamily::AnnealBandit,
        113 => ColumnFamily::AnnealSoak,
        114 => ColumnFamily::AnnealReport,
        115 => ColumnFamily::AnnealGrowth,
        116 => ColumnFamily::TimeIndex,
        123 => ColumnFamily::IndexBtree,
        124 => ColumnFamily::IndexInverted,
        125 => ColumnFamily::AnnealOperators,
        127 => ColumnFamily::Kernel,
        128 => ColumnFamily::Guard,
        129 => ColumnFamily::Compression,
        _ => {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "unknown CXLWAL2 fixed column-family tag {tag}"
            )));
        }
    })
}
