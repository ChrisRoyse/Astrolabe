//! Ledger hash-chain verification.

use std::collections::BTreeMap;
use std::ops::Range;

use calyx_core::{CalyxError, Result};

use crate::append::LedgerCfStore;
use crate::codec::decode_unchecked;
use crate::entry::{HASH_BYTES, LedgerEntry, compute_entry_hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    Intact {
        count: u64,
    },
    Broken {
        at_seq: u64,
        expected: [u8; HASH_BYTES],
        found: [u8; HASH_BYTES],
    },
    Corrupt {
        at_seq: u64,
        reason: String,
    },
}

impl VerifyResult {
    pub fn quarantine_seq(&self) -> Option<u64> {
        match self {
            Self::Intact { .. } => None,
            Self::Broken { at_seq, .. } | Self::Corrupt { at_seq, .. } => Some(*at_seq),
        }
    }
}

pub fn verify_chain(store: &dyn LedgerCfStore, range: Range<u64>) -> Result<VerifyResult> {
    if range.start > range.end {
        return Err(CalyxError::ledger_corrupt(format!(
            "invalid ledger range {}..{}",
            range.start, range.end
        )));
    }
    if range.start == range.end {
        return Ok(VerifyResult::Intact { count: 0 });
    }
    let anchor = store.head_anchor()?;
    if range.start == 0
        && let Some(anchor) = &anchor
        && range.end != anchor.height
    {
        return Ok(corrupt_result(
            range.end.min(anchor.height),
            format!(
                "ledger head anchor mismatch: requested head {}, anchored head {}",
                range.end, anchor.height
            ),
        ));
    }
    let rows = store
        .scan()?
        .into_iter()
        .map(|row| (row.seq, row.bytes))
        .collect::<BTreeMap<_, _>>();
    let mut expected_prev = match expected_prev_hash(&rows, range.start)? {
        StartHash::Ready(hash) => hash,
        StartHash::Corrupt(result) => return Ok(result),
    };
    let mut count = 0_u64;

    for seq in range.clone() {
        let Some(bytes) = rows.get(&seq) else {
            return Ok(corrupt_result(
                seq,
                format!("missing ledger row for seq {seq}"),
            ));
        };
        let entry = match decode_unchecked(bytes) {
            Ok(entry) => entry,
            Err(error) => {
                return Ok(corrupt_result(
                    seq,
                    format!("decode ledger row seq {seq}: {error}"),
                ));
            }
        };
        if entry.seq != seq {
            return Ok(corrupt_result(
                seq,
                format!("ledger key seq {seq} != encoded seq {}", entry.seq),
            ));
        }
        if entry.prev_hash != expected_prev {
            return Ok(VerifyResult::Broken {
                at_seq: seq,
                expected: expected_prev,
                found: entry.prev_hash,
            });
        }
        let expected_entry_hash = recompute_hash(&entry);
        if entry.entry_hash != expected_entry_hash {
            return Ok(VerifyResult::Broken {
                at_seq: seq,
                expected: expected_entry_hash,
                found: entry.entry_hash,
            });
        }
        expected_prev = entry.entry_hash;
        count += 1;
    }

    if range.start == 0
        && let Some(anchor) = &anchor
        && range.end == anchor.height
        && expected_prev != anchor.tip_hash
    {
        return Ok(VerifyResult::Broken {
            at_seq: range.end.saturating_sub(1),
            expected: anchor.tip_hash,
            found: expected_prev,
        });
    }

    Ok(VerifyResult::Intact { count })
}

enum StartHash {
    Ready([u8; HASH_BYTES]),
    Corrupt(VerifyResult),
}

fn expected_prev_hash(rows: &BTreeMap<u64, Vec<u8>>, start: u64) -> Result<StartHash> {
    if start == 0 {
        return Ok(StartHash::Ready([0; HASH_BYTES]));
    }
    let previous_seq = start - 1;
    let Some(bytes) = rows.get(&previous_seq) else {
        return Ok(StartHash::Corrupt(corrupt_result(
            start,
            format!("missing ledger row for previous seq {previous_seq}"),
        )));
    };
    let entry = match decode_unchecked(bytes) {
        Ok(entry) => entry,
        Err(error) => {
            return Ok(StartHash::Corrupt(corrupt_result(
                start,
                format!("cannot verify range start {start}: previous seq {previous_seq}: {error}"),
            )));
        }
    };
    if entry.seq != previous_seq {
        return Ok(StartHash::Corrupt(corrupt_result(
            start,
            format!(
                "previous key seq {previous_seq} != encoded seq {}",
                entry.seq
            ),
        )));
    }
    if !entry.verify() {
        return Ok(StartHash::Corrupt(corrupt_result(
            start,
            format!("cannot verify range start {start}: previous seq {previous_seq} is broken"),
        )));
    }
    Ok(StartHash::Ready(entry.entry_hash))
}

fn recompute_hash(entry: &LedgerEntry) -> [u8; HASH_BYTES] {
    compute_entry_hash(
        entry.seq,
        &entry.prev_hash,
        entry.kind,
        &entry.subject,
        &entry.payload,
        &entry.actor,
        entry.ts,
    )
}

fn corrupt_result(at_seq: u64, reason: impl Into<String>) -> VerifyResult {
    VerifyResult::Corrupt {
        at_seq,
        reason: reason.into(),
    }
}
