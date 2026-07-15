use std::ops::Range;

use calyx_core::{CalyxError, Result};

use crate::append::LedgerRow;
use crate::codec::decode_unchecked;
use crate::entry::{HASH_BYTES, LedgerEntry, compute_entry_hash};
use crate::head_anchor::LedgerHeadAnchor;
use crate::verify::VerifyResult;

#[derive(Debug)]
pub enum StreamingStart {
    Ready(StreamingChainVerifier),
    Complete(VerifyResult),
}

#[derive(Debug)]
pub struct StreamingChainVerifier {
    range: Range<u64>,
    next_seq: u64,
    expected_prev: [u8; HASH_BYTES],
    count: u64,
    anchor: Option<LedgerHeadAnchor>,
}

impl StreamingChainVerifier {
    pub fn start(
        range: Range<u64>,
        anchor: Option<LedgerHeadAnchor>,
        previous: Option<&LedgerRow>,
    ) -> Result<StreamingStart> {
        if range.start > range.end {
            return Err(CalyxError::ledger_corrupt(format!(
                "invalid ledger range {}..{}",
                range.start, range.end
            )));
        }
        if range.start == range.end {
            return Ok(StreamingStart::Complete(VerifyResult::Intact { count: 0 }));
        }
        if range.start == 0
            && let Some(anchor) = &anchor
            && range.end != anchor.height
        {
            return Ok(StreamingStart::Complete(corrupt_result(
                range.end.min(anchor.height),
                format!(
                    "ledger head anchor mismatch: requested head {}, anchored head {}",
                    range.end, anchor.height
                ),
            )));
        }
        let expected_prev = expected_prev_hash(range.start, previous)?;
        Ok(StreamingStart::Ready(Self {
            next_seq: range.start,
            range,
            expected_prev,
            count: 0,
            anchor,
        }))
    }

    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub const fn end(&self) -> u64 {
        self.range.end
    }

    pub const fn count(&self) -> u64 {
        self.count
    }

    pub fn verify_next(&mut self, row: Option<LedgerRow>) -> Result<Option<VerifyResult>> {
        let seq = self.next_seq;
        let Some(row) = row else {
            return Ok(Some(corrupt_result(
                seq,
                format!("missing ledger row for seq {seq}"),
            )));
        };
        let entry = match decode_unchecked(&row.bytes) {
            Ok(entry) => entry,
            Err(error) => {
                return Ok(Some(corrupt_result(
                    seq,
                    format!("decode ledger row seq {seq}: {error}"),
                )));
            }
        };
        if row.seq != seq || entry.seq != seq {
            return Ok(Some(corrupt_result(
                seq,
                format!("ledger key seq {seq} != encoded seq {}", entry.seq),
            )));
        }
        if entry.prev_hash != self.expected_prev {
            return Ok(Some(VerifyResult::Broken {
                at_seq: seq,
                expected: self.expected_prev,
                found: entry.prev_hash,
            }));
        }
        let expected_entry_hash = recompute_hash(&entry);
        if entry.entry_hash != expected_entry_hash {
            return Ok(Some(VerifyResult::Broken {
                at_seq: seq,
                expected: expected_entry_hash,
                found: entry.entry_hash,
            }));
        }
        self.expected_prev = entry.entry_hash;
        self.count += 1;
        self.next_seq += 1;
        Ok((self.next_seq == self.range.end).then(|| self.finish()))
    }

    fn finish(&self) -> VerifyResult {
        if self.range.start == 0
            && let Some(anchor) = &self.anchor
            && self.range.end == anchor.height
            && self.expected_prev != anchor.tip_hash
        {
            return VerifyResult::Broken {
                at_seq: self.range.end.saturating_sub(1),
                expected: anchor.tip_hash,
                found: self.expected_prev,
            };
        }
        VerifyResult::Intact { count: self.count }
    }
}

fn expected_prev_hash(start: u64, previous: Option<&LedgerRow>) -> Result<[u8; HASH_BYTES]> {
    if start == 0 {
        return Ok([0; HASH_BYTES]);
    }
    let previous_seq = start - 1;
    let Some(row) = previous else {
        return Err(CalyxError::ledger_corrupt(format!(
            "missing ledger row for previous seq {previous_seq}"
        )));
    };
    let entry = decode_unchecked(&row.bytes).map_err(|error| {
        CalyxError::ledger_corrupt(format!(
            "cannot verify range start {start}: previous seq {previous_seq}: {error}"
        ))
    })?;
    if row.seq != previous_seq || entry.seq != previous_seq {
        return Err(CalyxError::ledger_corrupt(format!(
            "previous key seq {previous_seq} != encoded seq {}",
            entry.seq
        )));
    }
    if !entry.verify() {
        return Err(CalyxError::ledger_corrupt(format!(
            "cannot verify range start {start}: previous seq {previous_seq} is broken"
        )));
    }
    Ok(entry.entry_hash)
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
