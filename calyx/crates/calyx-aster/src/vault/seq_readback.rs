use super::AsterVault;
use crate::cf::{ColumnFamily, KeyRange, ledger_key, ledger_range};
use crate::ledger_view::{AsterLedgerCfStore, LedgerPointReadTierStats, LedgerPointReadTrace};
use calyx_core::{CalyxError, Clock, Result, Seq};
use calyx_ledger::{LedgerHeadAnchor, LedgerRow, decode};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::time::Instant;

/// One bounded Ledger range copied from an exact durable head generation.
///
/// `anchor` and `snapshot_seq` are sampled under the same durable commit-lock
/// generation as `previous` and `rows`. The physical tip is independently
/// point-read and checked against `anchor` before this value is returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRangeSnapshot {
    /// Exact MVCC sequence retained while the rows were copied.
    pub snapshot_seq: Seq,
    /// External durable head witness observed for this sequence.
    pub anchor: Option<LedgerHeadAnchor>,
    /// Requested, head-clamped verification range.
    pub range: Range<u64>,
    /// Row immediately before `range`, when a non-genesis range needs it.
    pub previous: Option<LedgerRow>,
    /// Ledger rows whose keys fall in `range`, in sequence order.
    pub rows: Vec<LedgerRow>,
    /// True when tip validation required a separate point read because the
    /// bounded range did not already contain the anchored tip.
    pub tip_point_read: bool,
}

/// Refusal code for an invalid or non-durable bounded Ledger snapshot request.
pub const CALYX_LEDGER_RANGE_SNAPSHOT_INVALID: &str = "CALYX_LEDGER_RANGE_SNAPSHOT_INVALID";
const LEDGER_RANGE_SNAPSHOT_REMEDIATION: &str = "request a positive bounded row count from a durable vault with the Ledger column family selected";

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Reads one bounded Ledger suffix plus its predecessor from a single
    /// durable head generation.
    ///
    /// The returned `rows` length cannot exceed `limit`; at most one predecessor
    /// is copied, and the anchored physical tip is checked by one point read
    /// unless it is already in `rows`. No complete Ledger-CF scan is performed.
    ///
    /// # Errors
    ///
    /// Returns [`CALYX_LEDGER_RANGE_SNAPSHOT_INVALID`] for a zero limit or a
    /// volatile vault, and fails closed on a missing/regressed checkpoint,
    /// malformed head witness, missing physical row, or head-tip mismatch.
    pub fn read_bounded_ledger_snapshot(
        &self,
        start: u64,
        limit: u64,
    ) -> Result<LedgerRangeSnapshot> {
        if limit == 0 {
            return Err(CalyxError {
                code: CALYX_LEDGER_RANGE_SNAPSHOT_INVALID,
                message: "bounded Ledger snapshot limit must be positive".to_string(),
                remediation: LEDGER_RANGE_SNAPSHOT_REMEDIATION,
            });
        }
        if self.durable_root.is_none() {
            return Err(CalyxError {
                code: CALYX_LEDGER_RANGE_SNAPSHOT_INVALID,
                message: "bounded Ledger snapshot requires a durable head witness".to_string(),
                remediation: LEDGER_RANGE_SNAPSHOT_REMEDIATION,
            });
        }

        if self.read_only {
            self.ensure_retained_ledger_snapshot()?;
            self.read_bounded_ledger_snapshot_locked(start, limit)
        } else {
            self.with_durable_commit_lock(|| self.read_bounded_ledger_snapshot_locked(start, limit))
        }
    }

    fn read_bounded_ledger_snapshot_locked(
        &self,
        start: u64,
        limit: u64,
    ) -> Result<LedgerRangeSnapshot> {
        let root = self.durable_root.as_deref().ok_or_else(|| CalyxError {
            code: CALYX_LEDGER_RANGE_SNAPSHOT_INVALID,
            message: "bounded Ledger snapshot lost its durable root".to_string(),
            remediation: LEDGER_RANGE_SNAPSHOT_REMEDIATION,
        })?;
        let anchor = crate::ledger_head::read_head_anchor(root)?;
        let retained = self.retain_latest_snapshot();
        let snapshot = retained.snapshot();
        let snapshot_seq = retained.seq();

        let height = match &anchor {
            Some(anchor) => anchor.height,
            None => 0,
        };
        if start > height {
            return Err(CalyxError::ledger_chain_broken(format!(
                "bounded Ledger checkpoint {start} is ahead of durable head {height}"
            )));
        }

        if height == 0 {
            let rows = self.rows.scan_cf_range_page_at(
                snapshot,
                ColumnFamily::Ledger,
                &KeyRange {
                    start: Vec::new(),
                    end: None,
                },
                None,
                1,
                self.clock.as_ref(),
            )?;
            if let Some((key, _)) = rows.first() {
                return Err(CalyxError::ledger_chain_broken(format!(
                    "durable Ledger head is empty or absent but physical row {} exists",
                    hex_lower(key)
                )));
            }
            return Ok(LedgerRangeSnapshot {
                snapshot_seq,
                anchor,
                range: 0..0,
                previous: None,
                rows: Vec::new(),
                tip_point_read: false,
            });
        }

        let remaining = height - start;
        let end = start
            .checked_add(remaining.min(limit))
            .ok_or_else(|| CalyxError::ledger_corrupt("bounded Ledger range end overflow"))?;
        let needs_previous = start > 0 && start < end;
        let read_start = if needs_previous { start - 1 } else { start };
        let expected_rows = end - read_start;
        let mut copied = if expected_rows == 0 {
            Vec::new()
        } else {
            let expected_rows = usize::try_from(expected_rows).map_err(|_| CalyxError {
                code: CALYX_LEDGER_RANGE_SNAPSHOT_INVALID,
                message: "bounded Ledger snapshot row count exceeds the platform usize range"
                    .to_string(),
                remediation: LEDGER_RANGE_SNAPSHOT_REMEDIATION,
            })?;
            let fetch_limit = expected_rows.checked_add(1).ok_or_else(|| CalyxError {
                code: CALYX_LEDGER_RANGE_SNAPSHOT_INVALID,
                message: "bounded Ledger snapshot row limit exceeds the platform usize range"
                    .to_string(),
                remediation: LEDGER_RANGE_SNAPSHOT_REMEDIATION,
            })?;
            let rows = self.rows.scan_cf_range_page_at(
                snapshot,
                ColumnFamily::Ledger,
                &ledger_range(read_start, end),
                None,
                fetch_limit,
                self.clock.as_ref(),
            )?;
            if rows.len() > expected_rows {
                return Err(CalyxError::ledger_corrupt(format!(
                    "bounded Ledger range {read_start}..{end} returned more than {expected_rows} distinct keys"
                )));
            }
            decode_physical_rows(rows, read_start..end)?
        };

        let previous = if needs_previous && copied.first().is_some_and(|row| row.seq == start - 1) {
            Some(copied.remove(0))
        } else {
            None
        };

        let tip_seq = height - 1;
        let tip_point_read = end != height || start == end;
        let tip = if tip_point_read {
            self.rows
                .read_at(
                    snapshot,
                    ColumnFamily::Ledger,
                    &ledger_key(tip_seq),
                    self.clock.as_ref(),
                )?
                .map(|bytes| LedgerRow {
                    seq: tip_seq,
                    bytes,
                })
        } else {
            copied.iter().find(|row| row.seq == tip_seq).cloned()
        };
        validate_anchored_tip(
            anchor
                .as_ref()
                .ok_or_else(|| crate::ledger_head::missing_head_anchor(root, height))?,
            tip,
        )?;

        Ok(LedgerRangeSnapshot {
            snapshot_seq,
            anchor,
            range: start..end,
            previous,
            rows: copied,
            tip_point_read,
        })
    }

    /// Returns the visible MVCC sequence for one CF/key at `snapshot`.
    pub fn seq_for_key_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Seq>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows
            .seq_for_key_at(snapshot.snapshot(), cf, key, &self.clock)
    }

    /// Returns the visible MVCC sequence for one CF/key at the latest snapshot.
    pub fn seq_for_key(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Seq>> {
        self.seq_for_key_at(self.latest_seq(), cf, key)
    }

    /// Independently reads exact Ledger rows from their physical durable home.
    ///
    /// Durable vaults route through the manifest/WAL-aware physical point reader;
    /// volatile vaults point-read the live router at one exact snapshot and label
    /// that storage mode explicitly. No write receipt or in-memory ledger hook is
    /// trusted as readback evidence.
    pub fn read_physical_ledger_seqs(
        &self,
        seqs: &BTreeSet<u64>,
    ) -> Result<(BTreeMap<u64, LedgerRow>, LedgerPointReadTrace)> {
        if seqs.is_empty() {
            return Ok((BTreeMap::new(), LedgerPointReadTrace::default()));
        }
        if let Some(root) = self.durable_root.as_deref() {
            if self.read_only {
                self.ensure_retained_ledger_snapshot()?;
                return crate::ledger_view::read_ledger_seqs_unlocked_traced(
                    root,
                    seqs,
                    self.durable_tiering_policy.as_ref(),
                );
            }
            return crate::ledger_view::read_ledger_seqs_traced(root, seqs);
        }

        let started = Instant::now();
        let snapshot = self.latest_seq();
        let mut rows = BTreeMap::new();
        for seq in seqs {
            if let Some(bytes) =
                self.read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(*seq))?
            {
                rows.insert(*seq, LedgerRow { seq: *seq, bytes });
            }
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let resolved = seqs.iter().filter(|seq| rows.contains_key(seq)).count();
        Ok((
            rows,
            LedgerPointReadTrace {
                tiers: vec![LedgerPointReadTierStats {
                    tier: "volatile_router",
                    wanted: seqs.len(),
                    resolved,
                    files_opened: 0,
                    elapsed_ms,
                }],
            },
        ))
    }

    /// Copies the physical Ledger CF plus its external head anchor while this
    /// handle's retained shared commit lock still defines the read snapshot.
    ///
    /// This deliberately refuses volatile, writable, unguarded, and
    /// Ledger-unselected handles. Reopening the path here would attempt an
    /// exclusive lock acquisition while this handle owns the shared lock and
    /// would destroy the single-snapshot guarantee by splitting the reads.
    pub fn retained_read_only_ledger_store(&self) -> Result<AsterLedgerCfStore> {
        self.ensure_retained_ledger_snapshot()?;
        let root = self.durable_root.as_deref().ok_or_else(|| CalyxError {
            code: "CALYX_RETAINED_LEDGER_SNAPSHOT_NOT_DURABLE",
            message: "retained Ledger snapshot requires a durable vault root".to_string(),
            remediation: "open the durable vault read-only with the Ledger column family selected",
        })?;
        AsterLedgerCfStore::open_unlocked_with_tiering(root, self.durable_tiering_policy.as_ref())
    }

    /// Returns the physical head anchor from the same retained read snapshot.
    pub fn retained_read_only_ledger_head(&self) -> Result<Option<LedgerHeadAnchor>> {
        self.ensure_retained_ledger_snapshot()?;
        let root = self.durable_root.as_deref().ok_or_else(|| CalyxError {
            code: "CALYX_RETAINED_LEDGER_SNAPSHOT_NOT_DURABLE",
            message: "retained Ledger snapshot requires a durable vault root".to_string(),
            remediation: "open the durable vault read-only with the Ledger column family selected",
        })?;
        crate::ledger_head::read_head_anchor(root)
    }

    fn ensure_retained_ledger_snapshot(&self) -> Result<()> {
        if self.durable_root.is_none() {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_NOT_DURABLE",
                message: "retained Ledger snapshot requires a durable vault root".to_string(),
                remediation: "open the durable vault read-only with the Ledger column family selected",
            });
        }
        if !self.read_only {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_WRITABLE",
                message: "retained Ledger snapshot rejected a write-capable vault handle"
                    .to_string(),
                remediation: "open a dedicated read-only vault handle and retain it for the complete read transaction",
            });
        }
        if self._read_snapshot_guard.is_none() {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_LOCK_MISSING",
                message: "read-only durable vault has no retained shared commit lock".to_string(),
                remediation: "discard this handle and reopen the durable vault read-only before reading Ledger state",
            });
        }

        // A physical reader addresses files directly, so first force the live
        // router to enforce this selected-CF handle's exact Ledger capability.
        // Sequence zero is only a capability probe; its value is not trusted.
        let _ = self.read_cf_at(self.latest_seq(), ColumnFamily::Ledger, &ledger_key(0))?;
        Ok(())
    }
}

fn decode_physical_rows(
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    range: Range<u64>,
) -> Result<Vec<LedgerRow>> {
    let mut decoded = Vec::with_capacity(rows.len());
    for (key, bytes) in rows {
        let seq = crate::ledger_view::parse_aster_ledger_seq(&key)?;
        if !range.contains(&seq) {
            return Err(CalyxError::ledger_corrupt(format!(
                "bounded Ledger range {}..{} returned out-of-range seq {seq}",
                range.start, range.end
            )));
        }
        if decoded.last().is_some_and(|row: &LedgerRow| row.seq >= seq) {
            return Err(CalyxError::ledger_corrupt(format!(
                "bounded Ledger range returned duplicate or unordered seq {seq}"
            )));
        }
        decoded.push(LedgerRow { seq, bytes });
    }
    Ok(decoded)
}

fn validate_anchored_tip(anchor: &LedgerHeadAnchor, tip: Option<LedgerRow>) -> Result<()> {
    let tip_seq = anchor.height.checked_sub(1).ok_or_else(|| {
        CalyxError::ledger_corrupt("non-empty Ledger tip validation received a genesis anchor")
    })?;
    let tip = tip.ok_or_else(|| {
        CalyxError::ledger_chain_broken(format!(
            "durable Ledger head {} requires missing physical tip seq {tip_seq}",
            anchor.height
        ))
    })?;
    if tip.seq != tip_seq {
        return Err(CalyxError::ledger_corrupt(format!(
            "durable Ledger tip point read requested seq {tip_seq} but returned {}",
            tip.seq
        )));
    }
    let entry = decode(&tip.bytes)?;
    if entry.seq != tip_seq {
        return Err(CalyxError::ledger_corrupt(format!(
            "durable Ledger tip key seq {tip_seq} does not match encoded seq {}",
            entry.seq
        )));
    }
    if entry.entry_hash != anchor.tip_hash {
        return Err(CalyxError::ledger_chain_broken(format!(
            "durable Ledger tip hash at seq {tip_seq} does not match external head anchor"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
