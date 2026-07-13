use std::collections::BTreeMap;
use std::path::Path;

use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::ledger_view::{AsterLedgerCfStore, parse_aster_ledger_seq};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{CalyxError, Clock, Result as CalyxResult};
use calyx_ledger::{
    LedgerCfStore, LedgerHeadAnchor, LedgerRow, RedactionPolicy, VerifyResult, decode,
    verify_chain as calyx_verify_chain,
};
use serde::{Deserialize, Serialize};

use crate::registry::{IngestError, IngestResult};

const VERIFY_CHAIN_REMEDIATION: &str = "Quarantine the reported ledger sequence range, restore or rebuild the vault, then rerun astrolabe verify --deep.";

/// User-facing hash-chain verification state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyChainReport {
    /// `intact`, `broken`, or `corrupt`.
    pub status: String,
    /// Number of Ledger CF rows visible to the verifier.
    pub ledger_rows: u64,
    /// Start of the checked ledger sequence range.
    pub checked_range_start: u64,
    /// Exclusive end of the checked ledger sequence range.
    pub checked_range_end: u64,
    /// Verified row count for an intact chain.
    pub count: u64,
    /// First bad sequence for broken/corrupt chains.
    pub at_seq: Option<u64>,
    /// Expected hash for broken chains, lower-hex.
    pub expected_hash: Option<String>,
    /// Found hash for broken chains, lower-hex.
    pub found_hash: Option<String>,
    /// Corruption reason for corrupt chains.
    pub reason: Option<String>,
    /// First sequence to quarantine before serving reads.
    pub quarantine_seq: Option<u64>,
    /// Operator remediation when the chain is not intact.
    pub remediation: Option<&'static str>,
}

impl VerifyChainReport {
    /// Returns true when the whole checked range re-hashed cleanly.
    pub fn is_intact(&self) -> bool {
        self.status == "intact"
    }
}

/// Ledger-pairing facts checked by `astrolabe verify --deep`.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct LedgerPairingCounts {
    pub ledger_payload_rows: usize,
    pub base_ledger_pairs: usize,
}

/// Verifies the Ledger CF hash chain visible in an opened Aster vault.
pub fn verify_chain<C>(vault: &AsterVault<C>) -> IngestResult<VerifyChainReport>
where
    C: Clock,
{
    let store = AsterVaultLedgerStore { vault };
    verify_store_chain(&store)
}

/// Opens a physical durable Aster ledger view and verifies its hash chain.
pub fn verify_chain_vault_path(vault_dir: impl AsRef<Path>) -> IngestResult<VerifyChainReport> {
    let vault_dir = vault_dir.as_ref();
    if !vault_dir.exists() {
        return Err(IngestError::InvalidInput(format!(
            "vault dir does not exist: {}",
            vault_dir.display()
        )));
    }
    let store = match AsterLedgerCfStore::open(vault_dir) {
        Ok(store) => store,
        Err(error)
            if error.code == "CALYX_LEDGER_CORRUPT"
                && error.message.contains("requires real Aster ledger state") =>
        {
            return Ok(empty_report());
        }
        Err(error) => return Err(error.into()),
    };
    verify_store_chain(&store)
}

pub(crate) fn verify_ledger_pairing<C>(
    vault: &AsterVault<C>,
    errors: &mut Vec<String>,
) -> IngestResult<LedgerPairingCounts>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut ledger_rows = BTreeMap::new();
    let mut counts = LedgerPairingCounts::default();

    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
        let seq = match parse_aster_ledger_seq(&key) {
            Ok(seq) => seq,
            Err(err) => {
                errors.push(format!("decode ledger key {}: {err}", hex_lower(&key)));
                continue;
            }
        };
        match decode(&bytes) {
            Ok(entry) => {
                if entry.seq != seq {
                    errors.push(format!(
                        "ledger key seq {seq} does not match encoded seq {}",
                        entry.seq
                    ));
                    continue;
                }
                if let Err(err) = RedactionPolicy::check_payload(&entry.payload) {
                    errors.push(format!(
                        "ledger seq {seq} payload violates redaction: {err}"
                    ));
                    continue;
                }
                counts.ledger_payload_rows += 1;
                ledger_rows.insert(seq, entry);
            }
            Err(err) => errors.push(format!("decode ledger row seq {seq}: {err}")),
        }
    }

    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
        let decoded = match encode::decode_constellation_base(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                errors.push(format!("decode Base row {}: {err}", hex_lower(&key)));
                continue;
            }
        };
        match ledger_rows.get(&decoded.provenance.seq) {
            Some(entry) if entry.entry_hash == decoded.provenance.hash => {
                counts.base_ledger_pairs += 1;
            }
            Some(entry) => errors.push(format!(
                "Base row {} provenance hash does not match ledger seq {}: expected {} found {}",
                decoded.cx_id,
                decoded.provenance.seq,
                hex_lower(&entry.entry_hash),
                hex_lower(&decoded.provenance.hash)
            )),
            None => errors.push(format!(
                "Base row {} points to missing ledger seq {}",
                decoded.cx_id, decoded.provenance.seq
            )),
        }
    }

    Ok(counts)
}

/// Refusal code for a janitor budget outside the declared knob bounds.
pub const ASTRO_FSV_JANITOR_BUDGET_INVALID: &str = "ASTRO_FSV_JANITOR_BUDGET_INVALID";

const JANITOR_BUDGET_REMEDIATION: &str = "Set the janitor ledger-entries-per-slice budget inside the declared FSV knob bounds, or pass None to use the registry default.";

/// A persisted checkpoint of the ledger prefix already verified by the janitor.
///
/// The janitor never re-walks the whole ledger per pass (#96): it caches how far
/// it has verified (`verified_through`, an exclusive sequence bound) and only
/// re-hashes the bounded suffix past that point, exactly like a transparent-log
/// client that keeps its verified prefix and checks only the new tail
/// (<https://research.swtch.com/tlog.pdf>).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct JanitorCheckpoint {
    /// Exclusive ledger sequence up to which the chain is already verified.
    pub verified_through: u64,
}

impl JanitorCheckpoint {
    /// A fresh checkpoint that has verified nothing yet.
    pub const GENESIS: Self = Self {
        verified_through: 0,
    };
}

impl Default for JanitorCheckpoint {
    fn default() -> Self {
        Self::GENESIS
    }
}

/// Result of one bounded background self-verification slice.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct JanitorSliceReport {
    /// Chain status of the verified slice: `intact`, `broken`, or `corrupt`.
    pub status: String,
    /// Inclusive-start sequence of the slice this pass verified.
    pub slice_start: u64,
    /// Exclusive-end sequence of the slice this pass verified.
    pub slice_end: u64,
    /// Ledger entries re-hashed in this slice (bounded by the budget knob).
    pub entries_verified: u64,
    /// Checkpoint after this slice; feed it to the next slice.
    pub checkpoint: JanitorCheckpoint,
    /// True when the janitor has now verified the whole persisted ledger.
    pub caught_up: bool,
    /// First bad sequence when the slice was not intact.
    pub at_seq: Option<u64>,
    /// Corruption reason when the slice was corrupt.
    pub reason: Option<String>,
    /// Operator remediation when the slice was not intact.
    pub remediation: Option<&'static str>,
}

impl JanitorSliceReport {
    /// Returns true only when the verified slice re-hashed cleanly.
    pub fn is_intact(&self) -> bool {
        self.status == "intact"
    }
}

/// Runs one bounded janitor self-verification slice against the persisted ledger.
///
/// Verifies the sequence range `[checkpoint.verified_through, end)` where `end`
/// is bounded by the janitor budget so a single pass never re-walks the whole
/// ledger (#96). The budget is the registry-declared knob
/// [`astrolabe_domain::knobs::FSV_JANITOR_LEDGER_ENTRIES_PER_SLICE_KNOB`];
/// `budget_override` may narrow or widen it within the declared bounds, and any
/// value outside those bounds is refused fail-closed.
///
/// A non-intact slice is a fail-closed corruption signal: the returned report
/// names the exact bad sequence and the checkpoint does **not** advance past it,
/// so the next pass re-examines the same range rather than skipping corruption.
///
/// # Errors
///
/// Returns [`ASTRO_FSV_JANITOR_BUDGET_INVALID`] when `budget_override` is outside
/// the declared knob bounds, or a Calyx error when the ledger cannot be scanned.
pub fn verify_chain_slice<C>(
    vault: &AsterVault<C>,
    checkpoint: JanitorCheckpoint,
    budget_override: Option<u64>,
) -> IngestResult<JanitorSliceReport>
where
    C: Clock,
{
    let budget = resolve_janitor_budget(budget_override)?;
    let store = AsterVaultLedgerStore { vault };
    let rows = store.scan()?;
    let height = rows
        .iter()
        .map(|row| row.seq.saturating_add(1))
        .max()
        .unwrap_or(0);

    let start = checkpoint.verified_through.min(height);
    if start >= height {
        // Already caught up: nothing new to verify, so no work and no rewalk.
        return Ok(JanitorSliceReport {
            status: "intact".to_string(),
            slice_start: start,
            slice_end: height,
            entries_verified: 0,
            checkpoint: JanitorCheckpoint {
                verified_through: height,
            },
            caught_up: true,
            at_seq: None,
            reason: None,
            remediation: None,
        });
    }
    let end = start.saturating_add(budget).min(height);
    let result = calyx_verify_chain(&store, start..end)?;
    Ok(janitor_report_from_result(result, start, end, height))
}

fn resolve_janitor_budget(budget_override: Option<u64>) -> IngestResult<u64> {
    let knob = astrolabe_domain::knobs::fsv_knob(
        astrolabe_domain::knobs::FSV_JANITOR_LEDGER_ENTRIES_PER_SLICE_KNOB,
    )
    .expect("janitor budget knob is declared in the FSV knob registry");
    match budget_override {
        None => Ok(knob.default),
        Some(value) if knob.accepts(value) => Ok(value),
        Some(value) => Err(IngestError::refused(
            ASTRO_FSV_JANITOR_BUDGET_INVALID,
            format!(
                "janitor ledger-entries-per-slice budget {value} is outside the declared knob bounds [{}, {}]",
                knob.min, knob.max
            ),
            JANITOR_BUDGET_REMEDIATION,
        )),
    }
}

fn janitor_report_from_result(
    result: VerifyResult,
    slice_start: u64,
    slice_end: u64,
    height: u64,
) -> JanitorSliceReport {
    match result {
        VerifyResult::Intact { count } => JanitorSliceReport {
            status: "intact".to_string(),
            slice_start,
            slice_end,
            entries_verified: count,
            checkpoint: JanitorCheckpoint {
                verified_through: slice_end,
            },
            caught_up: slice_end >= height,
            at_seq: None,
            reason: None,
            remediation: None,
        },
        VerifyResult::Broken { at_seq, .. } => JanitorSliceReport {
            status: "broken".to_string(),
            slice_start,
            slice_end,
            entries_verified: 0,
            // Do NOT advance past corruption: the checkpoint stays at the slice
            // start so the next pass re-examines the same range.
            checkpoint: JanitorCheckpoint {
                verified_through: slice_start,
            },
            caught_up: false,
            at_seq: Some(at_seq),
            reason: None,
            remediation: Some(VERIFY_CHAIN_REMEDIATION),
        },
        VerifyResult::Corrupt { at_seq, reason } => JanitorSliceReport {
            status: "corrupt".to_string(),
            slice_start,
            slice_end,
            entries_verified: 0,
            checkpoint: JanitorCheckpoint {
                verified_through: slice_start,
            },
            caught_up: false,
            at_seq: Some(at_seq),
            reason: Some(reason),
            remediation: Some(VERIFY_CHAIN_REMEDIATION),
        },
    }
}

pub(crate) fn verify_store_chain(store: &dyn LedgerCfStore) -> IngestResult<VerifyChainReport> {
    let rows = store.scan()?;
    let row_end = rows
        .iter()
        .map(|row| row.seq.saturating_add(1))
        .max()
        .unwrap_or(0);
    let anchor_end = store.head_anchor()?.map(|anchor| anchor.height);
    let checked_range_end = anchor_end.map_or(row_end, |height| height.max(row_end));
    let result = calyx_verify_chain(store, 0..checked_range_end)?;
    Ok(report_from_result(
        result,
        rows.len() as u64,
        checked_range_end,
    ))
}

fn report_from_result(
    result: VerifyResult,
    ledger_rows: u64,
    checked_range_end: u64,
) -> VerifyChainReport {
    match result {
        VerifyResult::Intact { count } => VerifyChainReport {
            status: "intact".to_string(),
            ledger_rows,
            checked_range_start: 0,
            checked_range_end,
            count,
            at_seq: None,
            expected_hash: None,
            found_hash: None,
            reason: None,
            quarantine_seq: None,
            remediation: None,
        },
        VerifyResult::Broken {
            at_seq,
            expected,
            found,
        } => VerifyChainReport {
            status: "broken".to_string(),
            ledger_rows,
            checked_range_start: 0,
            checked_range_end,
            count: 0,
            at_seq: Some(at_seq),
            expected_hash: Some(hex_lower(&expected)),
            found_hash: Some(hex_lower(&found)),
            reason: None,
            quarantine_seq: Some(at_seq),
            remediation: Some(VERIFY_CHAIN_REMEDIATION),
        },
        VerifyResult::Corrupt { at_seq, reason } => VerifyChainReport {
            status: "corrupt".to_string(),
            ledger_rows,
            checked_range_start: 0,
            checked_range_end,
            count: 0,
            at_seq: Some(at_seq),
            expected_hash: None,
            found_hash: None,
            reason: Some(reason),
            quarantine_seq: Some(at_seq),
            remediation: Some(VERIFY_CHAIN_REMEDIATION),
        },
    }
}

fn empty_report() -> VerifyChainReport {
    VerifyChainReport {
        status: "intact".to_string(),
        ledger_rows: 0,
        checked_range_start: 0,
        checked_range_end: 0,
        count: 0,
        at_seq: None,
        expected_hash: None,
        found_hash: None,
        reason: None,
        quarantine_seq: None,
        remediation: None,
    }
}

pub(crate) struct AsterVaultLedgerStore<'a, C> {
    pub(crate) vault: &'a AsterVault<C>,
}

impl<C> LedgerCfStore for AsterVaultLedgerStore<'_, C>
where
    C: Clock,
{
    fn scan(&self) -> CalyxResult<Vec<LedgerRow>> {
        let mut rows = self
            .vault
            .scan_cf_at(self.vault.latest_seq(), ColumnFamily::Ledger)?
            .into_iter()
            .map(|(key, bytes)| {
                Ok(LedgerRow {
                    seq: parse_aster_ledger_seq(&key)?,
                    bytes,
                })
            })
            .collect::<CalyxResult<Vec<_>>>()?;
        rows.sort_by_key(|row| row.seq);
        Ok(rows)
    }

    fn read_seq(&self, seq: u64) -> CalyxResult<Option<LedgerRow>> {
        self.vault
            .read_cf_at(
                self.vault.latest_seq(),
                ColumnFamily::Ledger,
                &ledger_key(seq),
            )?
            .map(|bytes| Ok(LedgerRow { seq, bytes }))
            .transpose()
    }

    fn put_new(&mut self, _seq: u64, _bytes: &[u8]) -> CalyxResult<()> {
        Err(CalyxError::ledger_append_only_violation(
            "Astrolabe verify store is read-only",
        ))
    }

    fn head_anchor(&self) -> CalyxResult<Option<LedgerHeadAnchor>> {
        Ok(None)
    }
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use calyx_aster::cf::ledger_key;
    use calyx_aster::pressure::{DiskPressureGuard, DiskSample, DiskSpaceProbe};
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{FixedClock, VaultId};
    use calyx_ledger::{ActorId, EntryKind, SubjectId};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    const CRASH_FSV_KEY: &[u8] = b"astrolabe:crash-fsv:v1";
    const CONCURRENT_PARENT_WRITES: usize = 16;
    const CONCURRENT_CHILD_WRITES: usize = 16;

    #[test]
    fn verify_chain_reports_intact_and_exact_broken_seq() {
        let vault = vault();
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(b"first".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("append first");
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(b"second".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("append second");

        let intact = verify_chain(&vault).expect("verify intact");
        assert_eq!(intact.status, "intact");
        assert_eq!(intact.count, 2);

        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(1))
            .expect("read ledger")
            .expect("ledger row");
        tampered[16] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(1), tampered)
            .expect("persist tamper");

        let broken = verify_chain(&vault).expect("verify broken");
        assert_eq!(broken.status, "broken");
        assert_eq!(broken.at_seq, Some(1));
        assert_eq!(broken.quarantine_seq, Some(1));
    }

    #[test]
    fn redaction_refuses_secret_payload_before_append_or_batch_commit() {
        let append_vault = vault();
        let err = append_vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(b"secret-test".to_vec()),
                secret_payload(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect_err("secret payload must be refused");

        assert_eq!(err.code, "CALYX_LEDGER_SECRET_IN_PAYLOAD");
        assert_eq!(
            verify_chain(&append_vault)
                .expect("verify empty chain")
                .ledger_rows,
            0
        );

        let batch_vault = vault();
        let data_key = b"secret-batch-row".to_vec();
        let err = batch_vault
            .write_cf_batch_with_ledger_entry(
                [(ColumnFamily::Kv, data_key.clone(), b"value".to_vec())],
                EntryKind::Ingest,
                SubjectId::Query(b"secret-batch-test".to_vec()),
                secret_payload(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect_err("secret batch payload must be refused");

        assert_eq!(err.code, "CALYX_LEDGER_GROUP_COMMIT_FAILED");
        assert!(
            err.message.contains("CALYX_LEDGER_SECRET_IN_PAYLOAD")
                || err.message.contains("secret-like")
                || err.message.contains("token-like secret"),
            "{err}"
        );
        assert!(
            batch_vault
                .read_cf_at(batch_vault.latest_seq(), ColumnFamily::Kv, &data_key)
                .expect("read refused data row")
                .is_none()
        );
        assert_eq!(
            verify_chain(&batch_vault)
                .expect("verify empty batch chain")
                .ledger_rows,
            0
        );
    }

    #[test]
    fn disk_tamper_reports_broken_seq_and_default_open_fails_closed() {
        let dir = test_dir("disk-tamper");
        fs::create_dir_all(&dir).expect("create durable vault dir");
        {
            let vault = AsterVault::new_durable(
                &dir,
                vault_id(),
                b"ledger-disk-tamper",
                VaultOptions::default(),
            )
            .expect("open durable vault");
            append_test_entry(&vault, b"first");
            append_test_entry(&vault, b"second");
            vault.flush().expect("flush durable vault");
        }

        let intact = verify_chain_vault_path(&dir).expect("verify intact physical ledger");
        assert_eq!(intact.status, "intact");
        assert_eq!(intact.count, 2);

        tamper_ledger_sst_value(&dir, 1);
        let broken = verify_chain_vault_path(&dir).expect("verify tampered physical ledger");
        assert_eq!(broken.status, "broken");
        assert_eq!(broken.at_seq, Some(1));
        assert_eq!(broken.quarantine_seq, Some(1));

        let open_err = AsterVault::new_durable(
            &dir,
            vault_id(),
            b"ledger-disk-tamper",
            VaultOptions::default(),
        )
        .expect_err("default durable open must fail closed on tampered ledger");
        assert!(
            matches!(
                open_err.code,
                "CALYX_LEDGER_CHAIN_BROKEN"
                    | "CALYX_LEDGER_CORRUPT"
                    | "CALYX_LEDGER_GROUP_COMMIT_FAILED"
            ),
            "{open_err}"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_commit_rejected_batch_reopens_with_neither_data_nor_ledger() {
        let dir = test_dir("same-commit-reject");
        fs::create_dir_all(&dir).expect("create durable vault dir");
        let key = b"astrolabe:same-commit-fsv".to_vec();
        {
            let vault = AsterVault::new_durable(
                &dir,
                vault_id(),
                b"ledger-same-commit",
                VaultOptions {
                    memtable_byte_cap: 1,
                    ..VaultOptions::default()
                },
            )
            .expect("open durable vault");
            let err = vault
                .write_cf_batch_with_ledger_entry(
                    [(
                        ColumnFamily::Kv,
                        key.clone(),
                        b"row too large for the injected memtable cap".to_vec(),
                    )],
                    EntryKind::Ingest,
                    SubjectId::Query(b"same-commit-fsv".to_vec()),
                    br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                    ActorId::Service("astrolabe-test".to_string()),
                )
                .expect_err("commit must be rejected before persisting rows");

            assert_eq!(err.code, "CALYX_BACKPRESSURE");
            assert!(
                vault
                    .read_cf_at(vault.latest_seq(), ColumnFamily::Kv, &key)
                    .expect("read rejected data row")
                    .is_none()
            );
            assert_eq!(
                verify_chain(&vault)
                    .expect("verify empty chain")
                    .ledger_rows,
                0
            );
        }

        let reopened = AsterVault::new_durable(
            &dir,
            vault_id(),
            b"ledger-same-commit",
            VaultOptions {
                read_only: true,
                restore_ledger_hook: false,
                selected_cfs: Some(vec![ColumnFamily::Kv, ColumnFamily::Ledger]),
                ..VaultOptions::default()
            },
        )
        .expect("reopen rejected vault");
        assert!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, &key)
                .expect("read reopened data row")
                .is_none()
        );
        assert_eq!(
            verify_chain(&reopened)
                .expect("verify reopened empty chain")
                .ledger_rows,
            0
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kill_after_wal_append_reopens_with_both_data_and_ledger() {
        let root = test_dir("kill-after-wal");
        let vault_dir = root.join("vault");
        let marker = root.join("after-wal.marker");
        fs::create_dir_all(&root).expect("create crash FSV root");

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("ledger_verify::tests::crash_after_wal_append_child")
            .arg("--nocapture")
            .env("ASTROLABE_CRASH_FSV_CHILD", "1")
            .env("ASTROLABE_CRASH_FSV_VAULT", &vault_dir)
            .env("CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER", &marker)
            .spawn()
            .expect("spawn crash FSV child");

        wait_for_marker_or_child_exit(&marker, &mut child);
        child.kill().expect("kill crash FSV child");
        let status = child.wait().expect("wait for crash FSV child");
        assert!(!status.success(), "child should be killed mid-commit");

        let marker_seq = fs::read_to_string(&marker)
            .expect("read crash marker")
            .trim()
            .parse::<u64>()
            .expect("marker seq");
        assert_eq!(marker_seq, 1);

        let reopened = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("reopen crashed vault");
        let data = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, CRASH_FSV_KEY)
            .expect("read recovered data row")
            .expect("data row recovered from WAL");
        assert_eq!(data, b"durable-before-process-kill");

        let chain = verify_chain(&reopened).expect("verify recovered ledger chain");
        assert_eq!(chain.status, "intact");
        assert_eq!(chain.ledger_rows, 1);

        let ledger = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Ledger, &ledger_key(0))
            .expect("read recovered ledger row")
            .expect("ledger row recovered from WAL");
        let entry = decode(&ledger).expect("decode recovered ledger row");
        assert_eq!(entry.kind, EntryKind::Ingest);
        assert!(matches!(
            entry.subject,
            SubjectId::Query(ref value) if value == b"crash-fsv"
        ));

        fs::remove_dir_all(&root).ok();
    }

    /// Toggleable disk-space probe for the disk-full recovery FSV (#60). The test
    /// flips `available` blocks between "all free" and "none free" to drive
    /// Calyx's disk-pressure guard across its high-water mark without a real
    /// filesystem quota -- no VHD and no admin rights, so it runs natively on
    /// Windows in a worktree.
    #[derive(Clone)]
    struct ToggleDiskProbe {
        blocks: u64,
        available: Arc<AtomicU64>,
    }

    impl DiskSpaceProbe for ToggleDiskProbe {
        fn sample(&self, _path: &Path) -> CalyxResult<DiskSample> {
            Ok(DiskSample {
                blocks: self.blocks,
                blocks_available: self.available.load(Ordering::SeqCst),
            })
        }
    }

    #[test]
    fn disk_full_write_fails_closed_and_vault_recovers_with_exact_ledger() {
        let root = test_dir("disk-full-recovery");
        let vault_dir = root.join("vault");
        fs::create_dir_all(&root).expect("create disk-full FSV root");

        // 100 blocks total; `available` starts full (all free). The guard rejects a
        // write once used_ratio (= 1 - available/total) reaches the high-water mark.
        let available = Arc::new(AtomicU64::new(100));
        let probe = ToggleDiskProbe {
            blocks: 100,
            available: Arc::clone(&available),
        };
        // high_water_ratio 0.85: available=0 -> used_ratio 1.0 >= 0.85 -> disk full;
        // available=100 -> used_ratio 0.0 -> writes admitted.
        let guard = DiskPressureGuard::with_probe(
            vault_dir.clone(),
            0.85,
            Arc::new(FixedClock::new(42)),
            Arc::new(probe),
        );
        let options = VaultOptions {
            disk_pressure_guard: Some(guard),
            ..VaultOptions::default()
        };

        let vault = AsterVault::new_durable(&vault_dir, vault_id(), b"ledger-disk-full", options)
            .expect("open durable vault with disk guard");

        // 1. Space free: a durable batch+ledger write commits.
        vault
            .write_cf_batch_with_ledger_entry(
                [(
                    ColumnFamily::Kv,
                    b"row-before".to_vec(),
                    b"v-before".to_vec(),
                )],
                EntryKind::Ingest,
                SubjectId::Query(b"before-full".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("write before disk-full commits");

        // 2. Disk full: the next write must fail closed BEFORE any WAL append, so it
        // leaves neither a data row nor a ledger entry (no torn write).
        available.store(0, Ordering::SeqCst);
        let err = vault
            .write_cf_batch_with_ledger_entry(
                [(
                    ColumnFamily::Kv,
                    b"row-during".to_vec(),
                    b"v-during".to_vec(),
                )],
                EntryKind::Ingest,
                SubjectId::Query(b"during-full".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect_err("write under disk pressure must fail closed");
        assert_eq!(err.code, "CALYX_DISK_PRESSURE");

        // 3. Recovery: space returns and a durable write commits again.
        available.store(100, Ordering::SeqCst);
        vault
            .write_cf_batch_with_ledger_entry(
                [(ColumnFamily::Kv, b"row-after".to_vec(), b"v-after".to_vec())],
                EntryKind::Ingest,
                SubjectId::Query(b"after-recovery".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("write after recovery commits");
        vault.flush().expect("flush recovered vault");
        drop(vault);

        // 4. Independent readback: reopen with a plain handle (no guard) and prove
        // the ledger chain is intact with EXACTLY the two committed entries -- the
        // disk-full-rejected write left no ledger gap and no orphaned data row.
        let reopened = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-disk-full",
            VaultOptions::default(),
        )
        .expect("reopen vault after disk-full episode");
        let chain = verify_chain(&reopened).expect("verify recovered chain");
        assert_eq!(chain.status, "intact");
        assert_eq!(chain.ledger_rows, 2);
        assert_eq!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, b"row-before")
                .expect("read row-before")
                .expect("row-before present"),
            b"v-before"
        );
        assert_eq!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, b"row-after")
                .expect("read row-after")
                .expect("row-after present"),
            b"v-after"
        );
        assert!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, b"row-during")
                .expect("read row-during")
                .is_none(),
            "the disk-full-rejected write must have persisted nothing"
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn kill_after_mvcc_commit_reopens_intact_chain_via_wal_replay() {
        // Ingest-stage crash matrix (#276): kill the writer at the
        // post-MVCC-commit / pre-checkpoint boundary. The batch is in the WAL
        // and MVCC memtable but the checkpoint manifest never advanced, so
        // recovery must WAL-replay it. FSV proves the reopened vault has the
        // data row and exactly one ledger entry with an intact chain.
        let root = test_dir("kill-after-mvcc");
        let vault_dir = root.join("vault");
        let marker = root.join("after-mvcc.marker");
        fs::create_dir_all(&root).expect("create crash FSV root");

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("ledger_verify::tests::crash_after_mvcc_commit_child")
            .arg("--nocapture")
            .env("ASTROLABE_CRASH_FSV_CHILD", "1")
            .env("ASTROLABE_CRASH_FSV_VAULT", &vault_dir)
            .env("CALYX_ASTER_CRASH_FSV_AFTER_MVCC_COMMIT_MARKER", &marker)
            .spawn()
            .expect("spawn crash FSV child");

        wait_for_marker_or_child_exit(&marker, &mut child);
        child.kill().expect("kill crash FSV child");
        let status = child.wait().expect("wait for crash FSV child");
        assert!(!status.success(), "child should be killed mid-commit");

        let marker_seq = fs::read_to_string(&marker)
            .expect("read crash marker")
            .trim()
            .parse::<u64>()
            .expect("marker seq");
        assert_eq!(marker_seq, 1);

        let reopened = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("reopen crashed vault");
        let data = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, CRASH_FSV_KEY)
            .expect("read recovered data row")
            .expect("data row recovered from WAL replay");
        assert_eq!(data, b"durable-before-process-kill");

        let chain = verify_chain(&reopened).expect("verify recovered ledger chain");
        assert_eq!(chain.status, "intact");
        assert_eq!(chain.ledger_rows, 1);

        let ledger = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Ledger, &ledger_key(0))
            .expect("read recovered ledger row")
            .expect("ledger row recovered from WAL replay");
        let entry = decode(&ledger).expect("decode recovered ledger row");
        assert_eq!(entry.kind, EntryKind::Ingest);
        // No partial state: exactly one ledger seq, no phantom second entry.
        assert!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Ledger, &ledger_key(1))
                .expect("read absent ledger seq 1")
                .is_none(),
            "recovery must not invent a second ledger entry"
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn kill_after_checkpoint_reopens_intact_chain_via_manifest() {
        // Ingest-stage crash matrix (#276): kill the writer at the
        // post-checkpoint / post-manifest-advance boundary. The batch's
        // durable-batch SSTs are written and the manifest has advanced, so
        // recovery reconciles the manifest + SSTs (checkpoint replay), a
        // distinct path from the WAL-replay case above. FSV proves the reopened
        // vault has the data row and exactly one ledger entry, chain intact.
        let root = test_dir("kill-after-checkpoint");
        let vault_dir = root.join("vault");
        let marker = root.join("after-checkpoint.marker");
        fs::create_dir_all(&root).expect("create crash FSV root");

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("ledger_verify::tests::crash_after_checkpoint_child")
            .arg("--nocapture")
            .env("ASTROLABE_CRASH_FSV_CHILD", "1")
            .env("ASTROLABE_CRASH_FSV_VAULT", &vault_dir)
            .env("CALYX_ASTER_CRASH_FSV_AFTER_CHECKPOINT_MARKER", &marker)
            .spawn()
            .expect("spawn crash FSV child");

        wait_for_marker_or_child_exit(&marker, &mut child);
        child.kill().expect("kill crash FSV child");
        let status = child.wait().expect("wait for crash FSV child");
        assert!(!status.success(), "child should be killed post-checkpoint");

        let marker_seq = fs::read_to_string(&marker)
            .expect("read crash marker")
            .trim()
            .parse::<u64>()
            .expect("marker seq");
        assert_eq!(marker_seq, 1);

        let reopened = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("reopen crashed vault");
        let data = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Kv, CRASH_FSV_KEY)
            .expect("read recovered data row")
            .expect("data row recovered from checkpoint");
        assert_eq!(data, b"durable-before-process-kill");

        let chain = verify_chain(&reopened).expect("verify recovered ledger chain");
        assert_eq!(chain.status, "intact");
        assert_eq!(chain.ledger_rows, 1);

        let ledger = reopened
            .read_cf_at(reopened.latest_seq(), ColumnFamily::Ledger, &ledger_key(0))
            .expect("read recovered ledger row")
            .expect("ledger row recovered from checkpoint");
        let entry = decode(&ledger).expect("decode recovered ledger row");
        assert_eq!(entry.kind, EntryKind::Ingest);
        // No partial state: exactly one ledger seq survives the checkpoint crash.
        assert!(
            reopened
                .read_cf_at(reopened.latest_seq(), ColumnFamily::Ledger, &ledger_key(1))
                .expect("read absent ledger seq 1")
                .is_none(),
            "recovery must not invent a second ledger entry"
        );

        fs::remove_dir_all(&root).ok();
    }

    /// Production-build guard control (#276). Crash failpoints must be
    /// impossible to arm in a shipped build. The build-time `compile_error!` in
    /// `calyx-aster` refuses to compile `--features crash-fsv` into a release
    /// build; this control proves the paired startup guard's decision fires on
    /// exactly the armed-and-optimized combination and permits every legitimate
    /// one, and that the live guard permits this debug/test build.
    #[test]
    fn crash_fsv_production_guard_refuses_armed_optimized_build() {
        use calyx_aster::vault::{
            CRASH_FSV_ARMED_IN_PRODUCTION, crash_fsv_guard_decision,
            guard_against_production_failpoints,
        };

        // Armed failpoints + optimized (release) + non-test => refuse, fail closed.
        let err = crash_fsv_guard_decision(true, true, false)
            .expect_err("an armed optimized production build must be refused");
        // The refusal carries the exact fail-closed wire code.
        assert_eq!(err.code, "CALYX_CRASH_FSV_ARMED_IN_PRODUCTION");
        assert_eq!(err.code, CRASH_FSV_ARMED_IN_PRODUCTION);
        assert!(
            !err.remediation.is_empty(),
            "guard error carries remediation"
        );

        // Every legitimate combination is permitted:
        //  - armed + debug build (the crash-FSV suite itself),
        crash_fsv_guard_decision(true, false, false).expect("armed debug build permitted");
        //  - armed + optimized + `cfg(test)` build (`cargo test --release`),
        crash_fsv_guard_decision(true, true, true).expect("armed test build permitted");
        //  - unarmed + optimized (a normal shipped build without the feature).
        crash_fsv_guard_decision(false, true, false).expect("unarmed production permitted");

        // The live wrapper, reading this build's real cfg (debug + crash-fsv
        // feature via dev-deps), must permit and never block a durable-vault open.
        guard_against_production_failpoints().expect("current debug/test build permitted");
    }

    #[test]
    fn durable_vault_concurrent_open_serializes_cross_process_writes() {
        let root = test_dir("concurrent-open");
        let vault_dir = root.join("vault");
        let ready = root.join("child.ready");
        let go = root.join("child.go");
        fs::create_dir_all(&root).expect("create concurrent-open FSV root");

        let parent_vault = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-concurrent-open",
            VaultOptions::default(),
        )
        .expect("open parent durable vault");
        append_marker_entry(&parent_vault, "parent-baseline");
        parent_vault.flush().expect("flush baseline");

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--ignored")
            .arg("--exact")
            .arg("ledger_verify::tests::concurrent_open_child_process")
            .arg("--nocapture")
            .env("ASTROLABE_CONCURRENT_OPEN_CHILD", "1")
            .env("ASTROLABE_CONCURRENT_OPEN_VAULT", &vault_dir)
            .env("ASTROLABE_CONCURRENT_OPEN_READY", &ready)
            .env("ASTROLABE_CONCURRENT_OPEN_GO", &go)
            .spawn()
            .expect("spawn concurrent-open child");

        wait_for_marker_or_child_exit(&ready, &mut child);
        fs::write(&go, b"go").expect("release concurrent-open child");

        for index in 0..CONCURRENT_PARENT_WRITES {
            append_marker_entry(&parent_vault, &format!("parent-{index:02}"));
            std::thread::sleep(Duration::from_millis(1));
        }

        let output = child
            .wait_with_output()
            .expect("wait for concurrent-open child");
        assert!(
            output.status.success(),
            "concurrent-open child failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        append_marker_entry(&parent_vault, "parent-after-child");
        parent_vault
            .flush()
            .expect("flush cross-process ledger rows");
        drop(parent_vault);

        let expected_count = 2 + CONCURRENT_PARENT_WRITES + CONCURRENT_CHILD_WRITES;
        let chain = verify_chain_vault_path(&vault_dir).expect("verify physical concurrent chain");
        assert_eq!(chain.status, "intact");
        assert_eq!(chain.ledger_rows, expected_count as u64);
        assert_eq!(chain.count, expected_count as u64);

        let reopened = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-concurrent-open",
            VaultOptions::default(),
        )
        .expect("reopen concurrent vault");
        let markers = ledger_markers(&reopened);
        assert_eq!(markers.len(), expected_count);
        assert!(markers.contains("parent-baseline"));
        assert!(markers.contains("parent-after-child"));
        for index in 0..CONCURRENT_PARENT_WRITES {
            assert!(markers.contains(&format!("parent-{index:02}")));
        }
        for index in 0..CONCURRENT_CHILD_WRITES {
            assert!(markers.contains(&format!("child-{index:02}")));
        }

        drop(reopened);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    #[ignore = "child process helper for kill_after_wal_append_reopens_with_both_data_and_ledger"]
    fn crash_after_wal_append_child() {
        if std::env::var_os("ASTROLABE_CRASH_FSV_CHILD").is_none() {
            return;
        }
        let vault_dir =
            std::env::var_os("ASTROLABE_CRASH_FSV_VAULT").expect("ASTROLABE_CRASH_FSV_VAULT");
        let vault = AsterVault::new_durable(
            PathBuf::from(vault_dir),
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("open child crash FSV vault");
        vault
            .write_cf_batch_with_ledger_entry(
                [(
                    ColumnFamily::Kv,
                    CRASH_FSV_KEY.to_vec(),
                    b"durable-before-process-kill".to_vec(),
                )],
                EntryKind::Ingest,
                SubjectId::Query(b"crash-fsv".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("crash failpoint should pause after WAL append");
        panic!("crash FSV failpoint did not pause");
    }

    #[test]
    #[ignore = "child process helper for kill_after_mvcc_commit_reopens_intact_chain_via_wal_replay"]
    fn crash_after_mvcc_commit_child() {
        if std::env::var_os("ASTROLABE_CRASH_FSV_CHILD").is_none() {
            return;
        }
        let vault_dir =
            std::env::var_os("ASTROLABE_CRASH_FSV_VAULT").expect("ASTROLABE_CRASH_FSV_VAULT");
        let vault = AsterVault::new_durable(
            PathBuf::from(vault_dir),
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("open child crash FSV vault");
        // The post-MVCC-commit failpoint parks inside this write, after the WAL
        // append and MVCC commit but before the checkpoint manifest advances.
        vault
            .write_cf_batch_with_ledger_entry(
                [(
                    ColumnFamily::Kv,
                    CRASH_FSV_KEY.to_vec(),
                    b"durable-before-process-kill".to_vec(),
                )],
                EntryKind::Ingest,
                SubjectId::Query(b"crash-fsv".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("crash failpoint should pause after MVCC commit");
        panic!("crash FSV failpoint did not pause");
    }

    #[test]
    #[ignore = "child process helper for kill_after_checkpoint_reopens_intact_chain_via_manifest"]
    fn crash_after_checkpoint_child() {
        if std::env::var_os("ASTROLABE_CRASH_FSV_CHILD").is_none() {
            return;
        }
        let vault_dir =
            std::env::var_os("ASTROLABE_CRASH_FSV_VAULT").expect("ASTROLABE_CRASH_FSV_VAULT");
        let vault = AsterVault::new_durable(
            PathBuf::from(vault_dir),
            vault_id(),
            b"ledger-crash-fsv",
            VaultOptions::default(),
        )
        .expect("open child crash FSV vault");
        // The write commits and stages the checkpoint; flush() writes the
        // durable-batch SSTs and advances the manifest, then the post-checkpoint
        // failpoint parks the process AFTER the manifest advance.
        vault
            .write_cf_batch_with_ledger_entry(
                [(
                    ColumnFamily::Kv,
                    CRASH_FSV_KEY.to_vec(),
                    b"durable-before-process-kill".to_vec(),
                )],
                EntryKind::Ingest,
                SubjectId::Query(b"crash-fsv".to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("write commits before checkpoint flush");
        vault
            .flush()
            .expect("crash failpoint should pause after checkpoint manifest advance");
        panic!("crash FSV checkpoint failpoint did not pause");
    }

    #[test]
    #[ignore = "child process helper for durable_vault_concurrent_open_serializes_cross_process_writes"]
    fn concurrent_open_child_process() {
        if std::env::var_os("ASTROLABE_CONCURRENT_OPEN_CHILD").is_none() {
            return;
        }
        let vault_dir = PathBuf::from(
            std::env::var_os("ASTROLABE_CONCURRENT_OPEN_VAULT")
                .expect("ASTROLABE_CONCURRENT_OPEN_VAULT"),
        );
        let ready = PathBuf::from(
            std::env::var_os("ASTROLABE_CONCURRENT_OPEN_READY")
                .expect("ASTROLABE_CONCURRENT_OPEN_READY"),
        );
        let go = PathBuf::from(
            std::env::var_os("ASTROLABE_CONCURRENT_OPEN_GO").expect("ASTROLABE_CONCURRENT_OPEN_GO"),
        );
        let child_vault = AsterVault::new_durable(
            &vault_dir,
            vault_id(),
            b"ledger-concurrent-open",
            VaultOptions::default(),
        )
        .expect("open child durable vault");
        fs::write(&ready, b"ready").expect("write child ready marker");
        wait_for_file(&go, "concurrent-open go marker");
        for index in 0..CONCURRENT_CHILD_WRITES {
            append_marker_entry(&child_vault, &format!("child-{index:02}"));
            std::thread::sleep(Duration::from_millis(2));
        }
        child_vault.flush().expect("flush child durable vault");
    }

    fn vault() -> AsterVault<FixedClock> {
        AsterVault::with_clock(vault_id(), b"ledger-verify-test", FixedClock::new(42))
    }

    fn append_test_entry<C>(vault: &AsterVault<C>, subject: &[u8])
    where
        C: Clock,
    {
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(subject.to_vec()),
                br#"{"schema":"test-ledger-v1"}"#.to_vec(),
                ActorId::Service("astrolabe-test".to_string()),
            )
            .expect("append ledger entry");
    }

    #[test]
    fn janitor_slice_verifies_bounded_suffix_without_full_rewalk() {
        // Ten entries, budget 3: each slice re-hashes at most 3 entries and the
        // checkpoint advances, so no single pass rewalks the whole ledger (#96).
        let vault = vault();
        for index in 0..10 {
            append_test_entry(&vault, format!("entry-{index}").as_bytes());
        }

        let mut checkpoint = JanitorCheckpoint::GENESIS;
        let mut total = 0_u64;
        let mut passes = 0;
        loop {
            let report = verify_chain_slice(&vault, checkpoint, Some(3)).expect("janitor slice");
            assert_eq!(report.status, "intact");
            assert!(
                report.entries_verified <= 3,
                "slice must respect the budget: {report:?}"
            );
            total += report.entries_verified;
            checkpoint = report.checkpoint;
            passes += 1;
            if report.caught_up {
                break;
            }
            assert!(passes < 20, "janitor did not converge");
        }
        assert_eq!(total, 10, "every entry verified exactly once across slices");
        assert_eq!(checkpoint.verified_through, 10);

        // A caught-up pass does zero work rather than rewalking.
        let idle = verify_chain_slice(&vault, checkpoint, Some(3)).expect("idle slice");
        assert!(idle.caught_up);
        assert_eq!(idle.entries_verified, 0);
    }

    #[test]
    fn janitor_slice_fails_closed_on_tampered_ledger_and_does_not_advance() {
        // Real persisted bytes: append six entries, verify the first three via a
        // clean slice (advancing the checkpoint), then flip a byte in a persisted
        // ledger row and prove the next slice over that range reports broken at
        // the exact seq and parks the checkpoint before the corruption.
        let vault = vault();
        for index in 0..6 {
            append_test_entry(&vault, format!("entry-{index}").as_bytes());
        }
        let clean = verify_chain_slice(&vault, JanitorCheckpoint::GENESIS, Some(3))
            .expect("clean first slice");
        assert_eq!(clean.status, "intact");
        assert_eq!(clean.checkpoint.verified_through, 3);

        // Independent readback of the persisted ledger row, then a one-byte flip.
        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(4))
            .expect("read persisted ledger row")
            .expect("ledger row 4 exists");
        tampered[20] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(4), tampered)
            .expect("persist tampered ledger row");

        let report = verify_chain_slice(&vault, clean.checkpoint, Some(3))
            .expect("janitor slice over tampered range");
        assert_eq!(report.status, "broken");
        assert_eq!(report.at_seq, Some(4));
        assert_eq!(
            report.checkpoint, clean.checkpoint,
            "checkpoint must not advance past detected corruption"
        );
        assert!(report.remediation.is_some());
    }

    #[test]
    fn janitor_budget_outside_knob_bounds_is_refused() {
        let vault = vault();
        append_test_entry(&vault, b"entry");
        let err = verify_chain_slice(&vault, JanitorCheckpoint::GENESIS, Some(0))
            .expect_err("zero budget must refuse");
        assert_eq!(err.code(), Some(ASTRO_FSV_JANITOR_BUDGET_INVALID));
        // The registry default is accepted when no override is supplied.
        let ok = verify_chain_slice(&vault, JanitorCheckpoint::GENESIS, None)
            .expect("default budget accepted");
        assert!(ok.is_intact());
    }

    fn secret_payload() -> Vec<u8> {
        br#"{"api_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
            .to_vec()
    }

    fn append_marker_entry<C>(vault: &AsterVault<C>, marker: &str)
    where
        C: Clock,
    {
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema": "astrolabe-concurrent-open-v1",
            "marker": marker,
        }))
        .expect("encode concurrent-open marker payload");
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Query(marker.as_bytes().to_vec()),
                payload,
                ActorId::Service("astrolabe-concurrent-open-test".to_string()),
            )
            .expect("append concurrent-open marker entry");
    }

    fn ledger_markers<C>(vault: &AsterVault<C>) -> BTreeSet<String>
    where
        C: Clock,
    {
        vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)
            .expect("scan Ledger CF")
            .into_iter()
            .filter_map(|(_, bytes)| {
                let entry = decode(&bytes).expect("decode Ledger CF row");
                let value: serde_json::Value =
                    serde_json::from_slice(&entry.payload).expect("decode ledger payload JSON");
                (value.get("schema").and_then(serde_json::Value::as_str)
                    == Some("astrolabe-concurrent-open-v1"))
                .then(|| {
                    value
                        .get("marker")
                        .and_then(serde_json::Value::as_str)
                        .expect("marker string")
                        .to_string()
                })
            })
            .collect()
    }

    fn vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().expect("vault id")
    }

    fn test_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "astrolabe-ledger-verify-{name}-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        dir
    }

    fn tamper_ledger_sst_value(vault_dir: &Path, seq: u64) {
        let wanted_key = ledger_key(seq);
        let ledger_dir = vault_dir.join("cf").join(ColumnFamily::Ledger.name());
        for entry in fs::read_dir(&ledger_dir).expect("read ledger dir") {
            let path = entry.expect("ledger dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("sst") {
                continue;
            }
            let mut bytes = fs::read(&path).expect("read ledger sst");
            let Some((key_start, value_start, value_len)) = first_sst_record_offsets(&bytes) else {
                continue;
            };
            let key = &bytes[key_start..value_start];
            if key != wanted_key.as_slice() {
                continue;
            }
            assert!(value_len > 17, "ledger value too short");
            bytes[value_start + 16] ^= 0xff;
            rewrite_sst_crcs(&mut bytes, key_start, value_start, value_len);
            fs::write(&path, bytes).expect("write tampered ledger sst");
            return;
        }
        panic!(
            "ledger SST for seq {seq} not found in {}",
            ledger_dir.display()
        );
    }

    fn first_sst_record_offsets(bytes: &[u8]) -> Option<(usize, usize, usize)> {
        const HEADER_LEN: usize = 32;
        const RECORD_HEADER_LEN: usize = 12;
        if bytes.len() < HEADER_LEN + RECORD_HEADER_LEN {
            return None;
        }
        let record = &bytes[HEADER_LEN..HEADER_LEN + RECORD_HEADER_LEN];
        let key_len = u32::from_le_bytes(record[0..4].try_into().expect("key len")) as usize;
        let value_len = u32::from_le_bytes(record[4..8].try_into().expect("value len")) as usize;
        let key_start = HEADER_LEN + RECORD_HEADER_LEN;
        let value_start = key_start + key_len;
        let value_end = value_start + value_len;
        (value_end <= bytes.len()).then_some((key_start, value_start, value_len))
    }

    fn rewrite_sst_crcs(bytes: &mut [u8], key_start: usize, value_start: usize, value_len: usize) {
        const HEADER_LEN: usize = 32;
        let value_end = value_start + value_len;
        let mut record_hasher = crc32fast::Hasher::new();
        record_hasher.update(&bytes[key_start..value_start]);
        record_hasher.update(&bytes[value_start..value_end]);
        bytes[HEADER_LEN + 8..HEADER_LEN + 12]
            .copy_from_slice(&record_hasher.finalize().to_le_bytes());

        let mut body_hasher = crc32fast::Hasher::new();
        body_hasher.update(&bytes[HEADER_LEN..]);
        bytes[28..32].copy_from_slice(&body_hasher.finalize().to_le_bytes());
    }

    fn wait_for_marker_or_child_exit(marker: &Path, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if marker.exists() {
                return;
            }
            if let Some(status) = child.try_wait().expect("poll crash FSV child") {
                panic!("crash FSV child exited before marker: {status}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        child.kill().ok();
        panic!(
            "timed out waiting for crash FSV marker {}",
            marker.display()
        );
    }

    fn wait_for_file(path: &Path, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for {label}: {}", path.display());
    }
}
