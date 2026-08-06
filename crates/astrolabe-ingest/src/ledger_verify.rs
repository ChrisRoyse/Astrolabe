use std::collections::BTreeMap;
use std::path::Path;

use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::ledger_view::{AsterLedgerCfStore, parse_aster_ledger_seq};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{CalyxError, Clock, Result as CalyxResult};
use calyx_ledger::{
    LedgerCfStore, LedgerHeadAnchor, LedgerRow, VerifyResult, decode,
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

/// Verifies the physical Ledger rows and external head anchor through one
/// already-open read-only vault snapshot.
///
/// The vault retains the shared durable commit lock for this complete operation;
/// no path reopen or lock upgrade occurs between copying the head and verifying
/// the rows.
pub fn verify_chain_and_head<C>(
    vault: &AsterVault<C>,
) -> IngestResult<(VerifyChainReport, Option<LedgerHeadAnchor>)>
where
    C: Clock,
{
    let store = vault.retained_read_only_ledger_store()?;
    let anchor = store.head_anchor()?;
    let report = verify_store_chain(&store)?;
    Ok((report, anchor))
}

/// Opens a physical durable Aster ledger view and verifies its hash chain.
pub fn verify_chain_vault_path(vault_dir: impl AsRef<Path>) -> IngestResult<VerifyChainReport> {
    Ok(verify_chain_and_head_vault_path(vault_dir)?.0)
}

/// Opens one physical durable Ledger snapshot and returns both its verified
/// chain report and the exact external head anchor copied under the same commit
/// lock. Callers that need a current `(height, tip hash)` must use this paired
/// read instead of combining a historical subsystem checkpoint with the live log.
pub fn verify_chain_and_head_vault_path(
    vault_dir: impl AsRef<Path>,
) -> IngestResult<(VerifyChainReport, Option<LedgerHeadAnchor>)> {
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
            return Ok((empty_report(), None));
        }
        Err(error) => return Err(error.into()),
    };
    let anchor = store.head_anchor()?;
    let report = verify_store_chain(&store)?;
    Ok((report, anchor))
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
