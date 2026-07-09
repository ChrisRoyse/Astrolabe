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

fn verify_store_chain(store: &dyn LedgerCfStore) -> IngestResult<VerifyChainReport> {
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

struct AsterVaultLedgerStore<'a, C> {
    vault: &'a AsterVault<C>,
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

fn hex_lower(bytes: &[u8]) -> String {
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
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{FixedClock, VaultId};
    use calyx_ledger::{ActorId, EntryKind, SubjectId};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
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
