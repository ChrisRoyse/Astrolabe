//! Public decoded-ledger-scan-by-subject API (#284).
//!
//! `get_provenance(mode="lineage")` must be built from the real persisted ledger,
//! not from row-sink JSON metadata. The honest lineage builder
//! (`astrolabe_provenance::build_symbol_lineage`) consumes *decoded ledger rows*
//! scoped to one subject; this module is the live scan that produces those rows
//! from a physically opened Aster vault.
//!
//! The scan turns real persisted `ledger` column-family bytes into
//! [`LedgerScanRow`]s — sequence, lower-hex entry hash (the chain pointer), stable
//! kind label, canonical subject key, and a deterministic summary rendered only
//! from persisted fields. It **never fabricates a row**: it fails closed on a
//! non-intact chain and on any row it cannot decode, rather than serving lineage
//! that reads as verified over a gap.

use std::path::Path;

use calyx_aster::ledger_view::AsterLedgerCfStore;
use calyx_aster::vault::AsterVault;
use calyx_core::Clock;
use calyx_ledger::{ActorId, LedgerCfStore, LedgerEntry, SubjectId, decode};

use crate::ledger_verify::{AsterVaultLedgerStore, hex_lower, verify_store_chain};
use crate::registry::{IngestError, IngestResult};

/// Refusal code: a subject-scoped lineage scan was requested with an empty
/// subject key. Fail closed rather than scan for "every subject" under an
/// operation whose contract is one subject.
pub const ASTRO_LEDGER_SCAN_SUBJECT_EMPTY: &str = "ASTRO_LEDGER_SCAN_SUBJECT_EMPTY";
/// Refusal code: the ledger hash-chain is not intact over the checked range, so
/// no lineage row can be trusted. The scan refuses to serve rows scoped to a
/// subject when the chain they hang from is broken or corrupt.
pub const ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT: &str = "ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT";
/// Refusal code: the chain verified intact yet a persisted ledger row could not
/// be decoded or its encoded sequence disagreed with its key. This is an
/// internal-consistency violation; fail closed rather than drop the row (which
/// would silently invent a gap in the lineage).
pub const ASTRO_LEDGER_SCAN_ROW_CORRUPT: &str = "ASTRO_LEDGER_SCAN_ROW_CORRUPT";

const SCAN_CHAIN_REMEDIATION: &str = "Run astrolabe verify --deep, quarantine the reported ledger sequence, and repair or re-import the ledger before requesting subject lineage.";
const SCAN_ROW_REMEDIATION: &str = "The ledger chain verified intact but a row failed to decode; quarantine the vault and re-import the ledger from source bytes before requesting subject lineage.";
const SCAN_SUBJECT_REMEDIATION: &str = "Pass the canonical subject key (for example \"cx:<hex>\") whose lineage you want; refusing rather than scanning for an empty subject.";

/// One decoded, subject-scoped ledger row in the exact shape the provenance
/// lineage builder (`astrolabe_provenance::build_symbol_lineage`) consumes.
///
/// Every field is derived only from persisted ledger bytes — `entry_hash` is the
/// lower-hex of the row's real chain-pointer hash, `subject` is the canonical
/// key of the row's persisted [`SubjectId`], and `summary` is a deterministic
/// rendering of the persisted kind and actor. The server maps these one-to-one
/// onto `astrolabe_provenance::LedgerScanRow` before building lineage.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LedgerScanRow {
    /// Ledger sequence of the persisted row (the node's ordinal).
    pub seq: u64,
    /// Lower-hex of the persisted entry hash; the node's provenance pointer.
    pub entry_hash: String,
    /// Stable ledger entry kind label (for example `ingest`, `measure`, `guard`).
    pub kind: String,
    /// Canonical subject key the row is scoped to (see [`ledger_subject_key`]).
    pub subject: String,
    /// Deterministic human-readable summary derived from persisted fields.
    pub summary: String,
}

/// Renders a persisted [`SubjectId`] to a canonical, collision-free subject key.
///
/// Every variant is tagged so a `Cx` id can never alias a `Query` payload with
/// the same bytes, and the value is derived purely from the persisted wire bytes:
/// `cx`/`lens` ids render as their stable lower-hex, and the byte-carrying
/// variants render as tagged lower-hex. This is both the value stamped into
/// [`LedgerScanRow::subject`] and the key a caller passes to scope a scan, so the
/// two always compare equal for the same underlying subject.
pub fn ledger_subject_key(subject: &SubjectId) -> String {
    match subject {
        SubjectId::Cx(id) => format!("cx:{id}"),
        SubjectId::Lens(id) => format!("lens:{id}"),
        SubjectId::Kernel(bytes) => format!("kernel:{}", hex_lower(bytes)),
        SubjectId::Guard(bytes) => format!("guard:{}", hex_lower(bytes)),
        SubjectId::Query(bytes) => format!("query:{}", hex_lower(bytes)),
    }
}

/// Scans and decodes the persisted ledger of an opened Aster vault, returning the
/// rows scoped to `subject` in ascending sequence order.
///
/// This is the honest live source for `get_provenance(mode="lineage")`: the rows
/// are decoded from the physical `ledger` column family and each carries its real
/// persisted entry hash as its provenance pointer.
///
/// Fails **closed**, never fabricating a row:
/// - [`ASTRO_LEDGER_SCAN_SUBJECT_EMPTY`] when `subject` is empty/whitespace;
/// - [`ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT`] when the ledger hash-chain is broken
///   or corrupt over the checked range (a tampered row is caught here);
/// - [`ASTRO_LEDGER_SCAN_ROW_CORRUPT`] when a row cannot be decoded or its
///   encoded sequence disagrees with its key.
///
/// An intact ledger with no row for `subject` returns an **empty** vector: the
/// absence of history is a truthful answer, and the downstream lineage builder
/// fails closed on it rather than this scan inventing a node.
pub fn scan_subject_ledger_rows<C>(
    vault: &AsterVault<C>,
    subject: &str,
) -> IngestResult<Vec<LedgerScanRow>>
where
    C: Clock,
{
    let store = AsterVaultLedgerStore { vault };
    scan_subject_rows_from_store(&store, subject)
}

/// Opens a physical durable Aster ledger view and scans it for `subject`.
///
/// Mirrors [`crate::verify_chain_vault_path`]: a vault directory whose ledger has
/// never been initialized is treated as an empty ledger (no rows for any
/// subject), not as an error.
pub fn scan_subject_ledger_rows_vault_path(
    vault_dir: impl AsRef<Path>,
    subject: &str,
) -> IngestResult<Vec<LedgerScanRow>> {
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
            return scan_empty_subject(subject);
        }
        Err(error) => return Err(error.into()),
    };
    scan_subject_rows_from_store(&store, subject)
}

/// Validates a subject key without a ledger present, so the empty-ledger path
/// still fails closed on an empty subject rather than returning `[]`.
fn scan_empty_subject(subject: &str) -> IngestResult<Vec<LedgerScanRow>> {
    require_non_empty_subject(subject)?;
    Ok(Vec::new())
}

fn require_non_empty_subject(subject: &str) -> IngestResult<&str> {
    let trimmed = subject.trim();
    if trimmed.is_empty() {
        return Err(IngestError::refused(
            ASTRO_LEDGER_SCAN_SUBJECT_EMPTY,
            "subject-scoped ledger lineage scan requires a non-empty subject key",
            SCAN_SUBJECT_REMEDIATION,
        ));
    }
    Ok(trimmed)
}

fn scan_subject_rows_from_store(
    store: &dyn LedgerCfStore,
    subject: &str,
) -> IngestResult<Vec<LedgerScanRow>> {
    let subject = require_non_empty_subject(subject)?;

    // Fail closed on chain gaps: a subject's lineage is only trustworthy when the
    // chain the rows hang from is intact over the whole checked range. A tampered
    // or severed row is reported here, before any row is served.
    let report = verify_store_chain(store)?;
    if !report.is_intact() {
        return Err(IngestError::refused(
            ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT,
            format!(
                "ledger chain is {status} at seq {at_seq}; refusing to serve subject lineage rows from a non-intact chain",
                status = report.status,
                at_seq = report
                    .at_seq
                    .map_or_else(|| "unknown".to_string(), |seq| seq.to_string()),
            ),
            SCAN_CHAIN_REMEDIATION,
        ));
    }

    let mut rows: Vec<LedgerScanRow> = Vec::new();
    for row in store.scan()? {
        let entry = decode(&row.bytes).map_err(|err| {
            IngestError::refused(
                ASTRO_LEDGER_SCAN_ROW_CORRUPT,
                format!("ledger row at seq {} failed to decode: {err}", row.seq),
                SCAN_ROW_REMEDIATION,
            )
        })?;
        if entry.seq != row.seq {
            return Err(IngestError::refused(
                ASTRO_LEDGER_SCAN_ROW_CORRUPT,
                format!(
                    "ledger key seq {} does not match encoded seq {}",
                    row.seq, entry.seq
                ),
                SCAN_ROW_REMEDIATION,
            ));
        }
        let key = ledger_subject_key(&entry.subject);
        if key == subject {
            rows.push(LedgerScanRow {
                seq: entry.seq,
                entry_hash: hex_lower(&entry.entry_hash),
                kind: entry.kind.as_str().to_string(),
                subject: key,
                summary: summarize_entry(&entry),
            });
        }
    }
    rows.sort_by_key(|row| row.seq);
    Ok(rows)
}

/// Renders a deterministic lineage-node summary from persisted entry fields only.
fn summarize_entry(entry: &LedgerEntry) -> String {
    format!(
        "{} entry by {}",
        entry.kind.as_str(),
        actor_description(&entry.actor)
    )
}

fn actor_description(actor: &ActorId) -> String {
    match actor {
        ActorId::Agent(name) => format!("agent {name}"),
        ActorId::Service(name) => format!("service {name}"),
        ActorId::System => "system".to_string(),
    }
}

/// Reads the persisted ledger row at `seq` straight from an opened vault and
/// returns its canonical `(entry_hash_hex, subject_key)` — an independent decode
/// path used by FSV tests to prove [`scan_subject_ledger_rows`] matches bytes.
#[cfg(test)]
pub(crate) fn read_row_identity<C>(vault: &AsterVault<C>, seq: u64) -> Option<(String, String)>
where
    C: Clock,
{
    use calyx_aster::cf::{ColumnFamily, ledger_key};

    let bytes = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(seq))
        .expect("read persisted ledger row")?;
    let entry = decode(&bytes).expect("decode persisted ledger row");
    Some((
        hex_lower(&entry.entry_hash),
        ledger_subject_key(&entry.subject),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use calyx_aster::cf::{ColumnFamily, ledger_key};
    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{CxId, FixedClock, VaultId};
    use calyx_ledger::{ActorId, EntryKind, SubjectId};
    use std::fs;
    use std::path::PathBuf;

    fn vault_id() -> VaultId {
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().expect("vault id")
    }

    fn vault() -> AsterVault<FixedClock> {
        AsterVault::with_clock(vault_id(), b"ledger-scan-test", FixedClock::new(7))
    }

    fn cx(seed: u8) -> CxId {
        CxId::from_bytes([seed; 16])
    }

    fn append_cx<C: Clock>(vault: &AsterVault<C>, subject: CxId, marker: &str) {
        let payload =
            format!("{{\"schema\":\"astrolabe-lineage-test-v1\",\"marker\":\"{marker}\"}}");
        vault
            .append_ledger_entry(
                EntryKind::Ingest,
                SubjectId::Cx(subject),
                payload.into_bytes(),
                ActorId::Service("astrolabe-scan-test".to_string()),
            )
            .expect("append cx ledger entry");
    }

    fn test_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "astrolabe-ledger-scan-{name}-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn subject_key_is_tagged_and_collision_free() {
        // Same 16 bytes under Cx vs a Query payload must never alias.
        let bytes = [0xAB; 16];
        assert_eq!(
            ledger_subject_key(&SubjectId::Cx(CxId::from_bytes(bytes))),
            format!("cx:{}", cx(0xAB))
        );
        assert_ne!(
            ledger_subject_key(&SubjectId::Cx(CxId::from_bytes(bytes))),
            ledger_subject_key(&SubjectId::Query(bytes.to_vec()))
        );
        assert_eq!(
            ledger_subject_key(&SubjectId::Query(vec![0x01, 0x0f])),
            "query:010f"
        );
    }

    #[test]
    fn scan_returns_subject_scoped_rows_in_seq_order_with_persisted_hashes() {
        // Boundary: two subjects interleaved (A at seq 0,2,4; B at seq 1,3). The
        // scan must return exactly A's three rows in ascending seq order, and each
        // row's entry_hash must match an independent readback of the persisted
        // ledger bytes (FSV).
        let vault = vault();
        let a = cx(0xA1);
        let b = cx(0xB2);
        append_cx(&vault, a, "a0"); // seq 0
        append_cx(&vault, b, "b0"); // seq 1
        append_cx(&vault, a, "a1"); // seq 2
        append_cx(&vault, b, "b1"); // seq 3
        append_cx(&vault, a, "a2"); // seq 4

        let subject = ledger_subject_key(&SubjectId::Cx(a));
        let rows = scan_subject_ledger_rows(&vault, &subject).expect("scan subject a");

        assert_eq!(
            rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![0, 2, 4],
            "only subject A's seqs, ascending"
        );
        for row in &rows {
            assert_eq!(row.subject, subject, "every row scoped to A");
            assert_eq!(row.kind, "ingest");
            assert!(!row.entry_hash.is_empty());
            assert_eq!(row.summary, "ingest entry by service astrolabe-scan-test");

            // FSV: independent decode path reads the persisted row and must yield
            // the same entry-hash pointer and subject key the scan returned.
            let (persisted_hash, persisted_subject) =
                read_row_identity(&vault, row.seq).expect("persisted ledger row exists");
            assert_eq!(
                persisted_hash, row.entry_hash,
                "scan entry_hash must equal persisted bytes at seq {}",
                row.seq
            );
            assert_eq!(persisted_subject, row.subject);
        }

        // Subject B is disjoint: scanning it returns only B's two rows.
        let subject_b = ledger_subject_key(&SubjectId::Cx(b));
        let rows_b = scan_subject_ledger_rows(&vault, &subject_b).expect("scan subject b");
        assert_eq!(rows_b.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn durable_path_and_vault_scans_agree_after_reopen() {
        // Dual-path within ingest: append + flush + drop, then scan the physical
        // vault dir AND a freshly reopened durable vault; both must produce the
        // byte-identical row set read back from fsync'd ledger bytes.
        let dir = test_dir("durable-agree");
        fs::create_dir_all(&dir).expect("create durable vault dir");
        let a = cx(0xC3);
        {
            let vault = AsterVault::new_durable(
                &dir,
                vault_id(),
                b"ledger-scan-durable",
                VaultOptions::default(),
            )
            .expect("open durable vault");
            append_cx(&vault, a, "d0");
            append_cx(&vault, cx(0xD4), "noise");
            append_cx(&vault, a, "d1");
            vault.flush().expect("flush durable vault");
        }

        let subject = ledger_subject_key(&SubjectId::Cx(a));
        let path_rows =
            scan_subject_ledger_rows_vault_path(&dir, &subject).expect("scan physical vault dir");
        assert_eq!(
            path_rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![0, 2],
            "subject A at seq 0 and 2 across the reopened ledger"
        );

        let reopened = AsterVault::new_durable(
            &dir,
            vault_id(),
            b"ledger-scan-durable",
            VaultOptions::default(),
        )
        .expect("reopen durable vault");
        let vault_rows =
            scan_subject_ledger_rows(&reopened, &subject).expect("scan reopened vault");
        assert_eq!(vault_rows, path_rows, "both scan paths agree byte-for-byte");

        // FSV: independent read_cf_at decode of each persisted seq matches the row.
        for row in &vault_rows {
            let bytes = reopened
                .read_cf_at(
                    reopened.latest_seq(),
                    ColumnFamily::Ledger,
                    &ledger_key(row.seq),
                )
                .expect("read persisted ledger row")
                .expect("ledger row exists");
            let entry = decode(&bytes).expect("decode persisted ledger row");
            assert_eq!(hex_lower(&entry.entry_hash), row.entry_hash);
            assert_eq!(ledger_subject_key(&entry.subject), row.subject);
        }

        drop(reopened);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_ledger_and_unmatched_subject_return_no_rows() {
        // Edge (empty): an intact but empty ledger has no lineage for any subject.
        let empty = vault();
        let subject = ledger_subject_key(&SubjectId::Cx(cx(0x11)));
        assert!(
            scan_subject_ledger_rows(&empty, &subject)
                .expect("empty scan")
                .is_empty(),
            "empty ledger yields no rows (downstream builder fails closed on it)"
        );

        // A populated ledger scanned for an absent subject also returns [].
        let vault = vault();
        append_cx(&vault, cx(0x22), "present");
        let absent = ledger_subject_key(&SubjectId::Cx(cx(0x33)));
        assert!(
            scan_subject_ledger_rows(&vault, &absent)
                .expect("absent-subject scan")
                .is_empty()
        );
    }

    #[test]
    fn empty_subject_key_is_refused() {
        // Edge (invalid format): an empty/whitespace subject key fails closed.
        let vault = vault();
        append_cx(&vault, cx(0x44), "present");
        for bad in ["", "   ", "\t"] {
            let err = scan_subject_ledger_rows(&vault, bad).expect_err("empty subject refused");
            assert_eq!(err.code(), Some(ASTRO_LEDGER_SCAN_SUBJECT_EMPTY));
            assert!(err.remediation().is_some());
        }
    }

    #[test]
    fn tampered_ledger_row_fails_closed_never_serving_rows() {
        // Edge (corrupt): flip a byte in a persisted ledger row, then prove the
        // subject scan refuses fail-closed rather than serving a lineage row that
        // hangs from a broken chain.
        let vault = vault();
        let a = cx(0x55);
        append_cx(&vault, a, "t0"); // seq 0
        append_cx(&vault, a, "t1"); // seq 1
        append_cx(&vault, a, "t2"); // seq 2

        let subject = ledger_subject_key(&SubjectId::Cx(a));
        // Before tamper: three intact rows are served.
        assert_eq!(
            scan_subject_ledger_rows(&vault, &subject)
                .expect("pre-tamper scan")
                .len(),
            3
        );

        // Independent readback of the persisted row, one-byte flip, persist back.
        let mut tampered = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(1))
            .expect("read persisted ledger row")
            .expect("ledger row 1 exists");
        tampered[16] ^= 0xff;
        vault
            .write_cf(ColumnFamily::Ledger, ledger_key(1), tampered)
            .expect("persist tampered ledger row");

        let err =
            scan_subject_ledger_rows(&vault, &subject).expect_err("tampered chain must refuse");
        assert_eq!(err.code(), Some(ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT));
        assert!(
            err.to_string().contains("seq 1"),
            "refusal names the tampered seq: {err}"
        );
        assert!(err.remediation().is_some());
    }
}
