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
