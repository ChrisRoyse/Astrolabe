//! Durable two-store transaction for index-time Assay signal cards (#885).
//!
//! SQLite cannot atomically commit an external append-only NDJSON file. The
//! protocol therefore publishes a FULL-synchronous prepared marker first while
//! the ledger's exact OS file lock is retained, syncs and read-verifies one
//! ledger batch, then commits every public card row plus the committed marker in
//! one SQLite transaction. Readers serve only a committed, hash-consistent state.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};

use super::*;

pub(crate) const SIGNAL_CARD_TRANSACTION_SCHEMA: &str =
    "astrolabe.assay_signal_card_transaction.v1";
const SIGNAL_CARD_TRANSACTION_SUFFIX: &str = "assay_signal_card_transaction";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignalCardBackendIdentity {
    provider: String,
    executor: String,
    forge_status: String,
}

impl SignalCardBackendIdentity {
    pub(crate) fn shipping_cpu() -> Self {
        Self {
            provider: "astrolabe-assay".to_string(),
            executor: "cpu".to_string(),
            forge_status: "not_commissioned".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignalCardBinding {
    axis: String,
    input_fingerprint: String,
    card_sha256: String,
    config_key: String,
    config_value_sha256: String,
    ledger_seq: u64,
    ledger_entry_hash: String,
    ledger_line: astrolabe_assay::AssayCardLineReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignalCardLedgerState {
    path: String,
    prior_file_bytes: u64,
    prior_file_blake3: String,
    file_bytes: Option<u64>,
    file_blake3: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignalCardTransactionMarker {
    schema: String,
    state: String,
    transaction_id: String,
    project: String,
    vault_id: String,
    panel_version: u32,
    base_seq: u64,
    produced_at: u64,
    backend: SignalCardBackendIdentity,
    cards: Vec<SignalCardBinding>,
    ledger: SignalCardLedgerState,
}

#[derive(Debug, Clone)]
struct SignalCardConfigRow {
    key: String,
    value: String,
}

#[derive(Debug)]
pub(crate) struct SignalCardTransactionPlan {
    prepared: SignalCardTransactionMarker,
    rows: Vec<SignalCardConfigRow>,
}

pub(crate) struct SignalCardTransactionContext<'a> {
    pub(crate) project: &'a str,
    pub(crate) vault_id: VaultId,
    pub(crate) panel_version: u32,
    pub(crate) base_seq: u64,
    pub(crate) produced_at: u64,
    pub(crate) backend: SignalCardBackendIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalCardPrepareDisposition {
    PreparedWritten,
    PreparedResumed,
    AlreadyCommitted,
}

#[derive(Debug)]
pub(crate) struct CommittedSignalCardState {
    pub(crate) marker: Value,
    pub(crate) rows: Vec<(String, String)>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn marker_identity(marker: &SignalCardTransactionMarker) -> Value {
    json!({
        "schema": marker.schema,
        "project": marker.project,
        "vault_id": marker.vault_id,
        "panel_version": marker.panel_version,
        "base_seq": marker.base_seq,
        "produced_at": marker.produced_at,
        "backend": marker.backend,
        "cards": marker.cards,
        "ledger": {
            "path": marker.ledger.path,
            "prior_file_bytes": marker.ledger.prior_file_bytes,
            "prior_file_blake3": marker.ledger.prior_file_blake3,
        },
    })
}

fn marker_transaction_id(marker: &SignalCardTransactionMarker) -> Result<String, DynError> {
    Ok(sha256_hex(&serde_json::to_vec(&marker_identity(marker))?))
}

pub(crate) fn signal_card_transaction_key(project: &str) -> String {
    metadata_key(project, SIGNAL_CARD_TRANSACTION_SUFFIX)
}

impl SignalCardTransactionPlan {
    pub(crate) fn build(
        context: SignalCardTransactionContext<'_>,
        prepared_ledger: &astrolabe_assay::PreparedAssayCardBatch,
        published_ledger_path: &Path,
    ) -> Result<Self, DynError> {
        let SignalCardTransactionContext {
            project,
            vault_id,
            panel_version,
            base_seq,
            produced_at,
            backend,
        } = context;
        if prepared_ledger.entries.len() != prepared_ledger.lines.len() {
            return Err("ASTRO_ASSAY_SIGNAL_TXN_PLAN_INVALID: prepared ledger entries and physical lines differ in count".into());
        }
        let mut rows = Vec::with_capacity(prepared_ledger.entries.len());
        let mut bindings = Vec::with_capacity(prepared_ledger.entries.len());
        let mut config_keys = BTreeSet::new();
        for (entry, line) in prepared_ledger.entries.iter().zip(&prepared_ledger.lines) {
            if entry.seq != line.seq || entry.entry_hash != line.entry_hash {
                return Err(format!(
                    "ASTRO_ASSAY_SIGNAL_TXN_PLAN_INVALID: ledger entry seq {} disagrees with its physical line receipt",
                    entry.seq
                )
                .into());
            }
            if entry.card.axis.is_empty() {
                return Err(
                    "ASTRO_ASSAY_SIGNAL_TXN_PLAN_INVALID: signal card axis is empty".into(),
                );
            }
            let trust = if entry.card.signals.iter().any(|signal| signal.provisional) {
                "provisional"
            } else {
                "trusted"
            };
            let key = measure_bits_card_key(project, "signals", Some(&entry.card.axis), None);
            if !config_keys.insert(key.clone()) {
                return Err(format!(
                    "ASTRO_ASSAY_SIGNAL_TXN_PLAN_INVALID: axis {:?} maps to a duplicate config key {key:?}",
                    entry.card.axis
                )
                .into());
            }
            let card_value = serde_json::to_value(&entry.card)?;
            let value = serde_json::to_string(&json!({
                "schema": ASSAY_CARD_SCHEMA,
                "mode": "signals",
                "project": project,
                "axis": entry.card.axis,
                "scope": Value::Null,
                "seq": entry.seq,
                "input_fingerprint": entry.input_fingerprint,
                "produced_at": produced_at,
                "freshness": "fresh",
                "freshness_lag": 0,
                "trust": trust,
                "provenance": [
                    format!("index_time_signal_cards:{project}"),
                    format!("ledger:signal-cards.ndjson#{}", entry.seq),
                    format!("axis:{}", entry.card.axis),
                ],
                "backend": backend.clone(),
                "ledger_ref": {
                    "seq": entry.seq,
                    "entry_hash": entry.entry_hash,
                    "offset": line.offset,
                    "bytes": line.bytes,
                    "line_blake3": line.line_blake3,
                },
                "card": card_value,
            }))?;
            let card_bytes = serde_json::to_vec(&entry.card)?;
            bindings.push(SignalCardBinding {
                axis: entry.card.axis.clone(),
                input_fingerprint: entry.input_fingerprint.clone(),
                card_sha256: sha256_hex(&card_bytes),
                config_key: key.clone(),
                config_value_sha256: sha256_hex(value.as_bytes()),
                ledger_seq: entry.seq,
                ledger_entry_hash: entry.entry_hash.clone(),
                ledger_line: line.clone(),
            });
            rows.push(SignalCardConfigRow { key, value });
        }
        let ledger_path = published_ledger_path.to_string_lossy().into_owned();
        let mut prepared = SignalCardTransactionMarker {
            schema: SIGNAL_CARD_TRANSACTION_SCHEMA.to_string(),
            state: "prepared".to_string(),
            transaction_id: String::new(),
            project: project.to_string(),
            vault_id: vault_id.to_string(),
            panel_version,
            base_seq,
            produced_at,
            backend,
            cards: bindings,
            ledger: SignalCardLedgerState {
                path: ledger_path,
                prior_file_bytes: prepared_ledger.prior_file_bytes,
                prior_file_blake3: prepared_ledger.prior_file_blake3.clone(),
                file_bytes: None,
                file_blake3: None,
            },
        };
        prepared.transaction_id = marker_transaction_id(&prepared)?;
        Ok(Self { prepared, rows })
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.prepared.transaction_id
    }

    pub(crate) fn prepared_marker(&self) -> &SignalCardTransactionMarker {
        &self.prepared
    }

    pub(crate) fn committed_marker(
        &self,
        receipt: &astrolabe_assay::AssayCardBatchReceipt,
    ) -> Result<SignalCardTransactionMarker, DynError> {
        if receipt.entries.len() != self.prepared.cards.len()
            || receipt.lines.len() != self.prepared.cards.len()
        {
            return Err("ASTRO_ASSAY_SIGNAL_TXN_LEDGER_READBACK_MISMATCH: ledger receipt count differs from the prepared transaction".into());
        }
        for ((binding, entry), line) in self
            .prepared
            .cards
            .iter()
            .zip(&receipt.entries)
            .zip(&receipt.lines)
        {
            if binding.ledger_seq != entry.seq
                || binding.ledger_entry_hash != entry.entry_hash
                || binding.ledger_line != *line
            {
                return Err("ASTRO_ASSAY_SIGNAL_TXN_LEDGER_READBACK_MISMATCH: published ledger identity differs from the prepared transaction".into());
            }
        }
        let mut committed = self.prepared.clone();
        committed.state = "committed".to_string();
        committed.ledger.file_bytes = Some(receipt.file_bytes);
        committed.ledger.file_blake3 = Some(receipt.file_blake3.clone());
        Ok(committed)
    }
}

fn configure_signal_transaction_connection(conn: &Connection, path: &Path) -> Result<(), DynError> {
    conn.pragma_update(None, "synchronous", "FULL")?;
    let synchronous: u32 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 2 {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_SQLITE_DURABILITY_INVALID: {} reported PRAGMA synchronous={synchronous}, expected FULL(2)",
            path.join("_config.db").display()
        )
        .into());
    }
    Ok(())
}

fn parse_marker(raw: &str, project: &str) -> Result<SignalCardTransactionMarker, DynError> {
    let marker: SignalCardTransactionMarker = serde_json::from_str(raw).map_err(|error| {
        format!(
            "ASTRO_ASSAY_SIGNAL_TXN_MARKER_CORRUPT: project {project:?} marker is invalid: {error}; preserve the row and use the explicit recovery protocol"
        )
    })?;
    if marker.schema != SIGNAL_CARD_TRANSACTION_SCHEMA || marker.project != project {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_MARKER_CORRUPT: project {project:?} marker schema/project identity mismatch; preserve the row and use the explicit recovery protocol"
        )
        .into());
    }
    let recomputed = marker_transaction_id(&marker)?;
    if marker.transaction_id != recomputed {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_MARKER_CORRUPT: project {project:?} transaction_id {} does not match recomputed {recomputed}; preserve the row and use the explicit recovery protocol",
            marker.transaction_id
        )
        .into());
    }
    if marker.backend != SignalCardBackendIdentity::shipping_cpu() {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_BACKEND_UNAVAILABLE: project {project:?} marker names an uncommissioned backend identity; no backend fallback is permitted"
        )
        .into());
    }
    Ok(marker)
}

pub(crate) fn persist_signal_card_prepared(
    cache_dir: &Path,
    marker: &SignalCardTransactionMarker,
) -> Result<SignalCardPrepareDisposition, DynError> {
    let key = signal_card_transaction_key(&marker.project);
    let serialized = serde_json::to_string(marker)?;
    let mut conn = open_config(cache_dir)?;
    configure_signal_transaction_connection(&conn, cache_dir)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing: Option<String> = transaction
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params![&key],
            |row| row.get(0),
        )
        .optional()?;
    let disposition = match existing {
        None => {
            transaction.execute(
                "INSERT INTO config (key, value) VALUES (?, ?)",
                params![&key, &serialized],
            )?;
            SignalCardPrepareDisposition::PreparedWritten
        }
        Some(raw) => {
            let observed = parse_marker(&raw, &marker.project)?;
            match observed.state.as_str() {
                "prepared" if observed == *marker => SignalCardPrepareDisposition::PreparedResumed,
                "prepared" => {
                    return Err(format!(
                        "ASTRO_ASSAY_SIGNAL_TXN_INCOMPLETE: project {:?} has prepared transaction {} but the requested transaction is {}; preserve both identities and use the explicit recovery protocol",
                        marker.project, observed.transaction_id, marker.transaction_id
                    )
                    .into());
                }
                "committed" if observed.transaction_id == marker.transaction_id => {
                    SignalCardPrepareDisposition::AlreadyCommitted
                }
                "committed" => {
                    transaction.execute(
                        "UPDATE config SET value = ? WHERE key = ?",
                        params![&serialized, &key],
                    )?;
                    SignalCardPrepareDisposition::PreparedWritten
                }
                state => {
                    return Err(format!(
                        "ASTRO_ASSAY_SIGNAL_TXN_MARKER_CORRUPT: project {:?} marker has unknown state {state:?}; preserve it and use the explicit recovery protocol",
                        marker.project
                    )
                    .into());
                }
            }
        }
    };
    transaction.commit()?;

    let readback = read_config_value(cache_dir, &key)?.ok_or_else(|| -> DynError {
        "ASTRO_ASSAY_SIGNAL_TXN_PREPARED_READBACK_MISSING: prepared marker was not independently readable after commit".into()
    })?;
    let observed = parse_marker(&readback, &marker.project)?;
    match disposition {
        SignalCardPrepareDisposition::AlreadyCommitted
            if observed.state == "committed"
                && observed.transaction_id == marker.transaction_id => {}
        _ if readback == serialized => {}
        _ => {
            return Err("ASTRO_ASSAY_SIGNAL_TXN_PREPARED_READBACK_MISMATCH: independently read marker differs from the committed prepared state".into());
        }
    }
    Ok(disposition)
}

pub(crate) fn commit_signal_card_transaction(
    cache_dir: &Path,
    plan: &SignalCardTransactionPlan,
    committed: &SignalCardTransactionMarker,
) -> Result<(), DynError> {
    if committed.state != "committed" || committed.transaction_id != plan.prepared.transaction_id {
        return Err("ASTRO_ASSAY_SIGNAL_TXN_COMMIT_PLAN_INVALID: committed marker identity/state differs from its prepared plan".into());
    }
    let marker_key = signal_card_transaction_key(&plan.prepared.project);
    let prepared_serialized = serde_json::to_string(&plan.prepared)?;
    let committed_serialized = serde_json::to_string(committed)?;
    let mut conn = open_config(cache_dir)?;
    configure_signal_transaction_connection(&conn, cache_dir)?;
    let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let raw: String = transaction.query_row(
        "SELECT value FROM config WHERE key = ?",
        params![&marker_key],
        |row| row.get(0),
    )?;
    let observed = parse_marker(&raw, &plan.prepared.project)?;
    let already_committed =
        observed.state == "committed" && observed.transaction_id == plan.prepared.transaction_id;
    if !already_committed && raw != prepared_serialized {
        return Err("ASTRO_ASSAY_SIGNAL_TXN_COMMIT_PRECONDITION_FAILED: current marker is neither the exact prepared transaction nor its committed replay".into());
    }
    if !already_committed {
        let escaped_prefix = measure_bits_card_key(&plan.prepared.project, "signals", None, None)
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let prefix = format!("{escaped_prefix}%");
        transaction.execute(
            "DELETE FROM config WHERE key LIKE ? ESCAPE '\\'",
            params![prefix],
        )?;
        for row in &plan.rows {
            transaction.execute(
                "INSERT INTO config (key, value) VALUES (?, ?)",
                params![&row.key, &row.value],
            )?;
        }
        transaction.execute(
            "UPDATE config SET value = ? WHERE key = ?",
            params![&committed_serialized, &marker_key],
        )?;
    }
    transaction.commit()?;

    let mut keys = Vec::with_capacity(plan.rows.len() + 1);
    keys.push(marker_key);
    keys.extend(plan.rows.iter().map(|row| row.key.clone()));
    let readback = read_config_values(cache_dir, &keys)?;
    if readback.first().and_then(Option::as_deref) != Some(committed_serialized.as_str()) {
        return Err("ASTRO_ASSAY_SIGNAL_TXN_COMMIT_READBACK_MISMATCH: committed marker differs on independent SQLite readback".into());
    }
    for (row, observed) in plan.rows.iter().zip(readback.iter().skip(1)) {
        if observed.as_deref() != Some(row.value.as_str()) {
            return Err(format!(
                "ASTRO_ASSAY_SIGNAL_TXN_COMMIT_READBACK_MISMATCH: config row {:?} differs on independent SQLite readback",
                row.key
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn read_committed_signal_card_state(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<CommittedSignalCardState>, DynError> {
    let marker_key = signal_card_transaction_key(project);
    let Some(raw) = read_config_value(cache_dir, &marker_key)? else {
        let legacy_rows = scan_config_prefix(
            cache_dir,
            &measure_bits_card_key(project, "signals", None, None),
        )?;
        if legacy_rows.is_empty() {
            classify_preserved_signal_card_state(cache_dir, project, &marker_key)?;
            return Ok(None);
        }
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_MARKER_MISSING: project {project:?} has {} signal-card rows but no transaction marker; preserve the legacy/split state and reindex through #885",
            legacy_rows.len()
        )
        .into());
    };
    let marker = parse_marker(&raw, project)?;
    if marker.state != "committed" {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_INCOMPLETE: project {project:?} transaction {} is {}; preserve the marker and ledger for explicit recovery",
            marker.transaction_id, marker.state
        )
        .into());
    }
    let keys = marker
        .cards
        .iter()
        .map(|binding| binding.config_key.clone())
        .collect::<Vec<_>>();
    let physical_rows = scan_config_prefix(
        cache_dir,
        &measure_bits_card_key(project, "signals", None, None),
    )?;
    let expected_keys = keys.iter().cloned().collect::<BTreeSet<_>>();
    let physical_keys = physical_rows
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    if physical_rows.len() != keys.len() || physical_keys != expected_keys {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_CONFIG_SET_MISMATCH: committed transaction {} binds {} rows but the physical signal-card prefix contains {}; preserve the database and reindex through the #885 producer",
            marker.transaction_id,
            keys.len(),
            physical_rows.len()
        )
        .into());
    }
    let values = read_config_values(cache_dir, &keys)?;
    let mut rows = Vec::with_capacity(keys.len());
    for ((binding, key), value) in marker.cards.iter().zip(&keys).zip(values) {
        let value = value.ok_or_else(|| -> DynError {
            format!(
                "ASTRO_ASSAY_SIGNAL_TXN_CONFIG_ROW_MISSING: committed transaction {} has no row {key:?}",
                marker.transaction_id
            )
            .into()
        })?;
        if sha256_hex(value.as_bytes()) != binding.config_value_sha256 {
            return Err(format!(
                "ASTRO_ASSAY_SIGNAL_TXN_CONFIG_HASH_MISMATCH: committed row {key:?} differs from transaction {}",
                marker.transaction_id
            )
            .into());
        }
        rows.push((key.clone(), value));
    }

    let expected_file_bytes = marker.ledger.file_bytes.ok_or_else(|| -> DynError {
        "ASTRO_ASSAY_SIGNAL_TXN_MARKER_CORRUPT: committed marker has no final ledger byte count"
            .into()
    })?;
    let mut ledger = File::open(&marker.ledger.path).map_err(|error| -> DynError {
        format!(
            "ASTRO_ASSAY_SIGNAL_TXN_LEDGER_MISSING: cannot open committed ledger {}: {error}",
            marker.ledger.path
        )
        .into()
    })?;
    let observed_file_bytes = ledger.metadata()?.len();
    if observed_file_bytes != expected_file_bytes {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_LEDGER_SIZE_MISMATCH: committed ledger {} has {observed_file_bytes} bytes, marker expects {expected_file_bytes}",
            marker.ledger.path
        )
        .into());
    }
    for binding in &marker.cards {
        ledger.seek(SeekFrom::Start(binding.ledger_line.offset))?;
        let line_bytes = usize::try_from(binding.ledger_line.bytes)?;
        let mut line = vec![0_u8; line_bytes];
        ledger.read_exact(&mut line)?;
        if blake3::hash(&line).to_hex().to_string() != binding.ledger_line.line_blake3
            || !line.ends_with(b"\n")
        {
            return Err(format!(
                "ASTRO_ASSAY_SIGNAL_TXN_LEDGER_LINE_MISMATCH: seq {} physical line hash/termination differs from transaction {}",
                binding.ledger_seq, marker.transaction_id
            )
            .into());
        }
        let entry: astrolabe_assay::AssayCardEntry =
            serde_json::from_slice(&line[..line.len() - 1])?;
        if entry.seq != binding.ledger_seq
            || entry.entry_hash != binding.ledger_entry_hash
            || entry.input_fingerprint != binding.input_fingerprint
            || sha256_hex(&serde_json::to_vec(&entry.card)?) != binding.card_sha256
        {
            return Err(format!(
                "ASTRO_ASSAY_SIGNAL_TXN_LEDGER_ENTRY_MISMATCH: seq {} content differs from transaction {}",
                binding.ledger_seq, marker.transaction_id
            )
            .into());
        }
    }
    Ok(Some(CommittedSignalCardState {
        marker: serde_json::to_value(&marker)?,
        rows,
    }))
}

/// Refuses when a canonical absence is explained by a preserved failed
/// publication. The slot is validated once and queried through one immutable
/// SQLite connection, so reading the diagnostic state cannot add WAL/SHM bytes
/// to the evidence directory.
fn classify_preserved_signal_card_state(
    cache_dir: &Path,
    project: &str,
    marker_key: &str,
) -> Result<(), DynError> {
    let Some((connection, _retained_config)) =
        open_validated_preserved_stage_config(cache_dir, project)?
    else {
        return Ok(());
    };
    let marker_raw = connection
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params![marker_key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ASSAY_SIGNAL_TXN_PRESERVED_CONFIG_READ_FAILED: reading marker {marker_key:?} from the validated preserved config failed: {error}; remediation: preserve the slot and inspect its SQLite integrity"
            )
            .into()
        })?;

    let prefix = measure_bits_card_key(project, "signals", None, None);
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("{escaped}%");
    let physical_card_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM config WHERE key LIKE ? ESCAPE '\\'",
            params![pattern],
            |row| row.get(0),
        )
        .map_err(|error| -> DynError {
            format!(
                "ASTRO_ASSAY_SIGNAL_TXN_PRESERVED_CONFIG_READ_FAILED: counting signal-card rows for project {project:?} in the validated preserved config failed: {error}; remediation: preserve the slot and inspect its SQLite integrity"
            )
            .into()
        })?;

    let Some(raw) = marker_raw else {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_PRESERVED_STAGE_INCOMPLETE: canonical signal state for project {project:?} is absent, but its validated preserved failed publication has no transaction marker and physical_card_count={physical_card_count}; remediation: preserve the complete slot and inspect the recorded abort before explicitly rebuilding"
        )
        .into());
    };
    let marker = parse_marker(&raw, project)?;
    if marker.state != "committed" {
        return Err(format!(
            "ASTRO_ASSAY_SIGNAL_TXN_INCOMPLETE: canonical signal state for project {project:?} is absent; validated preserved transaction {} is {} with physical_card_count={physical_card_count}; preserve the marker and ledger for explicit recovery",
            marker.transaction_id, marker.state
        )
        .into());
    }
    Err(format!(
        "ASTRO_ASSAY_SIGNAL_TXN_UNPUBLISHED: canonical signal state for project {project:?} is absent, but validated preserved transaction {} is internally committed with physical_card_count={physical_card_count}; preserve the slot and reconcile the failed outer publication before serving it",
        marker.transaction_id
    )
    .into())
}
